// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// diskDir returns a directory on a filesystem with a medium behind its page
// cache: the test's temp dir if it is one, else this package's own directory
// (a checkout is never on a memory filesystem). It fails rather than skips if
// neither is, because the O_DIRECT path would then go unexercised.
func diskDir(t *testing.T) string {
	t.Helper()

	for _, candidate := range []string{t.TempDir(), "."} {
		memory, err := cacheIsTheStorage(candidate)
		if err != nil {
			t.Fatalf("cacheIsTheStorage(%s): %v", candidate, err)
		}
		if memory {
			continue
		}
		dir, err := os.MkdirTemp(candidate, "medium-test-")
		if err != nil {
			t.Fatalf("MkdirTemp: %v", err)
		}
		// Device paths must be absolute (ValidateDevicePath).
		if dir, err = filepath.Abs(dir); err != nil {
			t.Fatalf("Abs: %v", err)
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(dir); err != nil {
				t.Errorf("removing %s: %v", dir, err)
			}
		})
		return dir
	}
	t.Fatal("neither the temp dir nor the package directory is on a disk filesystem; the O_DIRECT path cannot be exercised")
	return ""
}

// memoryDir returns a directory on tmpfs.
func memoryDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("/dev/shm", "medium-test-")
	if err != nil {
		t.Fatalf("MkdirTemp in /dev/shm: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("removing %s: %v", dir, err)
		}
	})
	memory, err := cacheIsTheStorage(dir)
	if err != nil || !memory {
		t.Fatalf("/dev/shm is not a memory filesystem here (%v, %v); the fallback cannot be exercised", memory, err)
	}
	return dir
}

// patternFile writes n patterned bytes to a new file in dir.
func patternFile(t *testing.T, dir string, n int) (string, []byte) {
	t.Helper()

	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i*7 + 3)
	}
	path := filepath.Join(dir, "device.img")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path, data
}

// TestReadDirectAtReadsTheBytes: a direct read returns the device's bytes from
// any offset, aligned or not, up to the length asked for or the end of the
// device, on a disk filesystem and on a memory one.
func TestReadDirectAtReadsTheBytes(t *testing.T) {
	for name, dir := range map[string]func(*testing.T) string{"disk": diskDir, "memory": memoryDir} {
		t.Run(name, func(t *testing.T) {
			path, data := patternFile(t, dir(t), 3*directIOAlign+100)
			for _, c := range []struct {
				off int64
				n   int
			}{{0, directIOAlign}, {0, len(data)}, {0, len(data) + 5000}, {directIOAlign, 100}, {513, 2 * directIOAlign}, {int64(len(data)) + 10, 10}} {
				got, err := readDirectAt(path, c.off, c.n)
				if err != nil {
					t.Fatalf("readDirectAt(%d, %d): %v", c.off, c.n, err)
				}
				var want []byte
				if c.off < int64(len(data)) {
					want = data[c.off:min(int(c.off)+c.n, len(data))]
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("readDirectAt(%d, %d) returned %d bytes that differ from the %d expected", c.off, c.n, len(got), len(want))
				}
			}
		})
	}
}

// TestReadDirectAtWhereODirectIsRefused: on a memory filesystem the cache is
// the storage and an ordinary read stands in; anywhere else the read is
// refused with ErrDirectIOUnsupported rather than reported as confirmed.
func TestReadDirectAtWhereODirectIsRefused(t *testing.T) {
	previous := openFileFunc
	t.Cleanup(func() { openFileFunc = previous })
	openFileFunc = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		if flag&unix.O_DIRECT != 0 {
			return nil, &os.PathError{Op: "open", Path: name, Err: unix.EINVAL}
		}
		return previous(name, flag, perm)
	}

	disk, _ := patternFile(t, diskDir(t), directIOAlign)
	if _, err := readDirectAt(disk, 0, directIOAlign); !errors.Is(err, ErrDirectIOUnsupported) {
		t.Fatalf("on a disk filesystem: got %v, want ErrDirectIOUnsupported", err)
	}

	memory, data := patternFile(t, memoryDir(t), directIOAlign)
	got, err := readDirectAt(memory, 100, 200)
	if err != nil || !bytes.Equal(got, data[100:300]) {
		t.Fatalf("on a memory filesystem: got %d bytes, %v; want the file's bytes", len(got), err)
	}

	if _, err := readDirectAt(filepath.Join(t.TempDir(), "absent.img"), 0, directIOAlign); err == nil {
		t.Fatal("readDirectAt of a missing device reported success")
	}
}

// TestCacheIsTheStorage: memory filesystems yes, disk no, a missing path is an
// error.
func TestCacheIsTheStorage(t *testing.T) {
	if memory, err := cacheIsTheStorage(diskDir(t)); err != nil || memory {
		t.Fatalf("disk dir: %v, %v", memory, err)
	}
	if memory, err := cacheIsTheStorage(memoryDir(t)); err != nil || !memory {
		t.Fatalf("/dev/shm: %v, %v", memory, err)
	}
	if _, err := cacheIsTheStorage(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("a missing path reported a filesystem")
	}
}

// fakeSysfs is a /sys/dev/block tree for devices a test cannot create, and the
// device numbers of the paths that stand for them.
type fakeSysfs struct {
	t    *testing.T
	root string
	rdev map[string]uint64
}

func newFakeSysfs(t *testing.T) *fakeSysfs {
	t.Helper()

	f := &fakeSysfs{t: t, root: t.TempDir(), rdev: map[string]uint64{}}
	previousRoot, previousRdev := sysDevBlockRoot, nodeRdev
	t.Cleanup(func() { sysDevBlockRoot, nodeRdev = previousRoot, previousRdev })
	sysDevBlockRoot = filepath.Join(f.root, "dev", "block")
	nodeRdev = func(path string) (uint64, error) {
		if rdev, ok := f.rdev[path]; ok {
			return rdev, nil
		}
		return previousRdev(path)
	}
	if err := os.MkdirAll(sysDevBlockRoot, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	return f
}

// device registers path as block device major:minor whose sysfs directory is
// devices/<name> (a nested path for a partition), linked from dev/block.
func (f *fakeSysfs) device(path string, major, minor uint32, name string) string {
	f.t.Helper()

	dir := filepath.Join(f.root, "devices", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Symlink(dir, filepath.Join(sysDevBlockRoot, fmt.Sprintf("%d:%d", major, minor))); err != nil {
		f.t.Fatalf("Symlink: %v", err)
	}
	f.rdev[path] = unix.Mkdev(major, minor)
	return dir
}

// loop makes dir a loop device over backing with the given direct-I/O flag
// and offset.
func (f *fakeSysfs) loop(dir, backing, dio, offset string) {
	f.t.Helper()

	if err := os.MkdirAll(filepath.Join(dir, "loop"), 0o755); err != nil {
		f.t.Fatalf("MkdirAll: %v", err)
	}
	for name, value := range map[string]string{"backing_file": backing + "\n", "dio": dio + "\n", "offset": offset + "\n"} {
		if value == "\n" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, "loop", name), []byte(value), 0o600); err != nil {
			f.t.Fatalf("WriteFile: %v", err)
		}
	}
}

// slave links slaveDir as a slave of dir.
func (f *fakeSysfs) slave(dir, slaveDir string) {
	f.t.Helper()

	if err := os.MkdirAll(filepath.Join(dir, "slaves"), 0o755); err != nil {
		f.t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Symlink(slaveDir, filepath.Join(dir, "slaves", filepath.Base(slaveDir))); err != nil {
		f.t.Fatalf("Symlink: %v", err)
	}
}

// TestMediumSourcesWalksTheStack: where a device's bytes must be read past a
// cache, for each kind of device the stack can hold.
func TestMediumSourcesWalksTheStack(t *testing.T) {
	file := filepath.Join(t.TempDir(), "plain.img")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Run("a regular file is its own medium", func(t *testing.T) {
		got, err := mediumSources(file)
		if err != nil || !slices.Equal(got, []mediumSource{{path: file}}) {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("a loop device with direct I/O adds its backing too", func(t *testing.T) {
		f := newFakeSysfs(t)
		f.loop(f.device("/dev/loop0", 7, 0, "loop0"), file, "1", "1024")
		got, err := mediumSources("/dev/loop0")
		if err != nil || !slices.Equal(got, []mediumSource{{path: "/dev/loop0"}, {path: file, offset: 1024}}) {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("a direct-I/O loop device over a buffered one reaches the file below both", func(t *testing.T) {
		f := newFakeSysfs(t)
		f.loop(f.device("/dev/loop1", 7, 1, "loop1"), file, "0", "512")
		f.loop(f.device("/dev/loop0", 7, 0, "loop0"), "/dev/loop1", "1", "4096")
		got, err := mediumSources("/dev/loop0")
		want := []mediumSource{{path: "/dev/loop0"}, {path: "/dev/loop1", offset: 4096}, {path: file, offset: 4608}}
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("got %v, %v; want %v", got, err, want)
		}
	})
	t.Run("a mapping over a direct-I/O loop device over a buffered one is refused", func(t *testing.T) {
		f := newFakeSysfs(t)
		f.loop(f.device("/dev/loop1", 7, 1, "loop1"), file, "0", "0")
		outer := f.device("/dev/loop0", 7, 0, "loop0")
		f.loop(outer, "/dev/loop1", "1", "0")
		f.slave(f.device("/dev/dm-0", 253, 0, "dm-0"), outer)
		if _, err := mediumSources("/dev/dm-0"); !errors.Is(err, ErrDirectIOUnsupported) || !strings.Contains(err.Error(), "loop1") {
			t.Fatalf("got %v, want ErrDirectIOUnsupported naming loop1", err)
		}
	})
	t.Run("a mapping over two direct-I/O loop devices over a buffered one is refused", func(t *testing.T) {
		f := newFakeSysfs(t)
		f.loop(f.device("/dev/loop2", 7, 2, "loop2"), file, "0", "0")
		f.loop(f.device("/dev/loop1", 7, 1, "loop1"), "/dev/loop2", "1", "0")
		outer := f.device("/dev/loop0", 7, 0, "loop0")
		f.loop(outer, "/dev/loop1", "1", "0")
		f.slave(f.device("/dev/dm-0", 253, 0, "dm-0"), outer)
		if _, err := mediumSources("/dev/dm-0"); !errors.Is(err, ErrDirectIOUnsupported) || !strings.Contains(err.Error(), "loop2") {
			t.Fatalf("got %v, want ErrDirectIOUnsupported naming loop2", err)
		}
		got, err := mediumSources("/dev/loop0")
		want := []mediumSource{{path: "/dev/loop0"}, {path: "/dev/loop1"}, {path: "/dev/loop2"}, {path: file}}
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("the stack itself: got %v, %v; want %v", got, err, want)
		}
	})
	t.Run("a mapping over a direct-I/O loop device over a file reaches the medium itself", func(t *testing.T) {
		f := newFakeSysfs(t)
		outer := f.device("/dev/loop0", 7, 0, "loop0")
		f.loop(outer, file, "1", "0")
		f.slave(f.device("/dev/dm-0", 253, 0, "dm-0"), outer)
		got, err := mediumSources("/dev/dm-0")
		if err != nil || !slices.Equal(got, []mediumSource{{path: "/dev/dm-0"}}) {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("a buffered loop device adds its backing file at the loop offset", func(t *testing.T) {
		f := newFakeSysfs(t)
		f.loop(f.device("/dev/loop0", 7, 0, "loop0"), file, "0", "4096")
		got, err := mediumSources("/dev/loop0")
		if err != nil || !slices.Equal(got, []mediumSource{{path: "/dev/loop0"}, {path: file, offset: 4096}}) {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("a buffered loop device over another adds both, offsets summed", func(t *testing.T) {
		f := newFakeSysfs(t)
		f.loop(f.device("/dev/loop1", 7, 1, "loop1"), file, "0", "512")
		f.loop(f.device("/dev/loop0", 7, 0, "loop0"), "/dev/loop1", "0", "4096")
		got, err := mediumSources("/dev/loop0")
		want := []mediumSource{{path: "/dev/loop0"}, {path: "/dev/loop1", offset: 4096}, {path: file, offset: 4608}}
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("got %v, %v; want %v", got, err, want)
		}
	})
	t.Run("a mapping over a buffered loop device is refused", func(t *testing.T) {
		f := newFakeSysfs(t)
		loop := f.device("/dev/loop0", 7, 0, "loop0")
		f.loop(loop, file, "0", "0")
		f.slave(f.device("/dev/dm-0", 253, 0, "dm-0"), loop)
		if _, err := mediumSources("/dev/dm-0"); !errors.Is(err, ErrDirectIOUnsupported) || !strings.Contains(err.Error(), "loop0") {
			t.Fatalf("got %v, want ErrDirectIOUnsupported naming loop0", err)
		}
	})
	t.Run("a mapping over a disk reaches the medium itself", func(t *testing.T) {
		f := newFakeSysfs(t)
		disk := f.device("/dev/sda", 8, 0, "sda")
		f.slave(f.device("/dev/dm-0", 253, 0, "dm-0"), disk)
		got, err := mediumSources("/dev/dm-0")
		if err != nil || !slices.Equal(got, []mediumSource{{path: "/dev/dm-0"}}) {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("a partition of a buffered loop device is refused", func(t *testing.T) {
		f := newFakeSysfs(t)
		f.loop(f.device("/dev/loop0", 7, 0, "loop0"), file, "0", "0")
		part := f.device("/dev/loop0p1", 259, 0, filepath.Join("loop0", "loop0p1"))
		if err := os.WriteFile(filepath.Join(part, "partition"), []byte("1\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := mediumSources("/dev/loop0p1"); !errors.Is(err, ErrDirectIOUnsupported) {
			t.Fatalf("got %v, want ErrDirectIOUnsupported", err)
		}
	})
	t.Run("unreadable loop attributes are errors, not answers", func(t *testing.T) {
		f := newFakeSysfs(t)
		f.loop(f.device("/dev/loop0", 7, 0, "loop0"), file, "", "0")
		if _, err := mediumSources("/dev/loop0"); err == nil {
			t.Fatal("a loop device with no dio attribute was judged")
		}
		f.loop(f.device("/dev/loop1", 7, 1, "loop1"), file, "0", "not-a-number")
		if _, err := mediumSources("/dev/loop1"); err == nil {
			t.Fatal("a loop device with a garbage offset was judged")
		}
		f.device("/dev/dm-0", 253, 0, "dm-0")
		if err := os.WriteFile(filepath.Join(f.root, "devices", "dm-0", "slaves"), []byte("not a directory"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := mediumSources("/dev/dm-0"); err == nil {
			t.Fatal("unlistable slaves were judged")
		}
		if _, err := mediumSources(filepath.Join(t.TempDir(), "absent")); err == nil {
			t.Fatal("a missing device was judged")
		}
	})
}

// TestRequireCacheMatchesMedium: identical reads pass; a cache that differs
// from the medium -- in either header copy, or in a loop device's backing
// file -- is refused, naming where; nothing past the two header copies is
// read; a read that fails is reported.
func TestRequireCacheMatchesMedium(t *testing.T) {
	device := filepath.Join(diskDir(t), "luks.img")
	placeImage(t, device, cryptsetupArgon2Prefix(t, false))
	hdr, _, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	headers := 2 * int64(hdr.HeaderSize)

	previous := readDeviceDirect
	t.Cleanup(func() { readDeviceDirect = previous })
	var furthest int64
	readDeviceDirect = func(path string, off int64, n int) ([]byte, error) {
		furthest = max(furthest, off+int64(n))
		return previous(path, off, n)
	}
	if err := requireCacheMatchesMedium(device); err != nil {
		t.Fatalf("an undisturbed device: %v", err)
	}
	if furthest != headers {
		t.Fatalf("the comparison read up to byte %d; want exactly the two header copies, %d bytes", furthest, headers)
	}

	flip := func(at int64) {
		readDeviceDirect = func(path string, off int64, n int) ([]byte, error) {
			medium, err := previous(path, off, n)
			if err == nil && at >= off && at < off+int64(len(medium)) {
				medium[at-off] ^= 0xff
			}
			return medium, err
		}
	}
	for _, at := range []int64{100, int64(hdr.HeaderSize) + 100} {
		flip(at)
		if err := requireCacheMatchesMedium(device); !errors.Is(err, ErrDeviceCacheStale) ||
			!strings.Contains(err.Error(), fmt.Sprintf("first difference at byte %d", at)) {
			t.Fatalf("a difference at byte %d: got %v", at, err)
		}
	}
	flip(headers + 100)
	if err := requireCacheMatchesMedium(device); err != nil {
		t.Fatalf("a difference past the header copies -- which must not even be read -- was reported: %v", err)
	}

	readDeviceDirect = func(path string, off int64, n int) ([]byte, error) {
		medium, err := previous(path, off, n)
		return medium[:n/2], err
	}
	if err := requireCacheMatchesMedium(device); !errors.Is(err, ErrDeviceCacheStale) {
		t.Fatalf("a shorter medium: got %v, want ErrDeviceCacheStale", err)
	}

	errRead := errors.New("injected: the direct read failed")
	readDeviceDirect = func(string, int64, int) ([]byte, error) { return nil, errRead }
	if err := requireCacheMatchesMedium(device); !errors.Is(err, errRead) {
		t.Fatalf("a failed direct read: got %v", err)
	}
	readDeviceDirect = previous

	t.Run("a loop device's backing file is compared at the loop offset", func(t *testing.T) {
		const offset = 8192
		backing := filepath.Join(diskDir(t), "backing.img")
		image := readPrefix(t, device, headers)
		placeImage(t, backing, append(make([]byte, offset), image...))
		f := newFakeSysfs(t)
		f.loop(f.device(device, 7, 0, "loop0"), backing, "0", fmt.Sprint(offset))
		if err := requireCacheMatchesMedium(device); err != nil {
			t.Fatalf("a backing file holding the same bytes: %v", err)
		}
		image[200] ^= 0xff
		placeImage(t, backing, append(make([]byte, offset), image...))
		if err := requireCacheMatchesMedium(device); !errors.Is(err, ErrDeviceCacheStale) || !strings.Contains(err.Error(), backing) {
			t.Fatalf("a backing file that differs: got %v, want ErrDeviceCacheStale naming it", err)
		}
	})

	t.Run("a device that cannot be resolved is refused", func(t *testing.T) {
		if err := requireCacheMatchesMedium(filepath.Join(t.TempDir(), "absent.img")); err == nil {
			t.Fatal("a missing device reported a match")
		}
	})

	t.Run("a primary whose size is not a header size is left to the reader", func(t *testing.T) {
		plain, _ := patternFile(t, diskDir(t), 4*directIOAlign)
		if err := requireCacheMatchesMedium(plain); err != nil {
			t.Fatalf("got %v", err)
		}
	})
}

// TestMigrateToFIPSNeverReadsTheDataSegmentToCompare is the small-layout
// case: a cryptsetup volume whose data starts 4 MiB in, inside the largest
// legal header span. Every comparison read stays inside the two header
// copies.
func TestMigrateToFIPSNeverReadsTheDataSegmentToCompare(t *testing.T) {
	if fipsMode() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	requireCryptsetup(t)
	pinDigestIterations(t, minPBKDF2Iterations)
	image := newImage(t, "small-layout.img")
	args := append(append([]string{"luksFormat"}, crashFormatArgs...),
		"--luks2-metadata-size", "32k", "--luks2-keyslots-size", "1m", "--offset", "8192", image)
	if code, out := runCryptsetup(t, conformancePassphrase, args...); code != 0 {
		t.Fatalf("cryptsetup luksFormat exited %d\n%s", code, out)
	}
	_, metadata, err := ReadHeader(image)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	dataOffset, err := parseSize(metadata.Segments["0"].Offset)
	if err != nil || dataOffset != 4<<20 {
		t.Fatalf("data offset %d (%v), want the 4 MiB the fixture asks for", dataOffset, err)
	}

	previous := readDeviceDirect
	t.Cleanup(func() { readDeviceDirect = previous })
	var furthest int64
	readDeviceDirect = func(path string, off int64, n int) ([]byte, error) {
		furthest = max(furthest, off+int64(n))
		return previous(path, off, n)
	}
	result, err := MigrateToFIPS(image, migrationPassphrase, cheapMigration())
	if err != nil || !result.Complete {
		t.Fatalf("MigrateToFIPS: %+v, %v", result, err)
	}
	if furthest == 0 || furthest > 2*(32<<10) {
		t.Fatalf("the comparison read up to byte %d; want it confined to the two 32 KiB header copies", furthest)
	}
}

// TestIsMemoryFilesystemMagic: tmpfs and ramfs, and nothing else -- including
// RAMFS_MAGIC, whose high bit is set, so it survives the int32 Statfs_t.Type
// of the 32-bit targets as the same 32 bits.
func TestIsMemoryFilesystemMagic(t *testing.T) {
	// The ramfs magic as the int32 f_type field of the 32-bit targets holds
	// it: a variable, as that field is, not a constant the compiler folds.
	var ramfsAsInt32 int32 = -2054924042
	for _, tc := range []struct {
		name  string
		magic uint32
		want  bool
	}{
		{"tmpfs", uint32(unix.TMPFS_MAGIC), true},
		{"ramfs", uint32(unix.RAMFS_MAGIC), true},
		{"ramfs through an int32 field", uint32(ramfsAsInt32), true}, // #nosec G115 -- the conversion under test
		{"ext4", uint32(unix.EXT4_SUPER_MAGIC), false},
		{"xfs", uint32(unix.XFS_SUPER_MAGIC), false},
		{"overlayfs", uint32(unix.OVERLAYFS_SUPER_MAGIC), false},
		{"zero", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isMemoryFilesystemMagic(tc.magic); got != tc.want {
				t.Fatalf("isMemoryFilesystemMagic(%#x) = %v, want %v", tc.magic, got, tc.want)
			}
		})
	}
}
