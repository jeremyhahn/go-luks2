// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// These exercise the real O_DIRECT reads, the sysfs loop-device walk and the
// memory-filesystem probe, which exist only on Linux (medium_linux.go); the
// medium_other.go sibling has nothing of this shape to test off Linux.

package device

import (
	"bytes"
	"context"
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
		memory, err := CacheIsTheStorage(candidate)
		if err != nil {
			t.Fatalf("CacheIsTheStorage(%s): %v", candidate, err)
		}
		if memory {
			continue
		}
		dir, err := os.MkdirTemp(candidate, "medium-test-")
		if err != nil {
			t.Fatalf("MkdirTemp: %v", err)
		}
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
	memory, err := CacheIsTheStorage(dir)
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

// TestReadPastCacheWhereODirectIsRefused: on a memory filesystem the cache is
// the storage and an ordinary read stands in; anywhere else the read is
// refused with ErrUnsupported rather than reported as confirmed.
func TestReadPastCacheWhereODirectIsRefused(t *testing.T) {
	refuseDirect := func(name string, flag int, perm os.FileMode) (*os.File, error) {
		if flag&unix.O_DIRECT != 0 {
			return nil, &os.PathError{Op: "open", Path: name, Err: unix.EINVAL}
		}
		return os.OpenFile(name, flag, perm)
	}

	disk, _ := patternFile(t, diskDir(t), directIOAlign)
	if _, err := ReadPastCache(context.Background(), "op", disk, 0, directIOAlign, refuseDirect); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("on a disk filesystem: got %v, want ErrUnsupported", err)
	}

	memory, data := patternFile(t, memoryDir(t), directIOAlign)
	got, err := ReadPastCache(context.Background(), "op", memory, 100, 200, refuseDirect)
	if err != nil || !bytes.Equal(got, data[100:300]) {
		t.Fatalf("on a memory filesystem: got %d bytes, %v; want the file's bytes", len(got), err)
	}

	if _, err := ReadPastCache(context.Background(), "op", filepath.Join(t.TempDir(), "absent.img"), 0, directIOAlign, refuseDirect); err == nil {
		t.Fatal("ReadPastCache of a missing device reported success")
	}
}

// fakeSysfs is a /sys/dev/block tree for devices a test cannot create, and
// the device numbers of the paths that stand for them.
type fakeSysfs struct {
	t    *testing.T
	root string
	rdev map[string]uint64
}

func newFakeSysfs(t *testing.T) *fakeSysfs {
	t.Helper()
	return &fakeSysfs{t: t, root: t.TempDir(), rdev: map[string]uint64{}}
}

func (f *fakeSysfs) blockRoot() string { return filepath.Join(f.root, "dev", "block") }

func (f *fakeSysfs) statRdev(path string) (uint64, error) {
	if rdev, ok := f.rdev[path]; ok {
		return rdev, nil
	}
	return StatRdev(path)
}

// device registers path as block device major:minor whose sysfs directory is
// devices/<name> (a nested path for a partition), linked from dev/block.
func (f *fakeSysfs) device(path string, major, minor uint32, name string) string {
	f.t.Helper()

	dir := filepath.Join(f.root, "devices", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.MkdirAll(f.blockRoot(), 0o755); err != nil {
		f.t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Symlink(dir, filepath.Join(f.blockRoot(), fmt.Sprintf("%d:%d", major, minor))); err != nil {
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

func (f *fakeSysfs) sources(path string) ([]MediumSource, error) {
	return MediumSources(path, f.blockRoot(), f.statRdev)
}

// TestMediumSourcesWalksTheStack: where a device's bytes must be read past a
// cache, for each kind of device the stack can hold.
func TestMediumSourcesWalksTheStack(t *testing.T) {
	file := filepath.Join(t.TempDir(), "plain.img")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Run("a regular file is its own medium", func(t *testing.T) {
		got, err := MediumSources(file, DefaultSysDevBlockRoot, StatRdev)
		if err != nil || !slices.Equal(got, []MediumSource{{Path: file}}) {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("a loop device with direct I/O adds its backing too", func(t *testing.T) {
		f := newFakeSysfs(t)
		f.loop(f.device("/dev/loop0", 7, 0, "loop0"), file, "1", "1024")
		got, err := f.sources("/dev/loop0")
		if err != nil || !slices.Equal(got, []MediumSource{{Path: "/dev/loop0"}, {Path: file, Offset: 1024}}) {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("a direct-I/O loop device over a buffered one reaches the file below both", func(t *testing.T) {
		f := newFakeSysfs(t)
		f.loop(f.device("/dev/loop1", 7, 1, "loop1"), file, "0", "512")
		f.loop(f.device("/dev/loop0", 7, 0, "loop0"), "/dev/loop1", "1", "4096")
		got, err := f.sources("/dev/loop0")
		want := []MediumSource{{Path: "/dev/loop0"}, {Path: "/dev/loop1", Offset: 4096}, {Path: file, Offset: 4608}}
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
		if _, err := f.sources("/dev/dm-0"); !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "loop1") {
			t.Fatalf("got %v, want ErrUnsupported naming loop1", err)
		}
	})
	t.Run("a mapping over two direct-I/O loop devices over a buffered one is refused", func(t *testing.T) {
		f := newFakeSysfs(t)
		f.loop(f.device("/dev/loop2", 7, 2, "loop2"), file, "0", "0")
		f.loop(f.device("/dev/loop1", 7, 1, "loop1"), "/dev/loop2", "1", "0")
		outer := f.device("/dev/loop0", 7, 0, "loop0")
		f.loop(outer, "/dev/loop1", "1", "0")
		f.slave(f.device("/dev/dm-0", 253, 0, "dm-0"), outer)
		if _, err := f.sources("/dev/dm-0"); !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "loop2") {
			t.Fatalf("got %v, want ErrUnsupported naming loop2", err)
		}
		got, err := f.sources("/dev/loop0")
		want := []MediumSource{{Path: "/dev/loop0"}, {Path: "/dev/loop1"}, {Path: "/dev/loop2"}, {Path: file}}
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("the stack itself: got %v, %v; want %v", got, err, want)
		}
	})
	t.Run("a mapping over a direct-I/O loop device over a file reaches the medium itself", func(t *testing.T) {
		f := newFakeSysfs(t)
		outer := f.device("/dev/loop0", 7, 0, "loop0")
		f.loop(outer, file, "1", "0")
		f.slave(f.device("/dev/dm-0", 253, 0, "dm-0"), outer)
		got, err := f.sources("/dev/dm-0")
		if err != nil || !slices.Equal(got, []MediumSource{{Path: "/dev/dm-0"}}) {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("a buffered loop device adds its backing file at the loop offset", func(t *testing.T) {
		f := newFakeSysfs(t)
		f.loop(f.device("/dev/loop0", 7, 0, "loop0"), file, "0", "4096")
		got, err := f.sources("/dev/loop0")
		if err != nil || !slices.Equal(got, []MediumSource{{Path: "/dev/loop0"}, {Path: file, Offset: 4096}}) {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("a buffered loop device over another adds both, offsets summed", func(t *testing.T) {
		f := newFakeSysfs(t)
		f.loop(f.device("/dev/loop1", 7, 1, "loop1"), file, "0", "512")
		f.loop(f.device("/dev/loop0", 7, 0, "loop0"), "/dev/loop1", "0", "4096")
		got, err := f.sources("/dev/loop0")
		want := []MediumSource{{Path: "/dev/loop0"}, {Path: "/dev/loop1", Offset: 4096}, {Path: file, Offset: 4608}}
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("got %v, %v; want %v", got, err, want)
		}
	})
	t.Run("a mapping over a buffered loop device is refused", func(t *testing.T) {
		f := newFakeSysfs(t)
		loop := f.device("/dev/loop0", 7, 0, "loop0")
		f.loop(loop, file, "0", "0")
		f.slave(f.device("/dev/dm-0", 253, 0, "dm-0"), loop)
		if _, err := f.sources("/dev/dm-0"); !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "loop0") {
			t.Fatalf("got %v, want ErrUnsupported naming loop0", err)
		}
	})
	t.Run("a mapping over a disk reaches the medium itself", func(t *testing.T) {
		f := newFakeSysfs(t)
		disk := f.device("/dev/sda", 8, 0, "sda")
		f.slave(f.device("/dev/dm-0", 253, 0, "dm-0"), disk)
		got, err := f.sources("/dev/dm-0")
		if err != nil || !slices.Equal(got, []MediumSource{{Path: "/dev/dm-0"}}) {
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
		if _, err := f.sources("/dev/loop0p1"); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("got %v, want ErrUnsupported", err)
		}
	})
	t.Run("unreadable loop attributes are errors, not answers", func(t *testing.T) {
		f := newFakeSysfs(t)
		f.loop(f.device("/dev/loop0", 7, 0, "loop0"), file, "", "0")
		if _, err := f.sources("/dev/loop0"); err == nil {
			t.Fatal("a loop device with no dio attribute was judged")
		}
		f.loop(f.device("/dev/loop1", 7, 1, "loop1"), file, "0", "not-a-number")
		if _, err := f.sources("/dev/loop1"); err == nil {
			t.Fatal("a loop device with a garbage offset was judged")
		}
		f.device("/dev/dm-0", 253, 0, "dm-0")
		if err := os.WriteFile(filepath.Join(f.root, "devices", "dm-0", "slaves"), []byte("not a directory"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := f.sources("/dev/dm-0"); err == nil {
			t.Fatal("unlistable slaves were judged")
		}
		if _, err := f.sources(filepath.Join(t.TempDir(), "absent")); err == nil {
			t.Fatal("a missing device was judged")
		}
	})
}

// TestCompareRegion: identical reads pass; a cache that differs from the
// medium is refused, naming where; a shorter medium and a failed read are
// both reported.
func TestCompareRegion(t *testing.T) {
	dir := diskDir(t)
	path, data := patternFile(t, dir, directIOAlign)
	cached := bytes.NewReader(data)
	sources := []MediumSource{{Path: path}}
	readPastCache := func(ctx context.Context, path string, off int64, n int) ([]byte, error) {
		return ReadPastCache(ctx, "read the device past the page cache", path, off, n, os.OpenFile)
	}

	if got, err := CompareRegion(context.Background(), cached, path, sources, len(data), readPastCache); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("an undisturbed comparison: got %v, %v", got, err)
	}

	flipped := bytes.Clone(data)
	flipped[100] ^= 0xff
	if _, err := CompareRegion(context.Background(), bytes.NewReader(flipped), path, sources, len(data), readPastCache); !errors.Is(err, ErrCacheStale) ||
		!strings.Contains(err.Error(), "first difference at byte 100") {
		t.Fatalf("a difference at byte 100: got %v", err)
	}

	errRead := errors.New("injected: the direct read failed")
	failRead := func(context.Context, string, int64, int) ([]byte, error) { return nil, errRead }
	if _, err := CompareRegion(context.Background(), cached, path, sources, len(data), failRead); !errors.Is(err, errRead) {
		t.Fatalf("a failed direct read: got %v", err)
	}
}
