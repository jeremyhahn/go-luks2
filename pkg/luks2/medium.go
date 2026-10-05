// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Confirming that what is read through the page cache is what is on the
// medium.
//
// An operation that destroys key material on the strength of what it READ --
// MigrateToFIPS removing Argon2 keyslots once both header copies agree -- is
// only as safe as that read. A buffered read is served from the page cache,
// and the cache can disagree with the medium: after a writeback error the
// kernel may keep the unwritten bytes as clean pages, which a later fsync
// succeeds without rewriting, and evicting them with posix_fadvise is
// advisory -- a page another process holds mapped stays cached and the call
// still succeeds. So eviction is not proof. Proof is reading the same bytes
// again past every cache between the caller and the medium, with O_DIRECT,
// and comparing.
//
// "Every cache" is the part that needs care. O_DIRECT on a loop device skips
// the loop device's cache, but a loop device without direct I/O reads its
// backing FILE through that file's page cache, so the backing file is read
// past its cache too, at the loop offset. Below any other stacked device
// (device-mapper, md, a partition) a buffered loop device cannot be mapped to
// an offset in general, and the check fails closed with the remedy named.

// directIOAlign is the buffer, offset and length alignment O_DIRECT reads use:
// the largest logical block size a device this library opens presents.
const directIOAlign = 4096

// sysDevBlockRoot is where the kernel exposes each block device by its device
// number. A variable, like devDir, so this package's tests can stand a sysfs
// tree up for devices they cannot create.
var sysDevBlockRoot = "/sys/dev/block"

// readDeviceDirect reads up to n bytes of path from offset off past the page
// cache. It is a seam because a cache that disagrees with the medium cannot be
// produced from a test without a failing device: this package's tests
// substitute it to model one. Unexported, substituted only by this package's
// tests.
var readDeviceDirect = readDirectAt

// readDirectAt is readDeviceDirect: an O_DIRECT read of up to n bytes from off.
// Where O_DIRECT is refused, it falls back to an ordinary read only if the
// page cache IS the storage (cacheIsTheStorage) -- there is no other medium to
// disagree with -- and otherwise fails with ErrDirectIOUnsupported: a read
// that cannot be confirmed is not reported as confirmed.
func readDirectAt(path string, off int64, n int) ([]byte, error) {
	f, err := openDevice("read the device past the page cache", path, os.O_RDONLY|unix.O_DIRECT)
	if err != nil {
		if !errors.Is(err, unix.EINVAL) {
			return nil, err
		}
		memory, statErr := cacheIsTheStorage(path)
		if statErr != nil {
			return nil, statErr
		}
		if !memory {
			return nil, &detailError{Kind: ErrDirectIOUnsupported, Detail: path, Err: err}
		}
		return readBufferedAt(path, off, n)
	}
	defer func() { _ = f.Close() }() // read-only: a close error loses nothing

	// O_DIRECT wants the offset, the length and the buffer aligned, so the
	// read covers the aligned span around the bytes asked for.
	start := off - off%directIOAlign
	skip := int(off - start)
	size := (skip + n + directIOAlign - 1) / directIOAlign * directIOAlign
	// An anonymous mapping is page aligned, which O_DIRECT requires of the
	// buffer, without reaching for unsafe to align a Go slice.
	buf, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return nil, &detailError{Detail: "failed to allocate an aligned buffer for a direct read", Err: err}
	}
	read, err := f.ReadAt(buf, start)
	var out []byte
	if read > skip {
		out = bytes.Clone(buf[skip:min(read, skip+n)])
	}
	if unmapErr := unix.Munmap(buf); unmapErr != nil {
		return nil, &detailError{Detail: "failed to release the direct-read buffer", Err: unmapErr}
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, &detailError{Detail: "failed to read the device past the page cache", Err: err}
	}
	return out, nil
}

// readBufferedAt reads up to n bytes of path from off through the page cache.
// A device shorter than off+n yields what it has.
func readBufferedAt(path string, off int64, n int) ([]byte, error) {
	f, err := openDevice("read the device", path, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only: a close error loses nothing

	buf := make([]byte, n)
	read, err := f.ReadAt(buf, off)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, &detailError{Detail: "failed to read the device", Err: err}
	}
	return buf[:read], nil
}

// cacheIsTheStorage reports whether path lives on a memory filesystem (tmpfs,
// ramfs), where the page cache is the only copy there is. A block device never
// does, whatever filesystem its node sits on (devtmpfs is tmpfs).
func cacheIsTheStorage(path string) (bool, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return false, &detailError{Detail: "failed to stat " + path, Err: err}
	}
	if st.Mode&unix.S_IFMT == unix.S_IFBLK {
		return false, nil
	}
	var fsStat unix.Statfs_t
	if err := unix.Statfs(path, &fsStat); err != nil {
		return false, &detailError{Detail: "failed to statfs " + path, Err: err}
	}
	// Statfs_t.Type is int32 on 386 and arm and int64 on amd64 and arm64, and
	// RAMFS_MAGIC (0x858458f6) does not fit an int32: compared as the
	// constant, it does not compile on the 32-bit targets. Every filesystem
	// magic compared here fits in 32 bits, and an int32 field holds those
	// same 32 bits, so the field is compared as a uint32.
	return isMemoryFilesystemMagic(uint32(fsStat.Type)), nil // #nosec G115 -- the magics compared fit 32 bits; the conversion keeps them
}

// isMemoryFilesystemMagic reports whether a statfs filesystem magic is a
// memory filesystem's: tmpfs or ramfs.
func isMemoryFilesystemMagic(magic uint32) bool {
	return magic == uint32(unix.TMPFS_MAGIC) || magic == uint32(unix.RAMFS_MAGIC)
}

// mediumSource is one place the bytes of a device can be read past a cache:
// path at offset.
type mediumSource struct {
	path   string
	offset int64
}

// mediumSources returns every place device's bytes must be read past a cache
// for the read to be the medium's: the device itself, and, for a loop device,
// its backing at the loop offset -- recursively, because a loop device with
// direct I/O can sit on one without it, whose backing file is then read
// through its cache whatever the loop above does. Reading a backing that a
// direct-I/O loop already reaches costs one read and proves the same thing
// twice. A stacked device with a buffered loop device anywhere below it is
// refused with ErrDirectIOUnsupported: its offset into the backing file is not
// knowable in general.
func mediumSources(device string) ([]mediumSource, error) {
	self := []mediumSource{{path: device}}
	rdev, err := nodeRdev(device)
	if err != nil {
		return nil, &detailError{Detail: "failed to stat " + device, Err: err}
	}
	if rdev == 0 {
		return self, nil // a regular file: its own O_DIRECT read reaches the medium
	}
	major, minor := decodeDevNo(rdev)
	dir := filepath.Join(sysDevBlockRoot, fmt.Sprintf("%d:%d", major, minor))

	backing, offset, _, isLoop, err := loopAttributes(dir)
	if err != nil {
		return nil, err
	}
	if isLoop {
		below, err := mediumSources(backing)
		if err != nil {
			return nil, err
		}
		for _, src := range below {
			self = append(self, mediumSource{path: src.path, offset: src.offset + offset})
		}
		return self, nil
	}

	loop, err := bufferedLoopBelow(dir)
	if err != nil {
		return nil, err
	}
	if loop != "" {
		return nil, &detailError{Kind: ErrDirectIOUnsupported, Detail: fmt.Sprintf(
			"%s sits on loop device %s, which reads its backing file through the page cache; "+
				"enable direct I/O on it (losetup --direct-io=on) or run on the backing file itself", device, loop)}
	}
	return self, nil
}

// loopAttributes reads the loop attributes of the sysfs block directory dir.
// isLoop is false, with no error, for a device that is not a loop device.
func loopAttributes(dir string) (backing string, offset int64, buffered, isLoop bool, err error) {
	data, err := os.ReadFile(filepath.Join(dir, "loop", "backing_file")) // #nosec G304 -- sysfs path built from a device number
	if errors.Is(err, fs.ErrNotExist) {
		return "", 0, false, false, nil
	}
	if err != nil {
		return "", 0, false, false, &detailError{Detail: "failed to read the loop device's backing file from sysfs", Err: err}
	}
	backing = strings.TrimSpace(string(data))
	dio, err := os.ReadFile(filepath.Join(dir, "loop", "dio")) // #nosec G304 -- sysfs path built from a device number
	if err != nil {
		return "", 0, false, false, &detailError{Detail: "failed to read whether the loop device uses direct I/O", Err: err}
	}
	buffered = strings.TrimSpace(string(dio)) != "1"
	raw, err := os.ReadFile(filepath.Join(dir, "loop", "offset")) // #nosec G304 -- sysfs path built from a device number
	if err != nil {
		return "", 0, false, false, &detailError{Detail: "failed to read the loop device's offset", Err: err}
	}
	offset, err = strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || offset < 0 {
		return "", 0, false, false, &detailError{Detail: "the loop device's offset " + strconv.Quote(string(raw)) + " is not a byte offset", Err: err}
	}
	return backing, offset, buffered, true, nil
}

// bufferedLoopBelow returns the name of a loop device without direct I/O
// anywhere below the sysfs block directory dir -- through its slaves and the
// whole disk a partition belongs to, each examined in full by bufferedLoopAt
// -- or "" if there is none.
func bufferedLoopBelow(dir string) (string, error) {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", &detailError{Detail: "failed to resolve the device in sysfs", Err: err}
	}
	var below []string
	if _, err := os.Stat(filepath.Join(resolved, "partition")); err == nil {
		below = append(below, filepath.Dir(resolved))
	}
	slaves, err := os.ReadDir(filepath.Join(resolved, "slaves"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", &detailError{Detail: "failed to list the device's slaves in sysfs", Err: err}
	}
	for _, slave := range slaves {
		below = append(below, filepath.Join(resolved, "slaves", slave.Name()))
	}
	for _, next := range below {
		if loop, err := bufferedLoopAt(next); err != nil || loop != "" {
			return loop, err
		}
	}
	return "", nil
}

// bufferedLoopAt examines the sysfs block directory dir and everything below
// it: a buffered loop device is the answer; a direct-I/O loop device is
// followed through its backing (bufferedLoopBehind), however many of them are
// stacked; and every device's slaves and partition parent are walked
// (bufferedLoopBelow). One walk, so no kind of device is a place it stops.
func bufferedLoopAt(dir string) (string, error) {
	backing, _, buffered, isLoop, err := loopAttributes(dir)
	if err != nil {
		return "", err
	}
	if isLoop && buffered {
		// Named as the kernel names it: /sys/dev/block/7:1 resolves to
		// .../block/loop1.
		resolved, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return "", &detailError{Detail: "failed to resolve the device in sysfs", Err: err}
		}
		return filepath.Base(resolved), nil
	}
	if isLoop {
		if loop, err := bufferedLoopBehind(backing); err != nil || loop != "" {
			return loop, err
		}
	}
	return bufferedLoopBelow(dir)
}

// bufferedLoopBehind is bufferedLoopAt for the backing of a loop device:
// nothing for a regular file, and for a block device the device itself and
// everything below it.
func bufferedLoopBehind(backing string) (string, error) {
	rdev, err := nodeRdev(backing)
	if err != nil {
		return "", &detailError{Detail: "failed to stat the loop device's backing " + backing, Err: err}
	}
	if rdev == 0 {
		return "", nil
	}
	major, minor := decodeDevNo(rdev)
	return bufferedLoopAt(filepath.Join(sysDevBlockRoot, fmt.Sprintf("%d:%d", major, minor)))
}

// requireCacheMatchesMedium refuses with ErrDeviceCacheStale if the header
// copies of device, read through the page cache, differ from the same bytes
// read past every cache to the medium (mediumSources).
//
// The region compared is the two header copies and nothing after them: the
// primary binary header is compared first, and its hdr_size then bounds the
// rest, so not a byte of the keyslots area or of the encrypted data is read.
// A primary whose size is not a legal header size is left for the header
// reader to refuse.
func requireCacheMatchesMedium(device string) error {
	f, err := openDevice("read the device", device, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // read-only: a close error loses nothing
	return requireCacheMatchesMediumOf(f, device)
}

// requireCacheMatchesMediumOf is requireCacheMatchesMedium for an operation
// that already holds the device: cached is what it reads through -- its pinned
// descriptor (#255) -- and path names the same file for the reads past the
// cache (keyslotDevice.mediumPath), so no step resolves the operator's path
// again.
func requireCacheMatchesMediumOf(cached io.ReaderAt, path string) error {
	device := path
	sources, err := mediumSources(device)
	if err != nil {
		return err
	}
	head, err := compareRegion(cached, device, sources, LUKS2HeaderSize)
	if err != nil {
		return err
	}
	if len(head) < LUKS2HeaderSize {
		return nil
	}
	size := binary.BigEndian.Uint64(head[8:16])
	if size < LUKS2HeaderMinSize || size > LUKS2HeaderMaxSize || !isPowerOf2(int(size)) {
		return nil
	}
	_, err = compareRegion(cached, device, sources, 2*int(size))
	return err
}

// compareRegion reads the first n bytes through r -- the page cache -- and
// past it at every source, and returns the cached bytes if all agree.
func compareRegion(r io.ReaderAt, device string, sources []mediumSource, n int) ([]byte, error) {
	cached := make([]byte, n)
	read, err := r.ReadAt(cached, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, &detailError{Detail: "failed to read the device", Err: err}
	}
	cached = cached[:read]
	for _, src := range sources {
		medium, err := readDeviceDirect(src.path, src.offset, len(cached))
		if err != nil {
			return nil, err
		}
		if bytes.Equal(cached, medium) {
			continue
		}
		at := min(len(cached), len(medium))
		for i := range at {
			if cached[i] != medium[i] {
				at = i
				break
			}
		}
		return nil, &detailError{Kind: ErrDeviceCacheStale, Detail: fmt.Sprintf(
			"%s: the first %d bytes read through the page cache differ from %s read past it at offset %d (first difference at byte %d); "+
				"another process may hold the device mapped, or an earlier write to it failed -- "+
				"release the device or drop the page cache, then retry", device, len(cached), src.path, src.offset, at)}
	}
	return cached, nil
}
