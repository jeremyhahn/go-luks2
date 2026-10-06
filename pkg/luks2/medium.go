// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"encoding/binary"
	"io"
	"os"

	"github.com/jeremyhahn/go-luks2/internal/device"
)

// Confirming that what is read through the page cache is what is on the
// medium.
//
// An operation that destroys key material on the strength of what it READ --
// MigrateToFIPS removing Argon2 keyslots once both header copies agree -- is
// only as safe as that read. The actual O_DIRECT reads, the loop-device stack
// walk and the byte comparison live in internal/device; this file keeps only
// the part that knows the LUKS2 header's own size fields, which internal/device
// cannot: it sits below internal/header in the import DAG.

// directIOAlign is the buffer, offset and length alignment O_DIRECT reads
// use: the largest logical block size a device this library opens presents.
const directIOAlign = 4096

// sysDevBlockRoot is where the kernel exposes each block device by its device
// number. A variable, like devDir, so this package's tests can stand a sysfs
// tree up for devices they cannot create.
var sysDevBlockRoot = device.DefaultSysDevBlockRoot

// readDeviceDirect reads up to n bytes of path from offset off past the page
// cache. It is a seam because a cache that disagrees with the medium cannot be
// produced from a test without a failing device: this package's tests
// substitute it to model one. Unexported, substituted only by this package's
// tests. The real work is internal/device.ReadPastCache.
var readDeviceDirect = readDirectAt

// readDirectAt is readDeviceDirect's default: an O_DIRECT read of up to n
// bytes from off, past the page cache.
func readDirectAt(path string, off int64, n int) ([]byte, error) {
	return device.ReadPastCache("read the device past the page cache", path, off, n, openFileFunc)
}

// cacheIsTheStorage reports whether path lives on a memory filesystem (tmpfs,
// ramfs), where the page cache is the only copy there is. A block device never
// does, whatever filesystem its node sits on (devtmpfs is tmpfs).
func cacheIsTheStorage(path string) (bool, error) {
	return device.CacheIsTheStorage(path)
}

// isMemoryFilesystemMagic reports whether a statfs filesystem magic is a
// memory filesystem's: tmpfs or ramfs.
func isMemoryFilesystemMagic(magic uint32) bool {
	return device.IsMemoryFilesystemMagic(magic)
}

// mediumSource is one place the bytes of a device can be read past a cache:
// path at offset.
type mediumSource struct {
	path   string
	offset int64
}

// mediumSources returns every place device's bytes must be read past a cache
// for the read to be the medium's. The stack walk itself is
// internal/device.MediumSources; this converts its result to and from this
// package's own type.
func mediumSources(path string) ([]mediumSource, error) {
	srcs, err := device.MediumSources(path, sysDevBlockRoot, nodeRdev)
	if err != nil {
		return nil, err
	}
	out := make([]mediumSource, len(srcs))
	for i, s := range srcs {
		out[i] = mediumSource{path: s.Path, offset: s.Offset}
	}
	return out, nil
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
func requireCacheMatchesMedium(path string) error {
	f, err := openDevice("read the device", path, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // read-only: a close error loses nothing
	return requireCacheMatchesMediumOf(f, path)
}

// requireCacheMatchesMediumOf is requireCacheMatchesMedium for an operation
// that already holds the device: cached is what it reads through -- its pinned
// descriptor (#255) -- and path names the same file for the reads past the
// cache (keyslotDevice.mediumPath), so no step resolves the operator's path
// again.
func requireCacheMatchesMediumOf(cached io.ReaderAt, path string) error {
	sources, err := device.MediumSources(path, sysDevBlockRoot, nodeRdev)
	if err != nil {
		return err
	}
	head, err := device.CompareRegion(cached, path, sources, LUKS2HeaderSize, readDeviceDirect)
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
	_, err = device.CompareRegion(cached, path, sources, 2*int(size), readDeviceDirect)
	return err
}
