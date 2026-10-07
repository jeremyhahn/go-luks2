// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"
	"encoding/binary"
	"io"
	"os"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/header"
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

// readDirectAt is readDeviceDirect's default: an O_DIRECT read of up to n
// bytes from off, past the page cache.
func readDirectAt(ctx context.Context, path string, off int64, n int, openFile device.OpenFunc) ([]byte, error) {
	return device.ReadPastCache(ctx, "read the device past the page cache", path, off, n, openFile)
}

// statRdev stats path and returns its raw device number. It FOLLOWS
// symlinks, because /dev/mapper/<name> is one and what matters is the
// device it names.
func statRdev(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Rdev), nil //nolint:unconvert // Rdev is not uint64 on every GOARCH
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
func mediumSources(path string, nodeRdev func(string) (uint64, error)) ([]mediumSource, error) {
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
func requireCacheMatchesMedium(path string, sys volumeSys) error {
	f, err := openDevice("read the device", path, os.O_RDONLY, sys)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // read-only: a close error loses nothing
	return requireCacheMatchesMediumOf(context.Background(), f, path, sys)
}

// requireCacheMatchesMediumOf is requireCacheMatchesMedium for an operation
// that already holds the device: cached is what it reads through -- its pinned
// descriptor (#255) -- and path names the same file for the reads past the
// cache (keyslotDevice.mediumPath), so no step resolves the operator's path
// again.
func requireCacheMatchesMediumOf(ctx context.Context, cached io.ReaderAt, path string, sys volumeSys) error {
	sources, err := device.MediumSources(path, sysDevBlockRoot, sys.nodeRdev)
	if err != nil {
		return err
	}
	head, err := device.CompareRegion(ctx, cached, path, sources, header.HeaderSize, sys.readDeviceDirect)
	if err != nil {
		return err
	}
	if len(head) < header.HeaderSize {
		return nil
	}
	size := binary.BigEndian.Uint64(head[8:16])
	if size < header.HeaderMinSize || size > header.HeaderMaxSize || !isPowerOf2(int(size)) {
		return nil
	}
	_, err = device.CompareRegion(ctx, cached, path, sources, 2*int(size), sys.readDeviceDirect)
	return err
}
