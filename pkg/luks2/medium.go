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

// Confirming that what is read through the page cache is on the medium; the I/O is in internal/device, the header size fields here.

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

// statRdev stats path, following symlinks, and returns its raw device number.
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

// mediumSources returns every place device's bytes must be read past a cache (internal/device.MediumSources).
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

// requireCacheMatchesMedium refuses with ErrDeviceCacheStale if the header copies read through the cache differ from the medium.
func requireCacheMatchesMedium(path string, sys volumeSys) error {
	f, err := openDevice("read the device", path, os.O_RDONLY, sys)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // read-only: a close error loses nothing
	return requireCacheMatchesMediumOf(context.Background(), f, path, sys)
}

// requireCacheMatchesMediumOf is requireCacheMatchesMedium through an already-held descriptor, with path for the reads past the cache.
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
