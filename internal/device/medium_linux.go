// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package device

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// directIOAlign is the buffer, offset and length alignment O_DIRECT reads
// use: the largest logical block size a device this library opens presents.
const directIOAlign = 4096

// ReadPastCache reads up to n bytes of path at off with O_DIRECT; without O_DIRECT it falls back only on memory filesystems, else ErrUnsupported.
func ReadPastCache(ctx context.Context, op, path string, off int64, n int, openFile OpenFunc) ([]byte, error) {
	f, err := Open(ctx, op, path, os.O_RDONLY|unix.O_DIRECT, openFile)
	if err != nil {
		if !errors.Is(err, unix.EINVAL) {
			return nil, err
		}
		memory, statErr := CacheIsTheStorage(path)
		if statErr != nil {
			return nil, statErr
		}
		if !memory {
			return nil, &errs.Error{Kind: ErrUnsupported, Detail: path, Err: err}
		}
		return readBufferedAt(ctx, path, off, n, openFile)
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
		return nil, &errs.Error{Kind: errs.ErrIO, Detail: "failed to allocate an aligned buffer for a direct read", Err: err}
	}
	read, err := f.ReadAt(buf, start)
	var out []byte
	if read > skip {
		out = bytes.Clone(buf[skip:min(read, skip+n)])
	}
	if unmapErr := unix.Munmap(buf); unmapErr != nil {
		return nil, &errs.Error{Kind: errs.ErrIO, Detail: "failed to release the direct-read buffer", Err: unmapErr}
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, &errs.Error{Kind: errs.ErrIO, Detail: "failed to read the device past the page cache", Err: err}
	}
	return out, nil
}

// readBufferedAt reads up to n bytes of path from off through the page
// cache. A device shorter than off+n yields what it has.
func readBufferedAt(ctx context.Context, path string, off int64, n int, openFile OpenFunc) ([]byte, error) {
	f, err := Open(ctx, "read the device", path, os.O_RDONLY, openFile)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only: a close error loses nothing

	buf := make([]byte, n)
	read, err := f.ReadAt(buf, off)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, &errs.Error{Kind: errs.ErrIO, Detail: "failed to read the device", Err: err}
	}
	return buf[:read], nil
}

// CacheIsTheStorage reports whether path lives on tmpfs or ramfs; a block device never does.
func CacheIsTheStorage(path string) (bool, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return false, &errs.Error{Kind: errs.ErrIO, Detail: "failed to stat " + path, Err: err}
	}
	if st.Mode&unix.S_IFMT == unix.S_IFBLK {
		return false, nil
	}
	var fsStat unix.Statfs_t
	if err := unix.Statfs(path, &fsStat); err != nil {
		return false, &errs.Error{Kind: errs.ErrIO, Detail: "failed to statfs " + path, Err: err}
	}
	// Statfs_t.Type is int32 on 32-bit targets, so compare as uint32.
	return IsMemoryFilesystemMagic(uint32(fsStat.Type)), nil // #nosec G115 -- the magics compared fit 32 bits; the conversion keeps them
}

// IsMemoryFilesystemMagic reports whether a statfs filesystem magic is a
// memory filesystem's: tmpfs or ramfs.
func IsMemoryFilesystemMagic(magic uint32) bool {
	return magic == uint32(unix.TMPFS_MAGIC) || magic == uint32(unix.RAMFS_MAGIC)
}
