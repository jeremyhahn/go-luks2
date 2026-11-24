// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package device

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// Confirming the page cache matches the medium: read the same bytes again with O_DIRECT past every cache, including a buffered loop device's backing file, and compare.

// DefaultSysDevBlockRoot is where the kernel exposes each block device by its
// device number.
const DefaultSysDevBlockRoot = "/sys/dev/block"

// MediumSource is one place the bytes of a device can be read past a cache:
// path at offset.
type MediumSource struct {
	Path   string
	Offset int64
}

// StatRdev reports the device number of the node at path, or 0 for a regular
// file. It is the default statRdev MediumSources takes.
func StatRdev(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Rdev), nil //nolint:unconvert // Rdev is not uint64 on every GOARCH
}

// MediumSources returns every place a device's bytes must be read past a cache, recursing through loop backings; a buffered loop below a stacked device is ErrUnsupported.
func MediumSources(path, sysDevBlockRoot string, statRdev func(string) (uint64, error)) ([]MediumSource, error) {
	self := []MediumSource{{Path: path}}
	rdev, err := statRdev(path)
	if err != nil {
		return nil, &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to stat " + path, Err: err}
	}
	if rdev == 0 {
		return self, nil // a regular file: its own O_DIRECT read reaches the medium
	}
	major, minor := unix.Major(rdev), unix.Minor(rdev)
	dir := filepath.Join(sysDevBlockRoot, fmt.Sprintf("%d:%d", major, minor))

	backing, offset, _, isLoop, err := loopAttributes(dir)
	if err != nil {
		return nil, err
	}
	if isLoop {
		below, err := MediumSources(backing, sysDevBlockRoot, statRdev)
		if err != nil {
			return nil, err
		}
		for _, src := range below {
			self = append(self, MediumSource{Path: src.Path, Offset: src.Offset + offset})
		}
		return self, nil
	}

	loop, err := bufferedLoopBelow(dir, sysDevBlockRoot, statRdev)
	if err != nil {
		return nil, err
	}
	if loop != "" {
		return nil, &errs.Error{Kind: ErrUnsupported, Detail: fmt.Sprintf(
			"%s sits on loop device %s, which reads its backing file through the page cache; "+
				"enable direct I/O on it (losetup --direct-io=on) or run on the backing file itself", path, loop)}
	}
	return self, nil
}

// loopAttributes reads the loop attributes of the sysfs block directory dir.
// isLoop is false, with no error, for a device that is not a loop device --
// which, off Linux or wherever sysfs has nothing at dir, is every device.
func loopAttributes(dir string) (backing string, offset int64, buffered, isLoop bool, err error) {
	data, err := os.ReadFile(filepath.Join(dir, "loop", "backing_file")) // #nosec G304 -- sysfs path built from a device number
	if errors.Is(err, fs.ErrNotExist) {
		return "", 0, false, false, nil
	}
	if err != nil {
		return "", 0, false, false, &errs.Error{Kind: errs.ErrIO, Detail: "failed to read the loop device's backing file from sysfs", Err: err}
	}
	backing = strings.TrimSpace(string(data))
	dio, err := os.ReadFile(filepath.Join(dir, "loop", "dio")) // #nosec G304 -- sysfs path built from a device number
	if err != nil {
		return "", 0, false, false, &errs.Error{Kind: errs.ErrIO, Detail: "failed to read whether the loop device uses direct I/O", Err: err}
	}
	buffered = strings.TrimSpace(string(dio)) != "1"
	raw, err := os.ReadFile(filepath.Join(dir, "loop", "offset")) // #nosec G304 -- sysfs path built from a device number
	if err != nil {
		return "", 0, false, false, &errs.Error{Kind: errs.ErrIO, Detail: "failed to read the loop device's offset", Err: err}
	}
	offset, err = strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || offset < 0 {
		return "", 0, false, false, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "the loop device's offset " + strconv.Quote(string(raw)) + " is not a byte offset", Err: err}
	}
	return backing, offset, buffered, true, nil
}

// bufferedLoopBelow returns the name of a loop device without direct I/O anywhere below the sysfs block directory dir, or "".
func bufferedLoopBelow(dir, sysDevBlockRoot string, statRdev func(string) (uint64, error)) (string, error) {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", &errs.Error{Kind: errs.ErrIO, Detail: "failed to resolve the device in sysfs", Err: err}
	}
	var below []string
	if _, err := os.Stat(filepath.Join(resolved, "partition")); err == nil {
		below = append(below, filepath.Dir(resolved))
	}
	slaves, err := os.ReadDir(filepath.Join(resolved, "slaves"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", &errs.Error{Kind: errs.ErrIO, Detail: "failed to list the device's slaves in sysfs", Err: err}
	}
	for _, slave := range slaves {
		below = append(below, filepath.Join(resolved, "slaves", slave.Name()))
	}
	for _, next := range below {
		if loop, err := bufferedLoopAt(next, sysDevBlockRoot, statRdev); err != nil || loop != "" {
			return loop, err
		}
	}
	return "", nil
}

// bufferedLoopAt walks dir and everything below it, following direct-I/O loop backings, and returns the first buffered loop device.
func bufferedLoopAt(dir, sysDevBlockRoot string, statRdev func(string) (uint64, error)) (string, error) {
	backing, _, buffered, isLoop, err := loopAttributes(dir)
	if err != nil {
		return "", err
	}
	if isLoop && buffered {
		// Named as the kernel names it: /sys/dev/block/7:1 resolves to
		// .../block/loop1.
		resolved, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return "", &errs.Error{Kind: errs.ErrIO, Detail: "failed to resolve the device in sysfs", Err: err}
		}
		return filepath.Base(resolved), nil
	}
	if isLoop {
		if loop, err := bufferedLoopBehind(backing, sysDevBlockRoot, statRdev); err != nil || loop != "" {
			return loop, err
		}
	}
	return bufferedLoopBelow(dir, sysDevBlockRoot, statRdev)
}

// bufferedLoopBehind is bufferedLoopAt for the backing of a loop device:
// nothing for a regular file, and for a block device the device itself and
// everything below it.
func bufferedLoopBehind(backing, sysDevBlockRoot string, statRdev func(string) (uint64, error)) (string, error) {
	rdev, err := statRdev(backing)
	if err != nil {
		return "", &errs.Error{Kind: errs.ErrIO, Detail: "failed to stat the loop device's backing " + backing, Err: err}
	}
	if rdev == 0 {
		return "", nil
	}
	major, minor := unix.Major(rdev), unix.Minor(rdev)
	return bufferedLoopAt(filepath.Join(sysDevBlockRoot, fmt.Sprintf("%d:%d", major, minor)), sysDevBlockRoot, statRdev)
}

// CompareRegion reads the first n bytes through cached and past it at every source with readPastCache, and returns them if all agree.
func CompareRegion(ctx context.Context, cached io.ReaderAt, device string, sources []MediumSource, n int, readPastCache func(ctx context.Context, path string, off int64, n int) ([]byte, error)) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to read the device", Err: err}
	}
	buf := make([]byte, n)
	read, err := cached.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to read the device", Err: err}
	}
	buf = buf[:read]
	for _, src := range sources {
		medium, err := readPastCache(ctx, src.Path, src.Offset, len(buf))
		if err != nil {
			return nil, err
		}
		if bytes.Equal(buf, medium) {
			continue
		}
		at := min(len(buf), len(medium))
		for i := range at {
			if buf[i] != medium[i] {
				at = i
				break
			}
		}
		return nil, &errs.Error{Kind: ErrCacheStale, Detail: fmt.Sprintf(
			"%s: the first %d bytes read through the page cache differ from %s read past it at offset %d (first difference at byte %d); "+
				"another process may hold the device mapped, or an earlier write to it failed -- "+
				"release the device or drop the page cache, then retry", device, len(buf), src.Path, src.Offset, at)}
	}
	return buf, nil
}
