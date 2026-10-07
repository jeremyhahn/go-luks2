// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package loop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// Find finds the loop device backing file.
//
// A device matches when the loop driver's record of its backing file -- the
// device and inode LOOP_GET_STATUS64 reports -- is the file's own, not when
// the path sysfs prints matches the argument string. A path string is not an
// identity; a device and inode are, and the two differ for the same file
// whenever the path runs through a symlink, a bind mount or another mount
// namespace (go-luks2 #250, C8).
func Find(ctx context.Context, file string) (*Device, error) {
	d, err := find(ctx, file, defaultSys())
	return d, errs.At("loop", "Find", file, err)
}

func find(ctx context.Context, file string, s sys) (*Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, &errs.Error{Kind: err}
	}
	path, backing, err := findLoopDeviceIn(s.sysBlockRoot, file, s)
	if err != nil {
		return nil, err
	}
	return &Device{path: path, backing: backing, sys: s}, nil
}

// findLoopDeviceIn is [Find] against a given sysfs root.
func findLoopDeviceIn(root, file string, s sys) (path, backing string, err error) {
	var st unix.Stat_t
	if err := unix.Stat(file, &st); err != nil {
		return "", "", &errs.Error{Kind: errs.ErrIO, Detail: "identify the backing file " + file, Err: err}
	}
	wantDev, wantIno := uint64(st.Dev), st.Ino //nolint:unconvert // Dev is not uint64 on every GOARCH

	entries, err := s.readDir(root)
	if err != nil {
		return "", "", err
	}

	// Counted rather than remembered, in the same idiom as waitForDetach.
	var unreadable int
	var lastErr error

	for _, entry := range entries {
		name := entry.Name()
		if len(name) < 4 || name[:4] != "loop" {
			continue
		}

		// sysfs says whether the device is bound at all; only a bound
		// device has a backing file to identify.
		state, err := readLoopStateIn(root, name)
		if err != nil {
			unreadable++
			lastErr = err
			continue
		}
		if state.backing == "" {
			continue
		}

		dev, ino, err := s.loopBackingIdentity(filepath.Join(s.devDir, name))
		if errors.Is(err, unix.ENXIO) {
			// Released between the sysfs read and the ioctl: the loop
			// driver's own "not bound" answer.
			continue
		}
		if err != nil {
			// Bound, and its backing file cannot be identified: that is
			// not evidence it is some other file. Counted, like an
			// unreadable sysfs entry.
			unreadable++
			lastErr = err
			continue
		}
		if dev == wantDev && ino == wantIno {
			return filepath.Join(s.devDir, name), state.backing, nil
		}
	}

	// "NOT ATTACHED" AND "COULD NOT TELL" ARE DIFFERENT ANSWERS, and only
	// the first may be acted on. The caller this misleads is the one asking
	// whether a file is ALREADY attached before attaching it: told "no"
	// when the truth was "the one device backing it could not be
	// inspected", it creates a SECOND loop device for the same backing
	// file, giving the kernel two independent writers of one LUKS
	// container.
	if unreadable > 0 {
		return "", "", &errs.Error{
			Kind: errs.ErrIO,
			Detail: fmt.Sprintf("find the loop device backing %s (%d of %d candidates could not be inspected, so absence cannot be concluded)",
				file, unreadable, len(entries)),
			Err: lastErr,
		}
	}

	return "", "", &errs.Error{Kind: ErrNotFound, Detail: file}
}

// loopBackingIdentityIoctl reports the device and inode of the file the loop
// device at path is backed by, as the loop driver itself records them
// (LOOP_GET_STATUS64).
func loopBackingIdentityIoctl(path string) (dev, ino uint64, err error) {
	f, err := os.Open(path) // #nosec G304 -- path is <devDir>/<name> for a loop device listed in sysfs
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = f.Close() }()
	info, err := unix.IoctlLoopGetStatus64(int(f.Fd()))
	if err != nil {
		return 0, 0, err
	}
	return info.Device, info.Inode, nil
}

// Lookup returns a [Device] for an already-named loop device node, such as
// "/dev/loop3". Unlike [Attach] and [Find], it does not require the device
// to be currently attached to a file: [Device.BackingFile] reports "" for
// one that is not.
func Lookup(ctx context.Context, path string) (*Device, error) {
	d, err := lookup(ctx, path, defaultSys())
	return d, errs.At("loop", "Lookup", path, err)
}

// isLoopNodeName reports whether name is what a loop device's own node is
// called: loop<N>, never a partition (loop0p1) or another block device.
func isLoopNodeName(name string) bool {
	digits, ok := strings.CutPrefix(name, "loop")
	if !ok || digits == "" {
		return false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func lookup(ctx context.Context, path string, s sys) (*Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, &errs.Error{Kind: err}
	}
	// Detach sends LOOP_CLR_FD to whatever this returns, so only a loop node
	// qualifies.
	if clean := filepath.Clean(path); filepath.Dir(clean) != s.devDir || !isLoopNodeName(filepath.Base(clean)) {
		return nil, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: fmt.Sprintf("%q is not a loop device node (%s/loopN)", path, s.devDir)}
	}
	state, err := readLoopStateIn(s.sysBlockRoot, path)
	if err != nil {
		return nil, err
	}
	return &Device{path: path, backing: state.backing, sys: s}, nil
}
