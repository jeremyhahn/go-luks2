// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package loop

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// defaultSysBlockRoot is where the kernel exposes block-device attributes.
// It is a [sys] field rather than a constant used directly so a reader's own
// failure branches can be exercised: every path under the real /sys/block
// either exists or does not, so an error that is NOT "absent" -- the one
// [readLoopStateIn] must never mistake for "detached" -- is unreachable from
// a real device name and would otherwise go untested.
const defaultSysBlockRoot = "/sys/block"

// loopState is one observation of a loop device's attributes.
type loopState struct {
	// backing is the file the device is attached to, or "" when it is
	// attached to nothing. It is only meaningful alongside a nil error: the
	// zero value is what an unreadable device gives too.
	backing string

	// autoclear reports the kernel's deferred-release flag.
	autoclear bool
}

// loopStateReader observes a loop device. An error means the state could not
// be determined -- which is NOT the same as the device being free, and the
// difference is the whole contract of the wait in detach.go.
type loopStateReader func(device string) (loopState, error)

// readLoopStateIn observes a loop device against a given sysfs root.
//
// The distinction it exists to make is between two ways of finding nothing:
//
//   - the BLOCK DEVICE is there and its loop attributes are gone -- the
//     device exists and is attached to nothing, which is a positive answer;
//   - the block device is not there at all -- which says nothing about any
//     loop association, because we are not looking at a loop device we can
//     observe.
//
// Collapsing the second into the first is a fail-open, and a subtle one: a
// device whose basename is not a top-level /sys/block entry -- a udev
// symlink, /dev/block/7:0, or a PARTITION such as /dev/loop0p1, which lives
// at /sys/block/loop0/loop0p1 -- would otherwise report "not attached" and
// let a caller conclude a release it never observed.
func readLoopStateIn(root, device string) (loopState, error) {
	name := filepath.Base(device)
	blockDir := filepath.Join(root, name)

	if _, err := os.Stat(blockDir); err != nil {
		return loopState{}, &errs.Error{Kind: errs.ErrIO, Detail: fmt.Sprintf("cannot observe block device %s", name), Err: err}
	}

	data, err := os.ReadFile(filepath.Join(blockDir, "loop", "backing_file")) // #nosec G304 -- sysfs path built from the device's base name
	switch {
	case loopAttributeSaysUnbound(err):
		// The block device is there and its loop attributes are not, so it
		// is attached to nothing. This is the authoritative negative.
		return loopState{}, nil
	case err != nil:
		return loopState{}, err
	}

	backing := strings.TrimRight(string(data), "\n")
	if backing == "" {
		return loopState{}, nil
	}

	abs, err := filepath.Abs(backing)
	if err != nil {
		return loopState{}, &errs.Error{
			Kind:   errs.ErrIO,
			Detail: fmt.Sprintf("unreadable backing file %q for %s", backing, device),
			Err:    err,
		}
	}

	return loopState{backing: abs, autoclear: readLoopFlag(blockDir, "autoclear")}, nil
}

// loopAttributeSaysUnbound reports whether a failed read of a loop device's
// sysfs backing_file means the device is attached to nothing.
//
// Kernels say it differently: some remove the loop attributes (ENOENT),
// others keep them and fail the read with ENODEV once the device is
// released -- measured on a CI runner, where the test harness's own release
// confirmation failed on exactly that (go-luks2 #141). ENXIO is the loop
// driver's "not bound" answer. Every other failure means the state could not
// be read, and stays an error.
func loopAttributeSaysUnbound(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENXIO)
}

// readLoopFlag reads a boolean loop attribute. It is best-effort by design:
// the flags are diagnostic, and a missing or unreadable one must not turn
// into a claim about the association itself -- that is what
// [readLoopStateIn]'s error is for.
func readLoopFlag(blockDir, name string) bool {
	data, err := os.ReadFile(filepath.Join(blockDir, "loop", name)) // #nosec G304 -- sysfs path built from the device's base name
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "1"
}
