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

// defaultSysBlockRoot is the sysfs block root; a [sys] field so tests can reach readLoopStateIn's non-absent error branches.
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

// readLoopStateIn observes a loop device under a sysfs root; a missing block device is an error, never "detached".
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

// loopAttributeSaysUnbound reports whether a failed backing_file read (ENOENT, ENODEV, ENXIO) means the device is attached to nothing.
func loopAttributeSaysUnbound(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENXIO)
}

// readLoopFlag reads a diagnostic boolean loop attribute, best-effort.
func readLoopFlag(blockDir, name string) bool {
	data, err := os.ReadFile(filepath.Join(blockDir, "loop", name)) // #nosec G304 -- sysfs path built from the device's base name
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "1"
}
