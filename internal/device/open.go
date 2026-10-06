// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package device

import (
	"errors"
	"os"
	"syscall"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// OpenFunc opens a file the way os.OpenFile does. Open takes it as a
// parameter rather than calling os.OpenFile directly, so a caller can inject
// a failing open for a test: a permission failure cannot be produced by
// permission bits in a test (CI runs as root, and root bypasses discretionary
// access checks), so this package has no fault to inject that way and takes
// the opener as a seam instead, one this package does not itself hold as
// mutable state.
type OpenFunc func(name string, flag int, perm os.FileMode) (*os.File, error)

// Open is the one way this package opens a device, so that the
// CLASSIFICATION of a failure lives in one place rather than at every call
// site. openFile is this package's fault-injection seam: production callers
// pass os.OpenFile (or a caller's own package-level seam var wrapping it).
//
// The mode argument is deliberately absent: nothing here passes O_CREATE, so
// permission bits would never be consulted. 0600 is passed for the write
// paths purely to match what the sites this replaced spelled out.
func Open(op, path string, flag int, openFile OpenFunc) (*os.File, error) {
	f, err := openFile(path, flag, 0600) // #nosec G304 -- the device path is the caller's subject, validated by the caller before every LUKS2 operation
	if err != nil {
		return nil, ClassifyOpen(op, err)
	}
	return f, nil
}

// ClassifyOpen adds this package's typed vocabulary to an open failure, and
// returns anything it cannot classify UNCHANGED.
//
// Returning the original error for the unclassified case is deliberate. The
// alternative -- wrapping everything in a house error type -- would rewrite
// the message of every failure to buy a distinction only some of them need,
// and *fs.PathError already says which path and which syscall.
//
// The permission case keeps the cause reachable through the chain, so
// errors.Is(err, os.ErrPermission) and errors.Is(err, ErrPermissionDenied)
// are both true of the same value.
func ClassifyOpen(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrPermission) {
		return &errs.Error{Kind: ErrPermissionDenied, Detail: "could not " + op + ". " + PermissionRemedy, Err: err}
	}
	// EBUSY is what an O_EXCL open of a block device returns while the
	// device is mounted, mapped or claimed by another exclusive opener.
	if errors.Is(err, syscall.EBUSY) {
		return &errs.Error{Kind: ErrInUse, Detail: "could not " + op + ": it is mounted, mapped or held open exclusively", Err: err}
	}
	return err
}
