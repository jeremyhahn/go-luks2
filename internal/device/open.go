// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package device

import (
	"context"
	"errors"
	"os"
	"syscall"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// OpenFunc opens a file like os.OpenFile; a parameter so tests can inject a failing open.
type OpenFunc func(name string, flag int, perm os.FileMode) (*os.File, error)

// Open opens a device through openFile and classifies any failure in one place.
func Open(ctx context.Context, op, path string, flag int, openFile OpenFunc) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "could not " + op + " " + path, Err: err}
	}
	f, err := openFile(path, flag, 0600) // #nosec G304 -- the device path is the caller's subject, validated by the caller before every LUKS2 operation
	if err != nil {
		return nil, ClassifyOpen(op, err)
	}
	return f, nil
}

// ClassifyOpen wraps an open failure in an *errs.Error (permission, not found, or I/O), keeping the cause reachable.
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
	if errors.Is(err, syscall.ENOENT) {
		return &errs.Error{Kind: ErrNotFound, Detail: "could not " + op + ": no such file or directory", Err: err}
	}
	if ctxKind := errs.KindOf(err, nil); ctxKind != nil {
		return &errs.Error{Kind: ctxKind, Detail: "could not " + op, Err: err}
	}
	return &errs.Error{Kind: errs.ErrIO, Detail: "could not " + op, Err: err}
}
