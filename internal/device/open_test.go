// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package device

import (
	"context"
	"errors"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"testing"
)

// TestClassifyOpenTypesAPermissionFailure is the contract itself: both errnos
// the kernel uses for "you may not", classified, with the cause still
// reachable.
func TestClassifyOpenTypesAPermissionFailure(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EACCES, syscall.EPERM} {
		t.Run(errno.Error(), func(t *testing.T) {
			cause := &fs.PathError{Op: "open", Path: "/dev/sdb1", Err: errno}

			err := ClassifyOpen("read the LUKS2 header", cause)
			if !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("ClassifyOpen = %v, want an error wrapping ErrPermissionDenied", err)
			}
			if !errors.Is(err, os.ErrPermission) {
				t.Fatalf("the classified error no longer matches os.ErrPermission: %v", err)
			}
			if !errors.Is(err, errno) {
				t.Fatalf("the classified error no longer reaches the errno: %v", err)
			}
			if !strings.Contains(err.Error(), "read the LUKS2 header") {
				t.Fatalf("the classified error does not name the operation: %v", err)
			}
			if !strings.Contains(err.Error(), "RAW BLOCK DEVICE") {
				t.Fatalf("the classified error carries no remedy: %v", err)
			}
		})
	}
}

// TestClassifyOpenTypesAnInUseFailure: EBUSY, what an O_EXCL open of a
// contended block device returns.
func TestClassifyOpenTypesAnInUseFailure(t *testing.T) {
	cause := &fs.PathError{Op: "open", Path: "/dev/sdb1", Err: syscall.EBUSY}
	err := ClassifyOpen("format the device", cause)
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("ClassifyOpen(EBUSY) = %v, want ErrInUse", err)
	}
	if !errors.Is(err, syscall.EBUSY) {
		t.Fatalf("the classified error no longer reaches EBUSY: %v", err)
	}
}

// TestClassifyOpenLeavesEverythingElseAlone is the other half. Wrapping every
// open failure would rewrite the message of every failure to buy a
// distinction only some of them need.
func TestClassifyOpenClassifiesEverythingElse(t *testing.T) {
	for errno, kind := range map[syscall.Errno]error{syscall.ENOENT: ErrNotFound, syscall.ENOTDIR: errs.ErrIO, syscall.EIO: errs.ErrIO} {
		t.Run(errno.Error(), func(t *testing.T) {
			cause := &fs.PathError{Op: "open", Path: "/dev/sdb1", Err: errno}
			err := ClassifyOpen("read the LUKS2 header", cause)
			var e *errs.Error
			if !errors.As(err, &e) || !errors.Is(err, kind) {
				t.Fatalf("ClassifyOpen of a %v failure = %v, want an *errs.Error of kind %v", errno, err, kind)
			}
			if !errors.Is(err, cause) {
				t.Fatalf("the cause of a %v failure is not reachable: %v", errno, err)
			}
			if errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("a %v failure was classified as a permission failure: %v", errno, err)
			}
		})
	}

	if err := ClassifyOpen("read the LUKS2 header", nil); err != nil {
		t.Fatalf("ClassifyOpen(nil) = %v, want nil", err)
	}
}

// TestOpenClassifiesAPermissionFailure covers the wrapper rather than the
// classifier, so a future Open that forgot to call it would be caught.
func TestOpenClassifiesAPermissionFailure(t *testing.T) {
	refuse := func(name string, _ int, _ os.FileMode) (*os.File, error) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: syscall.EACCES}
	}
	f, err := Open(context.Background(), "read the LUKS2 header", "/dev/sdb1", os.O_RDONLY, refuse)
	if err == nil {
		_ = f.Close()
		t.Fatal("Open reported success against a seam that always refuses")
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Open = %v, want an error wrapping ErrPermissionDenied", err)
	}
}
