// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package device

import (
	"errors"
	"io/fs"
	"syscall"
	"testing"
)

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
