// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package device

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestDiscardRefusesANonPositiveSize, before the ioctl is ever issued: a
// negative size cast to the ioctl's uint64 length would wrap to a huge range.
func TestDiscardRefusesANonPositiveSize(t *testing.T) {
	f, err := os.CreateTemp("", "luks-device-discard-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(f.Name()); _ = f.Close() }()

	for _, size := range []int64{0, -1} {
		if err := Discard(f, size); !errors.Is(err, unix.EINVAL) {
			t.Errorf("Discard(%d) = %v, want EINVAL", size, err)
		}
	}
}

// TestDiscardOnARegularFile: BLKDISCARD is a block-device ioctl, so a regular
// file reports the failure as a *Error rather than a silent success.
func TestDiscardOnARegularFile(t *testing.T) {
	f, err := os.CreateTemp("", "luks-device-discard-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(f.Name()); _ = f.Close() }()
	if err := f.Truncate(4096); err != nil {
		t.Fatal(err)
	}

	err = Discard(f, 4096)
	var de *Error
	if !errors.As(err, &de) {
		t.Fatalf("Discard on a regular file = %v, want a *Error", err)
	}
}

// TestDiscardOnAClosedFile reports the closed descriptor as a failure too.
func TestDiscardOnAClosedFile(t *testing.T) {
	f, err := os.CreateTemp("", "luks-device-discard-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	_ = f.Close()

	if err := Discard(f, 4096); err == nil {
		t.Fatal("Discard on a closed file = nil, want an error")
	}
}
