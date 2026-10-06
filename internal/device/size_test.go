// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package device

import (
	"os"
	"testing"
)

// TestSizeOfARegularFile: BLKGETSIZE64 (Linux) is refused on a regular file's
// descriptor, so Size falls back to its stat size -- the only path exercised
// without a real block device.
func TestSizeOfARegularFile(t *testing.T) {
	f, err := os.CreateTemp("", "luks-device-size-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(f.Name()); _ = f.Close() }()

	const want = 12345
	if err := f.Truncate(want); err != nil {
		t.Fatal(err)
	}

	got, err := Size(f)
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if got != want {
		t.Fatalf("Size = %d, want %d", got, want)
	}
}

// TestSizeOfAClosedFile: Stat fails on a closed descriptor, and that failure
// is reported rather than a plausible-looking zero.
func TestSizeOfAClosedFile(t *testing.T) {
	f, err := os.CreateTemp("", "luks-device-size-closed-*")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	defer func() { _ = os.Remove(path) }()
	_ = f.Close()

	if _, err := Size(f); err == nil {
		t.Fatal("Size on a closed descriptor = nil, want an error")
	}
}
