// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package device

import (
	"os"
	"testing"
)

// TestDropCache: a no-op in production usage here means it does not error on
// an ordinary open file.
func TestDropCache(t *testing.T) {
	f, err := os.CreateTemp("", "luks-device-dropcache-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(f.Name()); _ = f.Close() }()

	if err := DropCache(f); err != nil {
		t.Fatalf("DropCache: %v", err)
	}
}
