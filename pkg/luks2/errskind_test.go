// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestAddKeyRefusesAnEmptyExistingPassphraseAsInvalidCredential pins
// ErrInvalidCredential, the module-wide kind for a
// caller-supplied credential this package refuses before it is ever
// compared against a keyslot.
func TestAddKeyRefusesAnEmptyExistingPassphraseAsInvalidCredential(t *testing.T) {
	path := newImage(t, "invalid-credential.img")
	formatWithLibrary(t, path)

	_, err := addKeyForTest(path, nil, []byte("a-second-credential"), nil)
	if !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("addKeyForTest with an empty existing passphrase = %v, want ErrInvalidCredential", err)
	}
}

// TestIsLUKSOnAnEmptyFileIsErrIO: a read that hits EOF before the magic is ErrIO, not "not LUKS".
func TestIsLUKSOnAnEmptyFileIsErrIO(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty-file")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}

	_, err := isLUKSForTest(empty)
	if !errors.Is(err, ErrIO) {
		t.Fatalf("isLUKSForTest(%q) = %v, want ErrIO", empty, err)
	}
}
