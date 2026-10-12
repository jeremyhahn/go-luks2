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

// TestIsLUKSOnAnEmptyFileIsErrIO pins ErrIO, the
// module-wide kind for a read/write failure that is not itself classified:
// isLUKSForTest opens the file fine but its Read hits EOF before the magic
// bytes it is checking for, which is reported as ErrIO rather than as "not
// LUKS", because the file could not be read at all rather than having been
// read and found not to match.
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
