// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"errors"
	"testing"
)

// ImportToken used to write any token with a type (#248, B2): a nil keyslot
// list went to disk as "keyslots":null and a keyslot id the header does not
// have went to disk as written. cryptsetup refuses either header outright, so
// systemd-cryptsetup could no longer open the volume while this package still
// could.

// TestImportTokenWritesAKeyslotsArray: a token naming no keyslot is written
// with an empty array, and the caller's token is not changed.
func TestImportTokenWritesAKeyslotsArray(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "token-null-keyslots.img")
	formatWithLibrary(t, path)

	token := &Token{Type: TokenTypeSystemdRecovery}
	if err := ImportToken(path, 0, token); err != nil {
		t.Fatalf("ImportToken: %v", err)
	}
	if token.Keyslots != nil {
		t.Fatalf("ImportToken changed the caller's token: Keyslots = %#v", token.Keyslots)
	}
	if json := readAreaBytes(t, path, LUKS2HeaderSize, LUKS2DefaultSize); !bytes.Contains(json, []byte(`"keyslots":[]`)) ||
		bytes.Contains(json, []byte(`"keyslots":null`)) {
		t.Fatalf("the token was not written with an empty keyslots array:\n%s", bytes.TrimRight(json, "\x00"))
	}
	got, err := GetToken(path, 0)
	if err != nil || got.Keyslots == nil || len(got.Keyslots) != 0 {
		t.Fatalf("GetToken = %+v, %v; want a token with an empty keyslots array", got, err)
	}
}

// TestImportTokenRefusesAKeyslotTheHeaderDoesNotHave: a reference cryptsetup
// would refuse the header for is refused before anything is written.
func TestImportTokenRefusesAKeyslotTheHeaderDoesNotHave(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "token-dangling.img")
	formatWithLibrary(t, path)
	before := readAreaBytes(t, path, 0, 2*LUKS2HeaderMinSize)

	for _, refs := range [][]string{{"7"}, {"0", "31"}, {"00"}, {"-0"}} {
		err := ImportToken(path, 0, &Token{Type: TokenTypeSystemdRecovery, Keyslots: refs})
		if !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("ImportToken naming keyslots %q: got %v, want ErrInvalidHeader", refs, err)
		}
	}
	if !bytes.Equal(before, readAreaBytes(t, path, 0, 2*LUKS2HeaderMinSize)) {
		t.Fatal("a refused ImportToken changed the header")
	}

	if err := ImportToken(path, 0, &Token{Type: TokenTypeSystemdRecovery, Keyslots: []string{"0"}}); err != nil {
		t.Fatalf("ImportToken naming the keyslot the header has: %v", err)
	}
}

// TestAddKeyWritesNoMaterialItsHeaderCannotName: when the header carries damage
// the write-time validator refuses -- here a token naming a missing keyslot --
// AddKey is refused BEFORE the new keyslot's material is written, so no
// unreferenced, passphrase-wrapped copy of the volume key is left in the
// keyslots area.
func TestAddKeyWritesNoMaterialItsHeaderCannotName(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "addkey-damaged-header.img")
	formatWithLibrary(t, path)
	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	metadata.Tokens["0"] = &Token{Type: TokenTypeSystemdRecovery, Keyslots: []string{"7"}}
	if err := writeHeaderUnvalidated(path, hdr, metadata); err != nil {
		t.Fatalf("writeHeaderUnvalidated: %v", err)
	}
	before := fileDigest(t, path)

	_, err = AddKey(path, []byte(conformancePassphrase), []byte("a-second-credential"), &AddKeyOptions{
		KDFType: KDFTypePBKDF2, PBKDFIterTime: 1,
	})
	if !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("AddKey on a header carrying a dangling token: got %v, want ErrInvalidHeader", err)
	}
	if fileDigest(t, path) != before {
		t.Fatal("a refused AddKey wrote to the device")
	}
}
