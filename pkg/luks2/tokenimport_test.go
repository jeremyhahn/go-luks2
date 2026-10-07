// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// SetToken used to write any token with a type (#248, B2): a nil keyslot
// list went to disk as "keyslots":null and a keyslot id the header does not
// have went to disk as written. cryptsetup refuses either header outright, so
// systemd-cryptsetup could no longer open the volume while this package still
// could.

// TestSetTokenWritesAKeyslotsArray: a token naming no keyslot is written
// with an empty array.
func TestSetTokenWritesAKeyslotsArray(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "token-null-keyslots.img")
	formatWithLibrary(t, path)

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if err := v.SetToken(context.Background(), 0, Token{Type: TokenTypeRecovery}); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	if json := readAreaBytes(t, path, header.HeaderSize, header.DefaultSize); !bytes.Contains(json, []byte(`"keyslots":[]`)) ||
		bytes.Contains(json, []byte(`"keyslots":null`)) {
		t.Fatalf("the token was not written with an empty keyslots array:\n%s", bytes.TrimRight(json, "\x00"))
	}
	hdr, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header: %v", err)
	}
	got, ok := hdr.Tokens()[0]
	if !ok || got.Keyslots == nil || len(got.Keyslots) != 0 {
		t.Fatalf("Tokens()[0] = %+v, %v; want a token with an empty keyslots array", got, ok)
	}
}

// TestSetTokenRefusesAKeyslotTheHeaderDoesNotHave: a reference cryptsetup
// would refuse the header for is refused before anything is written.
func TestSetTokenRefusesAKeyslotTheHeaderDoesNotHave(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "token-dangling.img")
	formatWithLibrary(t, path)
	before := readAreaBytes(t, path, 0, 2*header.HeaderMinSize)

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	for _, refs := range [][]int{{7}, {0, 31}} {
		err := v.SetToken(context.Background(), 0, Token{Type: TokenTypeRecovery, Keyslots: refs})
		if !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("SetToken naming keyslots %v: got %v, want ErrInvalidHeader", refs, err)
		}
	}
	if !bytes.Equal(before, readAreaBytes(t, path, 0, 2*header.HeaderMinSize)) {
		t.Fatal("a refused SetToken changed the header")
	}

	if err := v.SetToken(context.Background(), 0, Token{Type: TokenTypeRecovery, Keyslots: []int{0}}); err != nil {
		t.Fatalf("SetToken naming the keyslot the header has: %v", err)
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
	hdr, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	metadata.Tokens["0"] = &LegacyToken{Type: TokenTypeRecovery, Keyslots: []string{"7"}}
	if err := writeHeaderUnvalidated(path, hdr, metadata); err != nil {
		t.Fatalf("writeHeaderUnvalidated: %v", err)
	}
	before := fileDigest(t, path)

	_, err = addKeyForTest(path, []byte(conformancePassphrase), []byte("a-second-credential"), &addKeyOptionsForTest{
		KDFType: kdfTypePBKDF2, PBKDFIterTime: 1,
	})
	if !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("AddKey on a header carrying a dangling token: got %v, want ErrInvalidHeader", err)
	}
	if fileDigest(t, path) != before {
		t.Fatal("a refused AddKey wrote to the device")
	}
}
