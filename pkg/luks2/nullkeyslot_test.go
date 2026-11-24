// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// A JSON null keyslot unmarshals to a present key with a nil pointer, so comma-ok reports it found; the header read must drop it.

// nullKeyslotVolume writes a container with a null keyslot at "0" (scanned first) and a healthy one, and returns its path.
func nullKeyslotVolume(t *testing.T, name string) string {
	t.Helper()

	path := newImage(t, name)
	formatWithLibrary(t, path)

	hdr, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	healthy := cloneKeyslot(metadata.Keyslots["0"])
	metadata.Keyslots = map[string]*header.Keyslot{
		"0": nil,
		"1": healthy,
	}
	for _, digest := range metadata.Digests {
		digest.Keyslots = []string{"0", "1"}
	}

	if err := writeHeaderUnvalidated(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the null-keyslot fixture: %v", err)
	}

	return path
}

// TestNullKeyslotDoesNotSurviveTheHeaderRead: the null is removed where metadata is parsed.
func TestNullKeyslotDoesNotSurviveTheHeaderRead(t *testing.T) {
	defer parallel(t)()
	path := nullKeyslotVolume(t, "null-keyslot.img")

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("a container with a null keyslot no longer reads: %v", err)
	}

	if _, present := metadata.Keyslots["0"]; present {
		t.Fatal("the null keyslot is still present in the parsed metadata")
	}
	if len(metadata.Keyslots) != 1 {
		t.Fatalf("metadata carries %d keyslots, want 1", len(metadata.Keyslots))
	}
	if metadata.Keyslots["1"] == nil {
		t.Fatal("the healthy keyslot was dropped along with the null one")
	}

	// Dropping is not enough on its own: a digest still naming the dropped slot
	// makes the header this read produced internally inconsistent.
	for id, digest := range metadata.Digests {
		for _, ks := range digest.Keyslots {
			if ks == "0" {
				t.Fatalf("digest %q still references the dropped keyslot %q", id, ks)
			}
		}
	}
}

// TestWipeKeyslotDoesNotPanicOnANullKeyslot: (*Volume).RemoveKeyslot tolerates a null keyslot.
func TestRemoveKeyslotDoesNotPanicOnANullKeyslot(t *testing.T) {
	defer parallel(t)()

	path := nullKeyslotVolume(t, "null-wipe.img")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	// After the boundary fix the slot is gone, so this is the ordinary
	// does-not-exist path -- which is the point. A null must be indistinguishable
	// from absent to every consumer.
	err = v.RemoveKeyslot(context.Background(), 0)
	if err == nil {
		t.Fatal("RemoveKeyslot acted on a keyslot that is not there")
	}
	if !strings.Contains(err.Error(), "0") {
		t.Fatalf("the error does not name the keyslot it refused: %v", err)
	}

	// The healthy keyslot is untouched: refusing a null must not damage the
	// volume around it.
	if err := testKeyForTest(path, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("the volume no longer opens after a refused RemoveKeyslot: %v", err)
	}
}

// TestGetMasterKeyDoesNotPanicOnANullKeyslot is the second: the scan
// dereferences .Type on whatever the map yields.
//
// The null is at "0", so the scan reaches it before the healthy slot rather
// than stopping at a success first.
func TestGetMasterKeyDoesNotPanicOnANullKeyslot(t *testing.T) {
	defer parallel(t)()

	path := nullKeyslotVolume(t, "null-scan.img")

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	key, err := getMasterKey(path, []byte(conformancePassphrase), metadata, testVolumeSys())
	if err != nil {
		t.Fatalf("a null keyslot ahead of a healthy one denied the volume: %v", err)
	}
	mustDestroy(t, key)
}

// TestEveryExportedPathToleratesANullKeyslot sweeps the exported surface.
func TestEveryExportedPathToleratesANullKeyslot(t *testing.T) {
	defer parallel(t)()

	passphrase := []byte(conformancePassphrase)

	// A fresh volume per operation: several of these mutate the header.
	t.Run("ReadHeader", func(t *testing.T) {
		if _, _, err := readHeaderForTest(nullKeyslotVolume(t, "n1.img")); err != nil {
			t.Fatalf("ReadHeader: %v", err)
		}
	})

	t.Run("GetVolumeInfo", func(t *testing.T) {
		info, err := getVolumeInfoForTest(nullKeyslotVolume(t, "n2.img"))
		if err != nil {
			t.Fatalf("GetVolumeInfo: %v", err)
		}
		for _, id := range info.ActiveKeyslots {
			if id == 0 {
				t.Fatal("GetVolumeInfo reports the dropped null keyslot as active")
			}
		}
	})

	t.Run("ListKeyslots", func(t *testing.T) {
		slots, err := listKeyslotsForTest(nullKeyslotVolume(t, "n3.img"))
		if err != nil {
			t.Fatalf("ListKeyslots: %v", err)
		}
		if len(slots) != 1 {
			t.Fatalf("ListKeyslots reported %d slots, want 1", len(slots))
		}
	})

	t.Run("TestKey", func(t *testing.T) {
		if err := testKeyForTest(nullKeyslotVolume(t, "n4.img"), passphrase); err != nil {
			t.Fatalf("TestKey: %v", err)
		}
	})

	t.Run("AddKey", func(t *testing.T) {
		path := nullKeyslotVolume(t, "n5.img")
		if _, err := addKeyForTest(path, passphrase, []byte("a-second-credential"), &addKeyOptionsForTest{
			KDFType:       kdfTypePBKDF2,
			PBKDFIterTime: 1,
		}); err != nil {
			t.Fatalf("AddKey: %v", err)
		}
	})

	t.Run("KillSlot", func(t *testing.T) {
		// Only one usable slot remains after the null is dropped, so this must
		// refuse -- cleanly, naming the reason, not panic.
		err := killSlotForTest(nullKeyslotVolume(t, "n6.img"), passphrase, 1)
		if err == nil {
			t.Fatal("KillSlot removed the last usable keyslot")
		}
	})

	t.Run("KillKeyslot", func(t *testing.T) {
		err := killKeyslotForTest(nullKeyslotVolume(t, "n7.img"), 0)
		if err == nil {
			t.Fatal("KillKeyslot acted on a keyslot that is not there")
		}
	})

	t.Run("RemoveKey", func(t *testing.T) {
		err := removeKeyForTest(nullKeyslotVolume(t, "n8.img"), passphrase, 0)
		if err == nil {
			t.Fatal("RemoveKey acted on a keyslot that is not there")
		}
	})

	t.Run("ChangeKey", func(t *testing.T) {
		err := changeKeyForTest(nullKeyslotVolume(t, "n9.img"), passphrase, []byte("a-new-credential"), 0)
		if err == nil {
			t.Fatal("ChangeKey acted on a keyslot that is not there")
		}
	})
}

// TestNullsAreRefusedWhereTheyCannotBeDropped: null segments and digests are refused rather than dropped.
func TestNullsAreRefusedWhereTheyCannotBeDropped(t *testing.T) {
	defer parallel(t)()

	cases := []struct {
		name   string
		mutate func(*header.Metadata)
	}{
		{"null segment", func(m *header.Metadata) { m.Segments["0"] = nil }},
		{"null digest", func(m *header.Metadata) { m.Digests["0"] = nil }},
		{"null config", func(m *header.Metadata) { m.Config = nil }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := newImage(t, "null-refused.img")
			formatWithLibrary(t, path)

			hdr, metadata, err := readHeaderForTest(path)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			tc.mutate(metadata)

			// Not a Skip. All three fixtures write today, and a skip here would
			// silently stop testing the refusal it exists for -- the failure
			// mode the entrypoint's `|| true` had.
			if err := writeHeaderUnvalidated(path, hdr, metadata); err != nil {
				t.Fatalf("the fixture could not be written, so the reader was never exercised: %v", err)
			}

			if _, _, err := readHeaderForTest(path); !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("a null that cannot be dropped was not refused: %v", err)
			}
		})
	}
}

// TestNullTokenIsDroppedToo covers the auxiliary unlock paths. A malformed TPM
// or FIDO2 token must not stop a volume opening by passphrase, so it is dropped
// on the same reasoning as a null keyslot.
func TestNullTokenIsDroppedToo(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "null-token.img")
	formatWithLibrary(t, path)

	hdr, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Tokens = map[string]*LegacyToken{"0": nil}

	if err := writeHeaderUnvalidated(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the fixture: %v", err)
	}

	_, reread, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("a container with a null token no longer reads: %v", err)
	}
	if _, present := reread.Tokens["0"]; present {
		t.Fatal("the null token survived the read")
	}

	if err := testKeyForTest(path, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("a null token stopped the volume opening by passphrase: %v", err)
	}
}
