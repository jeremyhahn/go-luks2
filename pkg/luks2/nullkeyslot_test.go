// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"strings"
	"testing"
)

// A keyslot written as JSON `null` is neither malformed enough to be refused
// nor populated enough to be used, and it does not vanish.
//
// A null in a map[string]*T unmarshals to a PRESENT key holding a nil pointer.
// So len() counts it, range yields it, and -- the part that has caught this
// package repeatedly -- the comma-ok idiom reports it as FOUND:
//
//	targetKeyslot, exists := metadata.Keyslots[slotIDStr]
//	if !exists { ... }
//
// `exists` is true. The map has the key. That check reads like a nil guard and
// is not one, and five sites lean on it as if it were.
//
// This is issue #67, and it is the same defect class as the four before it: a
// guarantee that exists at one call site and not at an earlier one on the same
// untrusted input. The difference here is that the guarantee lives in a CALLEE
// -- most of the sites survive only because they hand the keyslot to
// unlockKeyslot, which validates -- so they are one refactor away from
// panicking.

// nullKeyslotVolume writes a container carrying a healthy keyslot and a JSON
// null one, through the exported write path, and returns its path.
//
// The null is placed at "0" so the scan reaches it FIRST: whether a credential
// loop meets a null otherwise depends on scan order and on whether an earlier
// slot succeeds, which is exactly the kind of "passes by luck" this test must
// not rely on.
func nullKeyslotVolume(t *testing.T, name string) string {
	t.Helper()

	path := newImage(t, name)
	formatWithLibrary(t, path)

	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	healthy := cloneKeyslot(metadata.Keyslots["0"])
	metadata.Keyslots = map[string]*Keyslot{
		"0": nil,
		"1": healthy,
	}
	for _, digest := range metadata.Digests {
		digest.Keyslots = []string{"0", "1"}
	}

	if err := writeHeaderInternal(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the null-keyslot fixture: %v", err)
	}

	return path
}

// TestNullKeyslotDoesNotSurviveTheHeaderRead is the fix at the boundary.
//
// Guarding the dereferencing sites individually does not hold: on the
// issue/3-secure-buffer branch a review sweeping for exactly this enumerated
// seven sites and missed an eighth. An enumeration rots the moment anyone adds
// a consumer. So the null is removed where the metadata is parsed, and there is
// nothing left downstream to enumerate.
func TestNullKeyslotDoesNotSurviveTheHeaderRead(t *testing.T) {
	path := nullKeyslotVolume(t, "null-keyslot.img")

	_, metadata, err := ReadHeader(path)
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

// TestWipeKeyslotDoesNotPanicOnANullKeyslot is the first of the two sites that
// were not saved by a callee.
//
// WipeKeyslot is EXPORTED and reaches parseSize(ks.Area.Offset) with ks nil.
// There is no validateKeyslot call and no nil check anywhere in wipe.go, so a
// crafted header panics a public API.
func TestWipeKeyslotDoesNotPanicOnANullKeyslot(t *testing.T) {
	t.Parallel()

	path := nullKeyslotVolume(t, "null-wipe.img")

	// After the boundary fix the slot is gone, so this is the ordinary
	// does-not-exist path -- which is the point. A null must be indistinguishable
	// from absent to every consumer.
	err := WipeKeyslot(path, 0)
	if err == nil {
		t.Fatal("WipeKeyslot acted on a keyslot that is not there")
	}
	if !strings.Contains(err.Error(), "0") {
		t.Fatalf("the error does not name the keyslot it refused: %v", err)
	}

	// The healthy keyslot is untouched: refusing a null must not damage the
	// volume around it.
	if err := TestKey(path, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("the volume no longer opens after a refused WipeKeyslot: %v", err)
	}
}

// TestGetMasterKeyDoesNotPanicOnANullKeyslot is the second: the scan
// dereferences .Type on whatever the map yields.
//
// The null is at "0", so the scan reaches it before the healthy slot rather
// than stopping at a success first.
func TestGetMasterKeyDoesNotPanicOnANullKeyslot(t *testing.T) {
	t.Parallel()

	path := nullKeyslotVolume(t, "null-scan.img")

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	key, err := getMasterKey(path, []byte(conformancePassphrase), metadata)
	if err != nil {
		t.Fatalf("a null keyslot ahead of a healthy one denied the volume: %v", err)
	}
	mustDestroy(t, key)
}

// TestEveryExportedPathToleratesANullKeyslot sweeps the exported surface rather
// than the two sites that happen to panic today.
//
// The sites that survive do so because they hand the keyslot to unlockKeyslot,
// which validates -- a guarantee living in a callee, one refactor from being
// gone. Asserting the whole surface is what makes the boundary fix the thing
// being tested, rather than the two patches it would otherwise be.
func TestEveryExportedPathToleratesANullKeyslot(t *testing.T) {
	t.Parallel()

	passphrase := []byte(conformancePassphrase)

	// A fresh volume per operation: several of these mutate the header.
	t.Run("ReadHeader", func(t *testing.T) {
		if _, _, err := ReadHeader(nullKeyslotVolume(t, "n1.img")); err != nil {
			t.Fatalf("ReadHeader: %v", err)
		}
	})

	t.Run("GetVolumeInfo", func(t *testing.T) {
		info, err := GetVolumeInfo(nullKeyslotVolume(t, "n2.img"))
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
		slots, err := ListKeyslots(nullKeyslotVolume(t, "n3.img"))
		if err != nil {
			t.Fatalf("ListKeyslots: %v", err)
		}
		if len(slots) != 1 {
			t.Fatalf("ListKeyslots reported %d slots, want 1", len(slots))
		}
	})

	t.Run("TestKey", func(t *testing.T) {
		if err := TestKey(nullKeyslotVolume(t, "n4.img"), passphrase); err != nil {
			t.Fatalf("TestKey: %v", err)
		}
	})

	t.Run("AddKey", func(t *testing.T) {
		path := nullKeyslotVolume(t, "n5.img")
		if _, err := AddKey(path, passphrase, []byte("a-second-credential"), &AddKeyOptions{
			KDFType:       KDFTypePBKDF2,
			PBKDFIterTime: 1,
		}); err != nil {
			t.Fatalf("AddKey: %v", err)
		}
	})

	t.Run("KillSlot", func(t *testing.T) {
		// Only one usable slot remains after the null is dropped, so this must
		// refuse -- cleanly, naming the reason, not panic.
		err := KillSlot(nullKeyslotVolume(t, "n6.img"), passphrase, 1)
		if err == nil {
			t.Fatal("KillSlot removed the last usable keyslot")
		}
	})

	t.Run("KillKeyslot", func(t *testing.T) {
		err := KillKeyslot(nullKeyslotVolume(t, "n7.img"), 0)
		if err == nil {
			t.Fatal("KillKeyslot acted on a keyslot that is not there")
		}
	})

	t.Run("RemoveKey", func(t *testing.T) {
		err := RemoveKey(nullKeyslotVolume(t, "n8.img"), passphrase, 0)
		if err == nil {
			t.Fatal("RemoveKey acted on a keyslot that is not there")
		}
	})

	t.Run("ChangeKey", func(t *testing.T) {
		err := ChangeKey(nullKeyslotVolume(t, "n9.img"), passphrase, []byte("a-new-credential"), 0)
		if err == nil {
			t.Fatal("ChangeKey acted on a keyslot that is not there")
		}
	})
}

// TestNullsAreRefusedWhereTheyCannotBeDropped pins the other half of the rule.
//
// Dropping is right where a caller can do something USEFUL with the absence: a
// volume survives one damaged keyslot because it has others, and an auxiliary
// token is not the only way in. It is wrong where nothing useful remains --
// a segment whose location is unknown cannot be proved clear of, and a digest
// that cannot be evaluated must not be silently skipped, because skipping it
// weakens verification rather than degrading it.
func TestNullsAreRefusedWhereTheyCannotBeDropped(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		mutate func(*LUKS2Metadata)
	}{
		{"null segment", func(m *LUKS2Metadata) { m.Segments["0"] = nil }},
		{"null digest", func(m *LUKS2Metadata) { m.Digests["0"] = nil }},
		{"null config", func(m *LUKS2Metadata) { m.Config = nil }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := newImage(t, "null-refused.img")
			formatWithLibrary(t, path)

			hdr, metadata, err := ReadHeader(path)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			tc.mutate(metadata)

			// Not a Skip. All three fixtures write today, and a skip here would
			// silently stop testing the refusal it exists for -- the failure
			// mode the entrypoint's `|| true` had.
			if err := writeHeaderInternal(path, hdr, metadata); err != nil {
				t.Fatalf("the fixture could not be written, so the reader was never exercised: %v", err)
			}

			if _, _, err := ReadHeader(path); !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("a null that cannot be dropped was not refused: %v", err)
			}
		})
	}
}

// TestNullTokenIsDroppedToo covers the auxiliary unlock paths. A malformed TPM
// or FIDO2 token must not stop a volume opening by passphrase, so it is dropped
// on the same reasoning as a null keyslot.
func TestNullTokenIsDroppedToo(t *testing.T) {
	t.Parallel()

	path := newImage(t, "null-token.img")
	formatWithLibrary(t, path)

	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Tokens = map[string]*Token{"0": nil}

	if err := writeHeaderInternal(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the fixture: %v", err)
	}

	_, reread, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("a container with a null token no longer reads: %v", err)
	}
	if _, present := reread.Tokens["0"]; present {
		t.Fatal("the null token survived the read")
	}

	if err := TestKey(path, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("a null token stopped the volume opening by passphrase: %v", err)
	}
}
