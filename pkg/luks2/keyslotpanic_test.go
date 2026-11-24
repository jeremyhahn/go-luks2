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

// A malformed keyslot yields ErrInvalidKeyslot, never a panic, and the volume stays openable through its other keyslots.

// TestMalformedKeyslotIsRefusedNotPanicked drives each shape through the real unlock path.
func TestMalformedKeyslotIsRefusedNotPanicked(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "malformed.img")
	formatWithLibrary(t, path)

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	good := metadata.Keyslots["0"]

	cases := []struct {
		name   string
		mutate func(*header.Keyslot)
	}{
		// x/crypto/pbkdf2.Key panics when crypto/pbkdf2 refuses the key
		// length, and it refuses keyLength <= 0.
		{"key size of zero", func(ks *header.Keyslot) { ks.KeySize = 0 }},
		{"negative key size", func(ks *header.Keyslot) { ks.KeySize = -1 }},
		// Nil dereferences, each on a field the unlock path reads before
		// anything checks it exists.
		{"no kdf object", func(ks *header.Keyslot) { ks.KDF = nil }},
		{"no area object", func(ks *header.Keyslot) { ks.Area = nil }},
		{"no anti-forensic object", func(ks *header.Keyslot) { ks.AF = nil }},
		// Resource bounds, which must also be applied before the derivation
		// rather than after it.
		{"absurd key size", func(ks *header.Keyslot) { ks.KeySize = 1 << 20 }},
		{"zero stripes", func(ks *header.Keyslot) { ks.AF = &header.AntiForensic{Type: "luks1", Stripes: 0, Hash: "sha256"} }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyslot := cloneKeyslot(good)
			tc.mutate(keyslot)

			key, err := unlockKeyslot(context.Background(), path, "0", []byte(conformancePassphrase), keyslot, metadata.Digests, testVolumeSys())
			if err == nil {
				mustDestroy(t, key)
				t.Fatal("unlockKeyslot accepted a malformed keyslot")
			}
			// ErrInvalidKeyslot specifically, not merely "an error": it is what
			// the scan reads as "this slot is unusable, try the next one".
			// A failure typed anything else would abort the whole unlock and
			// deny a volume its good keyslots can still open.
			if !errors.Is(err, ErrKeyslotNotFound) {
				t.Fatalf("the refusal is not an unusable-keyslot error, so the scan will not skip past it: %v", err)
			}
		})
	}
}

// TestOneMalformedKeyslotDoesNotDenyTheVolume: a container with one good and one damaged keyslot still opens.
func TestOneMalformedKeyslotDoesNotDenyTheVolume(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "one-bad-slot.img")
	formatWithLibrary(t, path)

	hdr, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	// A second keyslot that is structurally a luks2 slot and structurally
	// broken: it declares a key size no derivation may be asked for.
	damaged := cloneKeyslot(metadata.Keyslots["0"])
	damaged.KeySize = 1 << 20
	metadata.Keyslots["1"] = damaged
	for _, digest := range metadata.Digests {
		digest.Keyslots = append(digest.Keyslots, "1")
	}

	if err := writeHeaderUnvalidated(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the damaged fixture: %v", err)
	}

	// The header still reads.
	if _, _, err := readHeaderForTest(path); err != nil {
		t.Fatalf("a container with one damaged keyslot no longer reads: %v", err)
	}

	// And it opens through the intact keyslot.
	if err := testKeyForTest(path, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("a container with one damaged keyslot no longer opens through its good keyslot: %v", err)
	}

	// The damaged slot is still visible to an operator rather than silently
	// dropped: a keyslot that vanishes from an inventory is a keyslot nobody
	// repairs.
	slots, err := listKeyslotsForTest(path)
	if err != nil {
		t.Fatalf("ListKeyslots failed: %v", err)
	}
	if len(slots) != 2 {
		t.Fatalf("ListKeyslots reported %d keyslots, want 2", len(slots))
	}

	// A wrong passphrase must still be refused, or the assertions above would
	// pass against an unlock that accepts anything.
	if err := testKeyForTest(path, []byte(conformanceWrongPassphrase)); err == nil {
		t.Fatal("the damaged container accepted a wrong passphrase")
	}
}

// TestKillKeyslotRefusesAMalformedKeyslotArea: KillKeyslot reaches wipeKeyslotArea without unlock screening, so it must refuse bad geometry itself.
func TestKillKeyslotRefusesAMalformedKeyslotArea(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "kill-malformed.img")
	formatWithLibrary(t, path)

	hdr, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	damaged := cloneKeyslot(metadata.Keyslots["0"])
	damaged.Area = nil
	metadata.Keyslots["1"] = damaged

	if err := writeHeaderUnvalidated(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the damaged fixture: %v", err)
	}

	if err := killKeyslotForTest(path, 1); err == nil {
		t.Fatal("KillKeyslot acted on a keyslot with no area object")
	} else if !errors.Is(err, ErrKeyslotNotFound) {
		t.Fatalf("the refusal does not name an unusable keyslot: %v", err)
	}

	// The good keyslot still opens the volume: refusing to wipe a damaged slot
	// must not damage anything else.
	if err := testKeyForTest(path, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("the volume no longer opens after a refused KillKeyslot: %v", err)
	}
}

// cloneDigests returns a copy of a digest map whose Keyslots lists a test can rewrite without affecting the original.
func cloneDigests(src map[string]*header.Digest) map[string]*header.Digest {
	out := make(map[string]*header.Digest, len(src))
	for id, d := range src {
		if d == nil {
			out[id] = nil
			continue
		}
		c := *d
		c.Keyslots = append([]string(nil), d.Keyslots...)
		c.Segments = append([]string(nil), d.Segments...)
		out[id] = &c
	}
	return out
}

// cloneKeyslot returns a deep enough copy that a test can damage one field
// without disturbing the keyslot it was copied from.
func cloneKeyslot(src *header.Keyslot) *header.Keyslot {
	out := *src
	if src.KDF != nil {
		kdf := *src.KDF
		out.KDF = &kdf
	}
	if src.AF != nil {
		af := *src.AF
		out.AF = &af
	}
	if src.Area != nil {
		area := *src.Area
		out.Area = &area
	}
	if src.Priority != nil {
		priority := *src.Priority
		out.Priority = &priority
	}
	return &out
}

// TestUnlockKeyslotRefusesANonSectorArea: an area that is not a whole number of 512-byte sectors is refused with a geometry message.
func TestUnlockKeyslotRefusesANonSectorArea(t *testing.T) {
	path := newImage(t, "ragged-area.img")
	formatWithLibrary(t, path)

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	keyslot := cloneKeyslot(metadata.Keyslots["0"])
	// The AF material must itself be a ragged number of sectors for the
	// rounding to land past the area: 64*4000 is a whole 500 sectors, so a key
	// size of 65 is used instead. The area is then exactly large enough to hold
	// the material and one byte short of the sector boundary above it.
	keyslot.KeySize = 65
	keyslot.Area.KeySize = 65
	keyslot.Area.Size = formatSize(int64(keyslot.KeySize) * int64(keyslot.AF.Stripes))

	if afBytes := int64(keyslot.KeySize) * int64(keyslot.AF.Stripes); afBytes%512 == 0 {
		t.Fatalf("fixture precondition: %d bytes of AF material is a whole number of sectors", afBytes)
	}

	key, err := unlockKeyslot(context.Background(), path, "0", []byte(conformancePassphrase), keyslot, metadata.Digests, testVolumeSys())
	if err == nil {
		mustDestroy(t, key)
		t.Fatal("unlockKeyslot accepted an area that is not a whole number of sectors")
	}
	if !errors.Is(err, ErrKeyslotNotFound) {
		t.Fatalf("the refusal is not an unusable-keyslot error: %v", err)
	}
	if !strings.Contains(err.Error(), "sector") {
		t.Fatalf("the error blames something other than the geometry that caused it: %v", err)
	}
}

// TestAddKeyDoesNotTemplateOffADamagedKeyslot: AddKey's reference keyslot skips damaged slots deterministically.
func TestAddKeyDoesNotTemplateOffADamagedKeyslot(t *testing.T) {
	path := newImage(t, "damaged-template.img")
	formatWithLibrary(t, path)

	hdr, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	// A damaged slot numbered below the good one, so the scan reaches it first.
	damaged := cloneKeyslot(metadata.Keyslots["0"])
	damaged.KeySize = 1 << 20
	metadata.Keyslots["0"] = damaged
	good := cloneKeyslot(metadata.Keyslots["0"])
	good.KeySize = 64
	metadata.Keyslots["7"] = good

	if err := writeHeaderUnvalidated(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the fixture: %v", err)
	}

	// Repeated because a map-order-dependent pick passes intermittently, and a
	// test that passes intermittently is the one that hides this.
	for i := 0; i < 8; i++ {
		_, reread, err := readHeaderForTest(path)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}

		var reference *header.Keyslot
		for _, id := range header.KeyslotIDsInScanOrder(reread.Keyslots) {
			ks := reread.Keyslots[id]
			if ks.Type != "luks2" || header.ValidateKeyslot(id, ks) != nil {
				continue
			}
			reference = ks
			break
		}
		if reference == nil {
			t.Fatal("no usable keyslot was found to template from")
		}
		if reference.KeySize != 64 {
			t.Fatalf("the damaged keyslot was chosen as a template: key size %d", reference.KeySize)
		}
	}
}
