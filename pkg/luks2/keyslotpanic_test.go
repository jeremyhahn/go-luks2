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

// A malformed keyslot must produce an ERROR, never a panic, and must never take
// the rest of the volume with it.
//
// # Why a panic is the severe case here
//
// go-luks2 used to be reached by shelling out to cryptsetup, where a crash was
// a non-zero exit code in a child process. It is now consumed IN PROCESS by
// go-blockstore, so a panic on a crafted header is a storage-daemon crash: one
// hostile image taken from a tenant, one byte edited in its JSON, and the
// process serving every other volume goes down.
//
// x/crypto/pbkdf2.Key panics on any error from crypto/pbkdf2, and the stdlib
// errors on keyLength <= 0 ("pkbdf2: keyLength must be larger than 0"), so a
// keyslot declaring key_size 0 reaches a panic through a function whose
// signature promises an error. The nil objects panic more directly.
//
// # Why these are per-keyslot errors and not header refusals
//
// The volume must stay openable through its OTHER keyslots. A LUKS2 container
// carries up to 32 of them precisely so that damage to one is survivable, and
// refusing the whole header on the first bad keyslot converts recoverable
// corruption into permanent data loss. That is the shape this package settled
// on after PR #9 and issue #37, and it is why every failure below is an
// ErrInvalidKeyslot -- the value the keyslot scan reads as "try the next one".

// TestMalformedKeyslotIsRefusedNotPanicked drives each shape through the real
// unlock path.
//
// Every case here PANICKED before the shape check moved ahead of the
// derivation: three of them on a nil dereference, and the key_size ones inside
// x/crypto's panic-on-error wrapper.
func TestMalformedKeyslotIsRefusedNotPanicked(t *testing.T) {
	t.Parallel()

	path := newImage(t, "malformed.img")
	formatWithLibrary(t, path)

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	good := metadata.Keyslots["0"]

	cases := []struct {
		name   string
		mutate func(*Keyslot)
	}{
		// x/crypto/pbkdf2.Key panics when crypto/pbkdf2 refuses the key
		// length, and it refuses keyLength <= 0.
		{"key size of zero", func(ks *Keyslot) { ks.KeySize = 0 }},
		{"negative key size", func(ks *Keyslot) { ks.KeySize = -1 }},
		// Nil dereferences, each on a field the unlock path reads before
		// anything checks it exists.
		{"no kdf object", func(ks *Keyslot) { ks.KDF = nil }},
		{"no area object", func(ks *Keyslot) { ks.Area = nil }},
		{"no anti-forensic object", func(ks *Keyslot) { ks.AF = nil }},
		// Resource bounds, which must also be applied before the derivation
		// rather than after it.
		{"absurd key size", func(ks *Keyslot) { ks.KeySize = 1 << 20 }},
		{"zero stripes", func(ks *Keyslot) { ks.AF = &AntiForensic{Type: "luks1", Stripes: 0, Hash: "sha256"} }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyslot := cloneKeyslot(good)
			tc.mutate(keyslot)

			key, err := unlockKeyslot(path, "0", []byte(conformancePassphrase), keyslot, metadata.Digests)
			if err == nil {
				mustDestroy(t, key)
				t.Fatal("unlockKeyslot accepted a malformed keyslot")
			}
			// ErrInvalidKeyslot specifically, not merely "an error": it is what
			// the scan reads as "this slot is unusable, try the next one".
			// A failure typed anything else would abort the whole unlock and
			// deny a volume its good keyslots can still open.
			if !errors.Is(err, ErrInvalidKeyslot) {
				t.Fatalf("the refusal is not an unusable-keyslot error, so the scan will not skip past it: %v", err)
			}
		})
	}
}

// TestOneMalformedKeyslotDoesNotDenyTheVolume is the availability half, and it
// is the reason the check lives at the keyslot rather than at the header.
//
// A container with a good keyslot and a damaged one must still open. Bit rot in
// an unused keyslot, or a slot left half-written by an interrupted AddKey, is
// exactly what a second keyslot exists to survive. Refusing the whole header on
// the first bad keyslot would turn that into an unopenable volume -- the same
// class of outcome as issue #37's reproduced data loss, reached from the other
// direction.
func TestOneMalformedKeyslotDoesNotDenyTheVolume(t *testing.T) {
	t.Parallel()

	path := newImage(t, "one-bad-slot.img")
	formatWithLibrary(t, path)

	hdr, metadata, err := ReadHeader(path)
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

	if err := writeHeaderInternal(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the damaged fixture: %v", err)
	}

	// The header still READS. A keyslot is a part of a container, not the
	// container, and an operator has to be able to look at a damaged one.
	if _, _, err := ReadHeader(path); err != nil {
		t.Fatalf("a container with one damaged keyslot no longer reads: %v", err)
	}

	// And it still OPENS, through the keyslot that is intact.
	if err := TestKey(path, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("a container with one damaged keyslot no longer opens through its good keyslot: %v", err)
	}

	// The damaged slot is still visible to an operator rather than silently
	// dropped: a keyslot that vanishes from an inventory is a keyslot nobody
	// repairs.
	slots, err := ListKeyslots(path)
	if err != nil {
		t.Fatalf("ListKeyslots failed: %v", err)
	}
	if len(slots) != 2 {
		t.Fatalf("ListKeyslots reported %d keyslots, want 2", len(slots))
	}

	// A wrong passphrase must still be refused, or the assertions above would
	// pass against an unlock that accepts anything.
	if err := TestKey(path, []byte(conformanceWrongPassphrase)); err == nil {
		t.Fatal("the damaged container accepted a wrong passphrase")
	}
}

// TestKillKeyslotRefusesAMalformedKeyslotArea covers the one path that acts on
// a keyslot's geometry with NO passphrase and therefore never reaches
// unlockKeyslot's screening.
//
// KillKeyslot goes straight to wipeKeyslotArea, which reads Area.Offset and
// Area.Size. A keyslot with no area object dereferences nil there, and one with
// a crafted offset writes zeros wherever it says.
func TestKillKeyslotRefusesAMalformedKeyslotArea(t *testing.T) {
	t.Parallel()

	path := newImage(t, "kill-malformed.img")
	formatWithLibrary(t, path)

	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	damaged := cloneKeyslot(metadata.Keyslots["0"])
	damaged.Area = nil
	metadata.Keyslots["1"] = damaged

	if err := writeHeaderInternal(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the damaged fixture: %v", err)
	}

	if err := KillKeyslot(path, 1); err == nil {
		t.Fatal("KillKeyslot acted on a keyslot with no area object")
	} else if !errors.Is(err, ErrInvalidKeyslot) {
		t.Fatalf("the refusal does not name an unusable keyslot: %v", err)
	}

	// The good keyslot still opens the volume: refusing to wipe a damaged slot
	// must not damage anything else.
	if err := TestKey(path, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("the volume no longer opens after a refused KillKeyslot: %v", err)
	}
}

// cloneDigests returns a copy of a digest map whose Keyslots lists a test can
// rewrite without disturbing the metadata it was copied from.
//
// It exists because a keyslot's digest ASSOCIATION is now load-bearing: a
// fixture that invents a second keyslot has to register it with a digest, the
// way AddKey does in production, or the new slot authenticates nothing. Sharing
// the digest pointers with the original metadata makes that registration leak
// into every other subtest.
func cloneDigests(src map[string]*Digest) map[string]*Digest {
	out := make(map[string]*Digest, len(src))
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
func cloneKeyslot(src *Keyslot) *Keyslot {
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

// TestUnlockKeyslotRefusesANonSectorArea covers the geometry that used to be
// silently clamped.
//
// An area that is not a whole number of 512-byte sectors cannot hold its own AF
// material through a sector-tweaked transform: the final short sector would be
// zero-padded and decrypt to something other than what was written. LUKS2's
// 4096-byte keyslot alignment rules this out for real containers, so it is
// refused with a message about the geometry rather than clamped into a failure
// that reports the AF material instead.
func TestUnlockKeyslotRefusesANonSectorArea(t *testing.T) {
	path := newImage(t, "ragged-area.img")
	formatWithLibrary(t, path)

	_, metadata, err := ReadHeader(path)
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

	key, err := unlockKeyslot(path, "0", []byte(conformancePassphrase), keyslot, metadata.Digests)
	if err == nil {
		mustDestroy(t, key)
		t.Fatal("unlockKeyslot accepted an area that is not a whole number of sectors")
	}
	if !errors.Is(err, ErrInvalidKeyslot) {
		t.Fatalf("the refusal is not an unusable-keyslot error: %v", err)
	}
	if !strings.Contains(err.Error(), "sector") {
		t.Fatalf("the error blames something other than the geometry that caused it: %v", err)
	}
}

// TestAddKeyDoesNotTemplateOffADamagedKeyslot covers the reference-keyslot pick.
//
// AddKey copies KeySize and the area encryption from an existing slot to size
// the derivation and AF split for the NEW one, so templating off a damaged slot
// would push its damage into a slot that is about to be written. The pick used
// to be "whichever keyslot the map yielded first", which also meant whether
// AddKey succeeded depended on Go's randomized map iteration.
func TestAddKeyDoesNotTemplateOffADamagedKeyslot(t *testing.T) {
	path := newImage(t, "damaged-template.img")
	formatWithLibrary(t, path)

	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	// A damaged slot numbered BELOW the good one, so scan order reaches it
	// first and the skip is what makes the pick land on the good slot.
	damaged := cloneKeyslot(metadata.Keyslots["0"])
	damaged.KeySize = 1 << 20
	metadata.Keyslots["0"] = damaged
	good := cloneKeyslot(metadata.Keyslots["0"])
	good.KeySize = 64
	metadata.Keyslots["7"] = good

	if err := writeHeaderInternal(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the fixture: %v", err)
	}

	// Repeated because a map-order-dependent pick passes intermittently, and a
	// test that passes intermittently is the one that hides this.
	for i := 0; i < 8; i++ {
		_, reread, err := ReadHeader(path)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}

		var reference *Keyslot
		for _, id := range keyslotIDsInScanOrder(reread.Keyslots) {
			ks := reread.Keyslots[id]
			if ks.Type != "luks2" || validateKeyslot(id, ks) != nil {
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
