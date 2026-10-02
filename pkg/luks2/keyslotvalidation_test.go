// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"fmt"
	"math"
	"runtime"
	"testing"
)

// A keyslot's declared fields come off an UNTRUSTED device and they size work.
//
// key_size decides how many bytes the KDF is asked to produce and therefore how
// much CPU PBKDF2 burns (its cost scales with the requested output length) and
// how much of the process's RLIMIT_MEMLOCK the derived key consumes. stripes and
// area.size decide how much is read, decrypted and merged.
//
// Bounding them at the point where the anti-forensic area is computed is too
// late: the passphrase derivation runs first. These tests pin the bounds ahead
// of that derivation, at every entry point that acts on a keyslot, and pin them
// as PER-KEYSLOT failures -- see keyslotpanic_test.go for why a header-wide
// refusal is the wrong shape.

// craftKeyslot writes a container and then rewrites keyslot 0's declared fields
// to whatever the caller wants, leaving everything else exactly as this library
// wrote it.
//
// The header is written through writeHeaderInternal, which does not validate
// keyslots, so the fixture really is a container an attacker could hand us.
func craftKeyslot(t *testing.T, name string, mutate func(*Keyslot)) string {
	t.Helper()

	path := newImage(t, name)
	formatWithLibrary(t, path)

	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed on the freshly formatted fixture: %v", err)
	}

	keyslot, ok := metadata.Keyslots["0"]
	if !ok {
		t.Fatal("fixture precondition: keyslot 0 is missing")
	}
	mutate(keyslot)

	if err := writeHeaderInternal(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the crafted header: %v", err)
	}

	return path
}

// TestCraftedKeySizeIsRefusedBeforeAnyDerivation is the regression test for the
// cost half.
//
// It asserts the refusal AND that the work never happened, because "returns an
// error eventually" is what the unfixed code already did -- it derived the whole
// oversized key first and only then failed on the cipher's key length. The
// allocation delta is what separates the two: runtime.MemStats.TotalAlloc is
// CUMULATIVE, so a derivation that has since been freed still shows up, which
// makes this a deterministic measurement rather than a timing one.
func TestCraftedKeySizeIsRefusedBeforeAnyDerivation(t *testing.T) {
	// 1 MiB: sixteen thousand times the largest key cryptsetup will format,
	// and small enough that a REGRESSION shows up as a slow failing test rather
	// than a hung one. Measured before the bound existed, 8 MiB here did not
	// finish inside the test binary's 480-second timeout.
	const craftedKeySize = 1 << 20

	device := craftKeyslot(t, "crafted-keysize.img", func(ks *Keyslot) {
		ks.KeySize = craftedKeySize
		ks.Area.KeySize = craftedKeySize
	})

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	err := TestKey(device, []byte(conformancePassphrase))

	runtime.ReadMemStats(&after)

	if err == nil {
		t.Fatalf("a keyslot declaring a %d-byte volume key was accepted", craftedKeySize)
	}

	// The error TestKey reports is deliberately not asserted on here. The scan
	// skips an unusable keyslot and, having skipped every one, reports that the
	// passphrase opened nothing -- which is the right thing for the scan to do
	// and the wrong thing to hang this measurement on. The keyslot-level error
	// is pinned directly in TestCraftedKeyslotFieldsAreRefused; what is
	// measured HERE is the cost, which is the half a type assertion cannot see.
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated >= craftedKeySize {
		t.Fatalf("the attempt allocated %d bytes for a keyslot declaring a %d-byte key: the derivation ran before the bound was applied",
			allocated, craftedKeySize)
	}
	t.Logf("refused after allocating %d bytes for a header declaring a %d-byte key", allocated, craftedKeySize)
}

// TestCraftedKeySizeStillReadsButDoesNotOpen is the counterpart, and it pins the
// boundary between the two halves of this design.
//
// The header must still READ -- an operator has to be able to inspect a
// container whose keyslot is damaged, and that is exactly when they need to --
// while the keyslot must not OPEN. Asserting only the refusal would be
// satisfied by refusing the header outright, which is the shape this package
// deliberately does not have.
func TestCraftedKeySizeStillReadsButDoesNotOpen(t *testing.T) {
	device := craftKeyslot(t, "crafted-read.img", func(ks *Keyslot) {
		ks.KeySize = 1 << 24
		ks.Area.KeySize = 1 << 24
	})

	if _, _, err := ReadHeader(device); err != nil {
		t.Fatalf("a container with a damaged keyslot no longer reads: %v", err)
	}
	if err := TestKey(device, []byte(conformancePassphrase)); err == nil {
		t.Fatal("a keyslot declaring a 16 MiB volume key opened the volume")
	}
}

// TestCraftedKeyslotFieldsAreRefused covers the rest of the declared geometry
// through the real unlock path, including the shapes that made this library
// PANIC rather than merely work too hard.
func TestCraftedKeyslotFieldsAreRefused(t *testing.T) {
	// ONE container, reused by every case.
	//
	// Each case used to format its own, which is 16 formats -- and a format is
	// dominated by a 600000-iteration digest derivation, so on a CI runner
	// roughly fourteen times slower than a workstation this single test cost 72
	// seconds and helped push the package past the 10-minute go test timeout.
	// The mutation only has to reach unlockKeyslot, which takes a *Keyslot, so
	// it is applied to an in-memory clone and nothing is rewritten to disk.
	path := newImage(t, "crafted.img")
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
		{"key size of zero", func(ks *Keyslot) { ks.KeySize = 0 }},
		{"negative key size", func(ks *Keyslot) { ks.KeySize = -64 }},
		{"key size past the bound", func(ks *Keyslot) { ks.KeySize = MaxKeyslotKeySize + 1 }},
		{"zero stripes", func(ks *Keyslot) { ks.AF.Stripes = 0 }},
		{"negative stripes", func(ks *Keyslot) { ks.AF.Stripes = -1 }},
		{"stripes past the spec value", func(ks *Keyslot) { ks.AF.Stripes = AFStripes + 1 }},
		{"no anti-forensic object", func(ks *Keyslot) { ks.AF = nil }},
		{"no kdf object", func(ks *Keyslot) { ks.KDF = nil }},
		{"no area object", func(ks *Keyslot) { ks.Area = nil }},
		{"area size of zero", func(ks *Keyslot) { ks.Area.Size = "0" }},
		{"negative area size", func(ks *Keyslot) { ks.Area.Size = "-4096" }},
		{"area size that is not a number", func(ks *Keyslot) { ks.Area.Size = "lots" }},
		{"area offset that is not a number", func(ks *Keyslot) { ks.Area.Offset = "somewhere" }},
		{"area size past the bound", func(ks *Keyslot) {
			ks.Area.Size = formatSize(maxKeyslotAreaSize + 1)
		}},
		{"overflowing key size and stripe count", func(ks *Keyslot) {
			// math.MaxInt/4, not 1<<62. The property under test is that
			// KeySize * Stripes OVERFLOWS, and no single constant expresses
			// that on every width: 1<<62 overflows an int on a 32-bit target
			// at COMPILE time, so this file did not build for GOARCH=386 or
			// arm. Derived from the platform's own int width, the case means
			// the same thing everywhere it runs.
			ks.KeySize = math.MaxInt / 4
			ks.AF.Stripes = 8
		}},
		// Measured against cryptsetup 2.7.0: a keyslot whose AF material does
		// not fit its own declared area is refused by cryptsetup too --
		// luksOpen reports "Keyslot open failed" -- so refusing it here costs
		// no container that any implementation can open.
		{"anti-forensic material larger than the area that holds it", func(ks *Keyslot) {
			ks.Area.Size = formatSize(int64(ks.KeySize) * int64(ks.AF.Stripes) / 2)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyslot := cloneKeyslot(good)
			tc.mutate(keyslot)

			key, err := unlockKeyslot(path, "0", []byte(conformancePassphrase), keyslot, metadata.Digests)
			if err == nil {
				mustDestroy(t, key)
				t.Fatal("unlockKeyslot accepted the crafted keyslot")
			}
			if !errors.Is(err, ErrInvalidKeyslot) {
				t.Fatalf("the refusal is not an unusable-keyslot error: %v", err)
			}
		})
	}
}

// TestACraftedKeyslotStillLeavesTheHeaderReadable is the on-disk half, kept as
// ONE case rather than repeated for every field: what it establishes -- that
// damage to a keyslot is not damage to the header -- does not vary with which
// field was damaged, and re-establishing it sixteen times bought nothing but
// fifteen more formats.
func TestACraftedKeyslotStillLeavesTheHeaderReadable(t *testing.T) {
	device := craftKeyslot(t, "crafted-ondisk.img", func(ks *Keyslot) { ks.AF = nil })

	if _, _, err := ReadHeader(device); err != nil {
		t.Fatalf("a container with a crafted keyslot no longer reads: %v", err)
	}
	if err := TestKey(device, []byte(conformancePassphrase)); err == nil {
		t.Fatal("a keyslot with no anti-forensic object opened the volume")
	}
}

// TestValidKeyslotGeometryIsAccepted is the control. Without it every assertion
// above is satisfied by a validator that refuses everything, which would refuse
// every real container along with the crafted ones.
func TestValidKeyslotGeometryIsAccepted(t *testing.T) {
	// The two key sizes cryptsetup 2.7.0 will format in XTS mode -- it refuses
	// anything else outright with "Key size in XTS mode must be 256 or 512
	// bits" -- plus the AF geometry this library and cryptsetup both write.
	for _, keySize := range []int{32, 64} {
		t.Run(fmt.Sprintf("%d-byte key", keySize), func(t *testing.T) {
			keyslot := &Keyslot{
				Type:    "luks2",
				KeySize: keySize,
				KDF:     &KDF{Type: "pbkdf2", Hash: "sha256", Salt: "c2FsdA=="},
				AF:      &AntiForensic{Type: "luks1", Stripes: AFStripes, Hash: "sha256"},
				Area: &KeyslotArea{
					Type:       "raw",
					KeySize:    keySize,
					Offset:     "32768",
					Size:       formatSize(alignTo(int64(keySize)*AFStripes, KeyslotAreaAlignment)),
					Encryption: "aes-xts-plain64",
				},
			}

			if err := validateKeyslot("0", keyslot); err != nil {
				t.Fatalf("a keyslot cryptsetup would write was refused: %v", err)
			}
		})
	}
}

// TestKeyslotValidationLeavesOtherKeyslotTypesAlone protects containers this
// package does not open but should still be able to READ.
//
// LUKS2 defines a "reencrypt" keyslot alongside "luks2". It carries no
// anti-forensic object and its area is a checksum region rather than raw key
// material, so applying the luks2 rules to it would make a container in the
// middle of a reencryption unreadable -- including by GetVolumeInfo, which is
// exactly what an operator reaches for when something is wrong.
func TestKeyslotValidationLeavesOtherKeyslotTypesAlone(t *testing.T) {
	reencrypt := &Keyslot{
		Type:    "reencrypt",
		KeySize: 1,
		Area: &KeyslotArea{
			Type:   "checksum",
			Offset: "32768",
			Size:   "4096",
		},
	}

	if err := validateKeyslot("1", reencrypt); err != nil {
		t.Fatalf("a reencrypt keyslot was refused: %v", err)
	}

	// The generic resource bound still applies to it, though: an area size is
	// an area size whatever the keyslot type.
	reencrypt.Area.Size = formatSize(maxKeyslotAreaSize + 1)
	if err := validateKeyslot("1", reencrypt); !errors.Is(err, ErrInvalidKeyslot) {
		t.Fatalf("an absurd area size was accepted because the keyslot type is not luks2: %v", err)
	}
}

// TestUnlockKeyslotRefusesAKeyslotTypeItCannotOpen covers the direct callers.
//
// RemoveKey, ChangeKey and KillSlot pass a NAMED keyslot to unlockKeyslot
// without consulting its type, unlike the scan in getMasterKey. A reencrypt
// keyslot has no kdf object, so reaching the derivation with one dereferences
// nil.
func TestUnlockKeyslotRefusesAKeyslotTypeItCannotOpen(t *testing.T) {
	path := newImage(t, "wrong-type.img")
	formatWithLibrary(t, path)

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	reencrypt := &Keyslot{
		Type:    "reencrypt",
		KeySize: 1,
		Area:    &KeyslotArea{Type: "checksum", Offset: "32768", Size: "4096"},
	}

	key, err := unlockKeyslot(path, "0", []byte(conformancePassphrase), reencrypt, metadata.Digests)
	if err == nil {
		mustDestroy(t, key)
		t.Fatal("unlockKeyslot opened a keyslot type it does not implement")
	}
	if !errors.Is(err, ErrInvalidKeyslot) {
		t.Fatalf("the refusal does not name an unusable keyslot: %v", err)
	}
}

// TestListKeyslotsSurvivesAKeyslotWithNoKDF pins the other nil dereference the
// validation now prevents at read, at the one exported function that walks
// keyslots without opening them.
func TestListKeyslotsSurvivesAKeyslotWithNoKDF(t *testing.T) {
	path := newImage(t, "listable.img")
	formatWithLibrary(t, path)

	// Reached directly rather than through a crafted header, because the point
	// is that this function must not panic even if something hands it a keyslot
	// the reader would have refused.
	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Keyslots["1"] = &Keyslot{Type: "reencrypt", KeySize: 1}

	slots, err := listKeyslotsFrom(metadata)
	if err != nil {
		t.Fatalf("listKeyslotsFrom failed: %v", err)
	}
	if len(slots) != 2 {
		t.Fatalf("listKeyslotsFrom returned %d slots, want 2", len(slots))
	}
	for _, slot := range slots {
		if slot.ID == 1 && slot.KDFType != "" {
			t.Fatalf("a keyslot with no KDF reported KDF type %q", slot.KDFType)
		}
	}
}
