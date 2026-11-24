// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// A keyslot's declared fields size work, so they are bounded before the derivation, per keyslot (see keyslotpanic_test.go).

// craftKeyslot writes a container and rewrites keyslot 0's fields through writeHeaderInternal, which does not validate keyslots.
func craftKeyslot(t *testing.T, name string, mutate func(*header.Keyslot)) string {
	t.Helper()

	path := newImage(t, name)
	formatWithLibrary(t, path)

	hdr, metadata, err := readHeaderForTest(path)
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

// TestCraftedKeySizeIsRefusedBeforeAnyDerivation asserts the refusal and, by TotalAlloc, that no derivation ran.
func TestCraftedKeySizeIsRefusedBeforeAnyDerivation(t *testing.T) {
	// 1 MiB: far above any real key, small enough to fail fast on regression.
	const craftedKeySize = 1 << 20

	device := craftKeyslot(t, "crafted-keysize.img", func(ks *header.Keyslot) {
		ks.KeySize = craftedKeySize
		ks.Area.KeySize = craftedKeySize
	})

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	err := testKeyForTest(device, []byte(conformancePassphrase))

	runtime.ReadMemStats(&after)

	if err == nil {
		t.Fatalf("a keyslot declaring a %d-byte volume key was accepted", craftedKeySize)
	}

	// The error is pinned in TestCraftedKeyslotFieldsAreRefused; this measures cost.
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated >= craftedKeySize {
		t.Fatalf("the attempt allocated %d bytes for a keyslot declaring a %d-byte key: the derivation ran before the bound was applied",
			allocated, craftedKeySize)
	}
	t.Logf("refused after allocating %d bytes for a header declaring a %d-byte key", allocated, craftedKeySize)
}

// TestCraftedKeySizeStillReadsButDoesNotOpen: the header reads, the keyslot does not open.
func TestCraftedKeySizeStillReadsButDoesNotOpen(t *testing.T) {
	device := craftKeyslot(t, "crafted-read.img", func(ks *header.Keyslot) {
		ks.KeySize = 1 << 24
		ks.Area.KeySize = 1 << 24
	})

	if _, _, err := readHeaderForTest(device); err != nil {
		t.Fatalf("a container with a damaged keyslot no longer reads: %v", err)
	}
	if err := testKeyForTest(device, []byte(conformancePassphrase)); err == nil {
		t.Fatal("a keyslot declaring a 16 MiB volume key opened the volume")
	}
}

// TestCraftedKeyslotFieldsAreRefused covers the declared geometry through the real unlock path.
func TestCraftedKeyslotFieldsAreRefused(t *testing.T) {
	// One container for every case; mutations apply to an in-memory clone.
	path := newImage(t, "crafted.img")
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
		{"key size of zero", func(ks *header.Keyslot) { ks.KeySize = 0 }},
		{"negative key size", func(ks *header.Keyslot) { ks.KeySize = -64 }},
		{"key size past the bound", func(ks *header.Keyslot) { ks.KeySize = header.MaxKeyslotKeySize + 1 }},
		{"zero stripes", func(ks *header.Keyslot) { ks.AF.Stripes = 0 }},
		{"negative stripes", func(ks *header.Keyslot) { ks.AF.Stripes = -1 }},
		{"stripes past the spec value", func(ks *header.Keyslot) { ks.AF.Stripes = header.AFStripes + 1 }},
		{"no anti-forensic object", func(ks *header.Keyslot) { ks.AF = nil }},
		{"no kdf object", func(ks *header.Keyslot) { ks.KDF = nil }},
		{"no area object", func(ks *header.Keyslot) { ks.Area = nil }},
		{"area size of zero", func(ks *header.Keyslot) { ks.Area.Size = "0" }},
		{"negative area size", func(ks *header.Keyslot) { ks.Area.Size = "-4096" }},
		{"area size that is not a number", func(ks *header.Keyslot) { ks.Area.Size = "lots" }},
		{"area offset that is not a number", func(ks *header.Keyslot) { ks.Area.Offset = "somewhere" }},
		{"area size past the bound", func(ks *header.Keyslot) {
			ks.Area.Size = formatSize(header.MaxKeyslotAreaSize + 1)
		}},
		{"overflowing key size and stripe count", func(ks *header.Keyslot) {
			// math.MaxInt/4 so KeySize*Stripes overflows on every int width.
			ks.KeySize = math.MaxInt / 4
			ks.AF.Stripes = 8
		}},
		// Measured against cryptsetup 2.7.0: a keyslot whose AF material does
		// not fit its own declared area is refused by cryptsetup too --
		// luksOpen reports "header.Keyslot open failed" -- so refusing it here costs
		// no container that any implementation can open.
		{"anti-forensic material larger than the area that holds it", func(ks *header.Keyslot) {
			ks.Area.Size = formatSize(int64(ks.KeySize) * int64(ks.AF.Stripes) / 2)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyslot := cloneKeyslot(good)
			tc.mutate(keyslot)

			key, err := unlockKeyslot(context.Background(), path, "0", []byte(conformancePassphrase), keyslot, metadata.Digests, testVolumeSys())
			if err == nil {
				mustDestroy(t, key)
				t.Fatal("unlockKeyslot accepted the crafted keyslot")
			}
			if !errors.Is(err, ErrKeyslotNotFound) {
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
	device := craftKeyslot(t, "crafted-ondisk.img", func(ks *header.Keyslot) { ks.AF = nil })

	if _, _, err := readHeaderForTest(device); err != nil {
		t.Fatalf("a container with a crafted keyslot no longer reads: %v", err)
	}
	if err := testKeyForTest(device, []byte(conformancePassphrase)); err == nil {
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
			keyslot := &header.Keyslot{
				Type:    "luks2",
				KeySize: keySize,
				KDF:     &header.KDF{Type: "pbkdf2", Hash: "sha256", Salt: "c2FsdA=="},
				AF:      &header.AntiForensic{Type: "luks1", Stripes: header.AFStripes, Hash: "sha256"},
				Area: &header.KeyslotArea{
					Type:       "raw",
					KeySize:    keySize,
					Offset:     "32768",
					Size:       formatSize(alignTo(int64(keySize)*header.AFStripes, keyslotAreaAlignment)),
					Encryption: "aes-xts-plain64",
				},
			}

			if err := header.ValidateKeyslot("0", keyslot); err != nil {
				t.Fatalf("a keyslot cryptsetup would write was refused: %v", err)
			}
		})
	}
}

// TestKeyslotValidationLeavesOtherKeyslotTypesAlone: a reencrypt keyslot does not make the container unreadable.
func TestKeyslotValidationLeavesOtherKeyslotTypesAlone(t *testing.T) {
	reencrypt := &header.Keyslot{
		Type:    "reencrypt",
		KeySize: 1,
		Area: &header.KeyslotArea{
			Type:   "checksum",
			Offset: "32768",
			Size:   "4096",
		},
	}

	if err := header.ValidateKeyslot("1", reencrypt); err != nil {
		t.Fatalf("a reencrypt keyslot was refused: %v", err)
	}

	// The generic resource bound still applies to it, though: an area size is
	// an area size whatever the keyslot type.
	reencrypt.Area.Size = formatSize(header.MaxKeyslotAreaSize + 1)
	if err := header.ValidateKeyslot("1", reencrypt); !errors.Is(err, ErrKeyslotNotFound) {
		t.Fatalf("an absurd area size was accepted because the keyslot type is not luks2: %v", err)
	}
}

// TestUnlockKeyslotRefusesAKeyslotTypeItCannotOpen: a named reencrypt keyslot has no kdf and is refused.
func TestUnlockKeyslotRefusesAKeyslotTypeItCannotOpen(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "wrong-type.img")
	formatWithLibrary(t, path)

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	reencrypt := &header.Keyslot{
		Type:    "reencrypt",
		KeySize: 1,
		Area:    &header.KeyslotArea{Type: "checksum", Offset: "32768", Size: "4096"},
	}

	key, err := unlockKeyslot(context.Background(), path, "0", []byte(conformancePassphrase), reencrypt, metadata.Digests, testVolumeSys())
	if err == nil {
		mustDestroy(t, key)
		t.Fatal("unlockKeyslot opened a keyslot type it does not implement")
	}
	if !errors.Is(err, ErrKeyslotNotFound) {
		t.Fatalf("the refusal does not name an unusable keyslot: %v", err)
	}
}

// TestListKeyslotsSurvivesAKeyslotWithNoKDF pins the other nil dereference the
// validation now prevents at read, at the one exported function that walks
// keyslots without opening them.
func TestListKeyslotsSurvivesAKeyslotWithNoKDF(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "listable.img")
	formatWithLibrary(t, path)

	// Reached directly rather than through a crafted header, because the point
	// is that this function must not panic even if something hands it a keyslot
	// the reader would have refused.
	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Keyslots["1"] = &header.Keyslot{Type: "reencrypt", KeySize: 1}

	slots, err := listKeyslotsFrom(metadata)
	if err != nil {
		t.Fatalf("listKeyslotsFrom failed: %v", err)
	}
	if len(slots) != 2 {
		t.Fatalf("listKeyslotsFrom returned %d slots, want 2", len(slots))
	}
	for _, slot := range slots {
		if slot.ID == 1 && slot.KDF.Type != "" {
			t.Fatalf("a keyslot with no KDF reported KDF type %q", slot.KDF.Type)
		}
	}
}
