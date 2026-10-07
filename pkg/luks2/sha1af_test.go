// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"crypto/fips140"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/af"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// SHA-1 anti-forensic keyslots (#236), against volumes cryptsetup wrote.
//
// LUKS1 split the volume key with SHA-1 by default, so every LUKS1 volume
// converted to LUKS2 carries SHA-1 AF keyslots, as does any `cryptsetup
// luksFormat --hash sha1`. cryptsetup opens them. This package reads them
// outside FIPS mode, refuses them inside it with the typed import error naming
// SHA-1, imports them into FIPS mode with MigrateToFIPS, and never writes one.
//
// Every fixture here is cryptsetup's, never this package's: what is under test
// is agreement with the third party.

// sha1AFKind is a cryptsetup-written volume shape with SHA-1 AF keyslots.
type sha1AFKind struct {
	name string
	// build formats image with cryptsetup and conformancePassphrase.
	build func(t *testing.T, image string)
	// keyslot is how a FIPS process names keyslot 0's refusal.
	keyslot NonApprovedKDF
}

// sha1AFKinds are the two shapes the issue names.
var sha1AFKinds = []sha1AFKind{
	{
		name: "luks2 --hash sha1",
		build: func(t *testing.T, image string) {
			t.Helper()
			args := append(append([]string{"luksFormat", "--type", "luks2", "--hash", "sha1"}, crashArgon2Args...), image)
			if code, out := runCryptsetup(t, conformancePassphrase, args...); code != 0 {
				t.Fatalf("cryptsetup luksFormat --hash sha1 exited %d\n%s", code, out)
			}
		},
		keyslot: NonApprovedKDF{ID: 0, Type: kdfTypeArgon2id, Reason: "anti-forensic hash sha1"},
	},
	{
		name: "luks1 --hash sha1, converted",
		build: func(t *testing.T, image string) {
			t.Helper()
			if code, out := runCryptsetup(t, conformancePassphrase, "luksFormat", "--type", "luks1", "--hash", "sha1",
				"--pbkdf-force-iterations", "1000", "--batch-mode", image); code != 0 {
				t.Fatalf("cryptsetup luksFormat --type luks1 exited %d\n%s", code, out)
			}
			if code, out := runCryptsetup(t, "", "convert", "--type", "luks2", "--batch-mode", image); code != 0 {
				t.Fatalf("cryptsetup convert exited %d\n%s", code, out)
			}
		},
		keyslot: NonApprovedKDF{ID: 0, Type: kdfTypePBKDF2, Hash: "sha1", Reason: "anti-forensic hash sha1"},
	},
}

// sha1AFVolume formats a fresh image of kind and checks it is what the test
// claims: keyslot 0 split with SHA-1, digest 0 over PBKDF2-SHA1.
func sha1AFVolume(t *testing.T, kind sha1AFKind) string {
	t.Helper()

	requireCryptsetup(t)
	image := newImage(t, "sha1-af.img")
	kind.build(t, image)
	_, metadata, err := readHeaderForTest(image)
	if err != nil {
		t.Fatalf("ReadHeader on cryptsetup's volume failed: %v", err)
	}
	if ks := metadata.Keyslots["0"]; ks == nil || ks.AF == nil || ks.AF.Hash != "sha1" {
		t.Fatalf("fixture keyslot 0 is %+v, want an anti-forensic hash of sha1; the test would measure nothing", ks)
	}
	if d := metadata.Digests["0"]; d == nil || d.Hash != "sha1" {
		t.Fatalf("fixture digest 0 is %+v, want pbkdf2-sha1", d)
	}
	return image
}

// TestSHA1AFVolumesOpenWithCryptsetupsVolumeKey: outside FIPS mode both shapes
// open with the passphrase, to the volume key cryptsetup itself recovers --
// byte compatibility of the SHA-1 merge -- and a wrong passphrase is a
// credential verdict, not a header fault.
func TestSHA1AFVolumesOpenWithCryptsetupsVolumeKey(t *testing.T) {
	for _, kind := range sha1AFKinds {
		t.Run(kind.name, func(t *testing.T) {
			image := sha1AFVolume(t, kind)
			if fips140.Enabled() {
				assertImportRequired(t, testKeyForTest(image, migrationPassphrase), image,
					[]NonApprovedKDF{kind.keyslot}, []NonApprovedKDF{{ID: 0, Type: kdfTypePBKDF2, Hash: "sha1"}})
				return
			}
			if err := testKeyForTest(image, migrationPassphrase); err != nil {
				t.Fatalf("TestKey on cryptsetup's SHA-1 AF volume: %v", err)
			}
			if got, want := hex.EncodeToString(volumeKey(t, image, migrationPassphrase)), cryptsetupVolumeKey(t, image); got != want {
				t.Fatal("the volume key recovered through the SHA-1 merge differs from cryptsetup's")
			}
			if err := testKeyForTest(image, []byte(conformanceWrongPassphrase)); !errors.Is(err, ErrWrongKey) {
				t.Fatalf("a wrong passphrase: got %v, want ErrWrongKey", err)
			}
		})
	}
}

// TestSHA1AFVolumesAreRefusedUnderTheFIPSPolicy: in FIPS mode both shapes are
// refused with the typed import error, naming the keyslot's SHA-1 AF hash and
// the SHA-1 digest -- not reported as damage. Run in-process with the policy
// forced; the child-process test below runs it under real fips140=only.
func TestSHA1AFVolumesAreRefusedUnderTheFIPSPolicy(t *testing.T) {
	for _, kind := range sha1AFKinds {
		t.Run(kind.name, func(t *testing.T) {
			image := sha1AFVolume(t, kind)
			sys := testVolumeSys()
			sys.fipsMode = forceFIPSPolicy(t)
			err := testKeyForTestWithSys(image, migrationPassphrase, sys)
			assertImportRequired(t, err, image,
				[]NonApprovedKDF{kind.keyslot}, []NonApprovedKDF{{ID: 0, Type: kdfTypePBKDF2, Hash: "sha1"}})
			if !strings.Contains(err.Error(), "anti-forensic hash sha1") {
				t.Fatalf("the refusal does not name the SHA-1 anti-forensic hash: %v", err)
			}
		})
	}
}

// TestFIPSImportOfSHA1AFVolumes: each shape is migrated by a non-FIPS process,
// leaving no SHA-1 anywhere -- keyslot KDF, AF hash or digest -- and the same
// volume key; cryptsetup still recovers that key; and a process under
// GODEBUG=fips140=only opens it.
func TestFIPSImportOfSHA1AFVolumes(t *testing.T) {
	// Parallel at both levels, the shape parallel's comment allows: each
	// subtest pauses in t.Parallel before it asks for a slot, so the parent's
	// body returns -- and gives its slot back -- before any subtest waits for
	// one. Measured with a one-slot memlock limit (ulimit -l 2048): the
	// subtests run one after the other and nothing waits on the parent.
	defer parallel(t)()
	for _, kind := range sha1AFKinds {
		t.Run(kind.name, func(t *testing.T) {
			defer parallel(t)()
			image := sha1AFVolume(t, kind)
			volumeKeyBefore := cryptsetupVolumeKey(t, image)

			if code, out := runChild(t, childRoleOpen, image, "fips140=only", true); code != childImportRequired ||
				!strings.Contains(out, "anti-forensic hash sha1") {
				t.Fatalf("FIPS open of the un-migrated volume exited %d, want %d naming the SHA-1 AF hash\n%s", code, childImportRequired, out)
			}

			code, out := runChild(t, childRoleMigrate, image, "fips140=off", false)
			if code != childOK {
				t.Fatalf("migration in a non-FIPS process exited %d\n%s", code, out)
			}
			var result fipsMigrationResultForTest
			if err := json.Unmarshal([]byte(out), &result); err != nil {
				t.Fatalf("could not read the migration result %q: %v", out, err)
			}
			if !result.Complete || !result.KeyslotAdded || !slices.Equal(result.MigratedDigests, []string{"0"}) ||
				!slices.Equal(result.RemovedKeyslots, []string{"0"}) {
				t.Fatalf("migration result %+v, want a keyslot added, digest 0 migrated and keyslot 0 removed", result)
			}

			assertFIPSReady(t, image)
			_, metadata, err := readHeaderForTest(image)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			for id, ks := range metadata.Keyslots {
				if ks.AF == nil || ks.AF.Hash == "sha1" {
					t.Fatalf("keyslot %s still has anti-forensic hash %+v after the import", id, ks.AF)
				}
			}
			if got := cryptsetupVolumeKey(t, image); got != volumeKeyBefore {
				t.Fatal("cryptsetup recovers a different volume key after the import")
			}
			if code, out := runChild(t, childRoleOpen, image, "fips140=only", true); code != childOK {
				t.Fatalf("FIPS open of the imported volume exited %d\n%s", code, out)
			}
		})
	}
}

// TestNoKeyslotIsWrittenWithSHA1AF: every path that writes a keyslot writes a
// SHA-256 split. AddKey on a SHA-1 volume adds a SHA-256 keyslot; ChangeKey
// on a SHA-1 keyslot rewrites it with SHA-256, and cryptsetup opens both; and
// Format refuses a SHA-1 hash before it touches the device.
func TestNoKeyslotIsWrittenWithSHA1AF(t *testing.T) {
	if fips140.Enabled() {
		// Every step below opens a SHA-1 keyslot first, which FIPS mode
		// refuses; that refusal is TestSHA1AFVolumesOpenWithCryptsetupsVolumeKey's.
		image := sha1AFVolume(t, sha1AFKinds[1])
		if _, err := addKeyForTest(image, migrationPassphrase, []byte("another-credential"), &addKeyOptionsForTest{KDFType: kdfTypePBKDF2, PBKDFIterTime: 1}); !errors.Is(err, ErrFIPSNotApproved) {
			t.Fatalf("AddKey through a SHA-1 keyslot in FIPS mode: got %v, want ErrFIPSNotApproved", err)
		}
		return
	}

	for _, kind := range sha1AFKinds {
		t.Run(kind.name, func(t *testing.T) {
			image := sha1AFVolume(t, kind)
			other := []byte("another-credential")
			slot, err := addKeyForTest(image, migrationPassphrase, other, &addKeyOptionsForTest{KDFType: kdfTypePBKDF2, PBKDFIterTime: 1})
			if err != nil {
				t.Fatalf("AddKey on a SHA-1 AF volume: %v", err)
			}
			// ChangeKey keeps a keyslot's KDF and its cost, raised to this
			// package's floor -- 1.3M iterations for the converted keyslot's
			// PBKDF2-SHA1 -- so it runs on the Argon2 shape only: the AF rewrite
			// it is here for is the same code for both.
			credentials := []string{"another-credential"}
			if kind.keyslot.Type == kdfTypeArgon2id {
				if err := changeKeyForTest(image, migrationPassphrase, []byte("a-changed-credential"), 0); err != nil {
					t.Fatalf("ChangeKey on a SHA-1 AF keyslot: %v", err)
				}
				credentials = append(credentials, "a-changed-credential")
			}
			_, metadata, err := readHeaderForTest(image)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			for id, ks := range metadata.Keyslots {
				// Only keyslot 0 of the converted volume is cryptsetup's own,
				// untouched; everything this package wrote is SHA-256.
				if id == "0" && len(credentials) == 1 {
					continue
				}
				if ks.AF == nil || ks.AF.Hash != defaultHashAlgo {
					t.Fatalf("keyslot %s was written with anti-forensic hash %+v, want %s", id, ks.AF, defaultHashAlgo)
				}
			}
			for _, credential := range credentials {
				if code, out := runCryptsetup(t, credential, "luksOpen", "--test-passphrase", image); code != 0 {
					t.Fatalf("cryptsetup cannot open with credential %q (added keyslot %d): exit %d\n%s", credential, slot, code, out)
				}
			}
		})
	}

	t.Run("Format refuses sha1 before touching the device", func(t *testing.T) {
		image := filepath.Join(t.TempDir(), "format-sha1.img")
		placeImage(t, image, nil)
		before := fileDigest(t, image)
		opts := standardFormatOptions(image)
		opts.HashAlgo = "sha1"
		if err := formatForTest(opts); !errors.Is(err, ErrUnsupported) || !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("got %v, want ErrUnsupported and ErrInvalidArgument", err)
		}
		if fileDigest(t, image) != before {
			t.Fatal("the refused Format changed the device")
		}
	})
}

// TestSHA1AFKeyslotFIPSClassification: a SHA-1 AF hash makes a keyslot
// non-approved whatever its KDF, and names itself; under the FIPS policy a
// keyslot refused only for it is an import, while an unknown AF hash is
// damage.
func TestSHA1AFKeyslotFIPSClassification(t *testing.T) {
	device := newImage(t, "classify.img")
	formatWithLibrary(t, device)
	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	approved := metadata.Keyslots["0"]
	original := approved.AF.Hash
	withAF := func(ks *header.Keyslot, hash string) *header.Keyslot {
		c := *ks
		af := *ks.AF
		af.Hash = hash
		c.AF = &af
		return &c
	}
	argon2 := *approved
	cost, memory, cpus := minArgon2Time, minArgon2MemoryKB, 1
	argon2.KDF = &rawKDF{Type: kdfTypeArgon2id, Salt: approved.KDF.Salt, Time: &cost, Memory: &memory, CPUs: &cpus}

	if refusal, ok := keyslotFIPSRefusal("0", withAF(approved, "sha1")); ok || refusal.Reason != "anti-forensic hash sha1" ||
		refusal.Type != kdfTypePBKDF2 {
		t.Fatalf("approved KDF with SHA-1 AF: %+v, %v", refusal, ok)
	}
	if refusal, ok := keyslotFIPSRefusal("0", withAF(&argon2, "sha1")); ok || refusal.Reason != "anti-forensic hash sha1" ||
		refusal.Type != kdfTypeArgon2id {
		t.Fatalf("argon2 with SHA-1 AF: %+v, %v", refusal, ok)
	}
	if _, ok := keyslotFIPSRefusal("0", approved); !ok {
		t.Fatal("an approved keyslot with a SHA-256 AF hash was refused")
	}

	forced := forceFIPSPolicy(t)
	if !keyslotRefusedByFIPS("0", withAF(approved, "sha1"), metadata.Digests, forced) {
		t.Fatal("a keyslot refused only for its SHA-1 AF hash was not classified as a FIPS refusal")
	}
	if !keyslotRefusedByFIPS("0", withAF(&argon2, "sha1"), metadata.Digests, forced) {
		t.Fatal("an Argon2 keyslot with a SHA-1 AF hash was not classified as a FIPS refusal")
	}
	if keyslotRefusedByFIPS("0", withAF(&argon2, "md5"), metadata.Digests, forced) {
		t.Fatal("an unknown AF hash was classified as a FIPS refusal; it is damage")
	}
	if approved.AF.Hash != original {
		t.Fatal("classifying a copy mutated the keyslot it was copied from")
	}
}

// TestChangeKeyAndAFMergeFailuresAreTyped: the failure paths of the two
// functions this change touches classify with errors.Is -- a keyslot number
// out of range or not present, a wrong old passphrase, and AF material of the
// wrong size.
func TestChangeKeyAndAFMergeFailuresAreTyped(t *testing.T) {
	device := newImage(t, "changekey-errors.img")
	formatWithLibrary(t, device)
	newPassphrase := []byte("a-new-credential-for-the-test")

	if err := changeKeyForTest(device, migrationPassphrase, newPassphrase, MaxKeyslots); !errors.Is(err, ErrKeyslotNotFound) {
		t.Fatalf("out-of-range keyslot: got %v, want ErrInvalidKeyslot", err)
	}
	if err := changeKeyForTest(device, migrationPassphrase, newPassphrase, 5); !errors.Is(err, ErrKeyslotNotFound) ||
		!strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("absent keyslot: got %v, want ErrInvalidKeyslot saying it does not exist", err)
	}
	if err := changeKeyForTest(device, []byte(conformanceWrongPassphrase), newPassphrase, 0); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong old passphrase: got %v, want ErrWrongKey reachable", err)
	}
	// An EXISTING credential is refused only when nothing could open a
	// keyslot with it (#249, A7): empty. A short one is tried, like any other.
	if err := changeKeyForTest(device, nil, newPassphrase, 0); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("an invalid old passphrase: got %v, want the validation error, not a credential verdict", err)
	}

	if _, err := afCodec(testVolumeSys()).Merge(enclaveFrom(t, make([]byte, 100)), 32, af.Params{Stripes: 4, Hash: "sha256"}); !errors.Is(err, ErrKeyslotNotFound) {
		t.Fatalf("AF material of the wrong size: got %v, want ErrInvalidKeyslot", err)
	}
}
