// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"crypto/fips140"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// No keyslot or digest is created with a SHA-1 KDF (#239, BREAKING).
//
// #236 stopped this package writing SHA-1 anti-forensic splits; this closes
// the other half of a keyslot. Every creation path refuses a PBKDF2-SHA1 KDF
// with ErrInvalidArgument before it derives or writes anything, ChangeKey
// rewrites an existing PBKDF2-SHA1 keyslot as PBKDF2-SHA256, and existing
// SHA-1 keyslots still open outside FIPS mode (sha1af_test.go opens a
// cryptsetup-converted LUKS1 volume, whose keyslot is PBKDF2-SHA1, to
// cryptsetup's volume key).

// countDerivations counts keyslot-key derivations for the rest of the test.
// The unlock derives before it reads anything, so zero derivations means no
// keyslot was even unlocked.
func countDerivations(t *testing.T) (*int, volumeSys) {
	t.Helper()

	n := new(int)
	sys := testVolumeSys()
	real := sys.passphraseKDF
	sys.passphraseKDFOverride = func(ctx context.Context, passphrase []byte, kdf *header.KDF, keySize int) (*enclave.MemoryEnclave, error) {
		*n++
		return real(ctx, passphrase, kdf, keySize)
	}
	return n, sys
}

// TestNoCreationPathWritesASHA1KDF: Format, AddKey and the digest writer refuse
// every way of asking for SHA-1 -- the pbkdf2-sha1 type, a sha1 hash in any
// case -- with ErrInvalidArgument, deriving nothing and writing nothing.
func TestNoCreationPathWritesASHA1KDF(t *testing.T) {
	format := func(kdfType, hash string) func(device string, sys volumeSys) error {
		return func(device string, sys volumeSys) error {
			opts := standardFormatOptions(device)
			opts.KDFType, opts.HashAlgo = kdfType, hash
			return formatWithSys(opts, sys)
		}
	}
	addKey := func(kdfType, hash string) func(device string, sys volumeSys) error {
		return func(device string, sys volumeSys) error {
			_, err := addKeyWithPolicy(context.Background(), device, migrationPassphrase, []byte("a-new-credential"),
				&addKeyOptionsForTest{KDFType: kdfType, Hash: hash, PBKDFIterTime: 1}, callerSuppliedCredential, sys)
			return err
		}
	}
	cases := []struct {
		name      string
		formatted bool // the path needs an existing volume
		run       func(device string, sys volumeSys) error
		also      error
	}{
		{"Format pbkdf2-sha1", false, format(kdfTypePBKDF2SHA1, ""), ErrUnsupported},
		{"Format pbkdf2 with sha1", false, format(kdfTypePBKDF2, "sha1"), ErrUnsupported},
		{"Format argon2id with sha1", false, format(kdfTypeArgon2id, "SHA1"), ErrUnsupported},
		{"AddKey pbkdf2-sha1", true, addKey(kdfTypePBKDF2SHA1, ""), ErrUnsupported},
		{"AddKey pbkdf2 with sha1", true, addKey(kdfTypePBKDF2, "sha1"), ErrUnsupported},
		{"AddKey argon2id with sha1", true, addKey(kdfTypeArgon2id, " Sha1 "), ErrUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			device := newImage(t, "sha1-kdf.img")
			if tc.formatted {
				formatWithLibrary(t, device)
			}
			before := fileDigest(t, device)
			derivations, sys := countDerivations(t)

			err := tc.run(device, sys)
			if !errors.Is(err, ErrInvalidArgument) || !errors.Is(err, tc.also) {
				t.Fatalf("got %v, want ErrInvalidArgument and %v", err, tc.also)
			}
			if *derivations != 0 {
				t.Fatalf("%d keyslot key(s) were derived before the refusal; want none", *derivations)
			}
			if fileDigest(t, device) != before {
				t.Fatal("the refused call changed the device")
			}
		})
	}

	t.Run("createDigest", func(t *testing.T) {
		mk := secretOf(t, make([]byte, 64))
		if kdf, value, err := createDigest(mk, "sha1", testVolumeSys()); kdf != nil || value != "" || !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("createDigest sha1: got %+v, %q, %v; want ErrInvalidArgument", kdf, value, err)
		}
	})
}

// TestRefuseSHA1ForCreation pins the predicate: SHA-1 by type or by hash, in
// any case and spacing, and nothing else.
func TestRefuseSHA1ForCreation(t *testing.T) {
	for _, tc := range []struct {
		kdfType, hash string
		refused       bool
	}{
		{kdfTypePBKDF2SHA1, "", true},
		{" PBKDF2-SHA1 ", "", true},
		{kdfTypePBKDF2, "sha1", true},
		{kdfTypeArgon2id, "SHA1", true},
		{"", " sha1", true},
		{kdfTypePBKDF2, "sha256", false},
		{kdfTypePBKDF2SHA256, "", false},
		{kdfTypeArgon2id, "", false},
		{"", "", false},
		{kdfTypePBKDF2, "sha512", false},
	} {
		err := refuseSHA1ForCreation(tc.kdfType, tc.hash)
		if refused := errors.Is(err, ErrInvalidArgument); refused != tc.refused {
			t.Fatalf("refuseSHA1ForCreation(%q, %q) = %v, want refused=%v", tc.kdfType, tc.hash, err, tc.refused)
		}
	}
}

// TestChangeKeyRewritesAPBKDF2SHA1KeyslotAsSHA256: ChangeKey on the keyslot of
// a cryptsetup-converted LUKS1 volume -- PBKDF2-SHA1 at cryptsetup's floor of
// 1000 iterations -- leaves a PBKDF2-SHA256 keyslot with a SHA-256 split at no
// fewer iterations than it had, raised to this package's SHA-256 floor. The
// new passphrase opens it in cryptsetup to the same volume key, and the old
// one no longer does.
func TestChangeKeyRewritesAPBKDF2SHA1KeyslotAsSHA256(t *testing.T) {
	image := sha1AFVolume(t, sha1AFKinds[1])
	_, metadata, err := readHeaderForTest(image)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	old := metadata.Keyslots["0"].KDF
	if old.Type != kdfTypePBKDF2 || old.Hash != "sha1" || old.Iterations == nil {
		t.Fatalf("fixture keyslot 0 KDF is %+v, want pbkdf2-sha1", old)
	}
	oldIterations := *old.Iterations
	volumeKeyBefore := cryptsetupVolumeKey(t, image)
	changed := []byte("a-changed-credential")
	// A machine whose HMAC-SHA256 costs twice an HMAC-SHA1: the converted
	// count is the work bound, far under the SHA-256 floor at 1000.
	sys := modelPBKDF2Cost(t, func(int) float64 { return 1 }, func(int) float64 { return 2 })

	err = changeKeyWithSys(image, migrationPassphrase, changed, 0, sys)
	if fips140.Enabled() {
		// Opening the SHA-1 keyslot is refused in FIPS mode, before anything
		// is written; the rewrite is what MigrateToFIPS is for there.
		if !errors.Is(err, ErrFIPSNotApproved) {
			t.Fatalf("ChangeKey through a SHA-1 keyslot in FIPS mode: got %v, want ErrFIPSNotApproved", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("ChangeKey on a PBKDF2-SHA1 keyslot: %v", err)
	}

	_, metadata, err = readHeaderForTest(image)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	ks := metadata.Keyslots["0"]
	converted, err := sha256IterationsForSHA1(oldIterations, ks.KeySize, sys)
	if err != nil {
		t.Fatalf("sha256IterationsForSHA1: %v", err)
	}
	want := max(converted, int(math.Ceil(pbkdf2IterationFloor("sha256", pbkdf2ReferenceTargetMs))))
	if ks.KDF.Type != kdfTypePBKDF2 || ks.KDF.Hash != "sha256" || ks.KDF.Iterations == nil || *ks.KDF.Iterations != want {
		t.Fatalf("rewritten keyslot KDF is %+v, want pbkdf2-sha256 at %d iterations", ks.KDF, want)
	}
	if *ks.KDF.Iterations < oldIterations {
		t.Fatalf("the rewrite lowered the iteration count from %d to %d", oldIterations, *ks.KDF.Iterations)
	}
	if ks.AF.Hash != defaultHashAlgo {
		t.Fatalf("rewritten keyslot AF hash is %q, want %s", ks.AF.Hash, defaultHashAlgo)
	}
	if code, out := runCryptsetup(t, string(changed), "luksOpen", "--test-passphrase", image); code != 0 {
		t.Fatalf("cryptsetup cannot open the rewritten keyslot: exit %d\n%s", code, out)
	}
	if code, _ := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", image); code == 0 {
		t.Fatal("the old passphrase still opens the volume after ChangeKey")
	}
	if got := cryptsetupVolumeKeyWith(t, image, string(changed)); got != volumeKeyBefore {
		t.Fatal("cryptsetup recovers a different volume key after ChangeKey")
	}
	if got := hex.EncodeToString(volumeKey(t, image, changed)); got != volumeKeyBefore {
		t.Fatal("this library recovers a different volume key after ChangeKey")
	}
}

// cryptsetupVolumeKeyWith is cryptsetupVolumeKey for a given passphrase.
func cryptsetupVolumeKeyWith(t *testing.T, image, passphrase string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "vk")
	if code, out := runCryptsetup(t, passphrase, "luksDump", "--dump-volume-key",
		"--volume-key-file", path, "--batch-mode", image); code != 0 {
		t.Fatalf("cryptsetup luksDump --dump-volume-key exited %d\n%s", code, out)
	}
	key, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("reading the dumped volume key failed: %v", err)
	}
	defer clearBytes(key)
	return hex.EncodeToString(key)
}

// modelPBKDF2Cost replaces the timer the SHA-1 conversion measures with: a
// derivation costs iterations x output blocks x the per-HMAC cost the model
// gives for that hash on that call (in microseconds), so tests decide what
// the "machine" measures instead of depending on the wall clock (#234). The
// call index lets a model vary between samples, as a noisy machine does.
func modelPBKDF2Cost(t *testing.T, sha1Cost, sha256Cost func(call int) float64) volumeSys {
	t.Helper()

	sys := testVolumeSys()
	calls := map[int]int{}
	sys.sha1CostTimer = func(hashFunc func() hash.Hash, iterations, keySize int) (time.Duration, error) {
		size := hashFunc().Size()
		cost := sha256Cost
		if size == sha1.Size {
			cost = sha1Cost
		}
		blocks := (keySize + size - 1) / size
		perHMAC := cost(calls[size])
		calls[size]++
		return time.Duration(float64(iterations*blocks) * perHMAC * float64(time.Microsecond)), nil
	}
	return sys
}

// TestSHA256IterationsForSHA1 pins the conversion: the larger of equal work
// (fixed by the block counts) and equal measured time (slowest SHA-1 sample
// against fastest SHA-256 sample), never fewer HMACs than the SHA-1 keyslot
// took, and a count past the ceiling reported as such.
func TestSHA256IterationsForSHA1(t *testing.T) {
	if fips140.Enabled() {
		if _, err := sha256IterationsForSHA1(1000, 64, testVolumeSys()); !errors.Is(err, ErrFIPSNotApproved) {
			t.Fatalf("in FIPS mode SHA-1 is not measured: got %v, want ErrFIPSNotApproved", err)
		}
		return
	}

	constant := func(c float64) func(int) float64 { return func(int) float64 { return c } }
	cases := []struct {
		name               string
		n, keySize         int
		sha1Cost, sha2Cost func(int) float64
		want               int
	}{
		// 64-byte key: 4 SHA-1 blocks, 2 SHA-256 blocks.
		{"slower SHA-256: the work bound", 1_000_000, 64, constant(1), constant(2), 2_000_000},
		{"equal HMAC cost: work and time agree", 1_000_000, 64, constant(1), constant(1), 2_000_000},
		{"faster SHA-256 (SHA extensions): the time bound", 1_000_000, 64, constant(1), constant(0.9), 2_222_223},
		// 32-byte key: 2 SHA-1 blocks, 1 SHA-256 block.
		{"32-byte key", 500_000, 32, constant(1), constant(2), 1_000_000},
		// Noise: SHA-1 samples 100, 120, 110 µs per HMAC; SHA-256 90, 95, 100.
		// Costs this large make the first 1000-iteration probe of each sample
		// pass the probe floor, so call i is sample i. Slowest SHA-1 120 x 4
		// blocks over fastest SHA-256 90 x 2 blocks is 8/3.
		{"noisy samples, conservatively", 300_000, 64,
			func(i int) float64 { return []float64{100, 120, 110}[i%3] },
			func(i int) float64 { return []float64{90, 95, 100}[i%3] }, 800_000},
		{"past the ceiling", header.MaxKDFIterations, 64, constant(1), constant(1), header.MaxKDFIterations + 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sys := modelPBKDF2Cost(t, tc.sha1Cost, tc.sha2Cost)
			got, err := sha256IterationsForSHA1(tc.n, tc.keySize, sys)
			// Exactly tc.want, or one more where floating point lands a hair
			// above an integer -- rounding may err upward, never down.
			if err != nil || got < tc.want || got > tc.want+1 {
				t.Fatalf("sha256IterationsForSHA1(%d, %d) = %d, %v; want %d (or one more)", tc.n, tc.keySize, got, err, tc.want)
			}
			if got > header.MaxKDFIterations {
				return // the caller's range check refuses it; there is no count to compare
			}
			sha1HMACs := tc.n * ((tc.keySize + sha1.Size - 1) / sha1.Size)
			if sha256HMACs := got * ((tc.keySize + sha256.Size - 1) / sha256.Size); sha256HMACs < sha1HMACs {
				t.Fatalf("%d SHA-256 HMACs is fewer than the %d SHA-1 HMACs the keyslot took", sha256HMACs, sha1HMACs)
			}
		})
	}

	t.Run("refusals", func(t *testing.T) {
		for _, args := range [][2]int{{0, 64}, {-1, 64}, {1000, 0}} {
			if _, err := sha256IterationsForSHA1(args[0], args[1], testVolumeSys()); !errors.Is(err, ErrKeyslotNotFound) {
				t.Fatalf("sha256IterationsForSHA1(%d, %d): got %v, want ErrInvalidKeyslot", args[0], args[1], err)
			}
		}
		errTimer := errors.New("injected: the timer failed")
		sys := testVolumeSys()
		sys.sha1CostTimer = func(func() hash.Hash, int, int) (time.Duration, error) { return 0, errTimer }
		if _, err := sha256IterationsForSHA1(1000, 64, sys); !errors.Is(err, errTimer) {
			t.Fatalf("a failing timer: got %v", err)
		}
		sys.sha1CostTimer = func(func() hash.Hash, int, int) (time.Duration, error) { return 0, nil }
		if _, err := sha256IterationsForSHA1(1000, 64, sys); !errors.Is(err, ErrKDFCalibration) {
			t.Fatalf("a clock that never advances: got %v, want ErrKDFCalibration", err)
		}
	})
}

// TestChangeKeyConvertsAboveTheFloor: when the converted count exceeds the
// SHA-256 floor it is the count written -- the conversion, not the floor,
// decides -- and a conversion past the ceiling refuses before anything is
// written.
func TestChangeKeyConvertsAboveTheFloor(t *testing.T) {
	if fips140.Enabled() {
		return // the SHA-1 keyslot cannot be opened; TestChangeKeyRewritesAPBKDF2SHA1KeyslotAsSHA256 asserts the refusal
	}
	floor := int(math.Ceil(pbkdf2IterationFloor("sha256", pbkdf2ReferenceTargetMs)))

	t.Run("above the floor", func(t *testing.T) {
		image := sha1AFVolume(t, sha1AFKinds[1])
		// HMAC-SHA256 at 1/330 of HMAC-SHA1: 1000 SHA-1 iterations of a 64-byte
		// key convert to 660000, above the 600000 floor.
		sys := modelPBKDF2Cost(t, func(int) float64 { return 330 }, func(int) float64 { return 1 })
		want, err := sha256IterationsForSHA1(1000, 64, sys)
		if err != nil || want <= floor {
			t.Fatalf("the model converts to %d (%v); the test needs a count above the %d floor", want, err, floor)
		}
		if err := changeKeyWithSys(image, migrationPassphrase, []byte("a-changed-credential"), 0, sys); err != nil {
			t.Fatalf("ChangeKey: %v", err)
		}
		_, metadata, err := readHeaderForTest(image)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}
		if kdf := metadata.Keyslots["0"].KDF; kdf.Hash != "sha256" || *kdf.Iterations != want {
			t.Fatalf("rewritten KDF %s at %d iterations, want sha256 at %d", kdf.Hash, *kdf.Iterations, want)
		}
	})

	t.Run("past the ceiling", func(t *testing.T) {
		image := sha1AFVolume(t, sha1AFKinds[1])
		before := fileDigest(t, image)
		sys := modelPBKDF2Cost(t, func(int) float64 { return 1e9 }, func(int) float64 { return 1 })
		err := changeKeyWithSys(image, migrationPassphrase, []byte("a-changed-credential"), 0, sys)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("got %v, want ErrInvalidArgument", err)
		}
		if fileDigest(t, image) != before {
			t.Fatal("a refused ChangeKey changed the device")
		}
	})
}
