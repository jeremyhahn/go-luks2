// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"crypto/fips140"
	"errors"
	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/header"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// A header's KDF cost is bounded before deriving; a negative Time or Memory would otherwise wrap to an enormous uint32.

// TestExcessiveKDFCostIsRefusedBeforeDeriving: the refusal is typed and comes before the derivation.
func TestExcessiveKDFCostIsRefusedBeforeDeriving(t *testing.T) {
	path := newImage(t, "kdfcost.img")
	formatWithLibrary(t, path)

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	good := metadata.Keyslots["0"]

	// 1<<30, not 1<<31. The point is "past the ceiling", and 1<<31 does not
	// fit in an int on a 32-bit platform -- the file failed to compile for
	// GOARCH=386 and arm, which nothing noticed because no CI leg compiled
	// tests for a 32-bit target. A billion iterations is as far past the
	// ceiling as two billion for this assertion's purposes.
	huge := 1 << 30
	negative := -1
	zero := 0
	four := 4
	oneGiB := 1 << 20

	cases := []struct {
		name string
		kdf  *header.KDF
	}{
		{
			// ~1 billion iterations. Measured: cryptsetup does not refuse this
			// at format time -- it simply runs, and my probe was still running
			// when a ten-minute timeout fired.
			name: "pbkdf2 iterations past the ceiling",
			kdf:  &header.KDF{Type: "pbkdf2", Hash: "sha256", Salt: "c2FsdA==", Iterations: &huge},
		},
		{
			name: "pbkdf2 negative iterations",
			kdf:  &header.KDF{Type: "pbkdf2", Hash: "sha256", Salt: "c2FsdA==", Iterations: &negative},
		},
		{
			name: "pbkdf2 zero iterations",
			kdf:  &header.KDF{Type: "pbkdf2", Hash: "sha256", Salt: "c2FsdA==", Iterations: &zero},
		},
		{
			// uint32(-1) KiB is four terabytes of Argon2 matrix.
			name: "argon2 negative memory wraps to terabytes",
			kdf:  &header.KDF{Type: "argon2id", Salt: "c2FsdA==", Time: &four, Memory: &negative, CPUs: &four},
		},
		{
			name: "argon2 memory past cryptsetup's own ceiling",
			kdf:  &header.KDF{Type: "argon2id", Salt: "c2FsdA==", Time: &four, Memory: &huge, CPUs: &four},
		},
		{
			name: "argon2 time past the ceiling",
			kdf:  &header.KDF{Type: "argon2id", Salt: "c2FsdA==", Time: &huge, Memory: &oneGiB, CPUs: &four},
		},
		{
			name: "argon2 negative time",
			kdf:  &header.KDF{Type: "argon2id", Salt: "c2FsdA==", Time: &negative, Memory: &oneGiB, CPUs: &four},
		},
		{
			name: "argon2 missing its cost parameters",
			kdf:  &header.KDF{Type: "argon2id", Salt: "c2FsdA=="},
		},
	}

	// The derivation is observed directly, not timed.
	derivations := 0
	sys := testVolumeSys()
	// It does not derive: on a mutation that ran it first, deriving a billion
	// iterations would hang the test instead of failing it.
	sys.passphraseKDFOverride = func(context.Context, []byte, *header.KDF, int) (enclave.ByteAccess, error) {
		derivations++
		return nil, errors.New("the keyslot KDF was reached")
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyslot := cloneKeyslot(good)
			keyslot.KDF = tc.kdf

			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)

			derivations = 0
			key, err := unlockKeyslot(context.Background(), path, "0", []byte(conformancePassphrase), keyslot, metadata.Digests, sys)

			runtime.ReadMemStats(&after)

			if err == nil {
				mustDestroy(t, key)
				t.Fatal("unlockKeyslot ran a KDF whose declared cost is outside every accepted range")
			}
			// Entry-level, so a crafted keyslot costs its own keyslot and not
			// the volume.
			if !errors.Is(err, ErrKeyslotNotFound) {
				t.Fatalf("the refusal is not an unusable-keyslot error: %v", err)
			}

			// The keyslot KDF was never entered.
			if derivations != 0 {
				t.Fatalf("the keyslot KDF ran %d time(s) before the bound was applied", derivations)
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 8<<20 {
				t.Fatalf("refusing allocated %d bytes: the Argon2 matrix was sized before the bound was applied", allocated)
			}
		})
	}
}

// TestKDFCostCeilingsAcceptWhatCryptsetupWrites: values measured against cryptsetup 2.7.0 headers.
func TestKDFCostCeilingsAcceptWhatCryptsetupWrites(t *testing.T) {
	cases := []struct {
		name string
		kdf  *header.KDF
	}{
		// cryptsetup refuses PBKDF2 iterations below 1000 and accepts up to 100000000.
		{"pbkdf2 at cryptsetup's minimum", pbkdf2KDF(1000)},
		{"pbkdf2 at a benchmarked default", pbkdf2KDF(2000000)},
		{"pbkdf2 at a hardened value cryptsetup accepts", pbkdf2KDF(100000000)},

		// Argon2 memory: cryptsetup refuses 31 KiB and 4194305 KiB, and accepts
		// 32 KiB through 4194304 KiB. Those are hard boundaries, measured.
		{"argon2 at cryptsetup's minimum memory", argon2KDF(4, 32, 1)},
		{"argon2 at cryptsetup's default memory", argon2KDF(4, 1048576, 4)},
		{"argon2 at cryptsetup's maximum memory", argon2KDF(4, 4194304, 1)},

		// cryptsetup refuses Argon2 time 0 and 1 and writes up to 100.
		{"argon2 at a benchmarked time cost", argon2KDF(4, 1048576, 4)},
		{"argon2 at a hardened time cost cryptsetup writes", argon2KDF(100, 1024, 1)},

		// cryptsetup clamps written Argon2 parallelism to the host CPU count.
		{"argon2 at single-threaded", argon2KDF(4, 1024, 1)},
		{"argon2 at the uint8 limit", argon2KDF(4, 1024, 255)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := header.ValidateKDFCost(tc.kdf); err != nil {
				t.Fatalf("a KDF cryptsetup can write was refused: %v", err)
			}
		})
	}
}

// TestKDFCostCeilingsRefuseWhatNoHeaderCarries is the other side of the same
// boundary, at the values immediately outside.
func TestKDFCostCeilingsRefuseWhatNoHeaderCarries(t *testing.T) {
	cases := []struct {
		name string
		kdf  *header.KDF
	}{
		{"pbkdf2 one past the ceiling", pbkdf2KDF(header.MaxKDFIterations + 1)},
		{"argon2 memory one past cryptsetup's ceiling", argon2KDF(4, header.MaxArgon2Memory+1, 1)},
		{"argon2 time one past the ceiling", argon2KDF(header.MaxArgon2Time+1, 1024, 1)},
		{"argon2 parallelism past argon2's uint8 limit", argon2KDF(4, 1024, 256)},
		{"argon2 zero parallelism", argon2KDF(4, 1024, 0)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := header.ValidateKDFCost(tc.kdf); err == nil {
				t.Fatal("a cost outside every accepted range was allowed")
			}
		})
	}
}

// TestKDFCostNamesAnUnsupportedTypeAsSuch guards the reporting. Treating every
// non-Argon2 type as PBKDF2 reports a header claiming type "sha256-crypt" as
// "missing its iteration count" -- naming a field that type never claimed to
// have, and sending the reader looking for a value that was never meant to be
// there.
func TestKDFCostNamesAnUnsupportedTypeAsSuch(t *testing.T) {
	err := header.ValidateKDFCost(&header.KDF{Type: "sha256-crypt", Salt: "c2FsdA=="})
	if err == nil {
		t.Fatal("an unsupported KDF type was accepted")
	}
	if !contains(err.Error(), "sha256-crypt") {
		t.Fatalf("the error does not name the type it refused: %v", err)
	}
}

// TestExcessiveDigestKDFCostSkipsThatDigest: an absurd digest cost is skipped like an unusable digest.
func TestExcessiveDigestKDFCostSkipsThatDigest(t *testing.T) {
	path := newImage(t, "kdfcost-digest.img")
	formatWithLibrary(t, path)

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	usable := metadata.Digests["0"]
	if usable == nil {
		t.Fatal("fixture precondition: digest 0 is missing")
	}

	// An expensive digest ahead of the usable one, in a map so scan order is
	// not something this test controls -- both must be reachable.
	expensive := *usable
	expensive.Iterations = header.MaxKDFIterations + 1
	metadata.Digests["1"] = &expensive

	// The screen refuses the expensive digest before any derivation.
	if _, _, err := screenDigest(&expensive, fips.Probe); err == nil {
		t.Fatalf("the screen accepted a digest declaring %d iterations, past the %d ceiling", expensive.Iterations, header.MaxKDFIterations)
	}

	key, err := getMasterKey(path, []byte(conformancePassphrase), metadata, testVolumeSys())
	if err != nil {
		t.Fatalf("a volume with one expensive digest no longer opens through its usable one: %v", err)
	}
	mustDestroy(t, key)
}

func pbkdf2KDF(iterations int) *header.KDF {
	return &header.KDF{Type: "pbkdf2", Hash: "sha256", Salt: "c2FsdA==", Iterations: &iterations}
}

func argon2KDF(t, memory, cpus int) *header.KDF {
	return &header.KDF{Type: "argon2id", Salt: "c2FsdA==", Time: &t, Memory: &memory, CPUs: &cpus}
}

// TestCreateArgon2KDFRefusesANegativeCostRatherThanDefaultingIt: createArgon2KDF refuses a negative cost via header.ValidateKDFCost; under FIPS Argon2 is refused.
func TestCreateArgon2KDFRefusesANegativeCostRatherThanDefaultingIt(t *testing.T) {
	kdf, err := createArgon2KDF(kdfTypeArgon2id, formatOptionsForTest{Argon2Memory: -1}, "c2FsdA==")
	if err == nil {
		t.Fatalf("createArgon2KDF() = %+v for a memory cost of -1; the negative was defaulted instead of refused", kdf)
	}

	// And the end of the chain refuses it too, so a KDF that reached it some
	// other way would not be derived.
	if _, err := deriveArgon2id([]byte("passphrase"), []byte("saltsaltsaltsalt"), argon2KDF(1, -1, 1), 32); err == nil {
		t.Fatal("deriveArgon2id() accepted a memory cost of -1")
	}

	kdf, err = createKDFStrict(formatOptionsForTest{KDFType: "argon2id", Argon2Memory: -1}, 32)
	if kdf != nil || err == nil {
		t.Fatalf("CreateKDF(argon2id, memory -1) = %+v, %v; want a refusal", kdf, err)
	}
	if fips140.Enabled() && !errors.Is(err, ErrFIPSNotApproved) {
		t.Fatalf("in FIPS mode CreateKDF(argon2id) = %v, want ErrFIPSNotApproved", err)
	}
}

// Zero must still take the default, in both modes.
func TestCreateArgon2KDFStillDefaultsAZeroCost(t *testing.T) {
	defaulted := func(t *testing.T, kdf *header.KDF) {
		t.Helper()
		if kdf.Memory == nil || *kdf.Memory <= 0 {
			t.Fatalf("no explicit cost produced memory = %v, want a positive default", kdf.Memory)
		}
		if kdf.Time == nil || *kdf.Time <= 0 {
			t.Fatalf("no explicit cost produced time = %v, want a positive default", kdf.Time)
		}
		if kdf.CPUs == nil || *kdf.CPUs <= 0 {
			t.Fatalf("no explicit cost produced cpus = %v, want a positive default", kdf.CPUs)
		}
	}

	kdf, err := createArgon2KDF(kdfTypeArgon2id, formatOptionsForTest{}, "c2FsdA==")
	if err != nil {
		t.Fatalf("createArgon2KDF() error = %v", err)
	}
	defaulted(t, kdf)

	assertCreateKDFInThisMode(t, formatOptionsForTest{KDFType: "argon2id"}, defaulted)
}

// TestCreateArgon2KDFDefaultsToTheDocumentedCost pins keyslots
// engineering.md, KDF: an Argon2 keyslot with no cost set is written at
// time 4, memory 1048576 KiB (1 GiB) and 4 threads, for argon2id and argon2i
// alike, and a cost that is set is kept.
func TestCreateArgon2KDFDefaultsToTheDocumentedCost(t *testing.T) {
	for _, kdfType := range []string{kdfTypeArgon2id, kdfTypeArgon2i} {
		kdf, err := createArgon2KDF(kdfType, formatOptionsForTest{}, "c2FsdA==")
		if err != nil {
			t.Fatalf("createArgon2KDF(%s) error = %v", kdfType, err)
		}
		if *kdf.Time != 4 || *kdf.Memory != 1048576 || *kdf.CPUs != 4 {
			t.Errorf("%s default = time %d, memory %d KiB, %d threads; want 4, 1048576, 4",
				kdfType, *kdf.Time, *kdf.Memory, *kdf.CPUs)
		}
	}

	kdf, err := createArgon2KDF(kdfTypeArgon2id, formatOptionsForTest{
		Argon2Time: 2, Argon2Memory: 524288, Argon2Parallel: 1,
	}, "c2FsdA==")
	if err != nil {
		t.Fatalf("createArgon2KDF(set cost) error = %v", err)
	}
	if *kdf.Time != 2 || *kdf.Memory != 524288 || *kdf.CPUs != 1 {
		t.Errorf("a set cost was not kept: time %d, memory %d KiB, %d threads", *kdf.Time, *kdf.Memory, *kdf.CPUs)
	}
}

// assertCreateKDFInThisMode checks CreateKDF builds Argon2 outside FIPS and refuses it with ErrFIPSNotApproved under FIPS.
func assertCreateKDFInThisMode(t *testing.T, opts formatOptionsForTest, check func(*testing.T, *header.KDF)) {
	t.Helper()
	kdf, err := createKDFStrict(opts, 32)
	if fips140.Enabled() {
		if !errors.Is(err, ErrFIPSNotApproved) || kdf != nil {
			t.Fatalf("in FIPS mode CreateKDF(%s) = %v, %v; want no KDF and ErrFIPSNotApproved", opts.KDFType, kdf, err)
		}
		return
	}
	if err != nil {
		t.Fatalf("CreateKDF(%s) error = %v", opts.KDFType, err)
	}
	check(t, kdf)
}
