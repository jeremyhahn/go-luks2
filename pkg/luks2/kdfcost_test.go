// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"runtime"
	"testing"
	"time"
)

// A header declares how EXPENSIVE its own KDF is to run, and this package used
// to run it on the header's word.
//
// validateKeyslot established that a KDF object exists and bounded the keyslot's
// geometry, but nothing bounded Iterations, Time, Memory or Parallelism. So a
// crafted header could ask for four billion PBKDF2 iterations and occupy a
// worker until it was killed, or ask for a terabyte-scale Argon2 matrix and
// OOM the process -- before any authentication, since the derivation is what
// authentication is built on.
//
// # The negative values are the sharpest form
//
// Time and Memory are signed ints in the header and are converted with uint32()
// at the call site, so a NEGATIVE value does not fail. It wraps to an enormous
// positive one, and Argon2 is then asked for a matrix sized by it: -1 becomes
// 4294967295 KiB, four terabytes. An obviously-invalid header becomes a
// maximally-expensive request.

// TestExcessiveKDFCostIsRefusedBeforeDeriving is the regression test.
//
// Both halves matter. The refusal must be typed so the keyslot scan can skip
// past it, and it must happen BEFORE the derivation -- "eventually returns an
// error" is what the unfixed code did, after paying the cost the header asked
// for.
func TestExcessiveKDFCostIsRefusedBeforeDeriving(t *testing.T) {
	path := newImage(t, "kdfcost.img")
	formatWithLibrary(t, path)

	_, metadata, err := ReadHeader(path)
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
		kdf  *KDF
	}{
		{
			// ~1 billion iterations. Measured: cryptsetup does not refuse this
			// at format time -- it simply runs, and my probe was still running
			// when a ten-minute timeout fired.
			name: "pbkdf2 iterations past the ceiling",
			kdf:  &KDF{Type: "pbkdf2", Hash: "sha256", Salt: "c2FsdA==", Iterations: &huge},
		},
		{
			name: "pbkdf2 negative iterations",
			kdf:  &KDF{Type: "pbkdf2", Hash: "sha256", Salt: "c2FsdA==", Iterations: &negative},
		},
		{
			name: "pbkdf2 zero iterations",
			kdf:  &KDF{Type: "pbkdf2", Hash: "sha256", Salt: "c2FsdA==", Iterations: &zero},
		},
		{
			// uint32(-1) KiB is four terabytes of Argon2 matrix.
			name: "argon2 negative memory wraps to terabytes",
			kdf:  &KDF{Type: "argon2id", Salt: "c2FsdA==", Time: &four, Memory: &negative, CPUs: &four},
		},
		{
			name: "argon2 memory past cryptsetup's own ceiling",
			kdf:  &KDF{Type: "argon2id", Salt: "c2FsdA==", Time: &four, Memory: &huge, CPUs: &four},
		},
		{
			name: "argon2 time past the ceiling",
			kdf:  &KDF{Type: "argon2id", Salt: "c2FsdA==", Time: &huge, Memory: &oneGiB, CPUs: &four},
		},
		{
			name: "argon2 negative time",
			kdf:  &KDF{Type: "argon2id", Salt: "c2FsdA==", Time: &negative, Memory: &oneGiB, CPUs: &four},
		},
		{
			name: "argon2 missing its cost parameters",
			kdf:  &KDF{Type: "argon2id", Salt: "c2FsdA=="},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyslot := cloneKeyslot(good)
			keyslot.KDF = tc.kdf

			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)

			start := time.Now()
			key, err := unlockKeyslot(path, "0", []byte(conformancePassphrase), keyslot, metadata.Digests)
			elapsed := time.Since(start)

			runtime.ReadMemStats(&after)

			if err == nil {
				mustDestroy(t, key)
				t.Fatal("unlockKeyslot ran a KDF whose declared cost is outside every accepted range")
			}
			// Entry-level, so a crafted keyslot costs its own keyslot and not
			// the volume.
			if !errors.Is(err, ErrInvalidKeyslot) {
				t.Fatalf("the refusal is not an unusable-keyslot error: %v", err)
			}

			// The bound must run BEFORE the derivation. The correct answer takes
			// microseconds and the unbounded one takes minutes or allocates
			// gigabytes, so the thresholds below are six orders of magnitude
			// clear of the signal rather than a tight race.
			if elapsed > 5*time.Second {
				t.Fatalf("refusing took %s: the derivation ran before the bound was applied", elapsed)
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 8<<20 {
				t.Fatalf("refusing allocated %d bytes: the Argon2 matrix was sized before the bound was applied", allocated)
			}
		})
	}
}

// TestKDFCostCeilingsAcceptWhatCryptsetupWrites is the control, and it is the
// one that decides the NUMBERS rather than the mechanism.
//
// A ceiling that refuses a container cryptsetup can create is its own defect.
// Every value here was measured against cryptsetup 2.7.0 on this host by
// formatting a real container and reading back what landed in the header.
func TestKDFCostCeilingsAcceptWhatCryptsetupWrites(t *testing.T) {
	cases := []struct {
		name string
		kdf  *KDF
	}{
		// PBKDF2: cryptsetup REFUSES --pbkdf-force-iterations below 1000
		// ("Failed to set pbkdf parameters") and accepts everything above,
		// including 100000000.
		{"pbkdf2 at cryptsetup's minimum", pbkdf2KDF(1000)},
		{"pbkdf2 at a benchmarked default", pbkdf2KDF(2000000)},
		{"pbkdf2 at a hardened value cryptsetup accepts", pbkdf2KDF(100000000)},

		// Argon2 memory: cryptsetup refuses 31 KiB and 4194305 KiB, and accepts
		// 32 KiB through 4194304 KiB. Those are hard boundaries, measured.
		{"argon2 at cryptsetup's minimum memory", argon2KDF(4, 32, 1)},
		{"argon2 at cryptsetup's default memory", argon2KDF(4, 1048576, 4)},
		{"argon2 at cryptsetup's maximum memory", argon2KDF(4, 4194304, 1)},

		// Argon2 time: cryptsetup refuses 0 and 1, accepts 4, and WRITES 100
		// into a real header -- verified by formatting with
		// --pbkdf-force-iterations 100 and reading "Time cost: 100" back.
		{"argon2 at a benchmarked time cost", argon2KDF(4, 1048576, 4)},
		{"argon2 at a hardened time cost cryptsetup writes", argon2KDF(100, 1024, 1)},

		// Argon2 parallelism: cryptsetup accepts any --pbkdf-parallel but
		// CLAMPS what it writes to the host CPU count, so a header never
		// records more than that and never more than argon2's uint8 limit.
		{"argon2 at single-threaded", argon2KDF(4, 1024, 1)},
		{"argon2 at the uint8 limit", argon2KDF(4, 1024, 255)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateKDFCost(tc.kdf); err != nil {
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
		kdf  *KDF
	}{
		{"pbkdf2 one past the ceiling", pbkdf2KDF(maxKDFIterations + 1)},
		{"argon2 memory one past cryptsetup's ceiling", argon2KDF(4, maxArgon2Memory+1, 1)},
		{"argon2 time one past the ceiling", argon2KDF(maxArgon2Time+1, 1024, 1)},
		{"argon2 parallelism past argon2's uint8 limit", argon2KDF(4, 1024, 256)},
		{"argon2 zero parallelism", argon2KDF(4, 1024, 0)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateKDFCost(tc.kdf); err == nil {
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
	err := validateKDFCost(&KDF{Type: "sha256-crypt", Salt: "c2FsdA=="})
	if err == nil {
		t.Fatal("an unsupported KDF type was accepted")
	}
	if !contains(err.Error(), "sha256-crypt") {
		t.Fatalf("the error does not name the type it refused: %v", err)
	}
}

// TestExcessiveDigestKDFCostSkipsThatDigest covers the OTHER header-supplied
// KDF, which is easy to miss because it is not the keyslot's.
//
// verifyMasterKey derives once per digest. A digest declaring an absurd cost
// must be skipped exactly as an unusable one is -- the symmetry #58 established
// -- rather than run, and rather than aborting a volume whose other digests are
// fine.
func TestExcessiveDigestKDFCostSkipsThatDigest(t *testing.T) {
	path := newImage(t, "kdfcost-digest.img")
	formatWithLibrary(t, path)

	_, metadata, err := ReadHeader(path)
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
	expensive.Iterations = maxKDFIterations + 1
	metadata.Digests["1"] = &expensive

	start := time.Now()
	key, err := getMasterKey(path, []byte(conformancePassphrase), metadata)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("a volume with one expensive digest no longer opens through its usable one: %v", err)
	}
	mustDestroy(t, key)

	if elapsed > 10*time.Second {
		t.Fatalf("opening took %s: the expensive digest was derived rather than skipped", elapsed)
	}
}

func pbkdf2KDF(iterations int) *KDF {
	return &KDF{Type: "pbkdf2", Hash: "sha256", Salt: "c2FsdA==", Iterations: &iterations}
}

func argon2KDF(t, memory, cpus int) *KDF {
	return &KDF{Type: "argon2id", Salt: "c2FsdA==", Time: &t, Memory: &memory, CPUs: &cpus}
}

// TestCreateArgon2KDFCarriesANegativeCostToTheDerivation covers the SEAM the
// #112 fix depends on and which nothing else asserted.
//
// The propagation chain is AddKeyOptions -> addKeyFormatOptions -> CreateKDF ->
// createArgon2KDF -> deriveArgon2*. Both ends of it were tested and the middle
// was not: `addKeyFormatOptions` was shown to stop discarding a negative, and
// the derivation was shown to refuse one, but nothing checked that
// `createArgon2KDF` passes it through UNCHANGED -- and it is the one link that
// could quietly swallow it, because it defaults on `== 0` rather than on
// `<= 0`. Widen that comparison and the refusal this PR adds becomes
// unreachable while every other test stays green.
func TestCreateArgon2KDFCarriesANegativeCostToTheDerivation(t *testing.T) {
	kdf, err := CreateKDF(FormatOptions{KDFType: "argon2id", Argon2Memory: -1}, 32)
	if err != nil {
		t.Fatalf("CreateKDF() error = %v, want the cost carried to the derivation, not rejected here", err)
	}
	if kdf.Memory == nil {
		t.Fatal("CreateKDF() produced a KDF with no memory cost")
	}
	if *kdf.Memory != -1 {
		t.Fatalf("createArgon2KDF turned a memory cost of -1 into %d; the refusal downstream is then unreachable", *kdf.Memory)
	}

	// And the end of the chain refuses it, so the seam is not merely carrying a
	// value into a place that ignores it.
	if _, err := deriveArgon2id([]byte("passphrase"), []byte("saltsaltsaltsalt"), kdf, 32); err == nil {
		t.Fatal("deriveArgon2id() accepted a memory cost of -1")
	}
}

// The success control for the case above: zero MUST still take the default, or
// the test above would also pass against a createArgon2KDF that had stopped
// defaulting at all.
func TestCreateArgon2KDFStillDefaultsAZeroCost(t *testing.T) {
	kdf, err := CreateKDF(FormatOptions{KDFType: "argon2id"}, 32)
	if err != nil {
		t.Fatalf("CreateKDF() error = %v", err)
	}
	if kdf.Memory == nil || *kdf.Memory <= 0 {
		t.Fatalf("CreateKDF() with no explicit cost produced memory = %v, want a positive default", kdf.Memory)
	}
	if kdf.Time == nil || *kdf.Time <= 0 {
		t.Fatalf("CreateKDF() with no explicit cost produced time = %v, want a positive default", kdf.Time)
	}
	if kdf.CPUs == nil || *kdf.CPUs <= 0 {
		t.Fatalf("CreateKDF() with no explicit cost produced cpus = %v, want a positive default", kdf.CPUs)
	}
}
