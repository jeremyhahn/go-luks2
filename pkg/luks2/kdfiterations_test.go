// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"errors"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Tests for the explicit PBKDF2 iteration count -- the option that bypasses
// calibration so that a container can be provisioned reproducibly.
//
// The interesting assertions here are the REFUSALS. Calibration is where the
// iteration floor was enforced, so an option that skips calibration skips the
// floor unless something else applies it, and the whole security value of the
// feature rests on that something else existing. cryptsetup's
// --pbkdf-force-iterations does not have it; this does.

func TestForcedPBKDF2IterationsAcceptsACountAtOrAboveTheFloor(t *testing.T) {
	tests := []struct {
		hash       string
		iterations int
	}{
		// Exactly at the floor for each hash with a published recommendation.
		{"sha256", 600_000},
		{"sha384", 210_000},
		{"sha512", 210_000},
		// Above it.
		{"sha512", 4_000_000},
		// At the ceiling validateKDFCost enforces on read.
		{"sha512", maxKDFIterations},
		// A hash with no recommendation falls back to the absolute minimum.
		{"sha3-256", minPBKDF2Iterations},
	}

	for _, tt := range tests {
		t.Run(tt.hash+"/"+strconv.Itoa(tt.iterations), func(t *testing.T) {
			got, err := forcedPBKDF2Iterations(tt.hash, tt.iterations, callerSuppliedCredential)
			if err != nil {
				t.Fatalf("forcedPBKDF2Iterations(%s, %d) = %v", tt.hash, tt.iterations, err)
			}
			if got != tt.iterations {
				t.Fatalf("forcedPBKDF2Iterations(%s, %d) = %d; an accepted count must be written unchanged",
					tt.hash, tt.iterations, got)
			}
		})
	}
}

// TestForcedPBKDF2IterationsRefusesBelowTheFloor is the security constraint.
//
// cryptsetup accepts --pbkdf-force-iterations 1 and writes it. This package
// must not: nothing can strengthen a keyslot that is already on disk, so the
// only moment the floor can be enforced is this one.
func TestForcedPBKDF2IterationsRefusesBelowTheFloor(t *testing.T) {
	tests := []struct {
		name       string
		hash       string
		iterations int
		wantMin    int
	}{
		{"one", "sha512", 1, 210_000},
		{"zero", "sha512", 0, 210_000},
		{"negative", "sha512", -1, 210_000},
		{"cryptsetup's own minimum", "sha512", minPBKDF2Iterations, 210_000},
		{"one below the floor", "sha512", 209_999, 210_000},
		{"the sha512 floor under sha256", "sha256", 210_000, 600_000},
		{"below the absolute minimum for an unrecommended hash", "sha3-256", 999, minPBKDF2Iterations},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := forcedPBKDF2Iterations(tt.hash, tt.iterations, callerSuppliedCredential)
			if err == nil {
				t.Fatalf("forcedPBKDF2Iterations(%s, %d) = %d with no error; the floor was bypassed",
					tt.hash, tt.iterations, got)
			}
			if got != 0 {
				t.Errorf("a refused count still returned %d; a caller ignoring the error would write it", got)
			}
			if !errors.Is(err, ErrPBKDFIterationsTooLow) {
				t.Fatalf("error = %v, want ErrPBKDFIterationsTooLow", err)
			}

			var refusal *PBKDFIterationsError
			if !errors.As(err, &refusal) {
				t.Fatalf("error %v is not a *PBKDFIterationsError; a caller cannot learn the floor from it", err)
			}
			if refusal.Minimum != tt.wantMin {
				t.Errorf("reported minimum = %d, want %d", refusal.Minimum, tt.wantMin)
			}
			if refusal.Iterations != tt.iterations {
				t.Errorf("reported request = %d, want %d", refusal.Iterations, tt.iterations)
			}
			if refusal.Hash != tt.hash {
				t.Errorf("reported hash = %q, want %q", refusal.Hash, tt.hash)
			}

			// The operator has to be able to act on the message: both numbers,
			// not merely that something was too low.
			for _, want := range []string{strconv.Itoa(tt.iterations), strconv.Itoa(tt.wantMin), tt.hash} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %s", err.Error(), want)
				}
			}
		})
	}
}

// TestForcedPBKDF2IterationsRefusesAboveTheCeiling keeps the write path and the
// read path consistent: maxKDFIterations is what validateKDFCost rejects when
// the header is read back, so a larger count would produce a keyslot this
// package cannot open. Clamping instead would write less work than the caller
// asked for and report success.
func TestForcedPBKDF2IterationsRefusesAboveTheCeiling(t *testing.T) {
	for _, iterations := range []int{maxKDFIterations + 1, math.MaxInt32} {
		got, err := forcedPBKDF2Iterations("sha512", iterations, callerSuppliedCredential)
		if err == nil {
			t.Fatalf("forcedPBKDF2Iterations(sha512, %d) = %d with no error", iterations, got)
		}
		if got != 0 {
			t.Errorf("a refused count still returned %d", got)
		}
		if !errors.Is(err, ErrPBKDFIterationsTooHigh) {
			t.Fatalf("error = %v, want ErrPBKDFIterationsTooHigh", err)
		}

		var refusal *PBKDFIterationsError
		if !errors.As(err, &refusal) {
			t.Fatalf("error %v is not a *PBKDFIterationsError", err)
		}
		if refusal.Maximum != maxKDFIterations {
			t.Errorf("reported maximum = %d, want %d", refusal.Maximum, maxKDFIterations)
		}
	}
}

// TestForcedPBKDF2IterationsAppliesTheSameFloorAsCalibration is the property
// that makes the option safe to offer: it must not be a route to a keyslot
// BenchmarkPBKDF2 would have refused to produce. The two floors are compared
// directly rather than restated as a constant, so a change to one cannot
// silently diverge from the other.
func TestForcedPBKDF2IterationsAppliesTheSameFloorAsCalibration(t *testing.T) {
	for _, hashAlgo := range []string{"sha1", "sha256", "sha384", "sha512", "unrecommended"} {
		calibrationFloor := pbkdf2IterationFloor(hashAlgo, pbkdf2ReferenceTargetMs)

		// One below the calibration floor must be refused...
		below := int(math.Floor(calibrationFloor)) - 1
		if _, err := forcedPBKDF2Iterations(hashAlgo, below, callerSuppliedCredential); !errors.Is(err, ErrPBKDFIterationsTooLow) {
			t.Errorf("%s: %d is below the calibration floor of %.0f but forcedPBKDF2Iterations returned %v",
				hashAlgo, below, calibrationFloor, err)
		}

		// ...and the floor itself must be accepted.
		at := int(math.Ceil(calibrationFloor))
		if _, err := forcedPBKDF2Iterations(hashAlgo, at, callerSuppliedCredential); err != nil {
			t.Errorf("%s: the calibration floor of %d was refused: %v", hashAlgo, at, err)
		}
	}
}

// TestCreateKDFWritesAnExplicitIterationCount is the wiring: a count supplied
// through FormatOptions must appear in the keyslot verbatim, without the
// benchmark running.
func TestCreateKDFWritesAnExplicitIterationCount(t *testing.T) {
	const iterations = 750_000

	kdf, err := CreateKDF(FormatOptions{
		KDFType:         KDFTypePBKDF2,
		HashAlgo:        "sha512",
		PBKDFIterations: iterations,
		// Deliberately also set, and deliberately ignored: an explicit count
		// leaves calibration nothing to contribute. A budget of 1ms would
		// otherwise produce the hash floor instead.
		PBKDFIterTime: 1,
	}, 64)
	if err != nil {
		t.Fatalf("CreateKDF failed: %v", err)
	}
	if kdf.Iterations == nil {
		t.Fatal("the KDF has no iteration count")
	}
	if *kdf.Iterations != iterations {
		t.Fatalf("iterations = %d, want %d -- the explicit count did not reach the keyslot",
			*kdf.Iterations, iterations)
	}
}

// TestCreateKDFRefusesAnExplicitCountBelowTheFloor is the same wiring on the
// refusal side. The floor has to be reachable from the exported API, not only
// from the unexported validator.
func TestCreateKDFRefusesAnExplicitCountBelowTheFloor(t *testing.T) {
	kdf, err := CreateKDF(FormatOptions{
		KDFType:         KDFTypePBKDF2,
		HashAlgo:        "sha512",
		PBKDFIterations: 1,
	}, 64)
	if err == nil {
		t.Fatalf("CreateKDF accepted 1 iteration and produced %+v", kdf)
	}
	if kdf != nil {
		t.Error("CreateKDF returned a KDF alongside its error")
	}
	if !errors.Is(err, ErrPBKDFIterationsTooLow) {
		t.Fatalf("error = %v, want ErrPBKDFIterationsTooLow", err)
	}
}

// TestFormatWritesAnExplicitIterationCount takes it to the on-disk header,
// which is the only place the count actually matters: it is what an offline
// attacker pays per guess and nothing can change it afterwards.
func TestFormatWritesAnExplicitIterationCount(t *testing.T) {
	const iterations = 250_000

	path := newImage(t, "explicit-iterations.img")
	if err := Format(FormatOptions{
		Device:          path,
		Passphrase:      []byte(conformancePassphrase),
		Cipher:          "aes",
		CipherMode:      "xts-plain64",
		KeySize:         512,
		HashAlgo:        "sha512",
		SectorSize:      512,
		KDFType:         KDFTypePBKDF2,
		PBKDFIterations: iterations,
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	keyslot := metadata.Keyslots["0"]
	if keyslot == nil || keyslot.KDF == nil || keyslot.KDF.Iterations == nil {
		t.Fatal("the formatted container has no keyslot 0 with an iteration count")
	}
	if *keyslot.KDF.Iterations != iterations {
		t.Fatalf("the header records %d iterations, want %d", *keyslot.KDF.Iterations, iterations)
	}

	// The container must still open. A pinned count that produced a keyslot no
	// passphrase derives would be worse than a calibrated one.
	if err := TestKey(path, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("the passphrase does not open a container formatted with an explicit count: %v", err)
	}
}

// TestFormatRefusesAnExplicitCountBelowTheFloor is the property that makes the
// option safe to expose at all: the refusal must happen BEFORE anything is
// written, because a weak keyslot cannot be strengthened afterwards.
func TestFormatRefusesAnExplicitCountBelowTheFloor(t *testing.T) {
	path := newImage(t, "weak-iterations.img")
	before, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to read the blank image: %v", err)
	}

	err = Format(FormatOptions{
		Device:          path,
		Passphrase:      []byte(conformancePassphrase),
		Cipher:          "aes",
		CipherMode:      "xts-plain64",
		KeySize:         512,
		HashAlgo:        "sha512",
		SectorSize:      512,
		KDFType:         KDFTypePBKDF2,
		PBKDFIterations: minPBKDF2Iterations, // cryptsetup would accept this
	})
	if !errors.Is(err, ErrPBKDFIterationsTooLow) {
		t.Fatalf("Format = %v, want ErrPBKDFIterationsTooLow", err)
	}

	after, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to read the image back: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("Format wrote to the device before refusing the iteration count")
	}
}

// TestAddKeyWritesAnExplicitIterationCount covers the other entry point. The
// two must agree: a parameter accepted by Format and dropped by AddKey is the
// defect addKeyFormatOptions already documents for PBKDFIterTime.
func TestAddKeyWritesAnExplicitIterationCount(t *testing.T) {
	const iterations = 300_000

	path := newImage(t, "addkey-iterations.img")
	formatWithLibrary(t, path)

	if _, err := AddKey(path, []byte(conformancePassphrase), []byte("a-second-credential"), &AddKeyOptions{
		KDFType:         KDFTypePBKDF2,
		Hash:            "sha512",
		PBKDFIterations: iterations,
	}); err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	found := false
	for id, keyslot := range metadata.Keyslots {
		if id == "0" || keyslot.KDF == nil || keyslot.KDF.Iterations == nil {
			continue
		}
		found = true
		if *keyslot.KDF.Iterations != iterations {
			t.Fatalf("keyslot %s records %d iterations, want %d", id, *keyslot.KDF.Iterations, iterations)
		}
	}
	if !found {
		t.Fatal("AddKey did not create a second keyslot")
	}

	if err := TestKey(path, []byte("a-second-credential")); err != nil {
		t.Fatalf("the new passphrase does not open the volume: %v", err)
	}
}

// TestAddKeyRefusesAnExplicitCountBelowTheFloor closes the same gap on the
// add-key side, and checks the container is left alone.
func TestAddKeyRefusesAnExplicitCountBelowTheFloor(t *testing.T) {
	path := newImage(t, "addkey-weak.img")
	formatWithLibrary(t, path)

	_, before, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	_, err = AddKey(path, []byte(conformancePassphrase), []byte("a-second-credential"), &AddKeyOptions{
		KDFType:         KDFTypePBKDF2,
		Hash:            "sha512",
		PBKDFIterations: 1,
	})
	if !errors.Is(err, ErrPBKDFIterationsTooLow) {
		t.Fatalf("AddKey = %v, want ErrPBKDFIterationsTooLow", err)
	}

	_, after, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader after the refusal failed: %v", err)
	}
	if len(after.Keyslots) != len(before.Keyslots) {
		t.Fatalf("the container has %d keyslots after a refused AddKey, had %d",
			len(after.Keyslots), len(before.Keyslots))
	}
	if err := TestKey(path, []byte("a-second-credential")); err == nil {
		t.Fatal("the refused passphrase opens the volume")
	}
}

// TestChangeKeyPreservesTheKeyslotsPBKDF2Cost is the pbkdf2 half of a property
// the argon2 path already had.
//
// A passphrase change is not a request to re-cost the keyslot. ChangeKey copied
// the argon2 costs forward and left pbkdf2 to be recalibrated against the
// default budget, so an operator who had deliberately chosen a cost lost it to
// an unrelated operation -- and the volume still opened, which is why it went
// unnoticed. The hash went the same way, replaced with DefaultHashAlgo.
func TestChangeKeyPreservesTheKeyslotsPBKDF2Cost(t *testing.T) {
	const iterations = 640_000

	path := newImage(t, "changekey-cost.img")
	if err := Format(FormatOptions{
		Device:          path,
		Passphrase:      []byte(conformancePassphrase),
		Cipher:          "aes",
		CipherMode:      "xts-plain64",
		KeySize:         512,
		HashAlgo:        "sha512",
		SectorSize:      512,
		KDFType:         KDFTypePBKDF2,
		PBKDFIterations: iterations,
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	updated := []byte("the-replacement-credential")
	if err := ChangeKey(path, []byte(conformancePassphrase), updated, 0); err != nil {
		t.Fatalf("ChangeKey failed: %v", err)
	}

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	kdf := metadata.Keyslots["0"].KDF
	if kdf.Iterations == nil {
		t.Fatal("the keyslot has no iteration count after ChangeKey")
	}
	if *kdf.Iterations != iterations {
		t.Fatalf("ChangeKey re-costed the keyslot: %d iterations, was %d", *kdf.Iterations, iterations)
	}
	// The hash was being replaced with DefaultHashAlgo (sha256) by the same
	// block, which is the same defect in a second dimension.
	if kdf.Hash != "sha512" {
		t.Fatalf("ChangeKey changed the keyslot hash to %q, was sha512", kdf.Hash)
	}

	if err := TestKey(path, updated); err != nil {
		t.Fatalf("the new passphrase does not open the volume: %v", err)
	}
	if err := TestKey(path, []byte(conformancePassphrase)); err == nil {
		t.Fatal("the old passphrase still opens the volume")
	}
}
