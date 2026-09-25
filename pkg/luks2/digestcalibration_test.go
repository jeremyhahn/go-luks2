// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"os"
	"testing"
	"time"
)

// Tests for the master-key digest's calibrated cost.
//
// The parameter itself defends nothing -- the digest verifies a 512-bit CSPRNG
// master key, so no iteration count slows a search that does not exist -- and
// DigestIterationTargetMs says so at length. What these tests protect is the
// two things that DO matter: that the cost tracks a TIME target rather than
// drifting to whatever a constant happened to say, and that it stays pinnable
// so a header can be reproduced.

// recordDigestCalibration fixes the digest cost exactly as pinDigestIterations
// does and additionally records the hash each call asked for, so a test can
// assert that a digest was calibrated for the hash it declares.
func recordDigestCalibration(t *testing.T, iterations int) *[]string {
	t.Helper()

	asked := new([]string)
	previous := digestIterationsFor
	digestIterationsFor = func(hashAlgo string) (int, error) {
		*asked = append(*asked, hashAlgo)
		return iterations, nil
	}
	t.Cleanup(func() { digestIterationsFor = previous })

	return asked
}

// TestDigestCalibrationTargetsItsBudget is the property that replaced the
// constant: the count is whatever costs DigestIterationTargetMs on this
// machine, so it is right on hardware nobody has measured on.
//
// The assertion is on TIME, not on a count, because a count is exactly the
// thing that cannot travel between machines.
func TestDigestCalibrationTargetsItsBudget(t *testing.T) {
	for _, hashAlgo := range []string{"sha256", "sha512"} {
		t.Run(hashAlgo, func(t *testing.T) {
			iterations, err := calibrateDigestIterations(hashAlgo)
			if err != nil {
				t.Fatalf("calibrateDigestIterations failed: %v", err)
			}
			if iterations < minPBKDF2Iterations {
				t.Fatalf("calibrated to %d iterations, below the LUKS2 minimum of %d",
					iterations, minPBKDF2Iterations)
			}

			// Time the derivation the calibration was for: the SAME 64-byte
			// output cryptsetup benchmarks, which is what makes the target
			// comparable to its numbers at all.
			kdf := &KDF{Type: "pbkdf2", Hash: hashAlgo, Salt: encodeBase64(make([]byte, 32)), Iterations: &iterations}
			start := time.Now()
			// deriveKeyPlain, not the exported DeriveKey: #173 removed that
			// wrapper. This is an in-package test and wants the derivation
			// timed, not a key it keeps, so the unexported function it always
			// delegated to is the same measurement without the enclave
			// allocation DeriveKeyEnclave would add to the clock.
			if _, err := deriveKeyPlain([]byte("timing-probe-passphrase"), kdf, DigestCalibrationKeyLen); err != nil {
				t.Fatalf("deriveKeyPlain failed: %v", err)
			}
			elapsed := time.Since(start)

			// A wide band on purpose. This runs alongside the rest of the
			// suite, so the clock is contended; the failure worth catching is
			// a target that has moved by an order of magnitude, which is what
			// a reinstated constant would look like.
			low := time.Duration(DigestIterationTargetMs) * time.Millisecond / 4
			high := time.Duration(DigestIterationTargetMs) * time.Millisecond * 4
			if elapsed < low || elapsed > high {
				t.Errorf("a %d-iteration %s digest took %v; the %dms target puts it in %v..%v",
					iterations, hashAlgo, elapsed, DigestIterationTargetMs, low, high)
			}
		})
	}
}

// TestDigestCalibrationRejectsAnUnsupportedHash is the error half. A digest
// whose hash this package cannot compute must fail the format rather than
// produce a keyslot referencing a digest nothing can verify.
func TestDigestCalibrationRejectsAnUnsupportedHash(t *testing.T) {
	iterations, err := calibrateDigestIterations("md5")
	if err == nil {
		t.Fatalf("calibrateDigestIterations accepted md5 and returned %d", iterations)
	}
	if !errors.Is(err, ErrUnsupportedHash) {
		t.Fatalf("error = %v, want ErrUnsupportedHash", err)
	}
}

// TestFormatSurfacesADigestCalibrationFailure checks the failure reaches the
// caller instead of being swallowed into a default. A digest cost quietly
// substituted after a failed benchmark is the defect ErrKDFCalibration exists
// to prevent, and the digest path must not reintroduce it.
func TestFormatSurfacesADigestCalibrationFailure(t *testing.T) {
	previous := digestIterationsFor
	sentinel := errors.New("the digest benchmark could not run")
	digestIterationsFor = func(string) (int, error) { return 0, sentinel }
	t.Cleanup(func() { digestIterationsFor = previous })

	path := newImage(t, "digest-calibration-failure.img")
	before, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to read the blank image: %v", err)
	}

	err = Format(standardFormatOptions(path))
	if !errors.Is(err, sentinel) {
		t.Fatalf("Format = %v, want the calibration failure", err)
	}

	after, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to read the image back: %v", err)
	}
	if !bytesEqual(before, after) {
		t.Fatal("Format wrote to the device before the digest calibration failed")
	}
}

// TestPinnedDigestIterationsReachTheHeader is the pinnability requirement: a
// reproducible header needs every calibrated value fixable, and the digest is
// one of them.
//
// FormatOptions.PBKDFIterations deliberately does not pin this -- see
// digestIterationsFor -- so the two are checked to move independently, which is
// the property that distinguishes this package's API from cryptsetup's
// --pbkdf-force-iterations.
func TestPinnedDigestIterationsReachTheHeader(t *testing.T) {
	const digestCost = 123_456
	const keyslotCost = 250_000

	pinDigestIterations(t, digestCost)

	path := newImage(t, "pinned-digest.img")
	opts := standardFormatOptions(path)
	opts.PBKDFIterations = keyslotCost
	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if got := metadata.Digests["0"].Iterations; got != digestCost {
		t.Fatalf("digest iterations = %d, want the pinned %d", got, digestCost)
	}
	if got := metadata.Keyslots["0"].KDF.Iterations; got == nil || *got != keyslotCost {
		t.Fatalf("keyslot iterations = %v, want the pinned %d", got, keyslotCost)
	}
	if metadata.Digests["0"].Iterations == *metadata.Keyslots["0"].KDF.Iterations {
		t.Fatal("the keyslot and digest costs are the same value; the two knobs are not independent")
	}

	if err := TestKey(path, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("a container with a pinned digest cost does not open: %v", err)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
