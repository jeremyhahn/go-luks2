// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"fmt"
	"hash"
	"os"
	"testing"
	"time"
)

// Tests that the master-key digest cost tracks a time target and stays pinnable.

// recordDigestCalibration fixes the digest cost exactly as pinDigestIterations
// does and additionally records the hash each call asked for, so a test can
// assert that a digest was calibrated for the hash it declares.
func recordDigestCalibration(t *testing.T, iterations int) (*[]string, func(string) (int, error)) {
	t.Helper()

	asked := new([]string)
	return asked, func(hashAlgo string) (int, error) {
		*asked = append(*asked, hashAlgo)
		return iterations, nil
	}
}

// TestDigestCalibrationTargetsItsBudget: with an injected rate, the count is exactly the 100 ms target for a 64-byte key.
func TestDigestCalibrationTargetsItsBudget(t *testing.T) {
	const cryptsetupDigestTarget = 100 * time.Millisecond
	const cryptsetupBenchmarkBytes = 64
	target := cryptsetupDigestTarget
	for _, tc := range []struct {
		hashAlgo     string
		hashWidth    int
		perIteration time.Duration
	}{
		{"sha256", 32, time.Microsecond},
		{"sha256", 32, 3 * time.Microsecond},
		{"sha512", 64, 2 * time.Microsecond},
		{"sha512", 64, 300 * time.Nanosecond},
	} {
		t.Run(fmt.Sprintf("%s at %v per iteration", tc.hashAlgo, tc.perIteration), func(t *testing.T) {
			rate := &knownRate{perIteration: tc.perIteration}
			iterations, err := digestIterationsTimedBy(tc.hashAlgo, rate.time)
			if err != nil {
				t.Fatalf("digestIterationsTimedBy: %v", err)
			}

			// The count that costs exactly the target at this rate. Within
			// one iteration, for the float division the calibration does.
			want := int(target / tc.perIteration)
			if iterations < want-1 || iterations > want+1 {
				t.Fatalf("calibrated to %d iterations; at %v per iteration the %v target is %d",
					iterations, tc.perIteration, target, want)
			}

			// It extrapolated from the first probe of at least pbkdf2ProbeFloor.
			last := len(rate.probes) - 1
			if last < 0 || time.Duration(rate.probes[last])*tc.perIteration < pbkdf2ProbeFloor {
				t.Fatalf("probes %v: the last ran under the %v floor", rate.probes, pbkdf2ProbeFloor)
			}
			if last > 0 && time.Duration(rate.probes[last-1])*tc.perIteration >= pbkdf2ProbeFloor {
				t.Fatalf("probes %v: it kept doubling past a probe that already met the %v floor", rate.probes, pbkdf2ProbeFloor)
			}

			// It timed the derivation cryptsetup benchmarks -- 64 bytes
			// whatever the hash -- with the hash the digest declares.
			if len(rate.keySizes) == 0 {
				t.Fatal("the calibration timed nothing")
			}
			for i := range rate.keySizes {
				if rate.keySizes[i] != cryptsetupBenchmarkBytes || rate.hashWidths[i] != tc.hashWidth {
					t.Fatalf("probe %d derived %d bytes with a %d-byte hash; want %d bytes with %s",
						i, rate.keySizes[i], rate.hashWidths[i], cryptsetupBenchmarkBytes, tc.hashAlgo)
				}
			}
		})
	}
}

// TestDigestCalibrationNeverGoesBelowItsFloor: on a machine slow enough that
// the target buys fewer iterations than the floor, the floor is what is
// written -- with a known rate, exactly.
func TestDigestCalibrationNeverGoesBelowItsFloor(t *testing.T) {
	rate := &knownRate{perIteration: 100 * time.Microsecond} // 1000 iterations in the target
	iterations, err := digestIterationsTimedBy("sha256", rate.time)
	if err != nil {
		t.Fatalf("digestIterationsTimedBy: %v", err)
	}
	// sha256's recommended 600000 at the 2000ms reference, scaled to the
	// 100ms digest target.
	if want := 600_000 * 100 / 2000; iterations != want {
		t.Fatalf("calibrated to %d iterations on a slow machine, want the floor %d", iterations, want)
	}
}

// TestDigestCalibrationReportsAFailedProbe: a probe that could not run fails
// the calibration with its own error, never a default count.
func TestDigestCalibrationReportsAFailedProbe(t *testing.T) {
	broken := errors.New("the derivation could not run")
	iterations, err := digestIterationsTimedBy("sha512", func(func() hash.Hash, int, int) (time.Duration, error) {
		return 0, broken
	})
	if !errors.Is(err, broken) || iterations != 0 {
		t.Fatalf("digestIterationsTimedBy = %d, %v; want 0 and the probe's error", iterations, err)
	}
}

// BenchmarkDigestCalibrationCostsItsBudget checks a real calibrated derivation costs about the target, within 4x in thread CPU time; run by make test-calibration.
func BenchmarkDigestCalibrationCostsItsBudget(b *testing.B) {
	for _, hashAlgo := range []string{"sha256", "sha512"} {
		b.Run(hashAlgo, func(b *testing.B) {
			for b.Loop() {
				checkCalibrationCost(b, hashAlgo, digestCalibrationKeyLen, digestIterationTargetMs,
					func(timer pbkdf2Timer) (int, error) { return digestIterationsTimedBy(hashAlgo, timer) })
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
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("error = %v, want ErrUnsupported", err)
	}
}

// TestFormatSurfacesADigestCalibrationFailure checks the failure reaches the
// caller instead of being swallowed into a default. A digest cost quietly
// substituted after a failed benchmark is the defect ErrKDFCalibration exists
// to prevent, and the digest path must not reintroduce it.
func TestFormatSurfacesADigestCalibrationFailure(t *testing.T) {
	defer parallel(t)()
	sentinel := errors.New("the digest benchmark could not run")
	sys := testVolumeSys()
	sys.digestIterationsFor = func(string) (int, error) { return 0, sentinel }

	path := newImage(t, "digest-calibration-failure.img")
	before, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to read the blank image: %v", err)
	}

	err = formatWithSys(standardFormatOptions(path), sys)
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

// TestPinnedDigestIterationsReachTheHeader: the digest count is pinnable, independently of FormatOptions.PBKDFIterations.
func TestPinnedDigestIterationsReachTheHeader(t *testing.T) {
	defer parallel(t)()
	const digestCost = 123_456
	const keyslotCost = 250_000

	sys := testVolumeSys()
	sys.digestIterationsFor = pinDigestIterations(digestCost)

	path := newImage(t, "pinned-digest.img")
	opts := standardFormatOptions(path)
	opts.PBKDFIterations = keyslotCost
	if err := formatWithSys(opts, sys); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	_, metadata, err := readHeaderForTest(path)
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

	if err := testKeyForTest(path, []byte(conformancePassphrase)); err != nil {
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
