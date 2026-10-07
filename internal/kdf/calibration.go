// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package kdf

import (
	"context"
	"crypto/pbkdf2"
	"hash"
	"time"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

const (
	ProbeStart   = 1000
	ProbeFloor   = 50 * time.Millisecond
	ProbeCeiling = 1 << 24

	// MaxPBKDF2IterTimeMs bounds the iteration-time budget a calibration may
	// be asked for.
	MaxPBKDF2IterTimeMs = 600_000

	// PBKDF2ReferenceTargetMs is the 2-second budget PBKDF2IterationFloor
	// scales the OWASP-recommended count relative to.
	PBKDF2ReferenceTargetMs = 2000

	// DigestIterationTargetMs and DigestCalibrationKeyLen are the budget and
	// probe key length digest calibration (createDigest) runs
	// CalibrateWithTimer at.
	DigestIterationTargetMs = 100
	DigestCalibrationKeyLen = 64
)

// PBKDF2RecommendedIterations are OWASP's current PBKDF2-HMAC recommended
// counts at a 2-second budget, keyed by lowercase hash name.
var PBKDF2RecommendedIterations = map[string]int{
	"sha1":   1_300_000,
	"sha256": 600_000,
	"sha384": 210_000,
	"sha512": 210_000,
}

// Timer measures how long iterations rounds of hashFunc over keySize bytes
// take. Production uses WallClockPBKDF2; a test substitutes a model.
type Timer func(hashFunc func() hash.Hash, iterations, keySize int) (time.Duration, error)

// WallClockPBKDF2 is the production Timer: it runs the derivation and times
// it with the real clock.
func WallClockPBKDF2(hashFunc func() hash.Hash, iterations, keySize int) (time.Duration, error) {
	const calibrationPassphrase = "calibration"
	calibrationSalt := make([]byte, 32)

	start := time.Now()
	if _, err := pbkdf2.Key(hashFunc, calibrationPassphrase, calibrationSalt, iterations, keySize); err != nil {
		return 0, &errs.Error{Kind: errs.ErrIO, Detail: "crypto pbkdf2 benchmark", Err: err}
	}
	return time.Since(start), nil
}

// Calibrate estimates the PBKDF2 iteration count for hashAlgo that costs
// targetMs on this hardware, timed by WallClockPBKDF2.
func (d Deriver) Calibrate(ctx context.Context, hashAlgo string, keySize, targetMs int) (int, error) {
	return d.CalibrateWithTimer(ctx, hashAlgo, keySize, targetMs, WallClockPBKDF2)
}

// CalibrateWithTimer is Calibrate with the probe timer given explicitly, for
// the digest-calibration caller which measures at a different key length and
// budget, and for tests that model the timing instead of running it.
func (d Deriver) CalibrateWithTimer(ctx context.Context, hashAlgo string, keySize, targetMs int, timer Timer) (int, error) {
	hashFunc, err := PBKDF2HashFunc(d.FIPS, hashAlgo)
	if err != nil {
		return 0, err
	}
	return CalibratePBKDF2(ctx, hashFunc, hashAlgo, keySize, targetMs, ProbeFloor, ProbeCeiling, timer)
}

// CalibratePBKDF2 is the calibration loop itself, with every seam (the probe
// floor/ceiling and the timer) given explicitly so a test can bound or
// replace them without running real derivations.
func CalibratePBKDF2(ctx context.Context, hashFunc func() hash.Hash, hashAlgo string, keySize, targetMs int, probeFloor time.Duration, probeCeiling int, timer Timer) (int, error) {
	if targetMs <= 0 || targetMs > MaxPBKDF2IterTimeMs {
		return 0, &CalibrationError{
			Hash:     hashAlgo,
			TargetMs: targetMs,
			Err:      ErrCalibrationTargetInvalid,
		}
	}

	for probe := ProbeStart; ; probe *= 2 {
		// Checked before each probe (DESIGN.md §D.2): a probe, like a
		// derivation, cannot be interrupted once started.
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		elapsed, err := timer(hashFunc, probe, keySize)
		if err != nil {
			return 0, err
		}

		// Compared as a Duration, never as elapsed.Milliseconds(). Truncating
		// a sub-millisecond measurement to an integer is what made the
		// original extrapolation unreachable; truncating a 1ms one is what
		// made it wrong by up to 3x on the occasions it was reached.
		if elapsed >= probeFloor {
			return ScalePBKDF2Iterations(hashAlgo, probe, elapsed, targetMs), nil
		}

		// Checked after the probe rather than before, so the ceiling bounds
		// the largest probe actually RUN. Doubling past it would double the
		// work again for a measurement that has already failed to be
		// timeable.
		if probe > probeCeiling/2 {
			return 0, &CalibrationError{
				Hash:     hashAlgo,
				TargetMs: targetMs,
				Probe:    probe,
				Elapsed:  elapsed,
				Err:      ErrCalibrationImmeasurable,
			}
		}
	}
}

// ScalePBKDF2Iterations extrapolates a probe's measured cost to the iteration
// count that would cost targetMs, floored at PBKDF2IterationFloor and capped
// at MaxKDFIterations.
func ScalePBKDF2Iterations(hashAlgo string, probe int, elapsed time.Duration, targetMs int) int {
	perIteration := elapsed.Seconds() / float64(probe)
	scaled := (time.Duration(targetMs) * time.Millisecond).Seconds() / perIteration

	// Floor first, ceiling second: a budget large enough to push the floor
	// past the ceiling must land on the ceiling, not above it.
	if floor := PBKDF2IterationFloor(hashAlgo, targetMs); scaled < floor {
		scaled = floor
	}

	// MaxKDFIterations is the ceiling ValidateCost applies when the header is
	// read back, so exceeding it here would write a keyslot this package
	// would then refuse to open. Clamping is also what keeps the conversion
	// below defined -- Go leaves an out-of-range float-to-int conversion
	// implementation-specific.
	if scaled > MaxKDFIterations {
		scaled = MaxKDFIterations
	}

	return int(scaled)
}
