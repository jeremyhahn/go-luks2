// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"crypto/sha1" // #nosec G505 -- sized, never derived with: Size is the PBKDF2-SHA1 block length a rewrite replaces
	"crypto/sha256"
	"hash"
	"math"
	"strconv"
)

// Rewriting a PBKDF2-SHA1 keyslot as PBKDF2-SHA256 at no lower cost (#239).
//
// ChangeKey never writes SHA-1, so a PBKDF2-SHA1 keyslot -- a converted LUKS1
// one -- is rewritten as PBKDF2-SHA256. Its iteration count cannot simply be
// copied. PBKDF2 derives its output in blocks of the hash's length, and each
// block is a full chain of the iteration count's HMACs (RFC 8018 section 5.2):
// a 64-byte XTS key is four SHA-1 blocks but two SHA-256 blocks, so the same
// count is HALF the HMACs. Nor is an HMAC of either hash a fixed multiple of
// the other's: on CPUs with SHA extensions an HMAC-SHA256 can cost less than
// an HMAC-SHA1. So the count is converted from cost, by two bounds, and the
// larger is taken:
//
//   - equal work: as many SHA-256 HMACs as the SHA-1 keyslot took, which the
//     block counts fix exactly;
//   - equal time on this machine: the SHA-1 count scaled by the measured cost
//     of an iteration of each, measured conservatively -- the slowest SHA-1
//     sample against the fastest SHA-256 sample -- so measurement noise can
//     only raise the count.
//
// The caller then raises the result to the SHA-256 floor, and a count past
// the ceiling is refused by CreateKDF before anything is written.

// sha1CostTimer is the timer sha256IterationsForSHA1 measures with. A seam for
// the reason calibratePBKDF2 takes its timer as an argument: what it measures
// is the machine, and a test substitutes a model of one rather than depend on
// the wall clock.
var sha1CostTimer pbkdf2Timer = wallClockPBKDF2

// sha1CostSamples is how many times each hash is measured; the extreme of the
// samples is used in the conservative direction.
const sha1CostSamples = 3

// sha256IterationsForSHA1 returns the PBKDF2-SHA256 iteration count whose
// derivation of keySize bytes costs at least what sha1Iterations of
// PBKDF2-SHA1 to keySize bytes cost, by work and by measured time. A result
// past maxKDFIterations is returned as maxKDFIterations+1, for the caller's
// range check to refuse rather than for this to wrap.
func sha256IterationsForSHA1(sha1Iterations, keySize int) (int, error) {
	if sha1Iterations <= 0 || keySize <= 0 {
		return 0, &detailError{Kind: ErrInvalidKeyslot, Detail: "a PBKDF2-SHA1 keyslot of " + strconv.Itoa(sha1Iterations) +
			" iterations and " + strconv.Itoa(keySize) + " key bytes has no cost to carry over"}
	}

	blocks := func(hashSize int) float64 { return float64((keySize + hashSize - 1) / hashSize) }
	work := float64(sha1Iterations) * blocks(sha1.Size) / blocks(sha256.Size)

	sha1Func, err := getPBKDF2HashFunc("sha1")
	if err != nil {
		return 0, err
	}
	sha256Func, err := getPBKDF2HashFunc("sha256")
	if err != nil {
		return 0, err
	}
	slowestSHA1, fastestSHA256 := 0.0, math.MaxFloat64
	for range sha1CostSamples {
		s1, err := pbkdf2SecondsPerIteration(sha1Func, "sha1", keySize)
		if err != nil {
			return 0, err
		}
		s256, err := pbkdf2SecondsPerIteration(sha256Func, "sha256", keySize)
		if err != nil {
			return 0, err
		}
		slowestSHA1, fastestSHA256 = max(slowestSHA1, s1), min(fastestSHA256, s256)
	}
	measured := float64(sha1Iterations) * slowestSHA1 / fastestSHA256

	needed := math.Ceil(max(work, measured))
	if needed > maxKDFIterations {
		return maxKDFIterations + 1, nil
	}
	return int(needed), nil
}

// pbkdf2SecondsPerIteration measures one iteration of hashFunc's PBKDF2 to
// keySize bytes: the probe doubles, as calibratePBKDF2's does, until a run
// lasts pbkdf2ProbeFloor, and the run is divided by its count. Unlike the
// calibration it applies no floor or ceiling to what it reports -- a floor
// would make the two hashes' figures incomparable.
func pbkdf2SecondsPerIteration(hashFunc func() hash.Hash, hashAlgo string, keySize int) (float64, error) {
	for probe := pbkdf2ProbeStart; probe <= pbkdf2ProbeCeiling; probe *= 2 {
		elapsed, err := sha1CostTimer(hashFunc, probe, keySize)
		if err != nil {
			return 0, err
		}
		if elapsed >= pbkdf2ProbeFloor {
			return elapsed.Seconds() / float64(probe), nil
		}
	}
	return 0, &KDFCalibrationError{Hash: hashAlgo, Err: errCalibrationImmeasurable}
}
