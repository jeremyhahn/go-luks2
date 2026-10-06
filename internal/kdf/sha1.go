// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package kdf

import (
	"crypto/sha1" // #nosec G505 -- legacy LUKS interop only: used to size a cost conversion, never to derive a key
	"crypto/sha256"
	"hash"
	"math"
	"strconv"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

const sha1CostSamples = 3

// SHA1Iterations converts a PBKDF2-SHA1 keyslot's iteration count into the
// PBKDF2-SHA256 count that carries over the same work: a theoretical estimate
// from each hash's block count, reconciled against this host's measured
// relative speed of the two, so a host where SHA-1 happens to be slower than
// SHA-256 is not under-converted. timer is WallClockPBKDF2 in production; a
// test gives a model.
func (d Deriver) SHA1Iterations(sha1Iterations, keySize int, timer Timer) (int, error) {
	if sha1Iterations <= 0 || keySize <= 0 {
		return 0, &errs.Error{Kind: errs.ErrInvalidKeyslot, Detail: "a PBKDF2-SHA1 keyslot of " + strconv.Itoa(sha1Iterations) +
			" iterations and " + strconv.Itoa(keySize) + " key bytes has no cost to carry over"}
	}

	blocks := func(hashSize int) float64 { return float64((keySize + hashSize - 1) / hashSize) }
	work := float64(sha1Iterations) * blocks(sha1.Size) / blocks(sha256.Size)

	sha1Func, err := PBKDF2HashFunc(d.FIPS, "sha1")
	if err != nil {
		return 0, err
	}
	sha256Func, err := PBKDF2HashFunc(d.FIPS, "sha256")
	if err != nil {
		return 0, err
	}
	slowestSHA1, fastestSHA256 := 0.0, math.MaxFloat64
	for range sha1CostSamples {
		s1, err := pbkdf2SecondsPerIteration(sha1Func, "sha1", keySize, timer)
		if err != nil {
			return 0, err
		}
		s256, err := pbkdf2SecondsPerIteration(sha256Func, "sha256", keySize, timer)
		if err != nil {
			return 0, err
		}
		slowestSHA1, fastestSHA256 = max(slowestSHA1, s1), min(fastestSHA256, s256)
	}
	measured := float64(sha1Iterations) * slowestSHA1 / fastestSHA256

	needed := math.Ceil(max(work, measured))
	if needed > MaxKDFIterations {
		return MaxKDFIterations + 1, nil
	}
	return int(needed), nil
}

func pbkdf2SecondsPerIteration(hashFunc func() hash.Hash, hashAlgo string, keySize int, timer Timer) (float64, error) {
	for probe := ProbeStart; probe <= ProbeCeiling; probe *= 2 {
		elapsed, err := timer(hashFunc, probe, keySize)
		if err != nil {
			return 0, err
		}
		if elapsed >= ProbeFloor {
			return elapsed.Seconds() / float64(probe), nil
		}
	}
	return 0, &CalibrationError{Hash: hashAlgo, Err: ErrCalibrationImmeasurable}
}
