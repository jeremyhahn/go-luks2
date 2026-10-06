// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package kdf

import (
	"errors"
	"fmt"
	"time"
)

// Sentinels. Re-exported by value from pkg/luks2 (errors.md §4): they read
// "unsupported KDF type", not "kdf: unsupported KDF type", because the
// calling package's errs.Error composes its own prefix.
var (
	ErrUnsupportedKDF        = errors.New("unsupported KDF type")
	ErrKDFCalibration        = errors.New("PBKDF2 iteration count could not be calibrated")
	ErrPBKDFIterationsTooLow = errors.New("PBKDF2 iteration count is below the minimum this package will write")

	ErrPBKDFIterationsTooHigh = errors.New("PBKDF2 iteration count is above the maximum this package will write")

	ErrCalibrationTargetInvalid = errors.New("the iteration-time target must be positive and within the supported range")
	ErrCalibrationImmeasurable  = errors.New("no probe ran long enough to be timed; the clock is not advancing")
)

// CalibrationError reports why BenchmarkPBKDF2-style calibration could not
// produce an iteration count.
type CalibrationError struct {
	// Hash is the hash algorithm the calibration was for, as the caller
	// spelled it.
	Hash string

	// TargetMs is the iteration-time budget that was requested.
	TargetMs int

	// Probe is the largest iteration count that was actually run, or 0 when
	// the request was rejected before any probe ran.
	Probe int

	// Elapsed is how long that probe took. It is the value that was too small
	// to extrapolate from.
	Elapsed time.Duration

	// Err is the underlying cause, kept reachable through Unwrap.
	Err error
}

func (e *CalibrationError) Error() string {
	return fmt.Sprintf("%s: hash %s, target %dms, probe %d iterations in %v: %v",
		ErrKDFCalibration.Error(), e.Hash, e.TargetMs, e.Probe, e.Elapsed, e.Err)
}

func (e *CalibrationError) Unwrap() error { return e.Err }

func (e *CalibrationError) Is(target error) bool {
	return target == ErrKDFCalibration
}

// PBKDF2IterationsError reports an explicit PBKDF2 iteration count this
// package refuses to write, because it is outside the floor-to-ceiling range
// for its hash.
type PBKDF2IterationsError struct {
	// Hash is the hash algorithm the keyslot would use, as it will be
	// written.
	Hash string

	// Iterations is the count the caller asked for.
	Iterations int

	// Minimum is the smallest count that would have been accepted for Hash.
	Minimum int

	// Maximum is the largest count that would have been accepted. It is the
	// ceiling ValidateCost applies when the header is read back, and is not
	// hash-dependent.
	Maximum int

	// Err is the underlying cause, kept reachable through Unwrap.
	Err error
}

func (e *PBKDF2IterationsError) Error() string {
	return fmt.Sprintf("%s: hash %s, requested %d iterations, permitted range %d..%d",
		e.Err.Error(), e.Hash, e.Iterations, e.Minimum, e.Maximum)
}

func (e *PBKDF2IterationsError) Unwrap() error { return e.Err }

// Argon2CostError reports an Argon2 creation cost this package refuses to
// write, because it is outside the range the read path (ValidateCost) would
// accept back.
type Argon2CostError struct {
	// Parameter is the cost that was refused: "memory" or "time".
	Parameter string

	// Value is what the caller asked for. Memory is in KiB.
	Value int

	// Minimum is the smallest value that would have been accepted.
	Minimum int

	// Maximum is the largest value that would have been accepted: the
	// ceiling the read path applies, so a keyslot is never written that
	// cannot be opened. Zero when no ceiling was stated.
	Maximum int

	// Err is the underlying sentinel, kept reachable through Unwrap.
	Err error
}

func (e *Argon2CostError) Error() string {
	if e.Maximum > 0 {
		return fmt.Sprintf("%s: requested %s %d, permitted range %d..%d", e.Err.Error(), e.Parameter, e.Value, e.Minimum, e.Maximum)
	}
	return fmt.Sprintf("%s: requested %s %d, minimum %d", e.Err.Error(), e.Parameter, e.Value, e.Minimum)
}

func (e *Argon2CostError) Unwrap() error { return e.Err }
