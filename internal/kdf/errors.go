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
	ErrUnsupportedKDF = errors.New("unsupported KDF type")
	ErrKDFCalibration = errors.New("luks2: PBKDF2 iteration count could not be calibrated")

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

// Unwrap reports every CalibrationError as ErrKDFCalibration, so a caller
// can match the sentinel without depending on this type, and keeps the
// underlying cause reachable too.
func (e *CalibrationError) Unwrap() []error { return []error{ErrKDFCalibration, e.Err} }

// PBKDF2IterationsError and Argon2CostError are gone (DESIGN.md §B.6): a
// refused cost is luks2.KDFCostError now, constructed where it is
// exported -- pkg/luks2, not here. ForcedPBKDF2Iterations (cost.go) reports
// the same refusal as an *errs.Error with Kind errs.ErrInvalidArgument.
