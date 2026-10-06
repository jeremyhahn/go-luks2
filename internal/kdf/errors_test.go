// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package kdf

import (
	"errors"
	"strings"
	"testing"
)

func TestCalibrationErrorString(t *testing.T) {
	e := &CalibrationError{Hash: "sha256", TargetMs: 2000, Probe: 1024, Elapsed: 0, Err: ErrCalibrationImmeasurable}
	if !errors.Is(e, ErrKDFCalibration) {
		t.Fatal("Is does not match ErrKDFCalibration")
	}
	s := e.Error()
	for _, want := range []string{"sha256", "2000", "1024"} {
		if !strings.Contains(s, want) {
			t.Fatalf("Error() = %q, missing %q", s, want)
		}
	}
}

func TestPBKDF2IterationsErrorString(t *testing.T) {
	e := &PBKDF2IterationsError{Hash: "sha512", Iterations: 10, Minimum: 1000, Maximum: MaxKDFIterations, Err: ErrPBKDFIterationsTooLow}
	if !errors.Is(e, ErrPBKDFIterationsTooLow) {
		t.Fatal("Unwrap does not reach the sentinel")
	}
	s := e.Error()
	for _, want := range []string{"sha512", "10", "1000"} {
		if !strings.Contains(s, want) {
			t.Fatalf("Error() = %q, missing %q", s, want)
		}
	}
}

func TestArgon2CostErrorString(t *testing.T) {
	withCeiling := &Argon2CostError{Parameter: "memory", Value: 4, Minimum: MinArgon2MemoryKB, Maximum: MaxArgon2Memory, Err: errors.New("invalid argon2 memory")}
	if !strings.Contains(withCeiling.Error(), "permitted range") {
		t.Fatalf("Error() with a ceiling = %q, want it to mention the range", withCeiling.Error())
	}
	noCeiling := &Argon2CostError{Parameter: "time", Value: 0, Minimum: MinArgon2Time, Err: errors.New("invalid argon2 time")}
	if !strings.Contains(noCeiling.Error(), "minimum") || strings.Contains(noCeiling.Error(), "permitted range") {
		t.Fatalf("Error() with no ceiling = %q, want it to mention only the minimum", noCeiling.Error())
	}
	if errors.Unwrap(noCeiling) == nil {
		t.Fatal("Unwrap does not reach the underlying sentinel")
	}
}
