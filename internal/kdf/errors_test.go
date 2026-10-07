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

// PBKDF2IterationsError and Argon2CostError moved to luks2.KDFCostError
// (DESIGN.md §B.6); their message-shape coverage moved with them.
