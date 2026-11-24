// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"testing"
)

// Argon2 parallelism is refused at the same layer and in the same shape as Argon2 time and memory.

// TestAllThreeArgon2CostsAreRefusedAlike is the symmetry assertion. Each case
// is the same shape of caller mistake and must produce the same shape of error.
func TestAllThreeArgon2CostsAreRefusedAlike(t *testing.T) {
	tests := []struct {
		name      string
		opts      formatOptionsForTest
		parameter string
	}{
		{
			name:      "memory below the floor",
			opts:      formatOptionsForTest{KDFType: "argon2id", Argon2Memory: 32},
			parameter: "memory",
		},
		{
			name:      "negative time",
			opts:      formatOptionsForTest{KDFType: "argon2id", Argon2Time: -1},
			parameter: "time",
		},
		{
			name:      "negative parallelism",
			opts:      formatOptionsForTest{KDFType: "argon2id", Argon2Parallel: -1},
			parameter: "parallelism",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateArgon2CreateCost(tt.opts)
			if err == nil {
				t.Fatalf("validateArgon2CreateCost(%+v) = nil, want a refusal", tt.opts)
			}
			if !errors.Is(err, ErrInvalidArgument) {
				t.Errorf("error = %v, want errors.Is(_, ErrInvalidArgument)", err)
			}

			var costErr *KDFCostError
			if !errors.As(err, &costErr) {
				t.Fatalf("error = %v, want a *KDFCostError -- the shape its siblings produce", err)
			}
			if costErr.Param != tt.parameter {
				t.Errorf("Param = %q, want %q", costErr.Param, tt.parameter)
			}
		})
	}
}

// TestNegativeParallelismReachesTheCallerPreCheck is the defect proper: the
// value has to arrive at the pre-check, which means callerArgon2Options must
// forward it. Before the fix this returned nil.
func TestNegativeParallelismReachesTheCallerPreCheck(t *testing.T) {
	opts := &addKeyOptionsForTest{KDFType: "argon2id", Argon2Parallel: -1}

	forwarded := callerArgon2Options(opts)
	if forwarded.Argon2Parallel != -1 {
		t.Fatalf("callerArgon2Options dropped Argon2Parallel: got %d, want -1. "+
			"A cost the pre-check never sees is a cost refused a layer later (#176).",
			forwarded.Argon2Parallel)
	}

	if err := validateArgon2CreateCost(forwarded); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("validateArgon2CreateCost = %v, want ErrInvalidArgument", err)
	}
}

// TestZeroParallelismIsNotAChoice keeps the refusal from becoming too broad:
// zero means "caller said nothing" and must still inherit or default, exactly
// as it does for time and memory.
func TestZeroParallelismIsNotAChoice(t *testing.T) {
	for _, opts := range []formatOptionsForTest{
		{KDFType: "argon2id"},
		{KDFType: "argon2id", Argon2Parallel: 0},
		{KDFType: "argon2id", Argon2Parallel: 1},
		{KDFType: "argon2id", Argon2Parallel: 4},
	} {
		if err := validateArgon2CreateCost(opts); err != nil {
			t.Errorf("validateArgon2CreateCost(%+v) = %v, want nil", opts, err)
		}
	}
}

// TestParallelismIsNotCheckedForPBKDF2 pins the type guard: the Argon2 bounds
// must not fire on a pbkdf2 keyslot that happens to carry a stray value.
func TestParallelismIsNotCheckedForPBKDF2(t *testing.T) {
	opts := formatOptionsForTest{KDFType: kdfTypePBKDF2, Argon2Parallel: -1}
	if err := validateArgon2CreateCost(opts); err != nil {
		t.Errorf("validateArgon2CreateCost on a pbkdf2 keyslot = %v, want nil", err)
	}
}
