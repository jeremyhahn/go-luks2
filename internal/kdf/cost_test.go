// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package kdf

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

func TestValidateCostPBKDF2(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    Params
		ok   bool
	}{
		{"within range", Params{Type: "pbkdf2", Iterations: intPtr(1000)}, true},
		{"at the minimum", Params{Type: "pbkdf2", Iterations: intPtr(MinKDFIterations)}, true},
		{"at the ceiling", Params{Type: "pbkdf2", Iterations: intPtr(MaxKDFIterations)}, true},
		{"below the minimum", Params{Type: "pbkdf2", Iterations: intPtr(MinKDFIterations - 1)}, false},
		{"above the ceiling", Params{Type: "pbkdf2", Iterations: intPtr(MaxKDFIterations + 1)}, false},
		{"missing iterations", Params{Type: "pbkdf2"}, false},
		{"a pbkdf2 alias", Params{Type: "pbkdf2-sha256", Iterations: intPtr(1000)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCost(tc.p)
			if tc.ok && err != nil {
				t.Fatalf("got %v, want nil", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("got nil, want an error")
			}
		})
	}
}

func TestValidateCostArgon2(t *testing.T) {
	within := func(v int) *int { return intPtr(v) }
	for _, tc := range []struct {
		name string
		p    Params
		ok   bool
	}{
		{"within range", Params{Type: "argon2id", Time: within(4), Memory: within(65536), CPUs: within(4)}, true},
		{"time below the minimum", Params{Type: "argon2id", Time: within(MinArgon2Time - 1), Memory: within(65536), CPUs: within(4)}, false},
		{"time above the ceiling", Params{Type: "argon2id", Time: within(MaxArgon2Time + 1), Memory: within(65536), CPUs: within(4)}, false},
		{"memory below the minimum", Params{Type: "argon2id", Time: within(4), Memory: within(MinArgon2Memory - 1), CPUs: within(4)}, false},
		{"memory above the ceiling", Params{Type: "argon2id", Time: within(4), Memory: within(MaxArgon2Memory + 1), CPUs: within(4)}, false},
		{"parallelism below the minimum", Params{Type: "argon2id", Time: within(4), Memory: within(65536), CPUs: within(MinArgon2Parallel - 1)}, false},
		{"parallelism above the ceiling", Params{Type: "argon2id", Time: within(4), Memory: within(65536), CPUs: within(MaxArgon2Parallel + 1)}, false},
		{"missing cost", Params{Type: "argon2i"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCost(tc.p)
			if tc.ok && err != nil {
				t.Fatalf("got %v, want nil", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("got nil, want an error")
			}
		})
	}
}

func TestValidateCostUnsupportedType(t *testing.T) {
	err := ValidateCost(Params{Type: "sha256-crypt"})
	if err == nil {
		t.Fatal("an unsupported type was accepted")
	}
}

func TestPBKDF2FloorFor(t *testing.T) {
	if got := PBKDF2FloorFor("sha256", LibraryGeneratedCredential); got != MinPBKDF2Iterations {
		t.Fatalf("library-generated credential: got %d, want the absolute minimum %d", got, MinPBKDF2Iterations)
	}
	if got := PBKDF2FloorFor("sha512", CallerSuppliedCredential); got < MinPBKDF2Iterations {
		t.Fatalf("caller-supplied credential: got %d, below the absolute minimum %d", got, MinPBKDF2Iterations)
	}
}

func TestForcedPBKDF2Iterations(t *testing.T) {
	floor := PBKDF2FloorFor("sha512", CallerSuppliedCredential)

	if got, err := ForcedPBKDF2Iterations("sha512", floor, CallerSuppliedCredential); err != nil || got != floor {
		t.Fatalf("at the floor: got %d, %v; want %d, nil", got, err, floor)
	}

	if _, err := ForcedPBKDF2Iterations("sha512", floor-1, CallerSuppliedCredential); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("below the floor: got %v, want errs.ErrInvalidArgument", err)
	}

	if _, err := ForcedPBKDF2Iterations("sha512", MaxKDFIterations+1, CallerSuppliedCredential); !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("above the ceiling: got %v, want errs.ErrInvalidArgument", err)
	}

	if got, err := ForcedPBKDF2Iterations("sha512", MinPBKDF2Iterations, LibraryGeneratedCredential); err != nil || got != MinPBKDF2Iterations {
		t.Fatalf("library-generated at the absolute minimum: got %d, %v", got, err)
	}

	var refusal *errs.Error
	if _, err := ForcedPBKDF2Iterations("sha512", 1, CallerSuppliedCredential); !errors.As(err, &refusal) {
		t.Fatalf("got %v, want an *errs.Error", err)
	} else if !strings.Contains(refusal.Detail, fmt.Sprintf("..%d", MaxKDFIterations)) {
		t.Fatalf("detail = %q, want it to report the ceiling %d", refusal.Detail, MaxKDFIterations)
	}
}

func TestCostPolicyZeroValueIsCallerSupplied(t *testing.T) {
	var unset CostPolicy
	if unset != CallerSuppliedCredential {
		t.Fatal("the zero CostPolicy is not CallerSuppliedCredential; a forgotten argument would grant the exemption")
	}
}
