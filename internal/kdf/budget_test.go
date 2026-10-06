// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package kdf

import "testing"

func TestWorkAddSaturates(t *testing.T) {
	huge := Work{PBKDF2Blocks: ^uint64(0), Argon2KiBPasses: ^uint64(0)}
	if got := huge.Add(Work{PBKDF2Blocks: 1, Argon2KiBPasses: 1}); got != huge {
		t.Fatalf("the sum wrapped: %+v", got)
	}
}

func TestWorkExceeds(t *testing.T) {
	budget := Work{PBKDF2Blocks: 100, Argon2KiBPasses: 100}
	if (Work{PBKDF2Blocks: 101}).Exceeds(budget) != true {
		t.Fatal("a PBKDF2Blocks overage was not detected")
	}
	if (Work{Argon2KiBPasses: 101}).Exceeds(budget) != true {
		t.Fatal("an Argon2KiBPasses overage was not detected")
	}
	if (Work{PBKDF2Blocks: 100, Argon2KiBPasses: 100}).Exceeds(budget) {
		t.Fatal("exactly the budget was reported as exceeding it")
	}
}

func TestSaturatingAdd(t *testing.T) {
	if SaturatingAdd(^uint64(0), 1) != ^uint64(0) {
		t.Fatal("SaturatingAdd overflowed instead of saturating")
	}
	if SaturatingAdd(1, 2) != 3 {
		t.Fatal("SaturatingAdd got the ordinary case wrong")
	}
}

func TestSaturatingMul(t *testing.T) {
	if SaturatingMul(1<<40, 1<<40) != ^uint64(0) {
		t.Fatal("SaturatingMul overflowed instead of saturating")
	}
	if SaturatingMul(0, 5) != 0 {
		t.Fatal("SaturatingMul(0, x) should be 0")
	}
}

func TestDerivationWork(t *testing.T) {
	iterations, timeVal, memory := 1000, 4, 65536
	for _, tc := range []struct {
		name string
		p    Params
		out  int
		want Work
	}{
		{"pbkdf2-sha256 to 64 bytes: two blocks", Params{Type: "pbkdf2", Hash: "sha256", Iterations: &iterations}, 64, Work{PBKDF2Blocks: 2000}},
		{"pbkdf2-sha1 to 64 bytes: four blocks", Params{Type: "pbkdf2", Hash: "sha1", Iterations: &iterations}, 64, Work{PBKDF2Blocks: 4000}},
		{"pbkdf2-sha512 to 32 bytes: one block", Params{Type: "pbkdf2", Hash: "sha512", Iterations: &iterations}, 32, Work{PBKDF2Blocks: 1000}},
		{"argon2id", Params{Type: "argon2id", Time: &timeVal, Memory: &memory}, 64, Work{Argon2KiBPasses: 4 * 65536}},
		{"no output", Params{Type: "pbkdf2", Hash: "sha256", Iterations: &iterations}, 0, Work{}},
		{"argon2 missing its cost", Params{Type: "argon2i"}, 64, Work{}},
		{"pbkdf2 missing its count", Params{Type: "pbkdf2", Hash: "sha256"}, 64, Work{}},
		{"negative iterations", Params{Type: "pbkdf2", Hash: "sha256", Iterations: intPtr(-1)}, 64, Work{}},
	} {
		if got := DerivationWork(tc.p, tc.out); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestOperationBudgetScalesWithKeyslotCount(t *testing.T) {
	small := OperationBudget(1)
	large := OperationBudget(32)
	if !large.Exceeds(small) {
		t.Fatalf("OperationBudget(32) = %+v did not exceed OperationBudget(1) = %+v", large, small)
	}
	if large.PBKDF2Blocks != 32*small.PBKDF2Blocks || large.Argon2KiBPasses != 32*small.Argon2KiBPasses {
		t.Fatalf("OperationBudget does not scale linearly with keyslot count: 1->%+v, 32->%+v", small, large)
	}
}
