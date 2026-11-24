// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package kdf

import (
	"math"
	"strings"
)

const (
	maxDerivedKeyLen = 64
	minPRFOutputLen  = 20
)

// Work counts key-derivation cost in PBKDF2 PRF blocks and Argon2 KiB-passes; diagnostic, not precise.
type Work struct {
	PBKDF2Blocks    uint64
	Argon2KiBPasses uint64
}

// Add returns the saturating sum of w and o: a budget this large is already a
// refusal, so saturating is cheaper than reporting an overflow that changes
// nothing about the outcome.
func (w Work) Add(o Work) Work {
	return Work{
		PBKDF2Blocks:    SaturatingAdd(w.PBKDF2Blocks, o.PBKDF2Blocks),
		Argon2KiBPasses: SaturatingAdd(w.Argon2KiBPasses, o.Argon2KiBPasses),
	}
}

// Exceeds reports whether w spends more than budget in either unit.
func (w Work) Exceeds(budget Work) bool {
	return w.PBKDF2Blocks > budget.PBKDF2Blocks || w.Argon2KiBPasses > budget.Argon2KiBPasses
}

// SaturatingAdd returns a+b, or math.MaxUint64 if that would overflow: a
// budget this large is already a refusal, so saturating is cheaper than
// reporting an overflow that changes nothing about the outcome.
func SaturatingAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

// SaturatingMul is SaturatingAdd for multiplication.
func SaturatingMul(a, b uint64) uint64 {
	if a != 0 && b > math.MaxUint64/a {
		return math.MaxUint64
	}
	return a * b
}

// ceilingWork is the most a single derivation can cost at the ValidateCost ceiling.
var ceilingWork = Work{
	PBKDF2Blocks:    uint64(MaxKDFIterations) * uint64((maxDerivedKeyLen+minPRFOutputLen-1)/minPRFOutputLen),
	Argon2KiBPasses: uint64(MaxArgon2Time) * uint64(MaxArgon2Memory),
}

// OperationBudget is the most derivation work one operation may spend scanning up to maxKeyslots keyslots.
func OperationBudget(maxKeyslots int) Work {
	if maxKeyslots < 0 {
		maxKeyslots = 0
	}
	n := uint64(maxKeyslots) // #nosec G115 -- non-negative, checked above
	return Work{
		PBKDF2Blocks:    2 * n * ceilingWork.PBKDF2Blocks,
		Argon2KiBPasses: 2 * n * ceilingWork.Argon2KiBPasses,
	}
}

// DerivationWork estimates the cost of deriving outLen bytes under p; a malformed p contributes zero.
func DerivationWork(p Params, outLen int) Work {
	if outLen <= 0 {
		return Work{}
	}
	switch strings.ToLower(strings.TrimSpace(p.Type)) {
	case "argon2i", "argon2id":
		if p.Time == nil || p.Memory == nil || *p.Time < 0 || *p.Memory < 0 {
			return Work{}
		}
		return Work{Argon2KiBPasses: SaturatingMul(uint64(*p.Time), uint64(*p.Memory))} // #nosec G115 -- non-negative, checked above
	default:
		if p.Iterations == nil || *p.Iterations < 0 {
			return Work{}
		}
		hashLen := minPRFOutputLen
		if h, err := PBKDF2Hash(p.Hash); err == nil {
			hashLen = h.Size()
		}
		blocks := (outLen + hashLen - 1) / hashLen
		return Work{PBKDF2Blocks: SaturatingMul(uint64(*p.Iterations), uint64(blocks))} // #nosec G115 -- non-negative, checked above
	}
}
