// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package kdf

import (
	"fmt"
	"math"
	"strings"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// Cost floors and ceilings a header's KDF object is held to on read; the ceiling bounds every creation path.
const (
	MinKDFIterations = 1
	MaxKDFIterations = 100_000_000

	MinArgon2Time = 1
	MaxArgon2Time = 10_000

	// MinArgon2Memory is the floor a foreign header is held to on read; MinArgon2MemoryKB is the floor this package writes.
	MinArgon2Memory = 8
	MaxArgon2Memory = 4 << 20

	MinArgon2Parallel = 1
	MaxArgon2Parallel = 255

	// MinArgon2MemoryKB is the floor this package writes for a new Argon2
	// keyslot: 64 MiB, independent of MinArgon2Memory's read-side floor.
	MinArgon2MemoryKB = 65536

	// MinPBKDF2Iterations is the absolute floor this package writes,
	// independent of any hash's recommended count.
	MinPBKDF2Iterations = 1000
)

// CostPolicy exempts a library-generated credential from the iteration floor; the zero value, CallerSuppliedCredential, does not.
type CostPolicy int

const (
	CallerSuppliedCredential CostPolicy = iota
	LibraryGeneratedCredential
)

// ValidateCost checks p's cost fields against the accepted range; it applies no FIPS gate.
func ValidateCost(p Params) error {
	kdfType := strings.ToLower(strings.TrimSpace(p.Type))

	switch {
	case kdfType == "argon2i" || kdfType == "argon2id":
		// A positive minimum catches negative values that would wrap to huge unsigned costs.
		if p.Time == nil || p.Memory == nil || p.CPUs == nil {
			return &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "argon2 KDF is missing its time, memory or cpus cost"}
		}
		if *p.Time < MinArgon2Time || *p.Time > MaxArgon2Time {
			return &errs.Error{
				Kind:   errs.ErrInvalidArgument,
				Detail: fmt.Sprintf("argon2 time cost %d is outside %d..%d", *p.Time, MinArgon2Time, MaxArgon2Time),
			}
		}
		if *p.Memory < MinArgon2Memory || *p.Memory > MaxArgon2Memory {
			return &errs.Error{
				Kind: errs.ErrInvalidArgument,
				Detail: fmt.Sprintf("argon2 memory cost %d KiB is outside %d..%d",
					*p.Memory, MinArgon2Memory, MaxArgon2Memory),
			}
		}
		if *p.CPUs < MinArgon2Parallel || *p.CPUs > MaxArgon2Parallel {
			return &errs.Error{
				Kind: errs.ErrInvalidArgument,
				Detail: fmt.Sprintf("argon2 parallelism %d is outside %d..%d",
					*p.CPUs, MinArgon2Parallel, MaxArgon2Parallel),
			}
		}

	case isPBKDF2Type(kdfType):
		// Iterations drive CPU only -- nothing allocated scales with them --
		// so this ceiling is about not hanging on a crafted header rather
		// than about memory.
		if p.Iterations == nil {
			return &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "pbkdf2 KDF is missing its iteration count"}
		}
		if *p.Iterations < MinKDFIterations || *p.Iterations > MaxKDFIterations {
			return &errs.Error{
				Kind: errs.ErrInvalidArgument,
				Detail: fmt.Sprintf("pbkdf2 iteration count %d is outside %d..%d",
					*p.Iterations, MinKDFIterations, MaxKDFIterations),
			}
		}

	default:
		// An unsupported type is reported as such.
		return &errs.Error{Kind: ErrUnsupportedKDF, Detail: fmt.Sprintf("unsupported KDF type %q", p.Type)}
	}

	return nil
}

func isPBKDF2Type(normalizedType string) bool {
	switch normalizedType {
	case "pbkdf2", "pbkdf2-sha1", "pbkdf2-sha256", "pbkdf2-sha384", "pbkdf2-sha512":
		return true
	default:
		return false
	}
}

// PBKDF2IterationFloor scales the OWASP count for hashAlgo to targetMs, never below MinPBKDF2Iterations.
func PBKDF2IterationFloor(hashAlgo string, targetMs int) float64 {
	floor := float64(MinPBKDF2Iterations)

	recommended, ok := PBKDF2RecommendedIterations[strings.ToLower(hashAlgo)]
	if !ok {
		return floor
	}

	if scaled := float64(recommended) * float64(targetMs) / PBKDF2ReferenceTargetMs; scaled > floor {
		return scaled
	}
	return floor
}

// PBKDF2FloorFor is the minimum count this package writes for hashAlgo under policy, rounded up.
func PBKDF2FloorFor(hashAlgo string, policy CostPolicy) int {
	if policy == LibraryGeneratedCredential {
		return MinPBKDF2Iterations
	}
	return int(math.Ceil(PBKDF2IterationFloor(hashAlgo, PBKDF2ReferenceTargetMs)))
}

// ForcedPBKDF2Iterations checks an explicit, caller-given iteration count
// against the floor PBKDF2FloorFor reports and the MaxKDFIterations ceiling
// ValidateCost applies when the header is read back.
func ForcedPBKDF2Iterations(hashAlgo string, iterations int, policy CostPolicy) (int, error) {
	minimum := PBKDF2FloorFor(hashAlgo, policy)

	if iterations < minimum {
		return 0, &errs.Error{
			Kind: errs.ErrInvalidArgument,
			Detail: fmt.Sprintf("hash %s, requested %d iterations, permitted range %d..%d (below the minimum this package will write)",
				hashAlgo, iterations, minimum, MaxKDFIterations),
		}
	}

	if iterations > MaxKDFIterations {
		return 0, &errs.Error{
			Kind: errs.ErrInvalidArgument,
			Detail: fmt.Sprintf("hash %s, requested %d iterations, permitted range %d..%d (above the maximum this package will write)",
				hashAlgo, iterations, minimum, MaxKDFIterations),
		}
	}

	return iterations, nil
}
