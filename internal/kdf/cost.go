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

// Cost floors and ceilings a header's KDF object is held to on read. The
// ceiling is what WHAT IS WRITTEN MUST BE WHAT THE READER ACCEPTS (#249, A5)
// requires every creation path to stay under; the floor is this package's own
// minimum, which a foreign (cryptsetup-written) header is not held to beyond
// MinKDFIterations / MinArgon2Time / MinArgon2Parallel.
const (
	MinKDFIterations = 1
	MaxKDFIterations = 100_000_000

	MinArgon2Time = 1
	MaxArgon2Time = 10_000

	// MinArgon2Memory is the representable floor a FOREIGN header is held to
	// on read. MinArgon2MemoryKB, below, is the much higher floor this
	// package itself writes.
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

// CostPolicy distinguishes a caller-supplied credential, which is held to the
// full iteration floor, from a library-generated one (a recovery key, a FIDO2
// secret), which is exempt from it: the entropy is already known. The zero
// value is CallerSuppliedCredential, so a forgotten argument fails closed
// rather than granting the exemption.
type CostPolicy int

const (
	CallerSuppliedCredential CostPolicy = iota
	LibraryGeneratedCredential
)

// ValidateCost checks p's cost fields against the floor-to-ceiling range this
// package accepts on read. It does not inspect Salt or Hash beyond what the
// range check needs, and it does not apply a FIPS gate -- RequireKDF /
// RequireHash are separate screens.
func ValidateCost(p Params) error {
	kdfType := strings.ToLower(strings.TrimSpace(p.Type))

	switch {
	case kdfType == "argon2i" || kdfType == "argon2id":
		// Negative values are the sharpest form of this. Time, Memory and
		// CPUs are signed ints out of JSON and are converted with
		// uint32/uint8 at the derive call site, so -1 does not fail -- it
		// wraps to 4294967295, and Argon2 is then asked for a
		// four-terabyte matrix. Checking against a positive minimum is what
		// catches that; checking only the ceiling would not.
		if p.Time == nil || p.Memory == nil || p.CPUs == nil {
			return &errs.Error{Detail: "argon2 KDF is missing its time, memory or cpus cost"}
		}
		if *p.Time < MinArgon2Time || *p.Time > MaxArgon2Time {
			return &errs.Error{
				Detail: fmt.Sprintf("argon2 time cost %d is outside %d..%d", *p.Time, MinArgon2Time, MaxArgon2Time),
			}
		}
		if *p.Memory < MinArgon2Memory || *p.Memory > MaxArgon2Memory {
			return &errs.Error{
				Detail: fmt.Sprintf("argon2 memory cost %d KiB is outside %d..%d",
					*p.Memory, MinArgon2Memory, MaxArgon2Memory),
			}
		}
		if *p.CPUs < MinArgon2Parallel || *p.CPUs > MaxArgon2Parallel {
			return &errs.Error{
				Detail: fmt.Sprintf("argon2 parallelism %d is outside %d..%d",
					*p.CPUs, MinArgon2Parallel, MaxArgon2Parallel),
			}
		}

	case isPBKDF2Type(kdfType):
		// Iterations drive CPU only -- nothing allocated scales with them --
		// so this ceiling is about not hanging on a crafted header rather
		// than about memory.
		if p.Iterations == nil {
			return &errs.Error{Detail: "pbkdf2 KDF is missing its iteration count"}
		}
		if *p.Iterations < MinKDFIterations || *p.Iterations > MaxKDFIterations {
			return &errs.Error{
				Detail: fmt.Sprintf("pbkdf2 iteration count %d is outside %d..%d",
					*p.Iterations, MinKDFIterations, MaxKDFIterations),
			}
		}

	default:
		// An unsupported type must SAY unsupported type. Treating everything
		// non-argon2 as pbkdf2 reports a header claiming type "sha256-crypt"
		// as "missing its iteration count", naming a field that type never
		// claimed to have.
		return &errs.Error{Detail: fmt.Sprintf("unsupported KDF type %q", p.Type)}
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

// PBKDF2IterationFloor is the floor a calibrated count is held to for
// hashAlgo at targetMs: the OWASP-recommended count for hashAlgo, scaled by
// the budget relative to the 2-second reference, never below
// MinPBKDF2Iterations. It returns a float because ScalePBKDF2Iterations
// compares it against an unrounded extrapolation.
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

// PBKDF2FloorFor is the minimum iteration count this package will write for
// hashAlgo under policy: MinPBKDF2Iterations for a library-generated
// credential (the exemption; its entropy is already known), otherwise the
// 2-second-budget floor rounded UP, so a count one iteration below it is
// never admitted.
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
		return 0, &PBKDF2IterationsError{
			Hash:       hashAlgo,
			Iterations: iterations,
			Minimum:    minimum,
			Maximum:    MaxKDFIterations,
			Err:        ErrPBKDFIterationsTooLow,
		}
	}

	if iterations > MaxKDFIterations {
		return 0, &PBKDF2IterationsError{
			Hash:       hashAlgo,
			Iterations: iterations,
			Minimum:    minimum,
			Maximum:    MaxKDFIterations,
			Err:        ErrPBKDFIterationsTooHigh,
		}
	}

	return iterations, nil
}
