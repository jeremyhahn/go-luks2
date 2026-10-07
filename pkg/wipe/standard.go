// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package wipe

// Standard names a wipe methodology: a fixed sequence of passes and,
// typically, a requirement that the last of them be verified.
type Standard uint8

const (
	// NoStandard requests no named methodology: Params.Patterns, or a
	// single Zeros pass if that is empty too, decides the sequence.
	NoStandard Standard = iota

	// DoD3Pass is DoD 5220.22-M's 3-pass sequence: Zeros, Ones, Random.
	DoD3Pass

	// DoD7Pass is DoD 5220.22-M ECE's 7-pass sequence: three passes, a
	// fourth random pass, then the three again.
	DoD7Pass

	// NIST is NIST SP 800-88 Rev 1's single pass of random data.
	NIST
)

// String returns the lowercase name of s.
func (s Standard) String() string {
	switch s {
	case NoStandard:
		return "none"
	case DoD3Pass:
		return "dod3"
	case DoD7Pass:
		return "dod7"
	case NIST:
		return "nist"
	default:
		return "unknown"
	}
}

// Patterns returns the pass sequence s names, or nil for NoStandard.
func (s Standard) Patterns() []Pattern {
	switch s {
	case NIST:
		return []Pattern{Random}
	case DoD3Pass:
		return []Pattern{Zeros, Ones, Random}
	case DoD7Pass:
		return []Pattern{
			Zeros, Ones, Random,
			Random,
			Zeros, Ones, Random,
		}
	default:
		return nil
	}
}

// requiresVerification reports whether s's own methodology calls for
// verifying the last pass. Params.Verify can still override this either way.
func (s Standard) requiresVerification() bool {
	switch s {
	case DoD3Pass, DoD7Pass:
		return true
	default:
		return false
	}
}
