// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package wipe

// VerifyMode decides whether Sanitize reads the last pass back and compares
// it with what was written.
type VerifyMode uint8

const (
	// VerifyDefault leaves the decision to Params.Standard: verify if the
	// named standard calls for it, otherwise do not. With no Standard, this
	// is "do not verify".
	VerifyDefault VerifyMode = iota

	// VerifyAlways verifies regardless of what Standard would otherwise
	// decide.
	VerifyAlways

	// VerifyNever skips verification regardless of what Standard would
	// otherwise decide.
	VerifyNever
)

// Params configures a Sanitize call.
type Params struct {
	// Standard, if not NoStandard, supplies the pass sequence and the
	// default verification decision; it overrides Patterns.
	Standard Standard

	// Patterns is the pass sequence to use when Standard is NoStandard. An
	// empty sequence (the zero value) is a single Zeros pass.
	Patterns []Pattern

	// Verify overrides whatever Standard would otherwise decide.
	Verify VerifyMode

	// Discard issues TRIM/DISCARD for the whole device once every pass (and
	// any verification) has completed. Best effort: a device that does not
	// support it has already been overwritten.
	Discard bool

	// Progress, if not nil, is called after every chunk a pass or a
	// verification writes or reads.
	Progress func(Progress)
}

// Progress reports how far one pass, or the verification following it, has
// gone.
type Progress struct {
	// Pass is the 1-based index of the current pass. Verifying reports the
	// index after the last pass: Progress{Pass: Passes + 1, ...}.
	Pass, Passes int

	// Written is how far a pass has written, or a verification has read,
	// into [0, Total).
	Written, Total int64

	// Pattern is the current pass's pattern.
	Pattern Pattern

	// Verifying reports whether this progress is from the read-back
	// verification rather than from a pass itself.
	Verifying bool
}
