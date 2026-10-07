// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import "errors"

// Sentinels for the ways the gate's INPUTS can be unusable. Each one fails the
// gate: an input the gate cannot read is not evidence that coverage is fine.
var (
	// ErrProfileMalformed indicates a coverage profile line that is not in the
	// format `go test -coverprofile` writes.
	ErrProfileMalformed = errors.New("malformed coverage profile")

	// ErrProfileConflict indicates two profiles that disagree on how many
	// statements one block holds, which means they were built from different
	// source and cannot be merged into one measurement.
	ErrProfileConflict = errors.New("coverage profiles disagree about a block")

	// ErrFloorsMalformed indicates a floors-file line the gate cannot parse.
	ErrFloorsMalformed = errors.New("malformed coverage floors file")

	// ErrUsage indicates the gate was invoked without the inputs it needs.
	ErrUsage = errors.New("usage")
)
