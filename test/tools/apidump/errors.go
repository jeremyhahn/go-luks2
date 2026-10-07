// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import "errors"

var (
	// ErrUsage indicates apidump was invoked without the operands its
	// subcommand needs.
	ErrUsage = errors.New("usage")

	// ErrParse indicates a Go file in the dumped directory does not parse.
	ErrParse = errors.New("go source does not parse")

	// ErrNoAPI indicates a directory that declares no exported identifier,
	// which is a wrong path far more often than a real package.
	ErrNoAPI = errors.New("no exported API")

	// ErrMalformed indicates a dump or disposition file line apidump cannot
	// read.
	ErrMalformed = errors.New("malformed input file")

	// ErrCoverage indicates a disposition file that does not cover its
	// baseline exactly.
	ErrCoverage = errors.New("dispositions do not cover the baseline exactly")

	// ErrDishonored indicates a disposition the current API does not match:
	// a KEEP identifier that is gone, or a RENAME/MOVE/UNEXPORT/DELETE
	// identifier that is still there under its old name.
	ErrDishonored = errors.New("the current API does not honor every disposition")
)
