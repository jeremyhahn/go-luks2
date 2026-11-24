// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package wipe destroys the data on a block device or file with overwrite passes, optional read-back verification and optional TRIM/DISCARD.
package wipe

// Pattern is the data written by one wipe pass.
type Pattern uint8

const (
	// Zeros writes 0x00 throughout the pass.
	Zeros Pattern = iota

	// Ones writes 0xFF throughout the pass.
	Ones

	// Random writes a keyed AES-256-CTR stream, fresh per pass.
	Random
)

// String returns the lowercase name of p.
func (p Pattern) String() string {
	switch p {
	case Zeros:
		return "zeros"
	case Ones:
		return "ones"
	case Random:
		return "random"
	default:
		return "unknown"
	}
}
