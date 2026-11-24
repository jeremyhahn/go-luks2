// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package fips is the module's FIPS 140-3 policy; the mode is a value probed once, so tests can run both branches.
package fips

import (
	"crypto"
	"crypto/fips140"
	"strings"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// Mode reports whether the process runs in FIPS 140-3 mode.
type Mode bool

// Probe returns the mode this process runs in: crypto/fips140.Enabled.
func Probe() Mode { return Mode(fips140.Enabled()) }

// RequireKDF refuses a non-approved KDF (Argon2, outside the Go Cryptographic Module) when m is FIPS mode.
func (m Mode) RequireKDF(kdfType string) error {
	if !m {
		return nil
	}
	switch normalized := strings.ToLower(strings.TrimSpace(kdfType)); normalized {
	case "argon2i", "argon2id":
		return &errs.Error{Kind: ErrNotApproved, Detail: normalized}
	default:
		return nil
	}
}

// RequireHash refuses a non-approved hash for a PBKDF2 PRF or AF diffuser in FIPS mode, before the hash runs.
func (m Mode) RequireHash(use string, h crypto.Hash) error {
	if !bool(m) || ApprovedHash(h) {
		return nil
	}
	return &errs.Error{Kind: ErrNotApproved, Detail: use}
}

// ApprovedHash reports whether h is a hash FIPS 140-3 approves for key
// derivation: the SHA-2 and SHA-3 families. SHA-1 is not.
func ApprovedHash(h crypto.Hash) bool {
	switch h {
	case crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512, crypto.SHA512_224, crypto.SHA512_256,
		crypto.SHA3_224, crypto.SHA3_256, crypto.SHA3_384, crypto.SHA3_512:
		return true
	default:
		return false
	}
}
