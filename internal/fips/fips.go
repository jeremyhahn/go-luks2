// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package fips is this module's FIPS 140-3 policy: whether the process runs in
// FIPS mode, and which algorithms that mode refuses.
//
// The mode is a VALUE, probed once and handed to the code that decides,
// rather than a global each decision consults. FIPS mode is fixed at process
// start, so a process can only ever run one branch of every policy check;
// taking the mode as a value lets a test run both branches in one process,
// while what the Go Cryptographic Module itself enforces in strict mode
// (GODEBUG=fips140=only) is proved by the child-process tests and CI's full-tier FIPS job.
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

// RequireKDF refuses a KDF that is not FIPS-approved when m is FIPS mode.
//
// Argon2 is implemented in pure Go by golang.org/x/crypto (BLAKE2b) and never
// enters the Go Cryptographic Module, so GODEBUG=fips140=only cannot reject
// it. Without this check a FIPS-mode process would derive volume keys with a
// non-approved KDF while the FIPS gate reported green. The PBKDF2 PRF is
// checked separately, by RequireHash. Any other name passes: whether it names
// a KDF at all is the caller's question.
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

// RequireHash refuses a hash that is not FIPS-approved for use -- a PBKDF2
// PRF or an anti-forensic diffuser -- when m is FIPS mode.
//
// The refusal comes BEFORE the hash runs, and that is the point of it. Under
// GODEBUG=fips140=only the Go module makes PBKDF2 with SHA-1 panic, and makes
// sha1's Write return an error that hash.Hash callers discard, so an AF merge
// would complete with wrong bytes rather than fail.
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
