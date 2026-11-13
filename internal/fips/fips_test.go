// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package fips

import (
	"crypto"
	"crypto/fips140"
	"errors"
	"strings"
	"testing"
)

func TestProbeIsTheProcessMode(t *testing.T) {
	if Probe() != Mode(fips140.Enabled()) {
		t.Fatalf("Probe() = %v, crypto/fips140.Enabled() = %v", Probe(), fips140.Enabled())
	}
}

func TestRequireKDFRefusesArgon2OnlyInFIPSMode(t *testing.T) {
	for _, tt := range []struct {
		mode    Mode
		kdfType string
		refused bool
	}{
		{true, "argon2id", true},
		{true, " Argon2I ", true},
		{true, "pbkdf2", false},
		{true, "pbkdf2-sha512", false},
		{true, "scrypt", false},
		{false, "argon2id", false},
		{false, "argon2i", false},
	} {
		err := tt.mode.RequireKDF(tt.kdfType)
		if refused := err != nil; refused != tt.refused {
			t.Errorf("Mode(%v).RequireKDF(%q) = %v, refused %v", tt.mode, tt.kdfType, err, tt.refused)
			continue
		}
		if err != nil && (!errors.Is(err, ErrNotApproved) || !strings.Contains(err.Error(), strings.ToLower(strings.TrimSpace(tt.kdfType)))) {
			t.Errorf("Mode(%v).RequireKDF(%q) = %v, want ErrNotApproved naming the KDF", tt.mode, tt.kdfType, err)
		}
	}
}

func TestRequireHashRefusesSHA1OnlyInFIPSMode(t *testing.T) {
	for _, tt := range []struct {
		mode    Mode
		hash    crypto.Hash
		refused bool
	}{
		{true, crypto.SHA1, true},
		{true, crypto.MD5, true},
		{true, crypto.SHA256, false},
		{true, crypto.SHA384, false},
		{true, crypto.SHA512, false},
		{true, crypto.SHA3_256, false},
		{false, crypto.SHA1, false},
	} {
		err := tt.mode.RequireHash("pbkdf2-hmac", tt.hash)
		if refused := err != nil; refused != tt.refused {
			t.Errorf("Mode(%v).RequireHash(%v) = %v, refused %v", tt.mode, tt.hash, err, tt.refused)
			continue
		}
		if err != nil && (!errors.Is(err, ErrNotApproved) || !strings.Contains(err.Error(), "pbkdf2-hmac")) {
			t.Errorf("Mode(%v).RequireHash(%v) = %v, want ErrNotApproved naming the use", tt.mode, tt.hash, err)
		}
	}
}

// The approval is a positive list: the SHA-2 and SHA-3 families and nothing
// else, so a hash added to crypto later is refused until it is listed.
func TestApprovedHashIsExactlyTheSHA2AndSHA3Families(t *testing.T) {
	approved := map[crypto.Hash]bool{
		crypto.SHA224: true, crypto.SHA256: true, crypto.SHA384: true, crypto.SHA512: true,
		crypto.SHA512_224: true, crypto.SHA512_256: true,
		crypto.SHA3_224: true, crypto.SHA3_256: true, crypto.SHA3_384: true, crypto.SHA3_512: true,
	}
	for h := crypto.Hash(0); h <= crypto.BLAKE2b_512+1; h++ {
		if got := ApprovedHash(h); got != approved[h] {
			t.Errorf("ApprovedHash(%v) = %v, want %v", h, got, approved[h])
		}
		if err := Mode(true).RequireHash("use", h); (err == nil) != approved[h] {
			t.Errorf("Mode(true).RequireHash(%v) = %v, approved %v", h, err, approved[h])
		}
	}
}

// Under make test-fips-mode the process itself is in FIPS mode: the probed
// mode refuses Argon2 and SHA-1 there and allows them everywhere else.
func TestProcessModeRefusesArgon2AndSHA1ExactlyInFIPSMode(t *testing.T) {
	inFIPS := fips140.Enabled()
	for _, kdf := range []string{"argon2i", "argon2id", " Argon2ID "} {
		err := Probe().RequireKDF(kdf)
		if (err != nil) != inFIPS || (err != nil && !errors.Is(err, ErrNotApproved)) {
			t.Errorf("Probe().RequireKDF(%q) = %v with fips140.Enabled() = %v", kdf, err, inFIPS)
		}
	}
	if err := Probe().RequireKDF("pbkdf2"); err != nil {
		t.Errorf("Probe().RequireKDF(pbkdf2) = %v, want nil", err)
	}
	err := Probe().RequireHash("af-split", crypto.SHA1)
	if (err != nil) != inFIPS || (err != nil && !errors.Is(err, ErrNotApproved)) {
		t.Errorf("Probe().RequireHash(SHA1) = %v with fips140.Enabled() = %v", err, inFIPS)
	}
	if err := Probe().RequireHash("af-split", crypto.SHA256); err != nil {
		t.Errorf("Probe().RequireHash(SHA256) = %v, want nil", err)
	}
}
