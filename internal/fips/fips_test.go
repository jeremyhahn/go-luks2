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
