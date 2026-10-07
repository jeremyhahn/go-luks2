// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"testing"
)

// TestValidatePassphraseEnclave holds the enclave-based ValidatePassphrase
// (DESIGN.md §B.2) to the same bounds validatePassphraseBytes enforces for
// the legacy []byte path: the two must agree, since they share one policy.
//
// There is no empty-passphrase case here, unlike
// TestValidatePassphraseBytes: enclave.NewMemoryEnclaveCopy itself refuses
// empty material, so an empty passphrase can never reach ValidatePassphrase
// through the enclave boundary at all.
func TestValidatePassphraseEnclave(t *testing.T) {
	tests := []struct {
		name       string
		passphrase []byte
		wantErr    error
	}{
		{"too short", []byte("short"), ErrInvalidCredential},
		{"minimum length", []byte("12345678"), nil},
		{"valid length", []byte("this-is-a-valid-passphrase"), nil},
		{"maximum length", make([]byte, MaxPassphraseLength), nil},
		{"too long", make([]byte, MaxPassphraseLength+1), ErrInvalidCredential},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pass := enclaveFrom(t, tt.passphrase)
			err := ValidatePassphrase(pass)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ValidatePassphrase() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidatePassphraseEnclaveDoesNotConsumeItsArgument: the caller's
// enclave is only ever borrowed, so a second call against the same enclave
// gets the same answer rather than failing as though the material were gone.
func TestValidatePassphraseEnclaveDoesNotConsumeItsArgument(t *testing.T) {
	pass := enclaveFrom(t, []byte("a-valid-passphrase"))

	if err := ValidatePassphrase(pass); err != nil {
		t.Fatalf("first ValidatePassphrase = %v, want nil", err)
	}
	if err := ValidatePassphrase(pass); err != nil {
		t.Fatalf("second ValidatePassphrase = %v, want nil -- the first call consumed the enclave", err)
	}
}
