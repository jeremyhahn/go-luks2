// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// TestValidatePassphraseEnclave holds the enclave-based ValidatePassphrase
// to the same bounds validatePassphraseBytes enforces for
// the legacy []byte path: the two must agree, since they share one policy.
//
// There is no empty-passphrase case here, unlike
// TestValidatePassphraseBytes: enclave.NewMemoryCopy itself refuses
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

// TestValidatePassphraseErrorShape (#334): every failure ValidatePassphrase
// reports is an *Error with its kind and the operation name, the way every
// other exported entry point reports one -- a length failure is not a bare
// sentinel while a destroyed enclave is an *Error.
func TestValidatePassphraseErrorShape(t *testing.T) {
	destroyed := enclaveFrom(t, []byte("a-valid-passphrase"))
	if err := destroyed.Destroy(); err != nil {
		t.Fatalf("Destroy() = %v", err)
	}

	tests := []struct {
		name     string
		pass     *enclave.Memory
		wantKind error
	}{
		{"too short", enclaveFrom(t, []byte("short")), ErrInvalidCredential},
		{"too long", enclaveFrom(t, make([]byte, MaxPassphraseLength+1)), ErrInvalidCredential},
		{"destroyed enclave", destroyed, ErrProtectedMemory},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassphrase(tt.pass)
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("ValidatePassphrase() = %v (%T), want *Error", err, err)
			}
			if e.Kind != tt.wantKind {
				t.Errorf("Kind = %v, want %v", e.Kind, tt.wantKind)
			}
			if e.Op != "ValidatePassphrase" {
				t.Errorf("Op = %q, want %q", e.Op, "ValidatePassphrase")
			}
			if !errors.Is(err, tt.wantKind) {
				t.Errorf("errors.Is(%v, %v) = false", err, tt.wantKind)
			}
		})
	}
}
