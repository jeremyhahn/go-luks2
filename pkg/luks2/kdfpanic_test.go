// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// The derivation must not panic on any header parameter, even though x/crypto pbkdf2 and argon2 panic on some legal values.
func TestDeriveKeyDoesNotPanicOnHeaderControlledParameters(t *testing.T) {
	iterations := 1000
	zero := 0
	one := 1
	memory := 8
	cpus := 1

	cases := []struct {
		name    string
		kdf     *header.KDF
		keySize int
	}{
		{
			name:    "pbkdf2 with a zero key size",
			kdf:     &header.KDF{Type: "pbkdf2", Hash: "sha256", Salt: "c2FsdA==", Iterations: &iterations},
			keySize: 0,
		},
		{
			name:    "pbkdf2 with a negative key size",
			kdf:     &header.KDF{Type: "pbkdf2", Hash: "sha256", Salt: "c2FsdA==", Iterations: &iterations},
			keySize: -1,
		},
		{
			// argon2 panics on time < 1, and nothing checked it: the cpus
			// bound next to it was checked, which is what made the omission
			// easy to miss.
			name:    "argon2id with zero rounds",
			kdf:     &header.KDF{Type: "argon2id", Salt: "c2FsdA==", Time: &zero, Memory: &memory, CPUs: &cpus},
			keySize: 32,
		},
		{
			name:    "argon2i with zero rounds",
			kdf:     &header.KDF{Type: "argon2i", Salt: "c2FsdA==", Time: &zero, Memory: &memory, CPUs: &cpus},
			keySize: 32,
		},
		{
			name:    "argon2id with a zero key size",
			kdf:     &header.KDF{Type: "argon2id", Salt: "c2FsdA==", Time: &one, Memory: &memory, CPUs: &cpus},
			keySize: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := deriveKeyEnclave(context.Background(), []byte("a passphrase"), tc.kdf, tc.keySize, defaultVolumeSys())
			if err == nil {
				mustDestroy(t, key)
				t.Fatal("the derivation accepted a parameter no derivation can run with")
			}
			// A typed refusal, not a panic and not a bare string: callers
			// classify these, and #72 is what happens when they cannot.
			var typedErr *errs.Error
			if !errors.As(err, &typedErr) {
				t.Fatalf("the refusal is not a typed error: %v", err)
			}
		})
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	}()
}
