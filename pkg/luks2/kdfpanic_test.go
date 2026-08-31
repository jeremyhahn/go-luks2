// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"testing"
)

// The derivation must not panic on any parameter a header can carry.
//
// validateKeyslot now screens a keyslot before its KDF is run, and that is the
// primary guard. It is not the only one that should exist. A single guard means
// every future caller of the derivation -- and every path that reaches it other
// than through a keyslot -- is one oversight away from crashing the process,
// which is exactly how the keyslot panics arrived. These tests pin the
// derivation itself.
//
// Two libraries panic here for parameters a LUKS2 header may legally contain:
//
//	golang.org/x/crypto/pbkdf2.Key   panics on any error from crypto/pbkdf2,
//	                                 and the stdlib errors on keyLength <= 0
//	golang.org/x/crypto/argon2       panics directly on time < 1
//	                                 ("argon2: number of rounds too small")
func TestDeriveKeyDoesNotPanicOnHeaderControlledParameters(t *testing.T) {
	iterations := 1000
	zero := 0
	one := 1
	memory := 8
	cpus := 1

	cases := []struct {
		name    string
		kdf     *KDF
		keySize int
	}{
		{
			name:    "pbkdf2 with a zero key size",
			kdf:     &KDF{Type: "pbkdf2", Hash: "sha256", Salt: "c2FsdA==", Iterations: &iterations},
			keySize: 0,
		},
		{
			name:    "pbkdf2 with a negative key size",
			kdf:     &KDF{Type: "pbkdf2", Hash: "sha256", Salt: "c2FsdA==", Iterations: &iterations},
			keySize: -1,
		},
		{
			// argon2 panics on time < 1, and nothing checked it: the cpus
			// bound next to it was checked, which is what made the omission
			// easy to miss.
			name:    "argon2id with zero rounds",
			kdf:     &KDF{Type: "argon2id", Salt: "c2FsdA==", Time: &zero, Memory: &memory, CPUs: &cpus},
			keySize: 32,
		},
		{
			name:    "argon2i with zero rounds",
			kdf:     &KDF{Type: "argon2i", Salt: "c2FsdA==", Time: &zero, Memory: &memory, CPUs: &cpus},
			keySize: 32,
		},
		{
			name:    "argon2id with a zero key size",
			kdf:     &KDF{Type: "argon2id", Salt: "c2FsdA==", Time: &one, Memory: &memory, CPUs: &cpus},
			keySize: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := DeriveKeyEnclave([]byte("a passphrase"), tc.kdf, tc.keySize)
			if err == nil {
				key.Destroy()
				t.Fatal("the derivation accepted a parameter no derivation can run with")
			}
			// A typed refusal, not a panic and not a bare string: callers
			// classify these, and #72 is what happens when they cannot.
			var cryptoErr *CryptoError
			if !errors.As(err, &cryptoErr) {
				t.Fatalf("the refusal is not a typed crypto error: %v", err)
			}
		})
	}
}

// The property this file used to guard here -- that a refusal must not name the
// requested key length -- moved out with the bound that produced it.
//
// deriveKeyPlain no longer has an upper bound to violate (see kdf.go: it serves
// two trust domains and an untrusted-input ceiling there rejected a caller's own
// hardening), so the test could only skip, and a skipping test is a test nobody
// reads. Where the property still matters it is asserted directly:
// TestProtectedMemoryErrorDoesNotNameSizes, on the one error type that must
// stay silent about sizes.
//
// A keyslot refusal DOES name the size it rejected, deliberately -- key_size is
// a cleartext LUKS2 header field, and an operator diagnosing a bad container
// needs the number.

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
