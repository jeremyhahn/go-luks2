// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// TestParseIVTweak is GONE, with parseIVTweak itself (#40).
//
// It was a bug-defender: it asserted that "invalid", "-1" and "0x100" all
// produced 0 and that a value past 64 bits produced 18446744073709551615 --
// which is exactly the silent mapping of a malformed header field onto a
// valid-looking IV offset that the fix removes. A header's iv_tweak is now
// parsed by cryptTableParams, which refuses what does not parse; the refusals
// are pinned in segmentvalidation_test.go.

// TestVerifyMasterKey tests master key verification against digests
func TestVerifyMasterKey(t *testing.T) {
	// Create a known master key for testing
	testMasterKey := []byte("test-master-key-32-bytes-long!!!")

	t.Run("valid master key with pbkdf2 digest", func(t *testing.T) {
		// Derive the expected digest from the test master key
		iterations := 1000
		kdf := &KDF{
			Type:       "pbkdf2",
			Hash:       "sha256",
			Salt:       encodeBase64([]byte("test-salt-16byte")),
			Iterations: &iterations,
		}

		expectedDigest, err := DeriveKey(testMasterKey, kdf, 32)
		if err != nil {
			t.Fatalf("Failed to derive test digest: %v", err)
		}

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       kdf.Salt,
				Iterations: iterations,
				Digest:     encodeBase64(expectedDigest),
			},
		}

		err = verifyMasterKey(enclaveFrom(t, testMasterKey), "0", boundTo("0", digests))
		if err != nil {
			t.Errorf("verifyMasterKey failed with valid key: %v", err)
		}
	})

	t.Run("invalid master key", func(t *testing.T) {
		invalidKey := []byte("wrong-master-key-32-bytes-long!!")
		iterations := 1000
		kdf := &KDF{
			Type:       "pbkdf2",
			Hash:       "sha256",
			Salt:       encodeBase64([]byte("test-salt-16byte")),
			Iterations: &iterations,
		}

		// Derive digest from correct key
		correctDigest, err := DeriveKey(testMasterKey, kdf, 32)
		if err != nil {
			t.Fatalf("Failed to derive test digest: %v", err)
		}

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       kdf.Salt,
				Iterations: iterations,
				Digest:     encodeBase64(correctDigest),
			},
		}

		err = verifyMasterKey(enclaveFrom(t, invalidKey), "0", boundTo("0", digests))
		if err == nil {
			t.Error("verifyMasterKey should fail with invalid key")
		}
		if err.Error() != "master key verification failed" {
			t.Errorf("Expected 'master key verification failed', got: %v", err)
		}
	})

	// An EMPTY master key can no longer be constructed to test with: an enclave
	// over zero bytes is refused at the constructor (enclave.ErrEmptyEnclave),
	// so the case this subtest used to cover is now unrepresentable rather than
	// merely rejected. That is a stronger guarantee, and it is asserted at the
	// constructor instead.
	t.Run("empty master key cannot be held at all", func(t *testing.T) {
		e, err := newSecretEnclave("master key", 0)
		if err == nil {
			e.Destroy()
			t.Fatal("an enclave over an empty master key was created")
		}
		if !errors.Is(err, ErrProtectedMemory) {
			t.Errorf("error does not match ErrProtectedMemory: %v", err)
		}
	})

	t.Run("destroyed master key", func(t *testing.T) {
		iterations := 1000

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       encodeBase64([]byte("test-salt-16byte")),
				Iterations: iterations,
				Digest:     encodeBase64([]byte("some-digest-value-32-bytes!!!!!")),
			},
		}

		// A destroyed enclave is what "no readable master key" looks like once
		// custody is enclave-owned, and it must not verify.
		destroyed, err := randomSecret("master key", 32)
		if err != nil {
			t.Fatalf("randomSecret failed: %v", err)
		}
		destroyed.Destroy()

		if err := verifyMasterKey(destroyed, "0", boundTo("0", digests)); err == nil {
			t.Error("verifyMasterKey accepted a destroyed master key")
		}
	})

	t.Run("nil master key", func(t *testing.T) {
		iterations := 1000

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       encodeBase64([]byte("test-salt-16byte")),
				Iterations: iterations,
				Digest:     encodeBase64([]byte("some-digest-value-32-bytes!!!!!")),
			},
		}

		err := verifyMasterKey(nil, "0", boundTo("0", digests))
		if err == nil {
			t.Error("verifyMasterKey should fail with nil key")
		}
	})

	t.Run("empty digests map", func(t *testing.T) {
		digests := map[string]*Digest{}

		err := verifyMasterKey(enclaveFrom(t, testMasterKey), "0", boundTo("0", digests))
		if err == nil {
			t.Fatal("verifyMasterKey should fail with empty digests map")
		}
		// ErrInvalidHeader, NOT ErrMasterKeyVerification. This assertion used to
		// demand the verification message, which said a credential had been
		// judged and rejected when nothing had been judged at all: a header with
		// no digest cannot evaluate any key. The operator it misdirects is the
		// one whose header is truncated, and it sends them to their passphrase.
		if !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("a header with no digests is not reported as a header fault: %v", err)
		}
		if errors.Is(err, ErrMasterKeyVerification) {
			t.Errorf("a header with no digests was reported as a failed verification: %v", err)
		}
	})

	t.Run("nil digests map", func(t *testing.T) {
		err := verifyMasterKey(enclaveFrom(t, testMasterKey), "0", boundTo("0", nil))
		if err == nil {
			t.Error("verifyMasterKey should fail with nil digests map")
		}
	})

	t.Run("multiple digests, first invalid, second valid", func(t *testing.T) {
		iterations := 1000
		kdf := &KDF{
			Type:       "pbkdf2",
			Hash:       "sha256",
			Salt:       encodeBase64([]byte("test-salt-16byte")),
			Iterations: &iterations,
		}

		validDigest, err := DeriveKey(testMasterKey, kdf, 32)
		if err != nil {
			t.Fatalf("Failed to derive test digest: %v", err)
		}

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       kdf.Salt,
				Iterations: iterations,
				Digest:     encodeBase64([]byte("invalid-digest-value-32-bytes!!")),
			},
			"1": {
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       kdf.Salt,
				Iterations: iterations,
				Digest:     encodeBase64(validDigest),
			},
		}

		err = verifyMasterKey(enclaveFrom(t, testMasterKey), "0", boundTo("0", digests))
		if err != nil {
			t.Errorf("verifyMasterKey failed with at least one valid digest: %v", err)
		}
	})

	t.Run("invalid base64 in digest", func(t *testing.T) {
		iterations := 1000

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       encodeBase64([]byte("test-salt-16byte")),
				Iterations: iterations,
				Digest:     "!!!invalid-base64!!!",
			},
		}

		err := verifyMasterKey(enclaveFrom(t, testMasterKey), "0", boundTo("0", digests))
		if err == nil {
			t.Error("verifyMasterKey should fail with invalid base64 digest")
		}
	})

	t.Run("invalid hash algorithm", func(t *testing.T) {
		iterations := 1000

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "invalid-hash",
				Salt:       encodeBase64([]byte("test-salt-16byte")),
				Iterations: iterations,
				Digest:     encodeBase64([]byte("some-digest-value-32-bytes!!!!!")),
			},
		}

		err := verifyMasterKey(enclaveFrom(t, testMasterKey), "0", boundTo("0", digests))
		if err == nil {
			t.Error("verifyMasterKey should fail with invalid hash algorithm")
		}
	})

	t.Run("sha512 hash algorithm", func(t *testing.T) {
		iterations := 1000
		kdf := &KDF{
			Type:       "pbkdf2",
			Hash:       "sha512",
			Salt:       encodeBase64([]byte("test-salt-16byte")),
			Iterations: &iterations,
		}

		expectedDigest, err := DeriveKey(testMasterKey, kdf, 32)
		if err != nil {
			t.Fatalf("Failed to derive test digest: %v", err)
		}

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "sha512",
				Salt:       kdf.Salt,
				Iterations: iterations,
				Digest:     encodeBase64(expectedDigest),
			},
		}

		err = verifyMasterKey(enclaveFrom(t, testMasterKey), "0", boundTo("0", digests))
		if err != nil {
			t.Errorf("verifyMasterKey failed with sha512: %v", err)
		}
	})

	t.Run("zero iterations", func(t *testing.T) {
		iterations := 0

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       encodeBase64([]byte("test-salt-16byte")),
				Iterations: iterations,
				Digest:     encodeBase64([]byte("some-digest-value-32-bytes!!!!!")),
			},
		}

		err := verifyMasterKey(enclaveFrom(t, testMasterKey), "0", boundTo("0", digests))
		if err == nil {
			t.Error("verifyMasterKey should handle zero iterations")
		}
	})

	t.Run("invalid base64 in salt", func(t *testing.T) {
		iterations := 1000

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       "!!!invalid-base64!!!",
				Iterations: iterations,
				Digest:     encodeBase64([]byte("some-digest-value-32-bytes!!!!!")),
			},
		}

		err := verifyMasterKey(enclaveFrom(t, testMasterKey), "0", boundTo("0", digests))
		if err == nil {
			t.Error("verifyMasterKey should fail with invalid base64 salt")
		}
	})

	// The verifier derives to the length of the digest STORED IN THE HEADER,
	// so a header is verified at whatever length its author chose -- 32 bytes
	// from an old go-luks2, 64 from cryptsetup with sha512 -- rather than at
	// one length this package happens to prefer.
	//
	// This subtest previously asserted the opposite: that a 64-byte digest must
	// FAIL because the verifier derived a hardcoded 32. That assertion is the
	// read half of #73 written down as a test, and it is what made
	// cryptsetup-written sha512 volumes report "incorrect passphrase" for the
	// correct passphrase.
	// The accepted lengths are a whitelist: what the declared hash implies, plus
	// the 32-byte legacy carve-out for containers earlier versions of this
	// package wrote.
	for _, tc := range []struct {
		hash      string
		digestLen int
	}{
		{"sha256", 32}, // the hash's own length
		{"sha384", 48},
		{"sha512", 64},
		{"sha512", legacyDigestLen}, // old go-luks2: 32 bytes labeled sha512
		{"sha384", legacyDigestLen},
	} {
		t.Run(fmt.Sprintf("%s digest stored at %d bytes verifies", tc.hash, tc.digestLen), func(t *testing.T) {
			iterations := 1000
			kdf := &KDF{
				Type:       "pbkdf2",
				Hash:       tc.hash,
				Salt:       encodeBase64([]byte("test-salt-16byte")),
				Iterations: &iterations,
			}

			stored, err := DeriveKey(testMasterKey, kdf, tc.digestLen)
			if err != nil {
				t.Fatalf("Failed to derive test digest: %v", err)
			}

			digests := map[string]*Digest{
				"0": {
					Type:       "pbkdf2",
					Hash:       tc.hash,
					Salt:       kdf.Salt,
					Iterations: iterations,
					Digest:     encodeBase64(stored),
				},
			}

			if err := verifyMasterKey(enclaveFrom(t, testMasterKey), "0", boundTo("0", digests)); err != nil {
				t.Errorf("verifyMasterKey failed for a %d-byte %s digest: %v", tc.digestLen, tc.hash, err)
			}
		})
	}

	// Every other length is refused BEFORE any derivation is attempted. PBKDF2
	// will produce whatever length it is asked for, and a zero-length digest
	// would make the constant-time comparison succeed against every key.
	//
	// 16 and 20 are the interesting entries: both were accepted by the earlier
	// 16..64 range, and neither is a length anything legitimate writes under a
	// sha512 label.
	for _, tc := range []struct {
		hash      string
		digestLen int
	}{
		{"sha512", 0},
		{"sha512", 1},
		{"sha512", 16},
		{"sha512", 20},
		{"sha512", 48},
		{"sha512", 65},
		{"sha256", 64},
		{"sha256", 4096},
		{"md5", legacyDigestLen}, // unknown hash: no length is derivable
	} {
		t.Run(fmt.Sprintf("%s digest stored at %d bytes is refused as a header fault", tc.hash, tc.digestLen), func(t *testing.T) {
			iterations := 1000
			// The stored bytes are arbitrary: what is under test is that the
			// LENGTH is refused before any derivation is attempted, so the
			// value must not come from DeriveKey (which panics on a zero
			// length -- see the out-of-scope note in the report).
			stored := bytes.Repeat([]byte{0xA5}, tc.digestLen)

			digests := map[string]*Digest{
				"0": {
					Type:       "pbkdf2",
					Hash:       tc.hash,
					Salt:       encodeBase64([]byte("test-salt-16byte")),
					Iterations: iterations,
					Digest:     encodeBase64(stored),
				},
			}

			// ErrInvalidHeader, NOT ErrMasterKeyVerification (#41). This
			// assertion demanded the verification verdict until the boundary
			// was drawn, and it was DEFENDING the defect: the only digest that
			// attests this keyslot is unusable, so nothing was ever compared,
			// and a verification verdict claims a judgement that never
			// happened. The operator it misdirects is the one whose header is
			// damaged and whose passphrase is perfectly good.
			err := verifyMasterKey(enclaveFrom(t, testMasterKey), "0", boundTo("0", digests))
			if !errors.Is(err, ErrInvalidHeader) {
				t.Errorf("verifyMasterKey(%d-byte %s digest) = %v, want ErrInvalidHeader",
					tc.digestLen, tc.hash, err)
			}
			if errors.Is(err, ErrMasterKeyVerification) {
				t.Errorf("verifyMasterKey(%d-byte %s digest) claimed a verification that never ran: %v",
					tc.digestLen, tc.hash, err)
			}
		})
	}
}

// TestVerifyMasterKeyDoesNotModifyInput tests that verifyMasterKey doesn't modify the input
func TestVerifyMasterKeyDoesNotModifyInput(t *testing.T) {
	testMasterKey := []byte("test-master-key-32-bytes-long!!!")
	originalKey := make([]byte, len(testMasterKey))
	copy(originalKey, testMasterKey)

	iterations := 1000
	kdf := &KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       encodeBase64([]byte("test-salt-16byte")),
		Iterations: &iterations,
	}

	expectedDigest, err := DeriveKey(testMasterKey, kdf, 32)
	if err != nil {
		t.Fatalf("Failed to derive test digest: %v", err)
	}

	digests := map[string]*Digest{
		"0": {
			Type:       "pbkdf2",
			Hash:       "sha256",
			Salt:       kdf.Salt,
			Iterations: iterations,
			Digest:     encodeBase64(expectedDigest),
		},
	}

	_ = verifyMasterKey(enclaveFrom(t, testMasterKey), "0", boundTo("0", digests))

	if !bytes.Equal(testMasterKey, originalKey) {
		t.Error("verifyMasterKey modified the input master key")
	}
}

/*
 * Note: The following functions in unlock.go are not easily testable in unit tests
 * because they require actual device I/O or system resources:
 *
 * - unlockKeyslot: Requires reading from a real LUKS device
 * - getBlockDeviceSize: Requires a real block device or file descriptor
 * - Unlock: Requires a real LUKS device and device-mapper interaction
 * - Lock: Requires device-mapper interaction
 * - IsUnlocked: Requires checking /dev/mapper
 *
 * These functions should be tested in integration tests with a real or mocked
 * LUKS device in a containerized environment.
 */
