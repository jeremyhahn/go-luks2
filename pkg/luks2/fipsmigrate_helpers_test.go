// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// Direct tests of the helpers MigrateToFIPS and AddKey stand on, for the
// outcomes the end-to-end tests cannot reach without contriving a header for
// each: every refusal of verifyFIPSOpen, every choice of digestAttestingKey,
// and the refusal descriptions for malformed objects. All of them run on a
// PBKDF2 volume, so in FIPS mode and out of it.

// secretOf returns b in protected memory, released when the test ends
// (destroyOnCleanup).
func secretOf(t *testing.T, b []byte) *enclave.MemoryEnclave {
	t.Helper()

	e, err := copySecret("test key", b)
	if err != nil {
		t.Fatalf("copySecret: %v", err)
	}
	destroyOnCleanup(t, e)
	return e
}

// TestDigestAttestingKey: the digest a new keyslot joins is the one its key
// matches, a bound one before an unbound one, and no match is refused.
func TestDigestAttestingKey(t *testing.T) {
	device := newImage(t, "attesting.img")
	formatWithLibrary(t, device)
	key := volumeKey(t, device, migrationPassphrase)
	_, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	mk := secretOf(t, key)

	unbound := *metadata.Digests["0"]
	unbound.Segments = nil

	t.Run("bound", func(t *testing.T) {
		if id, err := digestAttestingKey(metadata, mk); err != nil || id != "0" {
			t.Fatalf("got %q, %v; want digest 0", id, err)
		}
	})
	t.Run("only an unbound digest matches", func(t *testing.T) {
		m := *metadata
		m.Digests = map[string]*Digest{"0": &unbound}
		if id, err := digestAttestingKey(&m, mk); err != nil || id != "0" {
			t.Fatalf("got %q, %v; want the unbound digest 0", id, err)
		}
	})
	t.Run("a bound digest is preferred to an unbound one that sorts first", func(t *testing.T) {
		m := *metadata
		m.Digests = map[string]*Digest{"0": &unbound, "1": metadata.Digests["0"], "2": nil}
		if id, err := digestAttestingKey(&m, mk); err != nil || id != "1" {
			t.Fatalf("got %q, %v; want the bound digest 1", id, err)
		}
	})
	t.Run("no digest matches", func(t *testing.T) {
		other := secretOf(t, bytes.Repeat([]byte{0x42}, len(key)))
		if _, err := digestAttestingKey(metadata, other); !errors.Is(err, ErrMasterKeyVerification) {
			t.Fatalf("got %v, want ErrMasterKeyVerification", err)
		}
	})
}

// TestVerifyFIPSOpenRefusesEveryUnprovenOpen: the real-open half of the
// verification passes only when the named keyslot is approved, opens through
// approved digests to the expected key, that key is bound to every segment,
// and the unlock scan agrees.
func TestVerifyFIPSOpenRefusesEveryUnprovenOpen(t *testing.T) {
	device := newImage(t, "verify.img")
	formatWithLibrary(t, device)
	key := volumeKey(t, device, migrationPassphrase)
	want := secretOf(t, key)

	if err := verifyFIPSOpen(device, migrationPassphrase, "0", want); err != nil {
		t.Fatalf("verifyFIPSOpen on an approved volume failed: %v", err)
	}

	refused := func(t *testing.T, err error, words string) {
		t.Helper()
		if !errors.Is(err, ErrFIPSMigrationVerification) || !strings.Contains(err.Error(), words) {
			t.Fatalf("got %v, want ErrFIPSMigrationVerification saying %q", err, words)
		}
	}

	t.Run("no such keyslot", func(t *testing.T) {
		refused(t, verifyFIPSOpen(device, migrationPassphrase, "7", want), "missing")
	})
	t.Run("wrong passphrase", func(t *testing.T) {
		refused(t, verifyFIPSOpen(device, []byte("not-the-passphrase"), "0", want), "does not open")
	})
	t.Run("a different key expected", func(t *testing.T) {
		other := secretOf(t, bytes.Repeat([]byte{0x42}, len(key)))
		refused(t, verifyFIPSOpen(device, migrationPassphrase, "0", other), "other than")
	})
	t.Run("a keyslot that is not approved", func(t *testing.T) {
		argon2 := fakeArgon2KeyslotVolume(t, "verify-argon2.img")
		refused(t, verifyFIPSOpen(argon2, migrationPassphrase, "0", want), "FIPS-approved KDF")
	})
	t.Run("a key bound to no segment", func(t *testing.T) {
		unbound := newImage(t, "verify-unbound.img")
		formatWithLibrary(t, unbound)
		writeFixture(t, unbound, func(m *LUKS2Metadata) { m.Digests["0"].Segments = []string{} })
		refused(t, verifyFIPSOpen(unbound, migrationPassphrase, "0", want), "segment")
	})
}

// TestFIPSRefusalDescribesMalformedObjects: a keyslot or digest that cannot be
// judged is refused, with the reason named, never approved.
func TestFIPSRefusalDescribesMalformedObjects(t *testing.T) {
	salt := encodeBase64(bytes.Repeat([]byte{1}, 32))
	iterations := 1000
	approvedKDF := &KDF{Type: KDFTypePBKDF2, Hash: "sha256", Salt: salt, Iterations: &iterations}

	keyslots := []struct {
		name    string
		keyslot *Keyslot
		reason  string
	}{
		{"nil keyslot", nil, "no KDF object"},
		{"no KDF", &Keyslot{KeySize: 64}, "no KDF object"},
		{"salt not base64", &Keyslot{KeySize: 64, KDF: &KDF{Type: KDFTypePBKDF2, Hash: "sha256", Salt: "!!!", Iterations: &iterations}}, "salt is not base64"},
		{"sha1", &Keyslot{KeySize: 64, KDF: &KDF{Type: KDFTypePBKDF2, Hash: "sha1", Salt: salt, Iterations: &iterations}}, ""},
	}
	for _, tc := range keyslots {
		t.Run("keyslot/"+tc.name, func(t *testing.T) {
			refusal, ok := keyslotFIPSRefusal("3", tc.keyslot)
			if ok || refusal.ID != "3" || refusal.Reason != tc.reason {
				t.Fatalf("got %+v, %v; want refused with reason %q", refusal, ok, tc.reason)
			}
		})
	}
	if _, ok := keyslotFIPSRefusal("0", &Keyslot{KeySize: 64, KDF: approvedKDF}); !ok {
		t.Fatal("an approved PBKDF2-SHA256 keyslot was refused")
	}

	value := encodeBase64(bytes.Repeat([]byte{2}, 32))
	digests := []struct {
		name   string
		digest *Digest
		reason string
	}{
		{"nil digest", nil, "digest is null"},
		{"value not base64", &Digest{Type: KDFTypePBKDF2, Hash: "sha256", Salt: salt, Iterations: 1000, Digest: "!!!"}, "digest value is not base64"},
		{"output too short", &Digest{Type: KDFTypePBKDF2, Hash: "sha256", Salt: salt, Iterations: 1000, Digest: encodeBase64([]byte{1, 2, 3})}, "output shorter than 112 bits"},
		{"argon2", &Digest{Type: KDFTypeArgon2id, Salt: salt, Digest: value}, ""},
	}
	for _, tc := range digests {
		t.Run("digest/"+tc.name, func(t *testing.T) {
			refusal, ok := digestFIPSRefusal("5", tc.digest)
			if ok || refusal.ID != "5" || refusal.Reason != tc.reason {
				t.Fatalf("got %+v, %v; want refused with reason %q", refusal, ok, tc.reason)
			}
		})
	}
	if _, ok := digestFIPSRefusal("0", &Digest{Type: KDFTypePBKDF2, Hash: "sha256", Salt: salt, Iterations: 1000, Digest: value}); !ok {
		t.Fatal("an approved PBKDF2-SHA256 digest was refused")
	}

	if got := (NonApprovedKDF{Type: KDFTypePBKDF2, Hash: "sha256", Reason: "salt shorter than 128 bits"}).String(); got != "pbkdf2-sha256 (salt shorter than 128 bits)" {
		t.Fatalf("String() = %q", got)
	}
}
