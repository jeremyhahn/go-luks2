// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"testing"
)

// Regression tests for #58: verifyMasterKey aborted on the FIRST digest whose
// derivation or base64 decode errored, instead of moving on to the next one.
//
// The mismatch path already continued, so the bug was invisible whenever every
// digest in a header was well-formed. It surfaced under GODEBUG=fips140=only,
// where DeriveKey refuses an argon2 KDF: a header carrying one argon2 digest
// and one usable digest opened or did not open depending on which one Go's
// randomized map iteration happened to visit first. The same header, the same
// passphrase, a different answer from run to run.
//
// These tests do not need FIPS mode to reproduce it. Any digest that cannot be
// derived or decoded exercises the same two return paths, and Go randomizes map
// iteration order on every range, so a suite that ran the mixed-digest cases
// enough times would have caught it -- which is why each of them is run
// repeatedly here rather than once.

// digestScanRepeats is how many times an order-dependent case is run. Go's map
// iteration order is randomized per range statement, so a single execution of a
// two-entry map hits the bad-first ordering only half the time; 64 runs makes a
// surviving order-dependence a 2^-64 event rather than a coin flip.
const digestScanRepeats = 64

// usableDigest builds a digest that the given master key verifies against.
func usableDigest(t *testing.T, masterKey []byte, length int) *Digest {
	t.Helper()

	iterations := 1000
	kdf := &KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       encodeBase64([]byte("digest-scan-salt")),
		Iterations: &iterations,
	}

	derived, err := DeriveKey(masterKey, kdf, length)
	if err != nil {
		t.Fatalf("failed to derive the usable digest: %v", err)
	}

	return &Digest{
		Type:       kdf.Type,
		Hash:       kdf.Hash,
		Salt:       kdf.Salt,
		Iterations: iterations,
		Digest:     encodeBase64(derived),
	}
}

// unusableDigests are the shapes that used to abort the whole scan. Each one
// fails at a different point: base64 decode, salt decode, KDF dispatch, and
// argon2 parameter validation -- the last standing in for the FIPS refusal,
// which cannot be toggled inside a running process.
func unusableDigests(t *testing.T) map[string]*Digest {
	t.Helper()

	iterations := 1000

	return map[string]*Digest{
		"undecodable digest value": {
			Type:       "pbkdf2",
			Hash:       "sha256",
			Salt:       encodeBase64([]byte("digest-scan-salt")),
			Iterations: iterations,
			Digest:     "this is not base64 !!!",
		},
		"undecodable salt": {
			Type:       "pbkdf2",
			Hash:       "sha256",
			Salt:       "this is not base64 !!!",
			Iterations: iterations,
			Digest:     encodeBase64(make([]byte, 32)),
		},
		"unsupported kdf type": {
			Type:       "not-a-kdf",
			Hash:       "sha256",
			Salt:       encodeBase64([]byte("digest-scan-salt")),
			Iterations: iterations,
			Digest:     encodeBase64(make([]byte, 32)),
		},
		"unsupported hash": {
			Type:       "pbkdf2",
			Hash:       "md5",
			Salt:       encodeBase64([]byte("digest-scan-salt")),
			Iterations: iterations,
			Digest:     encodeBase64(make([]byte, 32)),
		},
		"argon2 digest with no parameters": {
			// The stand-in for GODEBUG=fips140=only refusing argon2: same
			// return path out of DeriveKey, reachable without FIPS mode.
			Type:       "argon2id",
			Salt:       encodeBase64([]byte("digest-scan-salt")),
			Iterations: iterations,
			Digest:     encodeBase64(make([]byte, 32)),
		},
		"digest length agreeing with neither the hash nor the carve-out": {
			// 48 bytes is a real hash length (sha384) but not sha256's, and not
			// the 32-byte legacy carve-out.
			Type:       "pbkdf2",
			Hash:       "sha256",
			Salt:       encodeBase64([]byte("digest-scan-salt")),
			Iterations: iterations,
			Digest:     encodeBase64(make([]byte, 48)),
		},
		"digest of absurd length": {
			Type:       "pbkdf2",
			Hash:       "sha256",
			Salt:       encodeBase64([]byte("digest-scan-salt")),
			Iterations: iterations,
			Digest:     encodeBase64(make([]byte, 1<<20)),
		},
	}
}

// TestVerifyMasterKeySkipsUnusableDigests is the core regression test: one
// unusable digest must not hide a usable one, whichever order the map yields.
func TestVerifyMasterKeySkipsUnusableDigests(t *testing.T) {
	masterKey := []byte("digest-scan-master-key-32-bytes!")

	for name, bad := range unusableDigests(t) {
		t.Run(name, func(t *testing.T) {
			for i := 0; i < digestScanRepeats; i++ {
				digests := map[string]*Digest{
					"0": bad,
					"1": usableDigest(t, masterKey, 32),
				}

				if err := verifyMasterKey(enclaveFrom(t, masterKey), digests); err != nil {
					t.Fatalf("run %d: a %s hid the usable digest behind it: %v", i, name, err)
				}
			}
		})
	}
}

// TestVerifyMasterKeySkipsEveryUnusableDigestAtOnce puts all of them in front
// of the usable one, so the scan has to survive every failure mode in a single
// pass rather than one at a time.
func TestVerifyMasterKeySkipsEveryUnusableDigestAtOnce(t *testing.T) {
	masterKey := []byte("digest-scan-master-key-32-bytes!")

	for i := 0; i < digestScanRepeats; i++ {
		digests := map[string]*Digest{}
		id := 0
		for _, bad := range unusableDigests(t) {
			digests[string(rune('a'+id))] = bad
			id++
		}
		digests["z"] = usableDigest(t, masterKey, 32)

		if err := verifyMasterKey(enclaveFrom(t, masterKey), digests); err != nil {
			t.Fatalf("run %d: the usable digest was not reached past %d unusable ones: %v", i, id, err)
		}
	}
}

// TestVerifyMasterKeyFailsOnlyAfterExhaustingTheSet is the other half: skipping
// unusable digests must not turn into accepting a key that nothing verifies.
// A set with no usable digest fails, and it fails with one indistinguishable
// error whatever the cause was.
func TestVerifyMasterKeyFailsOnlyAfterExhaustingTheSet(t *testing.T) {
	masterKey := []byte("digest-scan-master-key-32-bytes!")

	t.Run("every digest unusable", func(t *testing.T) {
		digests := map[string]*Digest{}
		id := 0
		for _, bad := range unusableDigests(t) {
			digests[string(rune('a'+id))] = bad
			id++
		}

		err := verifyMasterKey(enclaveFrom(t, masterKey), digests)
		if !errors.Is(err, ErrMasterKeyVerification) {
			t.Fatalf("verifyMasterKey = %v, want ErrMasterKeyVerification", err)
		}
	})

	t.Run("a usable digest for a different key", func(t *testing.T) {
		digests := map[string]*Digest{
			"0": usableDigest(t, []byte("some-other-master-key-32-bytes!!"), 32),
		}

		err := verifyMasterKey(enclaveFrom(t, masterKey), digests)
		if !errors.Is(err, ErrMasterKeyVerification) {
			t.Fatalf("verifyMasterKey = %v, want ErrMasterKeyVerification", err)
		}
	})

	t.Run("the failure names no digest and no cause", func(t *testing.T) {
		// Deliberately asserting on the message: an error that distinguished
		// "digest 2 uses a KDF I refuse" from "digest 2 did not match" would
		// tell an attacker holding the device which keyslot to work on and how
		// the header is being interpreted.
		mismatch := verifyMasterKey(enclaveFrom(t, masterKey), map[string]*Digest{
			"0": usableDigest(t, []byte("some-other-master-key-32-bytes!!"), 32),
		})
		unusable := verifyMasterKey(enclaveFrom(t, masterKey), map[string]*Digest{
			"0": unusableDigests(t)["unsupported kdf type"],
		})

		if mismatch.Error() != unusable.Error() {
			t.Fatalf("a mismatch reports %q but an unusable digest reports %q; the two must be indistinguishable",
				mismatch, unusable)
		}
	})
}

// TestVerifyMasterKeyAcceptsAUsableDigestAloneIsNotEnough guards the control
// case that makes the tests above meaningful: the usable digest this file
// builds really does verify on its own. Without it, "the scan reached the
// usable digest" could be passing because verifyMasterKey accepts anything.
func TestVerifyMasterKeyAcceptsTheUsableDigestAlone(t *testing.T) {
	masterKey := []byte("digest-scan-master-key-32-bytes!")

	digests := map[string]*Digest{"0": usableDigest(t, masterKey, 32)}
	if err := verifyMasterKey(enclaveFrom(t, masterKey), digests); err != nil {
		t.Fatalf("the fixture's own usable digest does not verify: %v", err)
	}

	if err := verifyMasterKey(enclaveFrom(t, []byte("some-other-master-key-32-bytes!!")), digests); err == nil {
		t.Fatal("the fixture's usable digest verified a DIFFERENT master key")
	}
}
