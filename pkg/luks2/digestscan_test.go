// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// verifyMasterKey must move past a digest whose derivation or decode errors; each mixed case repeats because map order is random.

// digestScanRepeats is how many times an order-dependent case is run. Go's map
// iteration order is randomized per range statement, so a single execution of a
// two-entry map hits the bad-first ordering only half the time; 64 runs makes a
// surviving order-dependence a 2^-64 event rather than a coin flip.
const digestScanRepeats = 64

// boundTo declares every digest in the map as authenticating keyslot id.
func boundTo(id string, digests map[string]*header.Digest) map[string]*header.Digest {
	for _, d := range digests {
		if d != nil {
			d.Keyslots = []string{id}
		}
	}
	return digests
}

// usableDigest builds a digest the given master key verifies against, at the minimum iteration count.
func usableDigest(t *testing.T, masterKey []byte, length int) *header.Digest {
	t.Helper()

	iterations := header.MinKDFIterations
	kdf := &header.KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       encodeBase64([]byte("digest-scan-salt")),
		Iterations: &iterations,
	}

	derived, err := deriveKeyPlain(masterKey, kdf, length)
	if err != nil {
		t.Fatalf("failed to derive the usable digest: %v", err)
	}

	return &header.Digest{
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
func unusableDigests(t *testing.T) map[string]*header.Digest {
	t.Helper()

	iterations := 1000

	return map[string]*header.Digest{
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
			// Stands in for fips140=only refusing argon2: the same return path out of deriveKeyPlain.
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
	defer parallel(t)()

	masterKey := mustRandom(t, 32)

	for name, bad := range unusableDigests(t) {
		t.Run(name, func(t *testing.T) {
			defer parallel(t)()

			for i := 0; i < digestScanRepeats; i++ {
				digests := map[string]*header.Digest{
					"0": bad,
					"1": usableDigest(t, masterKey, 32),
				}

				if err := verifyMasterKey(context.Background(), enclaveFrom(t, masterKey), "0", boundTo("0", digests)); err != nil {
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
	defer parallel(t)()

	masterKey := mustRandom(t, 32)

	// Built once and re-keyed into a fresh map per repeat, so only iteration order varies.
	unusable := unusableDigests(t)
	usable := usableDigest(t, masterKey, 32)

	for i := 0; i < digestScanRepeats; i++ {
		digests := map[string]*header.Digest{}
		id := 0
		for _, bad := range unusable {
			digests[string(rune('a'+id))] = bad
			id++
		}
		digests["z"] = usable

		if err := verifyMasterKey(context.Background(), enclaveFrom(t, masterKey), "0", boundTo("0", digests)); err != nil {
			t.Fatalf("run %d: the usable digest was not reached past %d unusable ones: %v", i, id, err)
		}
	}
}

// TestVerifyMasterKeyFailsOnlyAfterExhaustingTheSet is the other half: skipping
// unusable digests must not turn into accepting a key that nothing verifies.
// A set with no usable digest fails, and it fails with one indistinguishable
// error whatever the cause was.
func TestVerifyMasterKeyFailsOnlyAfterExhaustingTheSet(t *testing.T) {
	defer parallel(t)()

	masterKey := mustRandom(t, 32)
	otherKey := mustRandom(t, 32)

	t.Run("every digest unusable is a HEADER fault, because nothing was compared", func(t *testing.T) {
		// No digest reaches a comparison, so this is a header fault, not ErrWrongKey.
		digests := map[string]*header.Digest{}
		id := 0
		for _, bad := range unusableDigests(t) {
			digests[string(rune('a'+id))] = bad
			id++
		}

		err := verifyMasterKey(context.Background(), enclaveFrom(t, masterKey), "0", boundTo("0", digests))
		if !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("verifyMasterKey = %v, want ErrInvalidHeader", err)
		}
		if errors.Is(err, ErrWrongKey) {
			t.Fatalf("a set nothing could compare was reported as a failed verification: %v", err)
		}
	})

	t.Run("one usable digest among unusable ones is still a CREDENTIAL verdict", func(t *testing.T) {
		// A comparison ran, so a wrong passphrase stays a credential failure despite an unusable digest beside it.
		for name, bad := range unusableDigests(t) {
			t.Run(name, func(t *testing.T) {
				digests := map[string]*header.Digest{
					"0": bad,
					"1": usableDigest(t, otherKey, 32),
				}

				err := verifyMasterKey(context.Background(), enclaveFrom(t, masterKey), "0", boundTo("0", digests))
				if !errors.Is(err, ErrWrongKey) {
					t.Fatalf("verifyMasterKey = %v, want ErrWrongKey", err)
				}
				if errors.Is(err, ErrInvalidHeader) {
					t.Fatalf("a set with one comparable digest was reported as a header fault: %v", err)
				}
			})
		}
	})

	t.Run("a usable digest for a different key", func(t *testing.T) {
		digests := map[string]*header.Digest{
			"0": usableDigest(t, otherKey, 32),
		}

		err := verifyMasterKey(context.Background(), enclaveFrom(t, masterKey), "0", boundTo("0", digests))
		if !errors.Is(err, ErrWrongKey) {
			t.Fatalf("verifyMasterKey = %v, want ErrWrongKey", err)
		}
	})

	t.Run("the failure names no digest and no cause", func(t *testing.T) {
		// The message must not tell a refused KDF from a mismatch; both sets reach a comparison and differ only by an unevaluable digest.
		mismatch := verifyMasterKey(context.Background(), enclaveFrom(t, masterKey), "0", boundTo("0", map[string]*header.Digest{
			"0": usableDigest(t, otherKey, 32),
		}))
		mixed := verifyMasterKey(context.Background(), enclaveFrom(t, masterKey), "0", boundTo("0", map[string]*header.Digest{
			"0": unusableDigests(t)["unsupported kdf type"],
			"1": usableDigest(t, otherKey, 32),
		}))

		if mismatch.Error() != mixed.Error() {
			t.Fatalf("a mismatch reports %q but a mismatch beside an unusable digest reports %q; the two must be indistinguishable",
				mismatch, mixed)
		}
	})
}

// TestVerifyMasterKeyAcceptsAUsableDigestAloneIsNotEnough guards the control
// case that makes the tests above meaningful: the usable digest this file
// builds really does verify on its own. Without it, "the scan reached the
// usable digest" could be passing because verifyMasterKey accepts anything.
func TestVerifyMasterKeyAcceptsTheUsableDigestAlone(t *testing.T) {
	masterKey := mustRandom(t, 32)
	otherKey := mustRandom(t, 32)

	digests := map[string]*header.Digest{"0": usableDigest(t, masterKey, 32)}
	if err := verifyMasterKey(context.Background(), enclaveFrom(t, masterKey), "0", boundTo("0", digests)); err != nil {
		t.Fatalf("the fixture's own usable digest does not verify: %v", err)
	}

	if err := verifyMasterKey(context.Background(), enclaveFrom(t, otherKey), "0", boundTo("0", digests)); err == nil {
		t.Fatal("the fixture's usable digest verified a DIFFERENT master key")
	}
}

// TestAWrongLengthDigestIsAHeaderFaultEndToEnd: a correct passphrase over a wrong-length digest is reported as a header fault.
func TestAWrongLengthDigestIsAHeaderFaultEndToEnd(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "wrong-length-digest.img")
	formatWithLibrary(t, path)

	hdr, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader on the freshly formatted container failed: %v", err)
	}
	if len(metadata.Digests) == 0 {
		t.Fatal("the formatted container carries no digest, so this fixture proves nothing")
	}
	for _, digest := range metadata.Digests {
		// 64 bytes under a sha256 label: it decodes cleanly, so this is not a
		// decode failure, and it agrees with neither the declared hash's output
		// length nor the 32-byte legacy carve-out.
		digest.Hash = "sha256"
		digest.Digest = encodeBase64(make([]byte, 64))
	}
	if err := writeHeaderInternal(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the wrong-length-digest fixture: %v", err)
	}

	err = testKeyForTest(path, []byte(conformancePassphrase))
	if err == nil {
		t.Fatal("TestKey accepted a container whose only digest cannot be compared against anything")
	}
	if !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("TestKey = %v, want an error wrapping ErrInvalidHeader", err)
	}
	if errors.Is(err, ErrWrongKey) {
		t.Fatalf("a correct passphrase over an uncomparable digest was reported as a failed verification: %v", err)
	}

	// The message must send the operator to the header. It names the keyslot
	// and the count deliberately and NOT which digest failed how -- see the
	// threat model at the branch in verifyMasterKey.
	if !strings.Contains(err.Error(), "unusable") {
		t.Fatalf("the failure does not tell an operator the header's digests are the problem: %v", err)
	}
}
