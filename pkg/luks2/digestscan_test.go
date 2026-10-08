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

// Regression tests for #58: verifyMasterKey aborted on the FIRST digest whose
// derivation or base64 decode errored, instead of moving on to the next one.
//
// The mismatch path already continued, so the bug was invisible whenever every
// digest in a header was well-formed. It surfaced under GODEBUG=fips140=only,
// where deriveKeyPlain refuses an argon2 KDF: a header carrying one argon2 digest
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

// boundTo declares every digest in the map as authenticating keyslot id.
//
// A spec-legal LUKS2 header always states that association -- "keyslots" is a
// mandatory member of a digest object -- and these fixtures used to omit it,
// which was harmless only while verifyMasterKey ignored it. It does not any
// more: a digest that names no keyslot authenticates no keyslot. Setting it
// here keeps the fixtures about what they were always about (the digest SCAN)
// instead of turning every one of them into a test of the association.
//
// The association rule itself is tested where it belongs, on its own fixtures,
// in digestbinding_test.go.
func boundTo(id string, digests map[string]*header.Digest) map[string]*header.Digest {
	for _, d := range digests {
		if d != nil {
			d.Keyslots = []string{id}
		}
	}
	return digests
}

// usableDigest builds a digest that the given master key verifies against.
//
// One iteration, the least a header may declare (header.MinKDFIterations): the subject
// here is the ORDER of the scan, which every case repeats digestScanRepeats
// times, and at the 1000 iterations this used to carry each repeat paid two
// full derivations for nothing it asserts -- these were among the slowest
// tests in the package under -race (#92).
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
			// The stand-in for GODEBUG=fips140=only refusing argon2: same
			// return path out of deriveKeyPlain, reachable without FIPS mode.
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

	masterKey := []byte("digest-scan-master-key-32-bytes!")

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

	masterKey := []byte("digest-scan-master-key-32-bytes!")

	// Built once and re-keyed into a fresh map per repeat. What the repeats
	// vary is the map's iteration order, which Go randomizes per range; the
	// digests themselves are the same every time, and rebuilding them per
	// repeat base64-encoded the 1 MiB "absurd length" digest 64 times over for
	// nothing (#92).
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

	masterKey := []byte("digest-scan-master-key-32-bytes!")

	t.Run("every digest unusable is a HEADER fault, because nothing was compared", func(t *testing.T) {
		// This subtest asserted ErrWrongKey until #41, and it was
		// DEFENDING the defect rather than guarding against one: not one of
		// these digests reaches EqualTo, so no key was ever judged, and a
		// verification verdict claims a judgement that did not happen.
		//
		// It now pins one side of the boundary drawn in verifyMasterKey. The
		// other side -- a set where at least one digest WAS compared -- is the
		// subtest below, and the two must not be collapsed: the whole reason
		// this case may be distinguished at all is that no comparison outcome
		// exists to leak.
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
		// The other side of the boundary, and the constraint #41 named
		// explicitly: a header carrying one wrong-length digest and one good
		// digest must still tell an operator with a genuinely wrong passphrase
		// that the credential failed. A comparison ran here, so the verdict is
		// a verdict -- and every unusable digest beside it must not upgrade it
		// into a header fault.
		for name, bad := range unusableDigests(t) {
			t.Run(name, func(t *testing.T) {
				digests := map[string]*header.Digest{
					"0": bad,
					"1": usableDigest(t, []byte("some-other-master-key-32-bytes!!"), 32),
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
			"0": usableDigest(t, []byte("some-other-master-key-32-bytes!!"), 32),
		}

		err := verifyMasterKey(context.Background(), enclaveFrom(t, masterKey), "0", boundTo("0", digests))
		if !errors.Is(err, ErrWrongKey) {
			t.Fatalf("verifyMasterKey = %v, want ErrWrongKey", err)
		}
	})

	t.Run("the failure names no digest and no cause", func(t *testing.T) {
		// Deliberately asserting on the message: an error that distinguished
		// "digest 2 uses a KDF I refuse" from "digest 2 did not match" would
		// tell an attacker holding the device which keyslot to work on and how
		// the header is being interpreted. That property is UNCHANGED by #41
		// and must stay unchanged.
		//
		// Both sets here reach a comparison, which is what makes them
		// comparable at all. Before #41 the second set was a lone unusable
		// digest; that set now lands on ErrInvalidHeader, and pairing it
		// against a mismatch would have turned this test into an assertion
		// about the new boundary instead of about the indistinguishability it
		// exists to pin. It carries a usable digest beside the unusable one so
		// that the ONLY difference between the two sets is the presence of a
		// digest that could not be evaluated.
		mismatch := verifyMasterKey(context.Background(), enclaveFrom(t, masterKey), "0", boundTo("0", map[string]*header.Digest{
			"0": usableDigest(t, []byte("some-other-master-key-32-bytes!!"), 32),
		}))
		mixed := verifyMasterKey(context.Background(), enclaveFrom(t, masterKey), "0", boundTo("0", map[string]*header.Digest{
			"0": unusableDigests(t)["unsupported kdf type"],
			"1": usableDigest(t, []byte("some-other-master-key-32-bytes!!"), 32),
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
	masterKey := []byte("digest-scan-master-key-32-bytes!")

	digests := map[string]*header.Digest{"0": usableDigest(t, masterKey, 32)}
	if err := verifyMasterKey(context.Background(), enclaveFrom(t, masterKey), "0", boundTo("0", digests)); err != nil {
		t.Fatalf("the fixture's own usable digest does not verify: %v", err)
	}

	if err := verifyMasterKey(context.Background(), enclaveFrom(t, []byte("some-other-master-key-32-bytes!!")), "0", boundTo("0", digests)); err == nil {
		t.Fatal("the fixture's usable digest verified a DIFFERENT master key")
	}
}

// TestAWrongLengthDigestIsAHeaderFaultEndToEnd is #41's own acceptance case,
// driven through the exported API on a real container rather than through
// verifyMasterKey directly.
//
// The passphrase is CORRECT. That is the whole point: the operator this defect
// misdirects is the one holding a good credential over a damaged header, and
// before the boundary was drawn they were told their master key failed
// verification -- a judgement that never happened, because the only digest
// attesting the keyslot decodes to a length nothing can compare against.
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
