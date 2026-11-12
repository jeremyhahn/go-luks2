// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// These three tests pin how a KDF observes cancellation: a derivation in flight when ctx is canceled is not interruptible
// and is not abandoned either -- it runs to completion, its output is
// destroyed, and the call reports ctx.Err()'s kind. internal/kdf.Deriver
// already proves this at the primitive (see internal/kdf/kdf_test.go); these
// prove the pkg/luks2 entry points -- deriveKeyEnclave, deriveKeySecret, and
// the passphraseKDF seam a real unlock reaches through -- carry the caller's
// ctx there rather than silently deriving against context.Background().
//
// A PBKDF2 iteration count well past each hash's floor, raced against a
// 1ms timeout, is the same technique internal/kdf's own
// TestDerivePlainCancelledDuringDerivationDestroysOutput uses: the timeout
// fires while the derivation is still running, not before it starts, so
// what is exercised is mid-flight cancellation, not an already-canceled ctx
// (covered elsewhere, e.g. TestVolumeFormatRefusesAnAlreadyCanceledContext).

func TestDerivedEnclaveCancelledDuringDerivationDestroysOutput(t *testing.T) {
	iterations := 100_000
	kdf := &header.KDF{Type: kdfTypePBKDF2, Hash: "sha256", Salt: encodeBase64([]byte("cancellation-salt")), Iterations: &iterations}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()

	key, err := deriveKeyEnclave(ctx, []byte("a passphrase"), kdf, 32, defaultVolumeSys())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deriveKeyEnclave canceled mid-derivation = %v, want context.DeadlineExceeded", err)
	}
	if key != nil {
		t.Fatal("deriveKeyEnclave canceled mid-derivation returned a live enclave instead of destroying it")
	}
}

func TestDeriveKeySecretCancelledDuringDerivationDestroysOutput(t *testing.T) {
	iterations := 100_000
	kdf := &header.KDF{Type: kdfTypePBKDF2, Hash: "sha256", Salt: encodeBase64([]byte("cancellation-salt")), Iterations: &iterations}
	material := secretOf(t, []byte("the master key, 32 bytes long!!"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()

	derived, err := deriveKeySecret(ctx, material, kdf, 32, testVolumeSys())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deriveKeySecret canceled mid-derivation = %v, want context.DeadlineExceeded", err)
	}
	if derived != nil {
		t.Fatal("deriveKeySecret canceled mid-derivation returned a live enclave instead of destroying it")
	}
}

// TestUnlockKeyslotCancelledDuringThePassphraseKDFDestroysTheOutput is the
// wiring proof: a real keyslot, unlocked through the production
// sys.passphraseKDF seam (not a direct deriveKeyEnclave call), still
// observes the caller's ctx rather than one of its own. The keyslot's own
// PBKDF2 cost is set high enough that the 1ms timeout below fires while
// unlockKeyslot is still inside the derivation it reaches through
// sys.passphraseKDF -- the same substituted-deriver spirit the lane brief
// asks for, proven here with the real deriver instead of a fake one so the
// seam itself, not a stand-in for it, is what gets exercised.
func TestUnlockKeyslotCancelledDuringThePassphraseKDFDestroysTheOutput(t *testing.T) {
	path := newImage(t, "kdfcancel.img")
	passphrase := []byte(conformancePassphrase)
	iterations := 300_000 // above the SHA-512 floor (210000) standardFormatOptions' hash requires

	opts := standardFormatOptions(path)
	opts.Passphrase = passphrase
	opts.PBKDFIterations = iterations
	if err := formatForTest(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	keyslot := metadata.Keyslots["0"]

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	key, err := unlockKeyslot(ctx, path, "0", passphrase, keyslot, metadata.Digests, testVolumeSys())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unlockKeyslot canceled mid-derivation = %v, want context.DeadlineExceeded", err)
	}
	if key != nil {
		t.Fatal("unlockKeyslot canceled mid-derivation returned a live enclave instead of destroying it")
	}
}

// TestVerifyKeyAgainstDigestsObservesCancellationBetweenDigests pins the
// keyslots architecture's third cancellation point: each digest check
// derives a key, so a canceled ctx stops the digest loop before the next
// derivation and is returned as ctx.Err(), not as a credential verdict. The
// context is canceled during the first of several digest evaluations, so a
// single check on entry would not catch it and the remaining digests would
// run. The control is the same key and header under a live ctx, which
// verifies.
func TestVerifyKeyAgainstDigestsObservesCancellationBetweenDigests(t *testing.T) {
	device, passphrase := unlockableVolume(t)
	key := volumeKeyEnclave(t, masterKeyOf(t, device, passphrase))

	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("reading the header failed: %v", err)
	}
	covers := func(*header.Digest) bool { return true }
	unverifiable := func(int) error { return ErrInvalidHeader }

	if err := verifyKeyAgainstDigests(context.Background(), key, metadata.Digests, covers, unverifiable, fips.Probe); err != nil {
		t.Fatalf("the premise does not hold -- the volume key failed its own digest: %v", err)
	}

	// Several applicable digests, none of which the key matches, so every one
	// would be evaluated if nothing stopped the loop. Each is the volume's own
	// digest with its stored value altered.
	var original *header.Digest
	for _, d := range metadata.Digests {
		original = d
	}
	stored, err := base64.StdEncoding.DecodeString(original.Digest)
	if err != nil || len(stored) == 0 {
		t.Fatalf("the volume's digest value does not decode: %v", err)
	}
	const digestCount = 4
	digests := make(map[string]*header.Digest, digestCount)
	for i := range digestCount {
		altered := slices.Clone(stored)
		altered[0] ^= byte(i + 1)
		d := *original
		d.Digest = base64.StdEncoding.EncodeToString(altered)
		digests[strconv.Itoa(i)] = &d
	}

	// fipsMode is consulted while a digest is evaluated and never before the
	// loop, so its calls count evaluation work. The calibration counts what
	// one digest costs.
	perDigest := 0
	single := map[string]*header.Digest{"0": digests["0"]}
	counting := func() fips.Mode { perDigest++; return fips.Probe() }
	if err := verifyKeyAgainstDigests(context.Background(), key, single, covers, unverifiable, counting); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("the premise does not hold -- an altered digest = %v, want ErrWrongKey", err)
	}
	if perDigest == 0 {
		t.Fatal("the premise does not hold -- evaluating a digest never consulted fipsMode")
	}

	// The context is canceled from inside the first evaluation: a check made
	// once on entry has already passed by then, and only a check before each
	// digest stops the next one from running.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	canceling := func() fips.Mode {
		calls++
		cancel()
		return fips.Probe()
	}
	err = verifyKeyAgainstDigests(ctx, key, digests, covers, unverifiable, canceling)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("verifyKeyAgainstDigests canceled during the first digest = %v, want context.Canceled", err)
	}
	if errors.Is(err, ErrWrongKey) {
		t.Fatalf("a cancellation was reported as a credential verdict: %v", err)
	}
	if calls != perDigest {
		t.Fatalf("evaluation consulted fipsMode %d time(s), want %d (one digest): the digests after the cancellation ran", calls, perDigest)
	}
}
