// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"errors"
	"testing"
	"time"

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
	defer parallel(t)()
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
