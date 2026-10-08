// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"errors"
	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/header"
	"testing"
)

// TestVerifyVolumeKeyConsultsOnlyTheSegmentsDigests pins which attestation
// an injected key is checked against. There is no keyslot on this path, so
// the digest that matters is the one naming the SEGMENT being mapped --
// what cryptsetup checks when it activates a volume by volume key. A
// header whose digests attest some other segment offers no attestation
// for this one at all, and that is a header fault rather than a credential
// verdict. UnlockWithVolumeKey (both the free function pkg/dmcrypt now
// activates through and (*Volume).UnlockWithVolumeKey) shares this check.
func TestVerifyVolumeKeyConsultsOnlyTheSegmentsDigests(t *testing.T) {
	defer parallel(t)()

	device, passphrase := unlockableVolume(t)
	volumeKey := volumeKeyEnclave(t, masterKeyOf(t, device, passphrase))

	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("reading the header failed: %v", err)
	}

	if err := verifyVolumeKeyForSegment(context.Background(), volumeKey, "0", metadata); err != nil {
		t.Fatalf("the volume key did not verify against segment 0's digest: %v", err)
	}

	for _, digest := range metadata.Digests {
		digest.Segments = []string{"1"}
	}
	err = verifyVolumeKeyForSegment(context.Background(), volumeKey, "0", metadata)
	if !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("a segment no digest attests was not reported as a header fault: %v", err)
	}
}

// TestVerifyVolumeKeyBindsTheKeyLength is the regression test for the hole
// the digest leaves open. HMAC zero-pads a short key, so the volume key
// with a zero byte appended produces the SAME digest -- and without a
// length check it would be accepted and handed to dm-crypt as a key of the
// wrong size. The length is bound to the keyslots' key_size, and a header
// that records none is refused.
func TestVerifyVolumeKeyBindsTheKeyLength(t *testing.T) {
	defer parallel(t)()

	device, passphrase := unlockableVolume(t)
	key := masterKeyOf(t, device, passphrase)

	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("reading the header failed: %v", err)
	}

	// The premise, checked rather than assumed: the zero-extended key DOES
	// pass the digest comparison on its own, so the length check is the
	// only thing refusing it.
	padded := volumeKeyEnclave(t, append(bytes.Clone(key), 0))
	if err := verifyKeyAgainstDigests(context.Background(), padded, metadata.Digests,
		func(*header.Digest) bool { return true },
		func(int) error { return ErrInvalidHeader }, fips.Probe); err != nil {
		t.Fatalf("the premise does not hold -- the zero-extended key failed the digest itself: %v", err)
	}

	if err := verifyVolumeKeyForSegment(context.Background(), padded, "0", metadata); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("a zero-extended volume key was not refused: %v", err)
	}

	for _, digest := range metadata.Digests {
		digest.Keyslots = nil
	}
	exact := volumeKeyEnclave(t, key)
	if err := verifyVolumeKeyForSegment(context.Background(), exact, "0", metadata); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("a header recording no volume key size was not refused as a header fault: %v", err)
	}
}

// TestUnlockErrorMessageShapes pins how UnlockError renders with and
// without an underlying cause, and that the cause stays reachable through
// errors.Is.
func TestUnlockErrorMessageShapes(t *testing.T) {
	withCause := &Error{Kind: ErrInvalidHeader, Detail: "invalid segment size: x"}
	if !errors.Is(withCause, ErrInvalidHeader) {
		t.Fatalf("the cause is not reachable through errors.Is: %v", withCause)
	}
	if got, want := withCause.Error(), ErrInvalidHeader.Error()+": invalid segment size: x"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}

	noCause := &Error{Kind: ErrKeyslotNotFound, Detail: "decrypt keyslot 0: decrypted data too small: got 1, need 2"}
	if got, want := noCause.Error(), ErrKeyslotNotFound.Error()+": decrypt keyslot 0: decrypted data too small: got 1, need 2"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if noCause.Err != nil {
		t.Fatal("an Error with no cause carries one")
	}
}
