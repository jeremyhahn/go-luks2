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

// TestVerifyVolumeKeyConsultsOnlyTheSegmentsDigests: an injected key is checked only against digests naming the mapped segment.
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

// TestVerifyVolumeKeyBindsTheKeyLength: a zero-extended key passes HMAC, so the length is bound to key_size.
func TestVerifyVolumeKeyBindsTheKeyLength(t *testing.T) {
	defer parallel(t)()

	device, passphrase := unlockableVolume(t)
	key := masterKeyOf(t, device, passphrase)

	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("reading the header failed: %v", err)
	}

	// The zero-extended key does pass the digest comparison.
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
