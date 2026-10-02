// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// UnlockWithVolumeKey is the unlock/attach half of #79: a volume key the
// caller already holds -- unsealed by hardware in a higher layer, which this
// package neither knows nor cares about -- opens the volume WITHOUT a
// passphrase and therefore without the keyslot KDF.
//
// These tests drive the REAL unlock path down to the device-mapper call, with
// the same dm and keyring fakes the passphrase path's tests use, so what they
// pin is the behavior of the shipped code rather than a stub of it.

// volumeKeyEnclave returns the volume key of a freshly formatted container,
// held in protected memory the way a caller's key provider would hand it over.
func volumeKeyEnclave(t *testing.T, key []byte) *enclave.MemoryEnclave {
	t.Helper()

	e, err := enclave.NewMemoryEnclaveCopy(key)
	if err != nil {
		t.Fatalf("placing the volume key in an enclave failed: %v", err)
	}
	destroyOnCleanup(t, e)
	return e
}

// forbidPassphraseKDF replaces the keyslot KDF with one that fails the test,
// and returns a counter of how often it was reached.
func forbidPassphraseKDF(t *testing.T) *int {
	t.Helper()

	calls := 0
	previous := passphraseKDF
	t.Cleanup(func() { passphraseKDF = previous })
	passphraseKDF = func(passphrase []byte, kdf *KDF, keySize int) (*enclave.MemoryEnclave, error) {
		calls++
		t.Errorf("the passphrase KDF was called (%s, %d bytes) on a path that holds the volume key already", kdf.Type, keySize)
		return nil, errors.New("passphrase KDF forbidden in this test")
	}
	return &calls
}

// TestUnlockWithVolumeKeyNeverCallsThePassphraseKDF is the owner-required
// verification: the injected-key unlock opens the volume, and the keyslot KDF
// -- the derivation that exists only because a credential started as a human
// secret -- is never on the path.
func TestUnlockWithVolumeKeyNeverCallsThePassphraseKDF(t *testing.T) {
	device, passphrase := unlockableVolume(t)
	key := masterKeyOf(t, device, passphrase)
	volumeKey := volumeKeyEnclave(t, key)

	fake := newFakeDeviceMapper()
	fake.install(t)
	calls := forbidPassphraseKDF(t)

	if err := UnlockWithVolumeKey(device, volumeKey, "injected"); err != nil {
		t.Fatalf("UnlockWithVolumeKey failed: %v", err)
	}
	if *calls != 0 {
		t.Fatalf("the passphrase KDF was called %d time(s)", *calls)
	}

	// The mapping was made, by keyring reference, for a key of the right size.
	table := fake.cryptTable(t)
	if len(table.Key) != 0 {
		t.Fatal("the injected volume key was placed in the device-mapper table")
	}
	if !strings.HasPrefix(table.KeyID, ":"+strconv.Itoa(len(key))+":logon:") {
		t.Fatalf("the keyring reference %q does not describe a %d-byte logon key", table.KeyID, len(key))
	}
	if _, live := fake.targets["injected"]; !live {
		t.Fatal("no target was created for the injected-key unlock")
	}

	// The enclave is the CALLER's. This package borrows it and must not
	// destroy it: the caller may unlock again, or hand it to another layer.
	if !volumeKey.IsAlive() {
		t.Fatal("UnlockWithVolumeKey destroyed an enclave it does not own")
	}
}

// TestThePassphraseUnlockReachesThePassphraseKDF is the control that keeps the
// test above from being a gate that cannot fail: the seam it forbids is the one
// the passphrase path really goes through.
func TestThePassphraseUnlockReachesThePassphraseKDF(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	fake := newFakeDeviceMapper()
	fake.install(t)

	calls := 0
	previous := passphraseKDF
	t.Cleanup(func() { passphraseKDF = previous })
	passphraseKDF = func(p []byte, kdf *KDF, keySize int) (*enclave.MemoryEnclave, error) {
		calls++
		return previous(p, kdf, keySize)
	}

	if err := Unlock(device, passphrase, "by-passphrase"); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	if calls == 0 {
		t.Fatal("the passphrase unlock never reached passphraseKDF, so forbidding it proves nothing")
	}
}

// TestUnlockWithVolumeKeyRefusesAKeyTheHeaderDoesNotAttest pins that the
// digest check is NOT bypassed. A wrong key would otherwise map garbage as the
// plaintext device, and the first mkfs a caller ran on it would destroy the
// volume.
func TestUnlockWithVolumeKeyRefusesAKeyTheHeaderDoesNotAttest(t *testing.T) {
	device, passphrase := unlockableVolume(t)
	key := masterKeyOf(t, device, passphrase)

	for name, wrong := range map[string][]byte{
		"one bit flipped": func() []byte { k := bytes.Clone(key); k[0] ^= 1; return k }(),
		"truncated":       key[:len(key)/2],
		"extended":        append(bytes.Clone(key), 0),
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeDeviceMapper()
			fake.install(t)
			forbidPassphraseKDF(t)

			err := UnlockWithVolumeKey(device, volumeKeyEnclave(t, wrong), "wrong-key")
			if !errors.Is(err, ErrMasterKeyVerification) {
				t.Fatalf("a key the header does not attest was not refused as ErrMasterKeyVerification: %v", err)
			}
			if len(fake.loaded) != 0 || len(fake.created) != 0 {
				t.Fatal("device-mapper was reached with a key that did not verify")
			}
		})
	}
}

// TestUnlockWithVolumeKeyRefusesAnUnusableEnclave covers the argument itself.
// Each is a caller error, reported as one, before the device is touched.
func TestUnlockWithVolumeKeyRefusesAnUnusableEnclave(t *testing.T) {
	device, _ := unlockableVolume(t)

	destroyed, err := enclave.NewMemoryEnclaveCopy(bytes.Repeat([]byte{7}, 64))
	if err != nil {
		t.Fatalf("creating an enclave failed: %v", err)
	}
	mustDestroy(t, destroyed)

	oversized := volumeKeyEnclave(t, make([]byte, MaxKeyslotKeySize+1))

	for name, key := range map[string]*enclave.MemoryEnclave{
		"nil":       nil,
		"destroyed": destroyed,
		"oversized": oversized,
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeDeviceMapper()
			fake.install(t)

			err := UnlockWithVolumeKey(device, key, "unusable")
			if !errors.Is(err, ErrInvalidVolumeKey) {
				t.Fatalf("the refusal is not matchable as ErrInvalidVolumeKey: %v", err)
			}
			var typed *UnlockError
			if !errors.As(err, &typed) {
				t.Fatalf("the refusal is not a typed *UnlockError: %T %v", err, err)
			}
			if len(fake.loaded) != 0 {
				t.Fatal("device-mapper was reached with an unusable volume key")
			}
		})
	}
}

// TestUnlockWithVolumeKeyKeepsTheHeaderAndNameValidation pins that the new
// entry point runs the same gates as the passphrase one: it replaces the
// source of the key, not the checks around it.
func TestUnlockWithVolumeKeyKeepsTheHeaderAndNameValidation(t *testing.T) {
	device, passphrase := unlockableVolume(t)
	volumeKey := volumeKeyEnclave(t, masterKeyOf(t, device, passphrase))

	t.Run("mapping name", func(t *testing.T) {
		fake := newFakeDeviceMapper()
		fake.install(t)

		err := UnlockWithVolumeKey(device, volumeKey, "../escape")
		if !errors.Is(err, ErrInvalidMappingName) {
			t.Fatalf("a hostile mapping name was not refused: %v", err)
		}
		if len(fake.loaded) != 0 {
			t.Fatal("device-mapper was reached with a refused name")
		}
	})

	t.Run("name already in use", func(t *testing.T) {
		fake := newFakeDeviceMapper()
		fake.install(t)
		fake.targets["taken"] = "CRYPT-LUKS2-other-taken"

		err := UnlockWithVolumeKey(device, volumeKey, "taken")
		if !errors.Is(err, ErrVolumeAlreadyUnlocked) {
			t.Fatalf("an in-use mapping name was not refused: %v", err)
		}
		var typed *UnlockError
		if !errors.As(err, &typed) {
			t.Fatalf("the in-use refusal is not a typed *UnlockError: %T %v", err, err)
		}
		if !strings.Contains(err.Error(), "luks close taken") {
			t.Fatalf("the in-use refusal lost its remedy: %v", err)
		}
	})

	t.Run("not a LUKS2 header", func(t *testing.T) {
		fake := newFakeDeviceMapper()
		fake.install(t)

		blank := filepath.Join(t.TempDir(), "blank.img")
		if err := os.WriteFile(blank, make([]byte, 16<<20), 0o600); err != nil {
			t.Fatalf("writing a blank image failed: %v", err)
		}

		if err := UnlockWithVolumeKey(blank, volumeKey, "blank"); err == nil {
			t.Fatal("a device with no LUKS2 header was unlocked")
		}
		if len(fake.loaded) != 0 {
			t.Fatal("device-mapper was reached for a device with no LUKS2 header")
		}
	})
}

// TestVerifyVolumeKeyConsultsOnlyTheSegmentsDigests pins which attestation the
// injected key is checked against. There is no keyslot on this path, so the
// digest that matters is the one naming the SEGMENT being mapped -- what
// cryptsetup checks for an activation by volume key. A header whose digests
// attest some other segment offers no attestation for this one at all, and
// that is a header fault rather than a credential verdict.
func TestVerifyVolumeKeyConsultsOnlyTheSegmentsDigests(t *testing.T) {
	device, passphrase := unlockableVolume(t)
	volumeKey := volumeKeyEnclave(t, masterKeyOf(t, device, passphrase))

	_, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("reading the header failed: %v", err)
	}

	if err := verifyVolumeKeyForSegment(volumeKey, "0", metadata); err != nil {
		t.Fatalf("the volume key did not verify against segment 0's digest: %v", err)
	}

	for _, digest := range metadata.Digests {
		digest.Segments = []string{"1"}
	}
	err = verifyVolumeKeyForSegment(volumeKey, "0", metadata)
	if !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("a segment no digest attests was not reported as a header fault: %v", err)
	}
}

// TestVerifyVolumeKeyBindsTheKeyLength is the regression test for the hole the
// digest leaves open. HMAC zero-pads a short key, so the volume key with a zero
// byte appended produces the SAME digest -- and without a length check it would
// be accepted and handed to dm-crypt as a key of the wrong size. The length is
// bound to the keyslots' key_size, and a header that records none is refused.
func TestVerifyVolumeKeyBindsTheKeyLength(t *testing.T) {
	device, passphrase := unlockableVolume(t)
	key := masterKeyOf(t, device, passphrase)

	_, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("reading the header failed: %v", err)
	}

	// The premise, checked rather than assumed: the zero-extended key DOES
	// pass the digest comparison on its own, so the length check is the only
	// thing refusing it.
	padded := volumeKeyEnclave(t, append(bytes.Clone(key), 0))
	if err := verifyKeyAgainstDigests(padded, metadata.Digests,
		func(*Digest) bool { return true },
		func(int) error { return ErrInvalidHeader }); err != nil {
		t.Fatalf("the premise does not hold -- the zero-extended key failed the digest itself: %v", err)
	}

	if err := verifyVolumeKeyForSegment(padded, "0", metadata); !errors.Is(err, ErrMasterKeyVerification) {
		t.Fatalf("a zero-extended volume key was not refused: %v", err)
	}

	for _, digest := range metadata.Digests {
		digest.Keyslots = nil
	}
	exact := volumeKeyEnclave(t, key)
	if err := verifyVolumeKeyForSegment(exact, "0", metadata); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("a header recording no volume key size was not refused as a header fault: %v", err)
	}
}

// TestUnlockErrorMessageShapes pins how UnlockError renders with and without
// an underlying cause, and that the cause stays reachable through errors.Is.
func TestUnlockErrorMessageShapes(t *testing.T) {
	withCause := &UnlockError{Op: "invalid segment size", Err: ErrInvalidHeader, Detail: "x"}
	if !errors.Is(withCause, ErrInvalidHeader) {
		t.Fatalf("the cause is not reachable through errors.Is: %v", withCause)
	}
	if got, want := withCause.Error(), "invalid segment size: "+ErrInvalidHeader.Error()+": x"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}

	noCause := &UnlockError{Op: "decrypt keyslot 0", Detail: "decrypted data too small: got 1, need 2"}
	if got, want := noCause.Error(), "decrypt keyslot 0: decrypted data too small: got 1, need 2"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if errors.Unwrap(noCause) != nil {
		t.Fatal("an UnlockError with no cause unwrapped to something")
	}
}
