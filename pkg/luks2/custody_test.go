// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// Custody tests.
//
// These do not check that the code runs -- the rest of the suite does that.
// They check WHERE key material lives: that a function hands back a handle to
// locked memory rather than a slice, that a borrow window is closed when the
// borrow returns, that material is released on the failure path as well as the
// success path, and that the locked pages actually go back to the kernel.
//
// A second group pins the rewrites that the enclave work required, against
// reference implementations of the code they replaced. Those rewrites are on
// paths that decide whether a container can be read back at all, so "it still
// round-trips through this package" is not sufficient evidence: the reference
// implementations here are what make a behavioral drift visible.

func TestDeriveKeyEnclaveAgreesWithTheUnprotectedDerivation(t *testing.T) {
	iterations := 1000
	kdf := &header.KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       encodeBase64([]byte("a-sixteen-byte!!")),
		Iterations: &iterations,
	}
	passphrase := []byte("custody-test-passphrase")

	held, err := deriveKeyEnclave(context.Background(), passphrase, kdf, 64)
	if err != nil {
		t.Fatalf("DeriveKeyEnclave failed: %v", err)
	}
	defer mustDestroy(t, held)

	plain, err := deriveKeyPlain(passphrase, kdf, 64)
	if err != nil {
		t.Fatalf("deriveKeyPlain failed: %v", err)
	}
	defer clearBytes(plain)

	// Constant-time comparison inside the enclave: the derived key is never
	// copied out to be checked.
	if ok, err := held.EqualTo(plain); err != nil || !ok {
		t.Fatal("the enclave derivation and the plain one produced different keys")
	}
	if held.Size() != 64 {
		t.Fatalf("derived key holds %d bytes, want 64", held.Size())
	}
}

// TestDeriveKeyEnclaveHandsBackAnEnclaveNotASlice asserts the custody property
// itself rather than the value: what comes back can be DESTROYED, and reading
// it afterwards fails. A []byte return has neither property -- a caller who
// forgets to wipe one gets no error, just a live copy of the key.
func TestDeriveKeyEnclaveHandsBackAnEnclaveNotASlice(t *testing.T) {
	iterations := 1000
	kdf := &header.KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       encodeBase64([]byte("a-sixteen-byte!!")),
		Iterations: &iterations,
	}

	held, err := deriveKeyEnclave(context.Background(), []byte("custody-test-passphrase"), kdf, 64)
	if err != nil {
		t.Fatalf("DeriveKeyEnclave failed: %v", err)
	}

	if !held.IsAlive() {
		t.Fatal("the derived key is not in live protected memory")
	}

	mustDestroy(t, held)

	if held.IsAlive() {
		t.Fatal("the derived key survived Destroy")
	}
	if err := held.WithBytes(func([]byte) error { return nil }); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("a destroyed derived key is still readable: %v", err)
	}
	if ok, err := held.EqualTo(make([]byte, 64)); ok || !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("a destroyed enclave compared as (%v, %v), want (false, ErrEnclaveDestroyed)", ok, err)
	}
}

func TestDeriveKeySecretKeepsTheInputInsideItsEnclave(t *testing.T) {
	iterations := 1000
	kdf := &header.KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       encodeBase64([]byte("a-sixteen-byte!!")),
		Iterations: &iterations,
	}

	secret := []byte("a master key that never leaves protected memory!")
	source := enclaveFrom(t, secret)

	derived, err := deriveKeySecret(context.Background(), source, kdf, 32, testVolumeSys())
	if err != nil {
		t.Fatalf("deriveKeySecret failed: %v", err)
	}
	defer mustDestroy(t, derived)

	// Same answer as deriving from the raw bytes, so routing through the
	// enclave changed custody and nothing else.
	want, err := deriveKeyPlain(secret, kdf, 32)
	if err != nil {
		t.Fatalf("deriveKeyPlain failed: %v", err)
	}
	defer clearBytes(want)

	if ok, err := derived.EqualTo(want); err != nil || !ok {
		t.Fatal("deriving from an enclave produced a different key")
	}

	// The source enclave is untouched: deriveKeySecret borrows, it does not
	// consume.
	if !source.IsAlive() {
		t.Fatal("deriveKeySecret destroyed the enclave it was given")
	}
}

func TestDeriveKeySecretRefusesADestroyedInput(t *testing.T) {
	iterations := 1000
	kdf := &header.KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       encodeBase64([]byte("a-sixteen-byte!!")),
		Iterations: &iterations,
	}

	source, err := custody.Random("master key", 64, testVolumeSys().cryptoRand)
	if err != nil {
		t.Fatalf("custody.Random failed: %v", err)
	}
	mustDestroy(t, source)

	derived, err := deriveKeySecret(context.Background(), source, kdf, 32, testVolumeSys())
	if err == nil {
		mustDestroy(t, derived)
		t.Fatal("deriveKeySecret derived from a destroyed enclave")
	}
	if !errors.Is(err, ErrProtectedMemory) {
		t.Fatalf("error does not match ErrProtectedMemory: %v", err)
	}
}

// TestUnlockKeyslotHoldsTheMasterKeyInProtectedMemory is the end-to-end custody
// assertion: a real container, opened through the real path, must hand back a
// live enclave and nothing else.
func TestUnlockKeyslotHoldsTheMasterKeyInProtectedMemory(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "custody.img")
	formatWithLibrary(t, path)

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	masterKey, err := getMasterKey(path, []byte(conformancePassphrase), metadata, testVolumeSys())
	if err != nil {
		t.Fatalf("getMasterKey failed: %v", err)
	}

	if !masterKey.IsAlive() {
		t.Fatal("the master key is not in live protected memory")
	}
	if masterKey.Size() != 64 {
		t.Fatalf("master key holds %d bytes, want 64", masterKey.Size())
	}
	// String must not spill the key if the handle is ever logged.
	if s := masterKey.String(); s != "MemoryEnclave(redacted)" {
		t.Fatalf("the master key handle renders as %q", s)
	}

	mustDestroy(t, masterKey)

	if err := masterKey.WithBytes(func([]byte) error { return nil }); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("the master key is still readable after Destroy: %v", err)
	}
}

// TestFailedUnlocksReleaseEveryLockedRegion is the failure-path half.
//
// A wrong passphrase runs the whole of unlockKeyslot -- derivation, a 256 KiB
// locked decryption buffer, an AF merge into another locked region -- and then
// throws all of it away. Nothing returns a handle to the caller on that path,
// so a missed Destroy is invisible except as locked memory that never comes
// back. Sixteen attempts against a real container would strand several
// megabytes if any of them leaked.
func TestFailedUnlocksReleaseEveryLockedRegion(t *testing.T) {
	path := newImage(t, "custody-failure.img")
	formatWithLibrary(t, path)

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	// One warm-up attempt first: the first pass through these paths allocates
	// package-level state that would otherwise be counted as a leak.
	if _, err := getMasterKey(path, []byte(conformanceWrongPassphrase), metadata, testVolumeSys()); err == nil {
		t.Fatal("a wrong passphrase opened the volume")
	}

	before := lockedKiB(t)

	// Four rounds, not sixteen. The signal is the SIZE of a leaked region, not
	// the count: each failed unlock locks a 256 KiB stripe buffer and the
	// tolerance below is one page, so a single leak is sixty-four times the
	// threshold and one round would show it. Sixteen rounds cost 86 seconds on
	// a CI runner and bought nothing the fourth did not.
	const attempts = 4
	for i := 0; i < attempts; i++ {
		key, err := getMasterKey(path, []byte(conformanceWrongPassphrase), metadata, testVolumeSys())
		if err == nil {
			mustDestroy(t, key)
			t.Fatal("a wrong passphrase opened the volume")
		}
	}

	if after := lockedKiB(t); after > before+lockedSlackKiB {
		t.Fatalf("locked memory grew from %d KiB to %d KiB across %d failed unlocks", before, after, attempts)
	}
}

// TestSuccessfulUnlocksReleaseEveryLockedRegion is the same assertion for the
// path that succeeds: the intermediate stripes and derived keys must be gone
// once the caller destroys the one handle it was given.
func TestSuccessfulUnlocksReleaseEveryLockedRegion(t *testing.T) {
	path := newImage(t, "custody-success.img")
	formatWithLibrary(t, path)

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	key, err := getMasterKey(path, []byte(conformancePassphrase), metadata, testVolumeSys())
	if err != nil {
		t.Fatalf("getMasterKey failed: %v", err)
	}
	mustDestroy(t, key)

	before := lockedKiB(t)

	// Three rounds, for the reason given in the failed-unlock test above.
	const attempts = 3
	for i := 0; i < attempts; i++ {
		key, err := getMasterKey(path, []byte(conformancePassphrase), metadata, testVolumeSys())
		if err != nil {
			t.Fatalf("getMasterKey failed: %v", err)
		}
		mustDestroy(t, key)
	}

	if after := lockedKiB(t); after > before+lockedSlackKiB {
		t.Fatalf("locked memory grew from %d KiB to %d KiB across %d unlocks", before, after, attempts)
	}
}

// TestUnlockKeyslotRefusesAnAbsurdKeyslotArea covers the bound that keeps a
// hostile header from asking for an unbounded locked allocation. Locked memory
// is process-wide and rlimited, so an unbounded request would not merely fail
// this unlock -- it would starve every other one in the process.
func TestUnlockKeyslotRefusesAnAbsurdKeyslotArea(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "custody-absurd-area.img")
	formatWithLibrary(t, path)

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	keyslot := metadata.Keyslots["0"]
	if keyslot == nil {
		t.Fatal("fixture precondition: keyslot 0 is missing")
	}

	for _, size := range []string{"0", "-1", formatSize(header.MaxKeyslotAreaSize + 1)} {
		t.Run(size, func(t *testing.T) {
			original := keyslot.Area.Size
			keyslot.Area.Size = size
			defer func() { keyslot.Area.Size = original }()

			key, err := unlockKeyslot(context.Background(), path, "0", []byte(conformancePassphrase), keyslot, metadata.Digests, testVolumeSys())
			if err == nil {
				mustDestroy(t, key)
				t.Fatalf("unlockKeyslot accepted a keyslot area of %s bytes", size)
			}
			// ErrInvalidKeyslot, not ErrInvalidHeader: damage to one keyslot
			// must let the scan move on to the others.
			if !errors.Is(err, ErrKeyslotNotFound) {
				t.Fatalf("error does not match ErrInvalidKeyslot: %v", err)
			}
		})
	}
}

// TestRecoveryKeyIsHeldInProtectedMemory guards the part of a recovery key that
// is easiest to leave behind: the printable form, which used to be a plain Go
// string that could never be wiped -- and which is now the credential itself.
func TestRecoveryKeyIsHeldInProtectedMemory(t *testing.T) {
	key, err := NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey failed: %v", err)
	}
	defer key.Destroy()

	var buf bytes.Buffer
	if _, err := key.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	rendered := buf.String()

	typedEnclave, err := enclave.NewMemoryEnclaveCopy([]byte(rendered))
	if err != nil {
		t.Fatalf("could not build a test enclave: %v", err)
	}
	defer func() { _ = typedEnclave.Destroy() }()

	typed, err := ParseRecoveryKey(typedEnclave)
	if err != nil {
		t.Fatalf("ParseRecoveryKey failed: %v", err)
	}
	defer mustDestroy(t, typed)

	if s := openSecret(t, typed); string(s) != rendered {
		t.Fatal("typing the displayed string back does not reproduce the credential")
	}
}

func TestRecoveryKeyRenderingRoundTripsInEveryFormat(t *testing.T) {
	for _, format := range []RecoveryKeyFormat{RecoveryHex, RecoveryBase64, RecoveryDashed} {
		t.Run(format.String(), func(t *testing.T) {
			key, err := NewRecoveryKey(WithRecoveryFormat(format))
			if err != nil {
				t.Fatalf("NewRecoveryKey failed: %v", err)
			}
			defer key.Destroy()

			var buf bytes.Buffer
			if _, err := key.WriteTo(&buf); err != nil {
				t.Fatalf("WriteTo failed: %v", err)
			}
			rendered := buf.String()

			typedEnclave, err := enclave.NewMemoryEnclaveCopy([]byte(rendered))
			if err != nil {
				t.Fatalf("could not build a test enclave: %v", err)
			}
			defer func() { _ = typedEnclave.Destroy() }()

			typed, err := ParseRecoveryKey(typedEnclave)
			if err != nil {
				t.Fatalf("ParseRecoveryKey(%q) failed: %v", rendered, err)
			}
			defer mustDestroy(t, typed)

			if s := openSecret(t, typed); string(s) != rendered {
				t.Fatalf("the %s credential does not survive being typed back", format)
			}

			// The credential is still a faithful rendering of 32 random bytes,
			// which is where its strength comes from. Nothing depends on the
			// decode any more, but if it ever stopped decoding to 32 bytes the
			// generator would be producing something other than what it claims.
			decoded, err := parseLegacyRecoveryKey(rendered)
			if err != nil {
				t.Fatalf("ParseRecoveryKey(%q) failed: %v", rendered, err)
			}
			defer mustDestroy(t, decoded)

			if decoded.Size() != 32 {
				t.Fatalf("the %s rendering decodes to %d bytes, want 32", format, decoded.Size())
			}
		})
	}
}

func mustRandom(t *testing.T, n int) []byte {
	t.Helper()

	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("failed to generate %d random bytes: %v", n, err)
	}
	return b
}
