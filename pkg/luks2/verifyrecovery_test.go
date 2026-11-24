// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// VerifyRecoveryKey must not report a key as wrong for reasons unrelated to the key; (false, nil) means only that no keyslot verified it.

func TestVerifyRecoveryKeyReportsAnUnreadableDevice(t *testing.T) {
	// A path that is not a LUKS container at all: the failure is the device,
	// and it must reach the caller as one.
	path := filepath.Join(t.TempDir(), "not-a-volume.img")
	if err := os.WriteFile(path, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatalf("failed to create the fixture: %v", err)
	}

	key := enclaveFrom(t, []byte("a recovery key that never gets tried"))

	ok, err := verifyRecoveryKeyForTest(path, key)
	if ok {
		t.Fatal("VerifyRecoveryKey reported success against a device with no LUKS header")
	}
	if err == nil {
		t.Fatal("a device with no LUKS header was reported as a wrong recovery key")
	}
}

func TestVerifyRecoveryKeyReportsAnUnusableKeyslot(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "verify-damaged.img")
	formatWithLibrary(t, path)

	hdr, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	// The only keyslot is damaged, so nothing can be tried.
	damaged := cloneKeyslot(metadata.Keyslots["0"])
	damaged.KeySize = 1 << 20
	metadata.Keyslots["0"] = damaged

	if err := writeHeaderInternal(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the damaged fixture: %v", err)
	}

	key := enclaveFrom(t, []byte(conformancePassphrase))

	ok, err := verifyRecoveryKeyForTest(path, key)
	if ok {
		t.Fatal("VerifyRecoveryKey reported success against a container whose only keyslot is unusable")
	}
	if err == nil {
		t.Fatal("a container whose only keyslot is unusable was reported as a wrong recovery key")
	}
	if !errors.Is(err, ErrKeyslotNotFound) {
		t.Fatalf("the failure does not name the unusable keyslot: %v", err)
	}
}

func TestVerifyRecoveryKeyReportsAProtectedMemoryFailure(t *testing.T) {
	path := newImage(t, "verify-memlock.img")
	formatWithLibrary(t, path)

	key := enclaveFrom(t, []byte(conformancePassphrase))

	// Fail-closed means a locked-memory failure aborts the operation. It must
	// not then be laundered into "your recovery key is wrong", which would send
	// an operator to look for a lost credential instead of at their memlock
	// ulimit.
	withFailingProtectedMemory(t)

	ok, err := verifyRecoveryKeyForTest(path, key)
	if ok {
		t.Fatal("VerifyRecoveryKey reported success while protected memory was unavailable")
	}
	if !errors.Is(err, ErrProtectedMemory) {
		t.Fatalf("a protected-memory failure was reported as something else: %v", err)
	}
}

// TestVerifyRecoveryKeyStillReportsAKeyThatDoesNotOpenTheVolume is the control.
//
// Every assertion above is satisfied by a function that returns an error for
// everything, which would make the boolean useless. A well-formed container and
// a key that simply is not one of its credentials must still be (false, nil).
func TestVerifyRecoveryKeyStillReportsAKeyThatDoesNotOpenTheVolume(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "verify-wrong.img")
	formatWithLibrary(t, path)

	wrong := enclaveFrom(t, []byte(conformanceWrongPassphrase))

	ok, err := verifyRecoveryKeyForTest(path, wrong)
	if err != nil {
		t.Fatalf("a key that merely does not open the volume produced an error: %v", err)
	}
	if ok {
		t.Fatal("VerifyRecoveryKey accepted a key that does not open the volume")
	}

	// The credential that opens it still verifies.
	right := enclaveFrom(t, []byte(conformancePassphrase))
	ok, err = verifyRecoveryKeyForTest(path, right)
	if err != nil {
		t.Fatalf("verifying a working credential failed: %v", err)
	}
	if !ok {
		t.Fatal("VerifyRecoveryKey rejected a credential that opens the volume")
	}
}

// TestGetMasterKeyDistinguishesFailureToTryFromFailureToVerify.
func TestGetMasterKeyDistinguishesFailureToTryFromFailureToVerify(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "classify.img")
	formatWithLibrary(t, path)

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	t.Run("tried and did not verify", func(t *testing.T) {
		key, err := getMasterKey(path, []byte(conformanceWrongPassphrase), metadata, testVolumeSys())
		if err == nil {
			mustDestroy(t, key)
			t.Fatal("a wrong credential opened the volume")
		}
		if !errors.Is(err, ErrWrongKey) {
			t.Fatalf("a credential that reached the digest and failed it is not reported as such: %v", err)
		}
		// It must not claim the passphrase is wrong.
	})

	t.Run("could not be tried", func(t *testing.T) {
		// Config and segments too: the scan confines keyslot areas before reading.
		damaged := &header.Metadata{
			Keyslots: map[string]*header.Keyslot{"0": cloneKeyslot(metadata.Keyslots["0"])},
			Digests:  metadata.Digests,
			Segments: metadata.Segments,
			Config:   metadata.Config,
		}
		damaged.Keyslots["0"].KDF = nil

		key, err := getMasterKey(path, []byte(conformancePassphrase), damaged, testVolumeSys())
		if err == nil {
			mustDestroy(t, key)
			t.Fatal("a keyslot with no kdf object opened the volume")
		}
		if !errors.Is(err, ErrKeyslotNotFound) {
			t.Fatalf("a keyslot that could not be tried is not reported as such: %v", err)
		}
		if errors.Is(err, ErrWrongKey) {
			t.Fatal("a keyslot that was never tried was reported as having failed verification")
		}
	})

	t.Run("a usable keyslot still opens the volume alongside an unusable one", func(t *testing.T) {
		// Keyslot 7 is registered with the digest, as AddKey does.
		digests := cloneDigests(metadata.Digests)
		for _, d := range digests {
			d.Keyslots = append(d.Keyslots, "7")
		}

		mixed := &header.Metadata{
			Keyslots: map[string]*header.Keyslot{
				"0": cloneKeyslot(metadata.Keyslots["0"]),
				"7": cloneKeyslot(metadata.Keyslots["0"]),
			},
			Digests:  digests,
			Segments: metadata.Segments,
			Config:   metadata.Config,
		}
		mixed.Keyslots["0"].KDF = nil

		key, err := getMasterKey(path, []byte(conformancePassphrase), mixed, testVolumeSys())
		if err != nil {
			t.Fatalf("an unusable keyslot ahead of a usable one denied the volume: %v", err)
		}
		mustDestroy(t, key)
	})
}

// withFailingProtectedMemory makes every protected-memory allocation fail for
// the duration of a test, so the fail-closed paths can be exercised without
// having to actually exhaust RLIMIT_MEMLOCK -- which is process-wide and would
// take the rest of the suite with it.
func withFailingProtectedMemory(t *testing.T) {
	t.Helper()

	previous := custody
	t.Cleanup(func() { custody = previous })
	refusal := &enclave.LockedMemoryError{Cause: errors.New("synthetic RLIMIT_MEMLOCK exhaustion")}
	custody = secret.Admitted(func() (enclave.Allocator, error) { return nil, refusal })
}
