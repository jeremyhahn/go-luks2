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
)

// VerifyRecoveryKey must not report "this key does not work" for reasons that
// have nothing to do with the key.
//
// The harm is specific and is what issue #72 was filed for: someone verifying a
// recovery key against a CORRUPTED volume is told the key is wrong, and they
// will discard a working recovery key. This function is where an operator turns
// when they are already worried about losing access, so it is the worst place
// in the package to flatten a cause.
//
// It also contradicted the fail-closed contract the enclave work introduced: a
// failure to obtain locked memory -- an operator-fixable RLIMIT_MEMLOCK
// condition -- surfaced as a bad credential.
//
// # What (false, nil) is still allowed to mean
//
// Only that no keyslot verified this key. NOT that the key is wrong. Per issue
// #68 three causes reach the digest comparison indistinguishably -- a wrong
// credential, the RIGHT credential over damaged key material, and a
// semantically wrong digest -- and naming that outcome is an open design
// question (#68) which #30 deliberately left untyped rather than guess. These
// tests fix the unambiguous half and do not guess at the rest.

func TestVerifyRecoveryKeyReportsAnUnreadableDevice(t *testing.T) {
	// A path that is not a LUKS container at all: the failure is the device,
	// and it must reach the caller as one.
	path := filepath.Join(t.TempDir(), "not-a-volume.img")
	if err := os.WriteFile(path, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatalf("failed to create the fixture: %v", err)
	}

	key := enclaveFrom(t, []byte("a recovery key that never gets tried"))

	ok, err := VerifyRecoveryKey(path, key)
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

	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	// The container's ONLY keyslot is damaged, so nothing can be tried. That is
	// not evidence about the key.
	damaged := cloneKeyslot(metadata.Keyslots["0"])
	damaged.KeySize = 1 << 20
	metadata.Keyslots["0"] = damaged

	if err := writeHeaderInternal(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the damaged fixture: %v", err)
	}

	key := enclaveFrom(t, []byte(conformancePassphrase))

	ok, err := VerifyRecoveryKey(path, key)
	if ok {
		t.Fatal("VerifyRecoveryKey reported success against a container whose only keyslot is unusable")
	}
	if err == nil {
		t.Fatal("a container whose only keyslot is unusable was reported as a wrong recovery key")
	}
	if !errors.Is(err, ErrInvalidKeyslot) {
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

	ok, err := VerifyRecoveryKey(path, key)
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

	ok, err := VerifyRecoveryKey(path, wrong)
	if err != nil {
		t.Fatalf("a key that merely does not open the volume produced an error: %v", err)
	}
	if ok {
		t.Fatal("VerifyRecoveryKey accepted a key that does not open the volume")
	}

	// And the credential that DOES open it still verifies, or the above would
	// pass against a function that always says no.
	right := enclaveFrom(t, []byte(conformancePassphrase))
	ok, err = VerifyRecoveryKey(path, right)
	if err != nil {
		t.Fatalf("verifying a working credential failed: %v", err)
	}
	if !ok {
		t.Fatal("VerifyRecoveryKey rejected a credential that opens the volume")
	}
}

// TestGetMasterKeyDistinguishesFailureToTryFromFailureToVerify pins the
// classification one level down, where VerifyRecoveryKey gets it from.
//
// A keyslot that could not be TRIED and a keyslot that was tried and did not
// verify are different facts about a volume, and collapsing them is what made
// every caller above wrong.
func TestGetMasterKeyDistinguishesFailureToTryFromFailureToVerify(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "classify.img")
	formatWithLibrary(t, path)

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	t.Run("tried and did not verify", func(t *testing.T) {
		key, err := getMasterKey(path, []byte(conformanceWrongPassphrase), metadata)
		if err == nil {
			mustDestroy(t, key)
			t.Fatal("a wrong credential opened the volume")
		}
		if !errors.Is(err, ErrMasterKeyVerification) {
			t.Fatalf("a credential that reached the digest and failed it is not reported as such: %v", err)
		}
		// It must NOT claim the passphrase is wrong. Per #68 a digest mismatch
		// cannot honestly say that: the same comparison fails for the correct
		// credential over damaged key material. The explicit assertion is gone
		// with ErrInvalidPassphrase itself (#70) -- the claim is no longer
		// expressible, which is a stronger guarantee than a test for it.
	})

	t.Run("could not be tried", func(t *testing.T) {
		damaged := &LUKS2Metadata{
			Keyslots: map[string]*Keyslot{"0": cloneKeyslot(metadata.Keyslots["0"])},
			Digests:  metadata.Digests,
		}
		damaged.Keyslots["0"].KDF = nil

		key, err := getMasterKey(path, []byte(conformancePassphrase), damaged)
		if err == nil {
			mustDestroy(t, key)
			t.Fatal("a keyslot with no kdf object opened the volume")
		}
		if !errors.Is(err, ErrInvalidKeyslot) {
			t.Fatalf("a keyslot that could not be tried is not reported as such: %v", err)
		}
		if errors.Is(err, ErrMasterKeyVerification) {
			t.Fatal("a keyslot that was never tried was reported as having failed verification")
		}
	})

	t.Run("a usable keyslot still opens the volume alongside an unusable one", func(t *testing.T) {
		// The invented keyslot 7 is REGISTERED with the digest, exactly as
		// AddKey does when it writes a real one. verifyMasterKey consults only
		// the digests that name the keyslot being opened, so a slot the header
		// never associated with a digest authenticates nothing -- and this
		// fixture would then be measuring that omission rather than the
		// scan-past-a-damaged-slot property it exists for.
		digests := cloneDigests(metadata.Digests)
		for _, d := range digests {
			d.Keyslots = append(d.Keyslots, "7")
		}

		mixed := &LUKS2Metadata{
			Keyslots: map[string]*Keyslot{
				"0": cloneKeyslot(metadata.Keyslots["0"]),
				"7": cloneKeyslot(metadata.Keyslots["0"]),
			},
			Digests: digests,
		}
		mixed.Keyslots["0"].KDF = nil

		key, err := getMasterKey(path, []byte(conformancePassphrase), mixed)
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

	previousNew, previousMove, previousCopy := newLockedRegion, moveIntoLockedRegion, copyIntoLockedRegion
	t.Cleanup(func() {
		newLockedRegion, moveIntoLockedRegion, copyIntoLockedRegion = previousNew, previousMove, previousCopy
	})

	refuse := func() (*enclave.MemoryEnclave, error) {
		return nil, &enclave.LockedMemoryError{
			Cause: errors.New("synthetic RLIMIT_MEMLOCK exhaustion"),
		}
	}
	newLockedRegion = func(int) (*enclave.MemoryEnclave, error) { return refuse() }
	moveIntoLockedRegion = func(b []byte) (*enclave.MemoryEnclave, error) {
		// go-enclave wipes the caller's slice on every path including failure,
		// and adoptSecret's contract depends on that, so the fake keeps it.
		enclave.Wipe(b)
		return refuse()
	}
	// The copy constructor never touches its source, so the fake must not
	// either: copySecret's callers keep reading the bytes they copied from.
	copyIntoLockedRegion = func([]byte) (*enclave.MemoryEnclave, error) { return refuse() }
}
