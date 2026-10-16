// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// unlockableVolume returns a formatted container and the passphrase that
// opens it, so a test exercises the real key-recovery path -- header
// parsing, keyslot scan, key derivation, digest verification -- rather
// than a stub of it.
func unlockableVolume(t *testing.T) (string, []byte) {
	t.Helper()

	path := newImage(t, "unlockable.img")
	formatWithLibrary(t, path)
	return path, []byte(conformancePassphrase)
}

// masterKeyOf recovers the volume key of a container a test just wrote, so
// an assertion can compare against it rather than merely assuming its
// shape.
func masterKeyOf(t *testing.T, device string, passphrase []byte) []byte {
	t.Helper()

	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("reading the header failed: %v", err)
	}
	secret, err := getMasterKey(device, passphrase, metadata, testVolumeSys())
	if err != nil {
		t.Fatalf("recovering the master key failed: %v", err)
	}
	defer mustDestroy(t, secret)

	var key []byte
	if err := secret.WithBytes(func(b []byte) error {
		key = append([]byte(nil), b...)
		return nil
	}); err != nil {
		t.Fatalf("borrowing the master key failed: %v", err)
	}
	return key
}

// volumeKeyEnclave returns key held in protected memory, the way a real
// caller's key provider would hand a volume key to UnlockWithVolumeKey.
func volumeKeyEnclave(t *testing.T, key []byte) enclave.ByteAccess {
	t.Helper()

	e, err := enclave.NewMemoryCopy(key)
	if err != nil {
		t.Fatalf("placing the volume key in an enclave failed: %v", err)
	}
	destroyOnCleanup(t, e)
	return e
}
