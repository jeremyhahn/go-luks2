// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package dmcrypt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	keyringpkg "github.com/jeremyhahn/go-luks2/internal/keyring"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// CheckKeyring verifies that this process can actually place a volume key
// in the kernel keyring, and returns the same typed, actionable error
// Activate would return if it cannot.
//
// # Why a preflight exists
//
// Activate fails closed when the keyring is unavailable, which is the
// right answer to the wrong question if it is asked for the first time
// halfway through a shift. The condition it detects -- a container started
// without the keyring syscalls -- is fixed at boot and cannot change
// afterwards, so discovering it at the first activation of a customer
// volume converts a configuration error into an outage. Calling this at
// startup converts it back: the process refuses to come up, and the error
// names the syscalls and the remedy.
//
// Long-lived consumers (a storage daemon, a node agent) should call it
// during initialization. It is cheap -- one add and one release of a
// 64-byte probe -- and it exercises the same syscalls, key type and ring
// resolution that an activation does, including the release path, so a
// kernel that can add but not revoke is caught here too rather than at
// teardown.
//
// A nil return is not a promise that a later activation will succeed; the
// quota can still be exhausted between the two. It is a promise that the
// syscalls are reachable, which is the failure this exists to move
// earlier.
func CheckKeyring(ctx context.Context) error {
	const op = "CheckKeyring"
	if err := ctxErr(ctx); err != nil {
		return errs.At(pkgName, op, "", err)
	}

	// Random probe description: never collides with a volume or a leftover probe.
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return errs.At(pkgName, op, "", keyringFailure("draw randomness for the keyring preflight", err))
	}
	probe := fmt.Sprintf("preflight-%d-%s", os.Getpid(), hex.EncodeToString(nonce))

	// A probe of a real volume key's length, filled with randomness inside the enclave.
	material, err := secret.System().Sized(64)
	if err != nil {
		return errs.At(pkgName, op, "", keyringFailure("hold the keyring preflight probe in protected memory", err))
	}
	defer func() { _ = material.Destroy() }()
	if err := material.WithBytes(func(b []byte) error {
		_, err := rand.Read(b)
		return err
	}); err != nil {
		return errs.At(pkgName, op, "", keyringFailure("draw randomness for the keyring preflight", err))
	}

	// Add and release on one discarded thread, as Activate does.
	err = keyringpkg.RunOnDiscardedThread(func() error {
		var entry *keyringpkg.VolumeKey
		if err := material.WithBytes(func(b []byte) error {
			var addErr error
			entry, addErr = keyringpkg.AddVolumeKey(ctx, sys.keyring, probe, b)
			return addErr
		}); err != nil {
			return classifyKeyringErr(err)
		}
		return classifyKeyringErr(entry.Release(sys.keyring))
	})
	return errs.At(pkgName, op, "", err)
}

// keyringFailure classifies an errno from a keyring-adjacent failure and
// attaches the remedy for that specific cause.
func keyringFailure(op string, err error) *KeyringError {
	return &KeyringError{Op: op, Kind: keyringpkg.Classify(err), Err: err}
}

// classifyKeyringErr converts an internal/keyring.UnavailableError into *KeyringError; other errors pass through.
func classifyKeyringErr(err error) error {
	if err == nil {
		return nil
	}
	var uae *keyringpkg.UnavailableError
	if errors.As(err, &uae) {
		return &KeyringError{Op: uae.Op, Kind: uae.Kind, Err: uae.Err}
	}
	return err
}
