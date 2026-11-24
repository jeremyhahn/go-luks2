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

// CheckKeyring verifies this process can place and release a volume key in the kernel keyring, returning Activate's error if not; call it at startup.
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
