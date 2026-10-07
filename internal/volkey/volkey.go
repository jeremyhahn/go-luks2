// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package volkey is the only route to a LUKS2 volume key's bytes outside
// pkg/luks2. A *Key never exposes its bytes through a field or an accessor;
// Borrow is the single function that can see them, for the exact call that
// must -- dm-crypt activation, through the kernel keyring.
package volkey

import (
	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// Key is a LUKS2 volume key, held in protected memory for its whole
// lifetime. It is bound to the keyslot it was recovered from, or -1 for a
// key supplied directly (UnlockWithVolumeKey).
type Key struct {
	enclave *enclave.MemoryEnclave
	keyslot int
}

// New wraps e as a Key recovered from (or bound to) keyslot. It takes
// ownership of e: destroying the Key destroys e, and the caller must not
// use e again afterwards.
func New(e *enclave.MemoryEnclave, keyslot int) *Key {
	return &Key{enclave: e, keyslot: keyslot}
}

// Keyslot is the keyslot this key was recovered from, or -1 if it was
// supplied directly rather than recovered from a keyslot.
func (k *Key) Keyslot() int { return k.keyslot }

// Size is the key's length in bytes.
func (k *Key) Size() int { return k.enclave.Size() }

// Destroy releases the key's protected memory. It is safe to call on a nil
// Key. The release outcome is dropped on purpose, matching
// secret.Custody.Release: there is nothing a caller can do differently for
// any outcome go-enclave's Destroy can report on a release path.
func (k *Key) Destroy() {
	if k == nil {
		return
	}
	_ = k.enclave.Destroy()
}

// Borrow hands fn the key's raw bytes for the exact call that must see
// them, never copying them out. op names the caller's operation, for the
// *errs.Error a failure to borrow is reported as.
func Borrow(op string, k *Key, fn func([]byte) error) error {
	return secret.Borrow(op, k.enclave, fn)
}
