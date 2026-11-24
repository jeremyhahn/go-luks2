// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package keyring places a volume key in the kernel keyring as a logon key and returns the dm-crypt reference, on a discarded OS thread.
package keyring

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

const (
	// KeyType is logon: its payload is write-only from userspace.
	KeyType = "logon"

	// DescriptionPrefix is the subsystem qualifier logon descriptions require.
	DescriptionPrefix = "luks2"
)

// Syscalls is the seam to the kernel key-management syscalls.
type Syscalls struct {
	SessionRing func() (int, error)
	Add         func(keyType, description string, payload []byte, ringID int) (int, error)
	Search      func(ringID int, keyType, description string) (int, error)
	Revoke      func(keyID int) error
	Unlink      func(keyID, ringID int) error
}

// Live returns the real kernel implementation; unix.AddKey hands the payload to the kernel without copying.
func Live() Syscalls {
	return Syscalls{
		SessionRing: func() (int, error) {
			// create=true: without it, a task with no session keyring gets
			// the uid-shared one installed instead of a fresh anonymous one.
			return unix.KeyctlGetKeyringID(unix.KEY_SPEC_SESSION_KEYRING, true)
		},
		Add: unix.AddKey,
		Search: func(ringID int, keyType, description string) (int, error) {
			return unix.KeyctlSearch(ringID, keyType, description, 0)
		},
		Revoke: func(keyID int) error {
			_, err := unix.KeyctlInt(unix.KEYCTL_REVOKE, keyID, 0, 0, 0)
			return err
		},
		Unlink: func(keyID, ringID int) error {
			_, err := unix.KeyctlInt(unix.KEYCTL_UNLINK, keyID, ringID, 0, 0)
			return err
		},
	}
}

// VolumeKey is a live keyring entry holding a volume key, and the dm-crypt
// reference that names it.
type VolumeKey struct {
	ID          int
	Ring        int
	Description string
	KeySize     int
}

// TableKeyID returns the dm-crypt key_string for this entry; the kernel checks its byte size.
func (k *VolumeKey) TableKeyID() string {
	return fmt.Sprintf(":%d:%s:%s", k.KeySize, KeyType, k.Description)
}

// Release revokes and unlinks the entry, then searches to verify it is gone; already gone is fine. It always runs to completion regardless of ctx.
func (k *VolumeKey) Release(s Syscalls) error {
	revokeErr := IgnoreAbsent(s.Revoke(k.ID))
	unlinkErr := IgnoreAbsent(s.Unlink(k.ID, k.Ring))

	joined := errors.Join(revokeErr, unlinkErr, k.verifyGone(s))
	if joined == nil {
		return nil
	}

	return &errs.Error{
		Kind: ErrKeyNotReleased,
		Detail: fmt.Sprintf("the volume key may still be present in the kernel keyring as %s %q; inspect it with `keyctl show %d` and remove it with `keyctl unlink %d %d`. %s",
			KeyType, k.Description, k.Ring, k.ID, k.Ring,
			trimTrailingPeriod(Remedy(Classify(joined)))),
		Err: joined,
	}
}

// verifyGone reports an error unless the kernel confirms the entry is no
// longer resolvable. See Release for why a successful unlink is not accepted
// as proof.
func (k *VolumeKey) verifyGone(s Syscalls) error {
	id, err := s.Search(k.Ring, KeyType, k.Description)
	switch {
	case err == nil:
		return &errs.Error{
			Kind:   ErrKeyNotReleased,
			Detail: fmt.Sprintf("the entry is still resolvable as key %d after being revoked and unlinked", id),
		}
	case IsAbsent(err):
		return nil
	default:
		return &errs.Error{
			Kind:   errs.ErrIO,
			Detail: "the keyring could not be searched to confirm the entry is gone",
			Err:    err,
		}
	}
}

func trimTrailingPeriod(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

// IgnoreAbsent maps "the key is not there" onto success and passes everything
// else through. See Release.
func IgnoreAbsent(err error) error {
	if err == nil || IsAbsent(err) || errors.Is(err, unix.EKEYREVOKED) {
		return nil
	}
	return err
}

// IsAbsent reports whether err is the kernel's no-such-key errno.
func IsAbsent(err error) bool {
	return errors.Is(err, unix.ENOKEY) || errors.Is(err, unix.ENOENT)
}

// AddVolumeKey adds key (borrowed from an enclave, never copied) under this mapping's description; an existing entry fails. The caller releases the entry.
func AddVolumeKey(ctx context.Context, s Syscalls, dmUUID string, key []byte) (*VolumeKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ring, err := s.SessionRing()
	if err != nil {
		return nil, Failure("resolve the session keyring", err)
	}

	description := Description(dmUUID)

	switch id, searchErr := s.Search(ring, KeyType, description); {
	case searchErr == nil:
		return nil, &errs.Error{
			Kind: ErrEntryExists,
			Detail: fmt.Sprintf("%s key %q (the digest of device-mapper UUID %q) is already present as key %d, so this unlock would silently overwrite or adopt key material it did not create; a leftover from a crashed process can be removed with `keyctl unlink %d %d`",
				KeyType, description, dmUUID, id, id, ring),
		}
	case IsAbsent(searchErr):
		// The expected case: nothing is there.
	default:
		return nil, Failure("search the session keyring", searchErr)
	}

	id, err := s.Add(KeyType, description, key, ring)
	if err != nil {
		return nil, Failure("add the volume key to the session keyring", err)
	}

	return &VolumeKey{
		ID:          id,
		Ring:        ring,
		Description: description,
		KeySize:     len(key),
	}, nil
}

// Description is the subsystem prefix plus the SHA-256 hex of the dm UUID: one safe, deterministic token for the dm table.
func Description(dmUUID string) string {
	digest := sha256.Sum256([]byte(dmUUID))
	return DescriptionPrefix + ":" + hex.EncodeToString(digest[:])
}

// PinOSThread pins the calling goroutine to the OS thread it is running on
// and returns the function that releases it.
func PinOSThread() func() {
	runtime.LockOSThread()
	return runtime.UnlockOSThread
}

// RunOnDiscardedThread runs fn on a goroutine locked to its OS thread that exits with it, so changed keyring credentials die with the thread; a panic is re-raised on the caller.
func RunOnDiscardedThread(fn func() error) error {
	type outcome struct {
		err      error
		panicked bool
		value    any
	}
	done := make(chan outcome, 1)
	go func() {
		runtime.LockOSThread()
		// Deliberately no runtime.UnlockOSThread: see above.
		defer func() {
			if r := recover(); r != nil {
				done <- outcome{panicked: true, value: r}
			}
		}()
		done <- outcome{err: fn()}
	}()
	result := <-done
	if result.panicked {
		panic(result.value)
	}
	return result.err
}
