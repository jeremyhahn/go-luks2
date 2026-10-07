// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package keyring places a LUKS2 volume key in the kernel keyring as a
// "logon" key and hands back the dm-crypt reference that names it, instead
// of letting the key reach dm-crypt's table inline (see AddVolumeKey).
//
// The add-and-verify-release sequence runs on a discarded OS thread
// (RunOnDiscardedThread), because resolving the session keyring can install
// new credentials on the calling thread and those credentials must not leak
// back to the goroutine scheduler.
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
	// KeyType is the kernel key type a volume key is stored under: a
	// "logon" key, whose payload is WRITE-ONLY from userspace (KEYCTL_READ
	// returns EOPNOTSUPP), unlike a "user" key any possessor can read back.
	KeyType = "logon"

	// DescriptionPrefix is the "subsystem" qualifier the kernel's
	// logon_vet_description REQUIRES: a logon key description must contain a
	// colon that is not its first character.
	DescriptionPrefix = "luks2"
)

// Syscalls is the seam between this package and the kernel's key management
// syscalls: a seccomp profile denying them, a release that does not take, or
// a pre-existing entry cannot all be produced for real in a test, so the
// mechanism is a value the caller can substitute.
type Syscalls struct {
	SessionRing func() (int, error)
	Add         func(keyType, description string, payload []byte, ringID int) (int, error)
	Search      func(ringID int, keyType, description string) (int, error)
	Revoke      func(keyID int) error
	Unlink      func(keyID, ringID int) error
}

// Live returns the real kernel implementation.
//
// unix.AddKey passes &payload[0] straight to the add_key syscall without
// copying, which is what makes it safe to hand it a slice borrowed from an
// enclave: the bytes go from locked memory into the kernel with nothing in
// between.
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

// TableKeyID returns the dm-crypt key_string for this entry -- the value that
// goes in CryptTable.KeyID instead of the key itself.
//
// The size is in BYTES and the kernel CHECKS it: crypt_ctr parses it out of
// the reference and crypt_set_keyring_key refuses the load with EINVAL if the
// keyring payload is a different length.
func (k *VolumeKey) TableKeyID() string {
	return fmt.Sprintf(":%d:%s:%s", k.KeySize, KeyType, k.Description)
}

// Release revokes the entry, unlinks it, and then VERIFIES that it is gone.
//
// The verification is the point. Revoking runs the key type's revoke method
// immediately, which for a logon key frees the payload through
// kfree_sensitive, and the unlink then removes the last link. But a return
// value of nil from either is a claim, not evidence, and the thing being
// claimed is that a volume master key is no longer in kernel memory. So the
// ring is searched again and the answer has to be "not there".
//
// A key that was ALREADY gone, or already revoked, is not a failure: ENOKEY
// and ENOENT mean the entry no longer exists, and EKEYREVOKED means its
// payload has already been freed. Anything else -- the key still resolving,
// or a search that cannot say -- means the volume key may still be sitting in
// the kernel keyring, and that is reported rather than swallowed.
// Release is cleanup: it always runs to completion regardless of ctx
// cancellation, the same as Locked.Unlock -- a volume key already placed in
// the kernel keyring must not be left there because the caller that asked
// for it was canceled.
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

// IsAbsent reports whether err is the kernel saying no such key, as opposed
// to any other reason a lookup can fail. The distinction decides whether a
// volume key is reported as possibly-still-present, so it is drawn on the
// errno rather than on message text.
func IsAbsent(err error) bool {
	return errors.Is(err, unix.ENOKEY) || errors.Is(err, unix.ENOENT)
}

// AddVolumeKey places key in the kernel keyring under a description that
// identifies this volume and mapping, and returns the handle that names it.
//
// key is a slice BORROWED from an enclave for the duration of this call. It
// is handed to add_key and to nothing else: no copy, no staging buffer, no
// string. The caller must release the returned entry.
//
// An entry that already exists under this description FAILS the operation.
// add_key would otherwise update it in place, so overwriting somebody else's
// key material or adopting a stale entry would both be silent.
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

// Description builds the key description for a mapping: the subsystem
// qualifier the kernel requires, and a SHA-256 digest of the volume's dm
// UUID.
//
// # Why a digest and not the UUID itself
//
// The description ends up inside CryptTable.KeyID, and devmapper.go joins the
// target specification with strings.Join(args, " ") -- so the reference is
// ONE SPACE-DELIMITED TOKEN in a positional grammar the kernel parses. The dm
// UUID is built from the LUKS2 header's uuid field and the caller's mapping
// name, neither of which this package controls the charset of.
//
// Hashing closes that BY CONSTRUCTION rather than by validation: the output
// is 64 characters of [0-9a-f] whatever the input was. Determinism is
// preserved, which is what the pre-add collision guard in AddVolumeKey
// depends on: the same volume and mapping always hash to the same
// description, so a leftover entry is still detected.
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

// RunOnDiscardedThread runs fn on a new goroutine locked to its OS thread,
// and lets that thread EXIT with the goroutine instead of returning it to the
// scheduler.
//
// # Why the thread is thrown away
//
// Keyrings belong to the TASK, and every Linux thread is a task with its own
// credentials. Resolving the session keyring with create set -- which
// AddVolumeKey does, deliberately -- INSTALLS a new session keyring when the
// task has none, through prepare_creds and commit_creds, which change the
// calling thread and no other. A goroutine that pinned, did that, and called
// UnlockOSThread would return a thread with diverged credentials to the Go
// scheduler, and whatever goroutine ran there next would inherit a keyring
// the rest of the process does not have (#250, C9).
//
// The Go runtime terminates a thread whose goroutine exits while still locked
// to it, so the work runs on a goroutine that locks and never unlocks, and
// the changed credentials die with the thread.
//
// A panic in fn is carried back and re-raised on the caller's goroutine, so
// it behaves as it would have inline instead of killing the process from a
// goroutine nobody can recover.
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
