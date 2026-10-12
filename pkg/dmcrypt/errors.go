// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package dmcrypt

import (
	"errors"

	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	keyringpkg "github.com/jeremyhahn/go-luks2/internal/keyring"
)

// Error is this package's one error shape, aliased from internal/errs so a
// caller outside the module can name the type without reaching into an
// internal package. See errs.Error for the fields.
type Error = errs.Error

var (
	// ErrActive indicates that Activate was asked to create a mapping under
	// a name that is already in use.
	ErrActive = errors.New("dmcrypt: mapping is already active")

	// ErrNotActive indicates that Deactivate or Lookup was asked about a
	// mapping name device-mapper has no target for.
	ErrNotActive = errors.New("dmcrypt: mapping is not active")

	// ErrBusy indicates that Deactivate could not remove a target that
	// something else is still holding open, after riding out the transient
	// hold a udev rule leaves behind.
	ErrBusy = errors.New("dmcrypt: device-mapper target is held open and could not be removed")

	// ErrStillLive indicates that Activate failed AFTER its own create
	// succeeded and could not confirm the target was removed again: a
	// plaintext mapping may still exist.
	ErrStillLive = errors.New("dmcrypt: plaintext device-mapper target may still be live after a failed activate")

	// ErrInvalidName indicates a device-mapper mapping name this package
	// will not create. See ValidateName.
	ErrInvalidName = errors.New("dmcrypt: invalid device-mapper mapping name")

	// ErrNodeUnverified indicates that no /dev node could be made, or
	// confirmed, to verifiably name the device-mapper target Activate
	// created.
	ErrNodeUnverified = errors.New("dmcrypt: no device node verifiably names the device-mapper target")

	// ErrIntegerOverflow indicates a value this package narrows to a
	// smaller or differently-signed integer type cannot fit: a negative
	// size or offset read from a segment that should never carry one. See
	// safeInt64ToUint64 (activate.go).
	ErrIntegerOverflow = errors.New("dmcrypt: integer overflow")

	// ErrPermissionDenied is internal/device's sentinel, re-exported by
	// value so errors.Is holds regardless of which package's name a caller
	// matches against.
	ErrPermissionDenied = device.ErrPermissionDenied

	// ErrDeviceChanged indicates the device-mapper target this package
	// just created was replaced or removed before it could be confirmed.
	// internal/device's sentinel, re-exported by value so errors.Is holds
	// under either package's name.
	ErrDeviceChanged = device.ErrChanged

	// The keyring family is internal/keyring's, re-exported by value for
	// the same reason: this package raises them, but does not own them,
	// because internal/keyring sits below it and below pkg/keyprovider too.
	ErrKeyring               = keyringpkg.ErrKeyring
	ErrKeyringUnavailable    = keyringpkg.ErrUnavailable
	ErrKeyringBlocked        = keyringpkg.ErrBlocked
	ErrKeyringUnsupported    = keyringpkg.ErrUnsupported
	ErrKeyringQuotaExhausted = keyringpkg.ErrQuotaExhausted
	ErrKeyringFailed         = keyringpkg.ErrFailed
	ErrKeyringEntryExists    = keyringpkg.ErrEntryExists
	ErrKeyringKeyNotReleased = keyringpkg.ErrKeyNotReleased
)

// KeyringError reports that the kernel keyring could not hold or release a
// volume key, names the step that failed, and carries the remedy for the
// specific cause.
//
// It is a new type, not an alias of internal/keyring.UnavailableError: a
// method cannot be added to an alias of a foreign type, and Remedy is a
// method this package's callers need (the H4 precedent for every error type
// this module moves across a layering boundary). classifyKeyringErr, in
// keyring.go, is what converts one into the other at the call sites that
// reach internal/keyring directly.
type KeyringError struct {
	// Op names the keyring step that failed. It never carries key content.
	Op string

	// Kind is the sentinel naming the cause: ErrKeyringBlocked,
	// ErrKeyringUnsupported, ErrKeyringQuotaExhausted or ErrKeyringFailed.
	Kind error

	// Err is the underlying errno, kept reachable through Unwrap so a
	// caller can match unix.EPERM, unix.EDQUOT or unix.ENOSYS directly.
	Err error
}

func (e *KeyringError) Error() string {
	return "could not " + e.Op + ": " + errString(e.Err) + ". " + e.Remedy()
}

// errString renders err's message, or "<nil>" rather than panicking, since
// formatting an error is the worst possible moment to fail on one that is
// unexpectedly nil.
func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

// Unwrap keeps the specific cause and the underlying errno reachable, and
// also reports every KeyringError as the ErrKeyringUnavailable umbrella and
// as the ErrKeyring root, so a caller can branch on the cause it can do
// something about and fall back to either umbrella for the rest.
func (e *KeyringError) Unwrap() []error {
	return []error{ErrKeyring, ErrKeyringUnavailable, e.Kind, e.Err}
}

// Remedy returns the operator guidance for this failure's cause.
func (e *KeyringError) Remedy() string {
	return keyringpkg.Remedy(e.Kind)
}
