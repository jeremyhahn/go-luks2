// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package dmcrypt

import (
	"errors"
	"os"

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

	// ErrStillLive indicates Activate failed after creating the target and could not confirm its removal.
	ErrStillLive = errors.New("dmcrypt: plaintext device-mapper target may still be live after a failed activate")

	// ErrInvalidName indicates a device-mapper mapping name this package
	// will not create. See ValidateName.
	ErrInvalidName = errors.New("dmcrypt: invalid device-mapper mapping name")

	// ErrNodeUnverified indicates that no /dev node could be made, or
	// confirmed, to verifiably name the device-mapper target Activate
	// created.
	ErrNodeUnverified = errors.New("dmcrypt: no device node verifiably names the device-mapper target")

	// ErrIntegerOverflow indicates a value that does not fit its narrower integer type.
	ErrIntegerOverflow = errors.New("dmcrypt: integer overflow")

	// ErrPermissionDenied is internal/device's sentinel, re-exported by
	// value so errors.Is holds regardless of which package's name a caller
	// matches against.
	ErrPermissionDenied = device.ErrPermissionDenied

	// ErrDeviceChanged indicates the new target was replaced or removed before confirmation; internal/device's sentinel.
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

// KeyringError reports that the kernel keyring could not hold or release a volume key, the failed step and its remedy.
type KeyringError struct {
	// Op names the keyring step that failed. It never carries key content.
	Op string

	// Kind is the sentinel naming the cause: ErrKeyringBlocked,
	// ErrKeyringUnsupported, ErrKeyringQuotaExhausted or ErrKeyringFailed.
	Kind error

	// Err is the underlying errno, reachable through Unwrap.
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

// dmKind is errs.KindOf for a dm or /dev step, mapping EPERM and EACCES to ErrPermissionDenied.
func dmKind(err, fallback error) error {
	if kind := errs.KindOf(err, nil); kind != nil {
		return kind
	}
	if errors.Is(err, os.ErrPermission) {
		return ErrPermissionDenied
	}
	return fallback
}

// Unwrap exposes the cause and errno and reports as ErrKeyringUnavailable and ErrKeyring.
func (e *KeyringError) Unwrap() []error {
	return []error{ErrKeyring, ErrKeyringUnavailable, e.Kind, e.Err}
}

// Remedy returns the operator guidance for this failure's cause.
func (e *KeyringError) Remedy() string {
	return keyringpkg.Remedy(e.Kind)
}
