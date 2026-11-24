// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package keyring

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// Failure classifies a keyring syscall errno and attaches the remedy for that cause.
func Failure(op string, err error) error {
	return &UnavailableError{Op: op, Kind: Classify(err), Err: err}
}

// Classify maps an errno onto the sentinel that names its cause.
func Classify(err error) error {
	switch {
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		// Docker's default seccomp profile denies add_key, keyctl and request_key; SYS_ADMIN does not lift it.
		return ErrBlocked
	case errors.Is(err, unix.ENOSYS):
		return ErrUnsupported
	case errors.Is(err, unix.EDQUOT), errors.Is(err, unix.EKEYREJECTED):
		return ErrQuotaExhausted
	default:
		return ErrFailed
	}
}

// Remedy returns the operator guidance for a cause. Each one is a complete
// instruction rather than a hint.
func Remedy(kind error) string {
	switch kind {
	case ErrBlocked:
		return "This is almost always a container seccomp profile: Docker's DEFAULT profile denies the add_key, keyctl and request_key syscalls, and (measured) --cap-add SYS_ADMIN does NOT lift that -- only relaxing seccomp does. " +
			"Allow those three syscalls in a NARROW custom profile and run with --security-opt seccomp=<profile>.json; prefer that over --security-opt seccomp=unconfined, which also drops every other syscall restriction. " +
			"Under Kubernetes the equivalent is a localhost seccomp profile in securityContext.seccompProfile. " +
			"Call dmcrypt.CheckKeyring at startup so this is found at boot rather than at the first unlock."
	case ErrUnsupported:
		return "The kernel was built without CONFIG_KEYS, so it cannot hold a volume key at all and no runtime configuration will change that. This library requires a kernel with keyring support; it does not fall back to putting the key in the device-mapper table."
	case ErrQuotaExhausted:
		return "Raise the per-user key quota (/proc/sys/kernel/keys/maxkeys and maxbytes, or root_maxkeys and root_maxbytes for uid 0), or find what is leaking keys with `keyctl show` -- this library releases every entry it creates as soon as the activation ioctl returns, so a growing key count is coming from elsewhere."
	default:
		return "The keyring syscalls are reachable and the operation was refused anyway; the cause reported above is the kernel's own answer."
	}
}

// Sentinel is the type of every keyring sentinel: each reports as ErrKeyring while staying distinct.
type Sentinel string

func (e Sentinel) Error() string { return string(e) }

// Is reports every sentinel as the ErrKeyring root, so a caller can match
// "any keyring condition" with one target and still match the specific one
// it can act on.
func (e Sentinel) Is(target error) bool { return target == ErrKeyring }

var (
	// ErrKeyring is the ROOT of every keyring condition this package raises,
	// and the only sentinel that is safe to use as a catch-all: every other
	// sentinel below matches it too.
	ErrKeyring error = Sentinel("dmcrypt: a kernel keyring operation failed")

	// ErrUnavailable indicates the volume key could not be placed in the kernel keyring and the operation was refused.
	ErrUnavailable error = Sentinel("dmcrypt: the volume key could not be placed in the kernel keyring")

	// ErrBlocked indicates the kernel keyring syscalls are refused by policy
	// rather than being absent -- almost always a container seccomp profile.
	ErrBlocked error = Sentinel("dmcrypt: the kernel keyring syscalls are blocked by policy")

	// ErrUnsupported indicates the kernel does not implement the keyring
	// syscalls at all -- built without CONFIG_KEYS.
	ErrUnsupported error = Sentinel("dmcrypt: this kernel does not implement the keyring syscalls")

	// ErrQuotaExhausted indicates the per-user kernel key quota is full.
	ErrQuotaExhausted error = Sentinel("dmcrypt: the kernel key quota for this user is exhausted")

	// ErrFailed indicates the keyring syscalls are reachable and the kernel
	// refused the operation anyway, for a reason none of the other three
	// describe.
	ErrFailed error = Sentinel("dmcrypt: the kernel keyring refused the operation")

	// ErrEntryExists indicates a key already existed under this unlock's description; refused.
	ErrEntryExists error = Sentinel("dmcrypt: a kernel keyring entry already exists for this volume")

	// ErrKeyNotReleased indicates a volume-key entry could not be revoked and unlinked and may still be present.
	ErrKeyNotReleased error = Sentinel("dmcrypt: a kernel keyring entry holding the volume key could not be released")
)

// UnavailableError reports that the kernel keyring could not hold the volume key, the failed step and its remedy; always fatal.
type UnavailableError struct {
	// Op names the keyring step that failed. It never carries key content.
	Op string

	// Kind is the sentinel naming the cause: ErrBlocked, ErrUnsupported,
	// ErrQuotaExhausted or ErrFailed.
	Kind error

	// Err is the underlying errno, reachable through Unwrap.
	Err error
}

func (e *UnavailableError) Error() string {
	return fmt.Sprintf("%s: could not %s: %v. %s", e.kind().Error(), e.Op, e.Err, Remedy(e.kind()))
}

// kind returns the classification, defaulting a zero value to ErrFailed.
// Nothing in this package constructs one without a Kind, but this type is
// exported and formatting an error is the worst possible moment to panic.
func (e *UnavailableError) kind() error {
	if e.Kind == nil {
		return ErrFailed
	}
	return e.Kind
}

func (e *UnavailableError) Unwrap() error { return e.Err }

// Is matches the specific cause, ErrUnavailable and ErrKeyring.
func (e *UnavailableError) Is(target error) bool {
	return target == ErrKeyring || target == ErrUnavailable || target == e.kind()
}
