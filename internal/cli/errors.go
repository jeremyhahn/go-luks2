// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// Error is the module's one error shape (internal/errs). The sentinels below
// are its Kinds: every site that raises one returns it inside an *Error, and
// errors.Is still matches the sentinel, so the exit-code mapping is unchanged.
type Error = errs.Error

// ErrUnknownCommand indicates the first argument did not name a registered
// command or command group.
var ErrUnknownCommand = errors.New("cli: unknown command")

// ErrNotConfirmed indicates a destructive operation's confirmation prompt
// saw anything but the literal answer YES.
var ErrNotConfirmed = errors.New("cli: not confirmed")

// ErrPassphraseMismatch indicates a passphrase and its typed confirmation
// did not match.
var ErrPassphraseMismatch = errors.New("cli: passphrase confirmation did not match")

// ErrEmptyKeyFilePath indicates --key-file was given an empty value. It is
// refused rather than read as "no key file", which would quietly fall back
// to a prompt or to standard input.
var ErrEmptyKeyFilePath = errors.New("cli: --key-file requires a path")

// ErrKeyFileTooLarge indicates a key file, or a line read from standard
// input, exceeded maxKeyFileSize.
var ErrKeyFileTooLarge = errors.New("cli: key material is too large")

// ErrEmptyCredential indicates a passphrase source produced zero bytes.
var ErrEmptyCredential = errors.New("cli: empty credential")

// errNotLUKSDevice is isluks's negative answer. It deliberately matches no
// exitTable sentinel, because isluks's exit code is its own 0/1 contract
// (0 is a LUKS device, 1 is not, as cryptsetup isLuks), not the generic error-to-exit-code mapping every other
// command uses.
var errNotLUKSDevice = errors.New("cli: not a LUKS device")

// UsageError reports that a subcommand's arguments could not be parsed, or
// did not have the right shape.
type UsageError struct {
	// Command is the subcommand that was being parsed.
	Command string

	// Detail says what was wrong, in the operator's own vocabulary.
	Detail string
}

func (e *UsageError) Error() string {
	return "usage: " + e.Command + ": " + e.Detail
}

// KeyInputError reports that a credential could not be read, naming the
// step and the source without ever carrying credential material.
type KeyInputError struct {
	// Op names the step, for example "read key file". It never carries
	// credential material.
	Op string

	// Source is where the credential was being read from -- a path,
	// "standard input", or "terminal".
	Source string

	Err error
}

func (e *KeyInputError) Error() string {
	return e.Op + " from " + e.Source + ": " + e.Err.Error()
}

func (e *KeyInputError) Unwrap() error { return e.Err }

// ConfirmationError reports that a destructive operation's confirmation was
// refused or could not be read.
type ConfirmationError struct {
	// Err is ErrNotConfirmed for an answer other than YES, or the read
	// failure -- io.ErrUnexpectedEOF for no answer at all.
	Err error
}

func (e *ConfirmationError) Error() string { return "confirmation: " + e.Err.Error() }

func (e *ConfirmationError) Unwrap() error { return e.Err }
