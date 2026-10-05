// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
)

// Errors raised by the tool itself, as opposed to the ones the library returns.
//
// They follow pkg/luks2/errors.go: a sentinel to match on, a structured type
// carrying what a diagnosis needs, and an Is that reports the type as the
// sentinel so a caller never has to know the type exists.

var (
	// ErrKeyInput is the sentinel every credential-input failure matches.
	ErrKeyInput = errors.New("key input")

	// ErrKeyFileTooLarge indicates a key file is larger than cryptsetup would
	// accept. The bound is not this tool's preference -- see maxKeyFileSize.
	ErrKeyFileTooLarge = errors.New("key file is too large")

	// ErrPassphraseMismatch indicates a passphrase and its confirmation differ.
	ErrPassphraseMismatch = errors.New("passphrases do not match")

	// ErrUsage indicates the arguments given cannot be parsed. It is separate
	// from a failed operation: nothing was attempted.
	ErrUsage = errors.New("usage")

	// ErrNotConfirmed indicates a destructive operation was not confirmed:
	// the answer was not YES, input ended, or it could not be read.
	ErrNotConfirmed = errors.New("not confirmed: type YES, or pass --batch-mode")

	// ErrEmptyKeyFilePath indicates --key-file or --new-key-file was given an
	// empty path. It is refused rather than read as "no key file", which would
	// silently fall back to a prompt or to standard input.
	ErrEmptyKeyFilePath = errors.New("the key file path is empty")

	// ErrDeviceHasData indicates create was pointed at a device that already
	// carries a LUKS header or a filesystem signature, without --force.
	ErrDeviceHasData = errors.New("the device already holds data")
)

// ConfirmationError reports a destructive operation that was not confirmed.
type ConfirmationError struct {
	// Err is ErrNotConfirmed for an answer other than YES, or the read
	// failure -- io.ErrUnexpectedEOF for no answer at all.
	Err error
}

func (e *ConfirmationError) Error() string {
	if errors.Is(e.Err, ErrNotConfirmed) {
		return e.Err.Error()
	}
	return fmt.Sprintf("%s: %v", ErrNotConfirmed.Error(), e.Err)
}

func (e *ConfirmationError) Unwrap() error { return e.Err }

// Is reports every ConfirmationError as ErrNotConfirmed.
func (e *ConfirmationError) Is(target error) bool {
	return target == ErrNotConfirmed
}

// DevicePathError reports a failure to inspect or prepare the path a command
// was given, naming it.
type DevicePathError struct {
	Path string
	Op   string
	Err  error
}

func (e *DevicePathError) Error() string {
	return fmt.Sprintf("%s %s: %v", e.Op, e.Path, e.Err)
}

func (e *DevicePathError) Unwrap() error { return e.Err }

// KeyInputError reports a failure to obtain a credential, naming where the
// credential was coming from.
type KeyInputError struct {
	// Op names the step, for example "read key file". It never carries
	// credential material.
	Op string

	// Source is where the credential was being read from -- a path, "standard
	// input", or "terminal". A path is the operator's own argument and is
	// echoed back so they can see which one was tried.
	Source string

	Err error
}

func (e *KeyInputError) Error() string {
	return fmt.Sprintf("%s: %s from %s: %v", ErrKeyInput.Error(), e.Op, e.Source, e.Err)
}

func (e *KeyInputError) Unwrap() error { return e.Err }

// Is reports every KeyInputError as ErrKeyInput, so a caller can match the
// sentinel without knowing this type, while errors.Is also still reaches the
// specific cause through Unwrap.
func (e *KeyInputError) Is(target error) bool {
	return target == ErrKeyInput
}

// UsageError reports an argument this tool cannot act on.
type UsageError struct {
	// Command is the subcommand that was being parsed.
	Command string

	// Detail says what was wrong, in the operator's own vocabulary.
	Detail string
}

func (e *UsageError) Error() string {
	return fmt.Sprintf("%s: %s: %s", ErrUsage.Error(), e.Command, e.Detail)
}

// Is reports every UsageError as ErrUsage.
func (e *UsageError) Is(target error) bool {
	return target == ErrUsage
}
