// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package keyprovider

import (
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// Error is this package's one error shape, aliased from internal/errs so a
// caller outside the module can name the type without reaching into an
// internal package. See errs.Error for the fields.
type Error = errs.Error

// errAt is this package's boundary call into errs.At: every
// exported entry point passes its error through it exactly once, with its
// own pkg prefix, on the way out.
func errAt(op, path string, err error) error {
	return errs.At("keyprovider", op, path, err)
}

// The sentinels every failure in this package matches.
var (
	// ErrInvalidArgument indicates a caller value this package cannot use.
	ErrInvalidArgument = errors.New("keyprovider: invalid argument")

	// ErrHelperFailed indicates a helper could not run, exited non-zero, or was refused as replaceable by others.
	ErrHelperFailed = errors.New("keyprovider: key helper failed")

	// ErrHelperOutput indicates a helper succeeded but produced output this package cannot use.
	ErrHelperOutput = errors.New("keyprovider: unusable key helper output")

	// ErrNoDevice indicates a FIDO2 operation was given no authenticator
	// device. The libfido2 helpers require one, and an empty argument in
	// its place is not a default.
	ErrNoDevice = errors.New("keyprovider: no FIDO2 authenticator device named")

	// ErrInvalidBinding indicates a FIDO2 binding is missing a field an
	// assertion needs, or carries one that does not decode.
	ErrInvalidBinding = errors.New("keyprovider: invalid FIDO2 binding")

	// ErrUnsupportedToken indicates a token names a mechanism this package
	// cannot drive. The token is left alone: another implementation may
	// well be able to use it.
	ErrUnsupportedToken = errors.New("keyprovider: unsupported token type")
)

// HelperError reports that a helper binary could not be run or refused, with its stderr (never the credential).
type HelperError struct {
	// Path is the binary that was run.
	Path string

	// ExitCode is the helper's exit status, or -1 when it never ran.
	ExitCode int

	// Stderr is what the helper said, bounded at maxHelperStderr.
	Stderr string

	// Kind classifies the failure. It is ErrHelperFailed on every path
	// this package builds one from.
	Kind error

	// Err is the underlying cause: an exec error when the helper never
	// ran, or its *exec.ExitError when it did.
	Err error
}

func (e *HelperError) Error() string {
	msg := fmt.Sprintf("%s exited %d", e.Path, e.ExitCode)
	if e.Stderr != "" {
		msg += ": " + e.Stderr
	}
	if e.Kind != nil {
		msg = e.Kind.Error() + ": " + msg
	}
	return msg
}

// Unwrap reaches both the classifying sentinel and the underlying cause, so
// errors.Is matches either without a hand-written Is (errs.Error's own
// precedent).
func (e *HelperError) Unwrap() []error {
	out := make([]error, 0, 2)
	if e.Kind != nil {
		out = append(out, e.Kind)
	}
	if e.Err != nil {
		out = append(out, e.Err)
	}
	return out
}
