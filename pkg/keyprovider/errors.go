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

// errAt is this package's boundary call into errs.At (DESIGN.md §C.2): every
// exported entry point passes its error through it exactly once, with its
// own pkg prefix, on the way out.
func errAt(op, path string, err error) error {
	return errs.At("keyprovider", op, path, err)
}

// The sentinels every failure in this package matches.
var (
	// ErrInvalidArgument indicates a caller-supplied value this package
	// cannot use: a helper path that is not absolute or not configured, a
	// negative line number, or a token with nothing to build a provider
	// from.
	ErrInvalidArgument = errors.New("keyprovider: invalid argument")

	// ErrHelperFailed indicates a helper could not be run, or ran and
	// exited non-zero -- the authenticator refused, the touch timed out,
	// the PIN was wrong.
	ErrHelperFailed = errors.New("keyprovider: key helper failed")

	// ErrHelperOutput indicates a helper SUCCEEDED and produced something
	// this package cannot use: too few lines, an empty credential, output
	// that is not the expected encoding, or output still held open by a
	// process the helper started.
	//
	// It is deliberately separate from ErrHelperFailed. A helper that
	// exits 0 and prints the wrong thing is a protocol mismatch -- a
	// different helper version, a changed output order -- and telling an
	// operator "the authenticator refused" would send them to look at the
	// hardware.
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

// HelperError reports that a helper binary could not be run, or ran and
// refused.
//
// Stderr is included because it is where these helpers say what actually
// happened -- "no device found", "PIN required", "operation denied" -- and
// an operator holding a key that will not open a volume needs that sentence
// rather than an exit code. It carries no credential material: the
// credential is on stdout, which is never put in an error.
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
