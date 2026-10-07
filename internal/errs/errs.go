// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package errs is the one error shape of this module.
//
// Every package in the module reports a failure as an *Error: the sentinel
// that classifies it (Kind), the object and the reason in words (Detail), and
// the typed cause (Err). errors.Is and errors.As reach both Kind and Err, so a
// caller can branch on the classification and still reach the cause, such as
// a *fs.PathError or a unix.Errno.
package errs

import (
	"context"
	"errors"
	"strings"
)

// Error is a classified failure.
type Error struct {
	// Op is the exported entry point that failed, "Type.Method" or "Func"
	// ("Volume.AddKeyslot"). Set once, by At, at the boundary; empty until
	// then.
	Op string

	// Path is the device or file the operation was opened on, if any. Set
	// together with Op, by At.
	Path string

	// Kind is the sentinel that classifies the failure.
	Kind error

	// Detail says which object failed and why, in words.
	Detail string

	// Err is the underlying cause, or nil.
	Err error

	// pkg is the reporting package's prefix ("luks2", "dmcrypt", ...), set
	// by At. It is never set directly by a literal: a package has exactly
	// one prefix, named at its own boundary.
	pkg string
}

// At fills Op and Path on err if it is an *Error with them unset, and
// returns err unchanged otherwise. Every exported entry point calls it
// exactly once, on the way out, with its own pkg prefix: this never stacks
// a second wrapper, because an err whose Op is already set (from a lower
// boundary that called At first) is left alone.
func At(pkg, op, path string, err error) error {
	if err == nil {
		return nil
	}
	e, ok := err.(*Error)
	if !ok {
		return err
	}
	if e.pkg == "" {
		e.pkg = pkg
	}
	if e.Op == "" {
		e.Op = op
	}
	if e.Path == "" {
		e.Path = path
	}
	return e
}

// KindOf reports the classification a new wrapper around err should carry:
// ctx's own error if err is a context cancellation or deadline (rule 5), the
// already-set Kind of err if it is an *Error (rule 4: a context wrapper
// around an already-classified error takes that error's kind), or fallback
// if err is not classified at all.
func KindOf(err error, fallback error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var e *Error
	if errors.As(err, &e) && e.Kind != nil {
		return e.Kind
	}
	return fallback
}

// Error renders "<pkg>: <op> <path>: <kind>: <detail>: <cause>", leaving out
// every part that is empty. pkg, Op and Path are empty until At has run, so
// an *Error built and never passed through At -- every site today -- renders
// exactly as before: "<kind>: <detail>: <cause>".
func (e *Error) Error() string {
	head := e.pkg
	if opPath := strings.TrimSpace(e.Op + " " + e.Path); opPath != "" {
		if head != "" {
			head += ": "
		}
		head += opPath
	}

	var tail strings.Builder
	part := func(s string) {
		if s == "" {
			return
		}
		if tail.Len() > 0 {
			tail.WriteString(": ")
		}
		tail.WriteString(s)
	}
	if e.Kind != nil {
		// The head already names the package once (§C.2 rule 3), so the
		// sentinel's own prefix -- its package's, or the module-wide
		// "luks2: " of a sentinel re-exported by value -- is dropped here.
		kind := e.Kind.Error()
		if head != "" {
			kind = strings.TrimPrefix(kind, e.pkg+": ")
			kind = strings.TrimPrefix(kind, "luks2: ")
		}
		part(kind)
	}
	part(e.Detail)
	if e.Err != nil {
		part(e.Err.Error())
	}

	switch {
	case head == "":
		return tail.String()
	case tail.Len() == 0:
		return head
	default:
		return head + ": " + tail.String()
	}
}

// Unwrap returns the classifying sentinel and the cause, so errors.Is and
// errors.As reach both.
func (e *Error) Unwrap() []error {
	out := make([]error, 0, 2)
	if e.Kind != nil {
		out = append(out, e.Kind)
	}
	if e.Err != nil {
		out = append(out, e.Err)
	}
	return out
}
