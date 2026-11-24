// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package errs is the module's one error shape: *Error carries Kind, Detail and the typed cause, all reachable by errors.Is and errors.As.
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

// At fills Op and Path on err if it is an *Error with them unset, and returns err unchanged otherwise.
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

// KindOf returns ctx's error for a cancellation, err's Kind if it is an *Error, or fallback.
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

// Error renders "<pkg>: <op> <path>: <kind>: <detail>: <cause>", leaving out empty parts.
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
		// The head already names the package, and a message names it
		// exactly once, so the sentinel's own prefix -- its package's, or the module-wide
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
