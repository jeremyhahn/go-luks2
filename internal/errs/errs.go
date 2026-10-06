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

import "strings"

// Error is a classified failure.
type Error struct {
	// Kind is the sentinel that classifies the failure.
	Kind error

	// Detail says which object failed and why, in words.
	Detail string

	// Err is the underlying cause, or nil.
	Err error
}

// Error renders "kind: detail: cause", leaving out the parts that are empty.
func (e *Error) Error() string {
	var b strings.Builder
	part := func(s string) {
		if s == "" {
			return
		}
		if b.Len() > 0 {
			b.WriteString(": ")
		}
		b.WriteString(s)
	}
	if e.Kind != nil {
		part(e.Kind.Error())
	}
	part(e.Detail)
	if e.Err != nil {
		part(e.Err.Error())
	}
	return b.String()
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
