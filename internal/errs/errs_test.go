// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package errs

import (
	"errors"
	"io/fs"
	"testing"
)

var errKind = errors.New("kind")

func TestErrorRendersOnlyThePartsThatArePresent(t *testing.T) {
	cause := errors.New("cause")
	for _, tc := range []struct {
		err  *Error
		want string
	}{
		{&Error{Kind: errKind, Detail: "detail", Err: cause}, "kind: detail: cause"},
		{&Error{Kind: errKind, Detail: "detail"}, "kind: detail"},
		{&Error{Kind: errKind, Err: cause}, "kind: cause"},
		{&Error{Kind: errKind}, "kind"},
		{&Error{Detail: "detail", Err: cause}, "detail: cause"},
		{&Error{Detail: "detail"}, "detail"},
		{&Error{Err: cause}, "cause"},
		{&Error{}, ""},
	} {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("%#v.Error() = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestUnwrapReachesTheKindAndTheCause(t *testing.T) {
	cause := &fs.PathError{Op: "open", Path: "/dev/x", Err: fs.ErrPermission}
	var err error = &Error{Kind: errKind, Detail: "open the device", Err: cause}

	if !errors.Is(err, errKind) {
		t.Error("the kind is not reachable")
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Error("the cause's own sentinel is not reachable")
	}
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) || pathErr != cause {
		t.Error("the typed cause is not reachable")
	}
	if got := (&Error{}).Unwrap(); len(got) != 0 {
		t.Errorf("an empty error unwraps to %v", got)
	}
}
