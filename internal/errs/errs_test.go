// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package errs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"testing"
	"time"
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

func TestErrorRendersTheBoundaryWhenAtHasRun(t *testing.T) {
	cause := errors.New("cause")
	for _, tc := range []struct {
		err  *Error
		want string
	}{
		{&Error{Op: "Volume.Open", Path: "/dev/loop0", Kind: errKind, Detail: "detail", Err: cause}, "Volume.Open /dev/loop0: kind: detail: cause"},
		{&Error{Op: "Volume.Open", Kind: errKind}, "Volume.Open: kind"},
		{&Error{Path: "/dev/loop0", Kind: errKind}, "/dev/loop0: kind"},
	} {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("%#v.Error() = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestErrorRendersThePkgPrefixOncePkgIsSet(t *testing.T) {
	err := At("luks2", "Volume.Open", "/dev/loop0", &Error{Kind: errKind, Detail: "detail"})
	want := "luks2: Volume.Open /dev/loop0: kind: detail"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestAtFillsOpAndPathOnlyWhenEmpty(t *testing.T) {
	e := &Error{Kind: errKind}
	got := At("luks2", "Volume.Open", "/dev/loop0", e)
	if got != e {
		t.Fatal("At must return the same *Error, not wrap it again")
	}
	if e.Op != "Volume.Open" || e.Path != "/dev/loop0" {
		t.Fatalf("At did not fill empty Op/Path: %+v", e)
	}

	// A second At, from an outer boundary, must not overwrite what the
	// first one already set -- "never stacks a second wrapper".
	At("luks2", "Volume.Format", "/dev/other", e)
	if e.Op != "Volume.Open" || e.Path != "/dev/loop0" {
		t.Fatalf("a second At overwrote the first boundary's Op/Path: %+v", e)
	}
}

func TestAtPassesThroughANonErrsError(t *testing.T) {
	plain := errors.New("not an *errs.Error")
	if got := At("luks2", "Volume.Open", "/dev/loop0", plain); got != plain {
		t.Errorf("At(%v) = %v, want the same error unchanged", plain, got)
	}
}

func TestAtOnNilReturnsNil(t *testing.T) {
	if got := At("luks2", "Volume.Open", "/dev/loop0", nil); got != nil {
		t.Errorf("At(nil) = %v, want nil", got)
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

func TestKindOfTakesTheInnerClassificationOverTheFallback(t *testing.T) {
	inner := &Error{Kind: errKind, Detail: "inner"}
	if got := KindOf(inner, io.ErrClosedPipe); got != errKind {
		t.Errorf("KindOf(classified, fallback) = %v, want the inner Kind %v", got, errKind)
	}
}

func TestKindOfFallsBackWhenErrIsNotClassified(t *testing.T) {
	plain := errors.New("not an *errs.Error")
	if got := KindOf(plain, io.ErrClosedPipe); got != io.ErrClosedPipe {
		t.Errorf("KindOf(unclassified, fallback) = %v, want fallback %v", got, io.ErrClosedPipe)
	}
}

func TestKindOfPrefersCtxErrOverAnythingElse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wrapped := fmt.Errorf("wrapped: %w", ctx.Err())
	if got := KindOf(wrapped, io.ErrClosedPipe); got != context.Canceled {
		t.Errorf("KindOf(canceled ctx, fallback) = %v, want context.Canceled", got)
	}

	deadlineCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	<-deadlineCtx.Done()
	if got := KindOf(deadlineCtx.Err(), io.ErrClosedPipe); got != context.DeadlineExceeded {
		t.Errorf("KindOf(expired deadline, fallback) = %v, want context.DeadlineExceeded", got)
	}
}
