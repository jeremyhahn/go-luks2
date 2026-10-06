// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package device

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestErrorFormatting(t *testing.T) {
	cause := errors.New("boom")
	e := &Error{Device: "/dev/sda1", Op: "lock", Err: cause}
	want := "lock /dev/sda1: boom"
	if got := e.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(e, cause) {
		t.Fatal("Unwrap does not reach the cause")
	}
}

func TestLockTimeoutErrorFormatting(t *testing.T) {
	cause := errors.New("resource temporarily unavailable")
	e := &LockTimeoutError{Path: "/dev/sda1", Waited: 30 * time.Second, Attempts: 42, Err: cause}
	msg := e.Error()
	for _, want := range []string{"/dev/sda1", "30s", "42", "fuser -v /dev/sda1", "lsof /dev/sda1"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("Error() = %q, missing %q", msg, want)
		}
	}
	if !errors.Is(e, cause) {
		t.Fatal("Unwrap does not reach the cause")
	}
	if !errors.Is(e, ErrLockContended) {
		t.Fatal("LockTimeoutError does not match ErrLockContended")
	}
}
