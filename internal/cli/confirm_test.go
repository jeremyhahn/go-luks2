// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestAbsPathRejectsEmpty(t *testing.T) {
	if _, err := absPath("test", ""); err == nil {
		t.Fatal("absPath(\"\"): want an error")
	}
}

func TestAbsPathResolvesRelative(t *testing.T) {
	got, err := absPath("test", "./x")
	if err != nil {
		t.Fatalf("absPath: %v", err)
	}
	if !strings.HasSuffix(got, "/x") {
		t.Errorf("absPath(./x) = %q, want a path ending in /x", got)
	}
}

func TestConfirmDestructiveBatchSkipsThePrompt(t *testing.T) {
	e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})
	if err := confirmDestructive(e, "prompt: ", true); err != nil {
		t.Fatalf("confirmDestructive: %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty when batch is true", stdout.String())
	}
}

func TestConfirmDestructiveAcceptsYES(t *testing.T) {
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("YES\n"))
	if err := confirmDestructive(e, "prompt: ", false); err != nil {
		t.Fatalf("confirmDestructive: %v", err)
	}
}

func TestConfirmDestructiveRefusesAnythingElse(t *testing.T) {
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("no\n"))
	err := confirmDestructive(e, "prompt: ", false)
	if err == nil {
		t.Fatal("confirmDestructive: want an error for an answer other than YES")
	}
	var ce *ConfirmationError
	if !errors.As(err, &ce) {
		t.Fatalf("confirmDestructive error = %T, want *ConfirmationError", err)
	}
	if !errors.Is(err, ErrNotConfirmed) {
		t.Error("confirmDestructive error should be ErrNotConfirmed")
	}
}

func TestConfirmDestructiveRefusesEOF(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := confirmDestructive(e, "prompt: ", false); err == nil {
		t.Fatal("confirmDestructive: want an error on EOF with no answer")
	}
}

func TestReadConfirmationTrimsCR(t *testing.T) {
	got, err := readConfirmation(strings.NewReader("YES\r\n"))
	if err != nil {
		t.Fatalf("readConfirmation: %v", err)
	}
	if got != "YES" {
		t.Errorf("readConfirmation = %q, want YES", got)
	}
}

func TestReadConfirmationEOFWithNoInput(t *testing.T) {
	if _, err := readConfirmation(strings.NewReader("")); err == nil {
		t.Fatal("readConfirmation: want an error for empty input")
	}
}

func TestReadConfirmationEOFWithoutTrailingNewline(t *testing.T) {
	got, err := readConfirmation(strings.NewReader("YES"))
	if err != nil {
		t.Fatalf("readConfirmation: %v", err)
	}
	if got != "YES" {
		t.Errorf("readConfirmation = %q, want YES", got)
	}
}

func TestRefuseUnconfirmed(t *testing.T) {
	e, _, _, _, stderr := newTestEnv(&bytes.Buffer{})
	err := refuseUnconfirmed(e, "Restore", ErrNotConfirmed)
	if !errors.Is(err, ErrNotConfirmed) {
		t.Errorf("refuseUnconfirmed err = %v, want ErrNotConfirmed", err)
	}
	if !strings.Contains(stderr.String(), "Restore canceled") {
		t.Errorf("stderr = %q, want it to mention the canceled operation", stderr.String())
	}
}
