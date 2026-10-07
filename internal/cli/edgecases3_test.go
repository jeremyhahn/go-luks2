// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestUnknownFlagAcrossCommands(t *testing.T) {
	cases := []struct {
		name string
		run  func(context.Context, *env, []string) error
		args []string
	}{
		{"create", runCreate, []string{"--bogus", "/dev/sdb1"}},
		{"recovery generate", runRecoveryGenerate, []string{"--bogus"}},
		{"recovery add", runRecoveryAdd, []string{"--bogus", "/dev/sdb1"}},
		{"recovery verify", runRecoveryVerify, []string{"--bogus", "/dev/sdb1"}},
		{"token export", runTokenExport, []string{"--bogus", "/dev/sdb1", "0"}},
		{"token import", runTokenImport, []string{"--bogus", "/dev/sdb1", "0"}},
	}
	for _, c := range cases {
		e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
		if err := c.run(context.Background(), e, c.args); err == nil {
			t.Errorf("%s: want an error for an unknown flag", c.name)
		}
	}
}

// failingReader always fails with a non-EOF error, to cover
// readConfirmation's generic I/O-error branch.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errSentinel }

func TestReadConfirmationReadError(t *testing.T) {
	if _, err := readConfirmation(failingReader{}); !errors.Is(err, errSentinel) {
		t.Errorf("readConfirmation error = %v, want %v", err, errSentinel)
	}
}

func TestReadConfirmationOverlongLine(t *testing.T) {
	line := strings.Repeat("x", maxConfirmationLine+10)
	answer, err := readConfirmation(bytes.NewBufferString(line))
	if err != nil {
		t.Fatalf("readConfirmation: %v", err)
	}
	if len(answer) < maxConfirmationLine {
		t.Errorf("answer length = %d, want at least %d", len(answer), maxConfirmationLine)
	}
}

func TestReadConfirmationEmptyInput(t *testing.T) {
	if _, err := readConfirmation(bytes.NewReader(nil)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("readConfirmation error = %v, want io.ErrUnexpectedEOF", err)
	}
}
