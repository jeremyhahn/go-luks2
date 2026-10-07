// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// TestSentinelsAreReturnedAsClassifiedErrors is S5: the package's sentinels
// are Kinds, and every site returns them inside an *Error, the one error
// shape of this module. errors.Is still reaches the sentinel, so the exit-code
// mapping is unchanged.
func TestSentinelsAreReturnedAsClassifiedErrors(t *testing.T) {
	custody := secret.System()
	confirm, _, _, _, _ := newTestEnv(bytes.NewBufferString("no\n"))
	isluks, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	plain := newPlainImage(t, "plain.img")

	_, errEmpty := readKeyFile(custody, strings.NewReader(""), "test", maxKeyFileSize)
	_, errLarge := readKeyFile(custody, strings.NewReader(strings.Repeat("a", 20)), "test", 16)
	_, errLine := readKeyLine(custody, strings.NewReader("\n"), maxKeyFileSize)
	_, errPath := readPassphrase(confirm, "prompt: ", false, keySource{path: "", given: func() bool { return true }})

	for _, tc := range []struct {
		name string
		err  error
		kind error
	}{
		{"empty credential", errEmpty, ErrEmptyCredential},
		{"key file too large", errLarge, ErrKeyFileTooLarge},
		{"empty line", errLine, ErrEmptyCredential},
		{"empty key file path", errPath, ErrEmptyKeyFilePath},
		{"not confirmed", confirmDestructive(confirm, "prompt: ", false), ErrNotConfirmed},
		{"not a LUKS device", runIsLUKS(context.Background(), isluks, []string{plain}), errNotLUKSDevice},
	} {
		var e *Error
		if !errors.As(tc.err, &e) || e.Kind != tc.kind {
			t.Errorf("%s: error = %#v, want an *Error of Kind %v", tc.name, tc.err, tc.kind)
		}
	}
}

func TestUsageErrorString(t *testing.T) {
	err := &UsageError{Command: "open", Detail: "want <device>"}
	if got := err.Error(); !strings.Contains(got, "open") || !strings.Contains(got, "want <device>") {
		t.Errorf("Error() = %q, want it to mention the command and detail", got)
	}
}

func TestKeyInputErrorString(t *testing.T) {
	err := &KeyInputError{Op: "read key file", Source: "standard input", Err: ErrEmptyCredential}
	got := err.Error()
	if !strings.Contains(got, "read key file") || !strings.Contains(got, "standard input") || !strings.Contains(got, ErrEmptyCredential.Error()) {
		t.Errorf("Error() = %q, want it to mention Op, Source and the cause", got)
	}
}

func TestConfirmationErrorString(t *testing.T) {
	err := &ConfirmationError{Err: ErrNotConfirmed}
	got := err.Error()
	if !strings.Contains(got, ErrNotConfirmed.Error()) {
		t.Errorf("Error() = %q, want it to mention the cause", got)
	}
}
