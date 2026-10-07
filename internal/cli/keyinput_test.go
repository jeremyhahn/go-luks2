// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/secret"
)

func readBack(t *testing.T, custody secret.Custody, e interface{ Destroy() error }) string {
	t.Helper()
	type borrower interface {
		WithBytes(func([]byte) error) error
	}
	b, ok := e.(borrower)
	if !ok {
		t.Fatalf("enclave does not support WithBytes")
	}
	var out string
	if err := b.WithBytes(func(p []byte) error {
		out = string(p)
		return nil
	}); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
	return out
}

func TestDefaultTerminalDelegates(t *testing.T) {
	var term defaultTerminal
	if term.IsTerminal(-1) {
		t.Error("IsTerminal(-1) = true, want false for an invalid descriptor")
	}
	if _, err := term.ReadPassword(-1); err == nil {
		t.Error("ReadPassword(-1): want an error for an invalid descriptor")
	}
}

func TestReadKeyFileReadsTheWholeInput(t *testing.T) {
	custody := secret.System()
	e, err := readKeyFile(custody, strings.NewReader("hunter2\n"), "test", maxKeyFileSize)
	if err != nil {
		t.Fatalf("readKeyFile: %v", err)
	}
	defer custody.Release(e)
	if got := readBack(t, custody, e); got != "hunter2\n" {
		t.Errorf("readKeyFile content = %q, want %q", got, "hunter2\n")
	}
}

func TestReadKeyFileEmptyIsRefused(t *testing.T) {
	custody := secret.System()
	if _, err := readKeyFile(custody, strings.NewReader(""), "test", maxKeyFileSize); !errors.Is(err, ErrEmptyCredential) {
		t.Fatalf("readKeyFile(\"\") error = %v, want ErrEmptyCredential", err)
	}
}

func TestReadKeyFileTooLarge(t *testing.T) {
	custody := secret.System()
	// A small limit, not maxKeyFileSize itself: proving the boundary logic
	// does not require allocating anywhere near 8 MiB of locked memory.
	_, err := readKeyFile(custody, strings.NewReader(strings.Repeat("a", 20)), "test", 16)
	if !errors.Is(err, ErrKeyFileTooLarge) {
		t.Fatalf("readKeyFile(too large) error = %v, want ErrKeyFileTooLarge", err)
	}
}

func TestReadKeyLineStopsAtNewline(t *testing.T) {
	custody := secret.System()
	e, err := readKeyLine(custody, strings.NewReader("line one\nline two\n"), maxKeyFileSize)
	if err != nil {
		t.Fatalf("readKeyLine: %v", err)
	}
	defer custody.Release(e)
	if got := readBack(t, custody, e); got != "line one" {
		t.Errorf("readKeyLine content = %q, want %q", got, "line one")
	}
}

func TestReadKeyLineGrowsPastInitialCapacity(t *testing.T) {
	custody := secret.System()
	long := strings.Repeat("x", 200) // > the buffer's 64-byte initial capacity
	e, err := readKeyLine(custody, strings.NewReader(long+"\n"), maxKeyFileSize)
	if err != nil {
		t.Fatalf("readKeyLine: %v", err)
	}
	defer custody.Release(e)
	if got := readBack(t, custody, e); got != long {
		t.Errorf("readKeyLine content length = %d, want %d", len(got), len(long))
	}
}

func TestReadKeyLineEOFWithoutNewline(t *testing.T) {
	custody := secret.System()
	e, err := readKeyLine(custody, strings.NewReader("no newline"), maxKeyFileSize)
	if err != nil {
		t.Fatalf("readKeyLine: %v", err)
	}
	defer custody.Release(e)
	if got := readBack(t, custody, e); got != "no newline" {
		t.Errorf("readKeyLine content = %q, want %q", got, "no newline")
	}
}

func TestReadKeyLineTooLarge(t *testing.T) {
	custody := secret.System()
	_, err := readKeyLine(custody, strings.NewReader(strings.Repeat("a", 20)), 16)
	if !errors.Is(err, ErrKeyFileTooLarge) {
		t.Fatalf("readKeyLine(too large) error = %v, want ErrKeyFileTooLarge", err)
	}
}

func TestReadKeyLineEmptyIsRefused(t *testing.T) {
	custody := secret.System()
	if _, err := readKeyLine(custody, strings.NewReader("\n"), maxKeyFileSize); !errors.Is(err, ErrEmptyCredential) {
		t.Fatalf("readKeyLine(empty line) error = %v, want ErrEmptyCredential", err)
	}
}

func TestReadPassphraseFromExplicitKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("filekey"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	src := keySource{path: path, given: func() bool { return true }}
	pass, err := readPassphrase(e, "prompt: ", false, src)
	if err != nil {
		t.Fatalf("readPassphrase: %v", err)
	}
	defer e.custody.Release(pass)
	if got := readBack(t, e.custody, pass); got != "filekey" {
		t.Errorf("content = %q, want filekey", got)
	}
}

func TestReadPassphraseFromStdinKeyFile(t *testing.T) {
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("stdinkey"))
	src := keySource{path: stdinKeyFile, given: func() bool { return true }}
	pass, err := readPassphrase(e, "prompt: ", false, src)
	if err != nil {
		t.Fatalf("readPassphrase: %v", err)
	}
	defer e.custody.Release(pass)
	if got := readBack(t, e.custody, pass); got != "stdinkey" {
		t.Errorf("content = %q, want stdinkey", got)
	}
}

func TestReadPassphraseEmptyKeyFilePathIsRefused(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	src := keySource{path: "", given: func() bool { return true }}
	if _, err := readPassphrase(e, "prompt: ", false, src); !errors.Is(err, ErrEmptyKeyFilePath) {
		t.Fatalf("readPassphrase error = %v, want ErrEmptyKeyFilePath", err)
	}
}

func TestReadPassphraseMissingKeyFile(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	src := keySource{path: filepath.Join(t.TempDir(), "nope"), given: func() bool { return true }}
	if _, err := readPassphrase(e, "prompt: ", false, src); err == nil {
		t.Fatal("readPassphrase: want an error for a missing key file")
	}
}

func TestReadPassphraseFromPipedStdin(t *testing.T) {
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("pipedkey\n"))
	pass, err := readPassphrase(e, "prompt: ", false, keySource{})
	if err != nil {
		t.Fatalf("readPassphrase: %v", err)
	}
	defer e.custody.Release(pass)
	if got := readBack(t, e.custody, pass); got != "pipedkey" {
		t.Errorf("content = %q, want pipedkey", got)
	}
}

func TestReadPassphrasePromptsTheTerminal(t *testing.T) {
	e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})
	e.term = &fakeTerminal{isTerm: true, answers: [][]byte{[]byte("typed")}}
	e.getStdinFd = func() int { return 0 }

	pass, err := readPassphrase(e, "Enter passphrase: ", false, keySource{})
	if err != nil {
		t.Fatalf("readPassphrase: %v", err)
	}
	defer e.custody.Release(pass)
	if got := readBack(t, e.custody, pass); got != "typed" {
		t.Errorf("content = %q, want typed", got)
	}
	if !strings.Contains(stdout.String(), "Enter passphrase: ") {
		t.Errorf("stdout = %q, want the prompt", stdout.String())
	}
}

func TestReadPassphrasePromptConfirmationMatches(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	e.term = &fakeTerminal{isTerm: true, answers: [][]byte{[]byte("same"), []byte("same")}}
	e.getStdinFd = func() int { return 0 }

	pass, err := readPassphrase(e, "Enter: ", true, keySource{})
	if err != nil {
		t.Fatalf("readPassphrase: %v", err)
	}
	e.custody.Release(pass)
}

func TestReadPassphrasePromptConfirmationMismatch(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	e.term = &fakeTerminal{isTerm: true, answers: [][]byte{[]byte("one"), []byte("two")}}
	e.getStdinFd = func() int { return 0 }

	_, err := readPassphrase(e, "Enter: ", true, keySource{})
	if !errors.Is(err, ErrPassphraseMismatch) {
		t.Fatalf("readPassphrase error = %v, want ErrPassphraseMismatch", err)
	}
}

func TestReadPassphraseTerminalReadFailure(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	e.term = &fakeTerminal{isTerm: true, failAt: 1}
	e.getStdinFd = func() int { return 0 }

	if _, err := readPassphrase(e, "Enter: ", false, keySource{}); err == nil {
		t.Fatal("readPassphrase: want an error when the terminal read fails")
	}
}

func TestEnclaveBufferGrowsAndReleases(t *testing.T) {
	custody := secret.System()
	b := newEnclaveBuffer(custody, "test", 2)
	for _, c := range []byte("abcdef") {
		if err := b.append(c); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if b.len() != 6 {
		t.Fatalf("len() = %d, want 6", b.len())
	}
	result, err := b.finish()
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	defer custody.Release(result)
	if got := readBack(t, custody, result); got != "abcdef" {
		t.Errorf("content = %q, want abcdef", got)
	}
}

func TestEnclaveBufferReleaseWithoutFinishIsSafe(t *testing.T) {
	custody := secret.System()
	b := newEnclaveBuffer(custody, "test", 4)
	if err := b.append('x'); err != nil {
		t.Fatalf("append: %v", err)
	}
	b.release()
	b.release() // idempotent
}
