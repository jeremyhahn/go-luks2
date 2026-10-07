// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package keyprovider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandTakesTheSelectedLine(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		line   int
		want   string
	}{
		{
			name:   "first line",
			stdout: "alpha\nbeta\ngamma\n",
			line:   1,
			want:   "alpha",
		},
		{
			name:   "fifth line, the fido2-cred credential id",
			stdout: "one\ntwo\nthree\nfour\nY3JlZA==\nsix\n",
			line:   fido2CredIDLine,
			want:   "Y3JlZA==",
		},
		{
			name:   "last line without a terminator",
			stdout: "one\ntwo",
			line:   2,
			want:   "two",
		},
		{
			name:   "a carriage return is not part of the credential",
			stdout: "one\r\ntwo\r\n",
			line:   1,
			want:   "one",
		},
		{
			// Line 0 is the whole of stdout VERBATIM. The trailing newline is
			// kept deliberately -- see the Command doc comment and the
			// cryptsetup --key-file measurement it refers to.
			name:   "line zero keeps the trailing newline",
			stdout: "secret\n",
			line:   0,
			want:   "secret\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewCommand(helperScript(t, "helper", tt.stdout), WithLine(tt.line))
			if err != nil {
				t.Fatalf("NewCommand() error = %v", err)
			}

			got, err := p.Passphrase(context.Background())
			if err != nil {
				t.Fatalf("Passphrase() error = %v", err)
			}
			defer mustDestroy(t, got)

			if s := string(openSecret(t, got)); s != tt.want {
				t.Errorf("credential = %q, want %q", s, tt.want)
			}
		})
	}
}

// TestNewCommandRefusesBadInput covers what used to be validated lazily, at
// Passphrase, and is now validated eagerly, at construction: a caller finds
// out a path is unusable before anything execs.
func TestNewCommandRefusesBadInput(t *testing.T) {
	tests := []struct {
		name string
		path string
		opts []CommandOption
	}{
		{name: "no path", path: ""},
		{name: "relative path", path: "helper"},
		{name: "bare name", path: "sub/../helper"},
		{name: "negative line", path: "/usr/bin/true", opts: []CommandOption{WithLine(-1)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewCommand(tt.path, tt.opts...); !errors.Is(err, ErrInvalidArgument) {
				t.Errorf("NewCommand() error = %v, want errors.Is(_, ErrInvalidArgument)", err)
			}
		})
	}
}

func TestCommandRefusesUnusableOutput(t *testing.T) {
	tests := []struct {
		name    string
		provide func(t *testing.T) *Command
		want    error
	}{
		{
			name: "fewer lines than the protocol promises",
			provide: func(t *testing.T) *Command {
				p, err := NewCommand(helperScript(t, "helper", "one\ntwo\n"), WithLine(5))
				if err != nil {
					t.Fatal(err)
				}
				return p
			},
			want: ErrHelperOutput,
		},
		{
			name: "the selected line is empty",
			provide: func(t *testing.T) *Command {
				p, err := NewCommand(helperScript(t, "helper", "one\n\nthree\n"), WithLine(2))
				if err != nil {
					t.Fatal(err)
				}
				return p
			},
			want: ErrHelperOutput,
		},
		{
			name: "no output at all",
			provide: func(t *testing.T) *Command {
				p, err := NewCommand(helperScript(t, "helper", ""), WithLine(0))
				if err != nil {
					t.Fatal(err)
				}
				return p
			},
			want: ErrHelperOutput,
		},
		{
			name: "the helper refused",
			provide: func(t *testing.T) *Command {
				p, err := NewCommand(helperScriptWith(t, "helper", "", "FIDO_ERR_NO_CREDENTIALS", 1), WithLine(1))
				if err != nil {
					t.Fatal(err)
				}
				return p
			},
			want: ErrHelperFailed,
		},
		{
			name: "the helper does not exist",
			provide: func(t *testing.T) *Command {
				p, err := NewCommand(filepath.Join(t.TempDir(), "absent"), WithLine(1))
				if err != nil {
					t.Fatal(err)
				}
				return p
			},
			want: ErrHelperFailed,
		},
		{
			name: "output larger than the bound is refused, not truncated",
			provide: func(t *testing.T) *Command {
				body := strings.Repeat("A", maxHelperOutput+1)
				p, err := NewCommand(helperScript(t, "helper", body), WithLine(0))
				if err != nil {
					t.Fatal(err)
				}
				return p
			},
			want: ErrHelperOutput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := tt.provide(t)

			got, err := p.Passphrase(context.Background())
			if err == nil {
				mustDestroy(t, got)
				t.Fatalf("Passphrase() succeeded, want %v", tt.want)
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("Passphrase() error = %v, want errors.Is(_, %v)", err, tt.want)
			}
		})
	}
}

// TestHelperErrorCarriesWhatTheHelperSaid pins the one thing an operator
// actually needs out of a refused assertion: the authenticator's own
// sentence.
func TestHelperErrorCarriesWhatTheHelperSaid(t *testing.T) {
	p, err := NewCommand(helperScriptWith(t, "helper", "", "FIDO_ERR_PIN_INVALID", 1), WithLine(1))
	if err != nil {
		t.Fatal(err)
	}

	_, err = p.Passphrase(context.Background())
	if err == nil {
		t.Fatal("Passphrase() succeeded, want a refusal")
	}

	var helperErr *HelperError
	if !errors.As(err, &helperErr) {
		t.Fatalf("error = %v, want a *HelperError", err)
	}
	if helperErr.ExitCode != 1 {
		t.Errorf("ExitCode = %d, want 1", helperErr.ExitCode)
	}
	if !strings.Contains(helperErr.Stderr, "FIDO_ERR_PIN_INVALID") {
		t.Errorf("Stderr = %q, want it to carry the helper's diagnostic", helperErr.Stderr)
	}
	if !strings.Contains(helperErr.Error(), "FIDO_ERR_PIN_INVALID") {
		t.Errorf("Error() = %q, want it to carry the helper's diagnostic", helperErr.Error())
	}
}

// TestCommandHonorsContext proves the unattended case: a helper waiting for
// a touch that never comes has to end.
func TestCommandHonorsContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocking")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nsleep 60\n"), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatalf("failed to write helper: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p, err := NewCommand(path, WithLine(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Passphrase(ctx); err == nil {
		t.Fatal("Passphrase() succeeded with a canceled context, want a refusal")
	}
}

// TestCommandRefusesOverlongOutputWithoutDeadlocking pins the LIVENESS half
// of the output bound, which the bounded-output case above cannot reach.
//
// That case writes maxHelperOutput+1 bytes: readFullish fills dst, peeks the
// one extra byte and refuses -- and the helper has already exited, because
// its whole output fit in the pipe. Nothing is left writing. A helper that
// overruns by more than a pipe buffer is a different situation: readFullish
// stops reading for good the moment it refuses, so the helper blocks in
// write(2) on a pipe nobody will drain again, and cmd.Wait() blocks waiting
// for a process that cannot exit. StdoutPipe's read end is closed by Wait,
// i.e. only AFTER the exit that is not coming.
//
// With a deadline-carrying context CommandContext eventually kills the
// helper and the deadlock unwedges. With context.Background() -- what an
// unattended UnlockWithProvider at boot typically passes, and what this test
// uses on purpose -- nothing ever interrupts it: Passphrase never returns,
// holding the child and maxHelperOutput bytes of locked memory. An unlock
// that hangs forever is strictly worse than one that fails.
func TestCommandRefusesOverlongOutputWithoutDeadlocking(t *testing.T) {
	// Comfortably past maxHelperOutput + 1 + a full pipe buffer (64 KiB on
	// Linux), so the helper is certainly still blocked in write(2) when
	// readFullish gives up.
	const flood = 4 * maxHelperOutput

	path := filepath.Join(t.TempDir(), "flood")
	script := fmt.Sprintf("#!/bin/sh\nyes A | head -c %d\n", flood)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatalf("failed to write helper: %v", err)
	}

	// Called directly, with no wall-clock guard (#233). A deadlock here does
	// not return, and the test binary's -timeout ends the run with every
	// goroutine's stack, naming this test.
	p, err := NewCommand(path, WithLine(0))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := p.Passphrase(context.Background())
	if credential != nil {
		mustDestroy(t, credential)
	}
	if !errors.Is(err, ErrHelperOutput) {
		t.Errorf("Passphrase() error = %v, want errors.Is(_, ErrHelperOutput)", err)
	}
}

// TestHelperDiagnosticsAreBounded: a helper that writes without end must not
// grow this process through a failure path.
func TestHelperDiagnosticsAreBounded(t *testing.T) {
	noisy := helperScriptWith(t, "helper", "", strings.Repeat("E", maxHelperStderr*3), 1)

	p, err := NewCommand(noisy, WithLine(1))
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Passphrase(context.Background())
	if err == nil {
		t.Fatal("Passphrase() succeeded, want a refusal")
	}

	var helperErr *HelperError
	if !errors.As(err, &helperErr) {
		t.Fatalf("error = %v, want a *HelperError", err)
	}
	if len(helperErr.Stderr) > maxHelperStderr {
		t.Errorf("kept %d bytes of stderr, want at most %d", len(helperErr.Stderr), maxHelperStderr)
	}
	if len(helperErr.Stderr) == 0 {
		t.Error("no stderr was kept at all; the operator gets no reason")
	}
}

// TestTooFewLinesWithoutATrailingNewline covers the other shape of the same
// refusal: a helper whose last line has no terminator.
func TestTooFewLinesWithoutATrailingNewline(t *testing.T) {
	p, err := NewCommand(helperScript(t, "helper", "one\ntwo\nthree"), WithLine(6))
	if err != nil {
		t.Fatal(err)
	}

	_, err = p.Passphrase(context.Background())
	if !errors.Is(err, ErrHelperOutput) {
		t.Fatalf("error = %v, want errors.Is(_, ErrHelperOutput)", err)
	}
	// The message says how many lines there actually were, which is the one
	// fact that tells a protocol mismatch from a broken helper.
	if !strings.Contains(err.Error(), "3 line") {
		t.Errorf("error = %v, want it to report 3 lines", err)
	}
}
