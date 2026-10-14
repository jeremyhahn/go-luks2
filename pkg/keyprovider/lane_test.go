// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package keyprovider

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/command"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// Regression tests for #246 D5-D7 and D9, carried over from pkg/luks2 with
// the code they pin (#271): how a helper is found and what it inherits, a
// helper whose output outlives it, and the FIDO2 device argument and
// requirement round trip.

// TestCommandRefusesAPathItWouldHaveToSearchFor is #246 D5. The doc said the
// helper is not searched for on PATH, and exec.CommandContext searches for
// any name without a slash: a helper named "fido2-assert" ran whatever the
// invoking user's PATH put first. Here PATH names a directory holding a
// helper that answers, and it must not be run.
func TestCommandRefusesAPathItWouldHaveToSearchFor(t *testing.T) {
	dir := filepath.Dir(helperScript(t, "substituted", "from-the-users-path\n"))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Chdir(dir)

	for _, name := range []string{"substituted", "./substituted", "sub/../substituted"} {
		if _, err := NewCommand(name, WithLine(1)); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("NewCommand(%q) = %v, want ErrInvalidArgument", name, err)
		}
	}
}

// TestCommandGivesTheHelperAMinimalEnvironment is #246 D5's second half: the
// helper inherited this process's whole environment, so anything the
// invoking user exported -- LD_PRELOAD, a library's debug hook -- reached
// the program that produces the credential. It gets the fixed system
// environment (internal/command.System) and what the caller passes in
// WithEnv, and nothing else.
func TestCommandGivesTheHelperAMinimalEnvironment(t *testing.T) {
	t.Setenv("LUKS2_TEST_INHERITED", "inherited")

	path := filepath.Join(privateDir(t), "env")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n/usr/bin/env\n"), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatal(err)
	}
	p, err := NewCommand(path, WithLine(0), WithEnv("FIDO_DEBUG=1"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.Passphrase(context.Background())
	if err != nil {
		t.Fatalf("Passphrase() = %v", err)
	}
	defer mustDestroy(t, out)

	got := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(openSecret(t, out))), "\n") {
		got[line] = true
	}
	want := map[string]bool{"FIDO_DEBUG=1": true}
	for _, e := range command.System().Env {
		want[e] = true
	}
	// sh may export PWD, SHLVL and _ on its own; those are the shell's, not
	// this process's.
	for line := range got {
		name, _, _ := strings.Cut(line, "=")
		if want[line] || name == "PWD" || name == "SHLVL" || name == "_" || name == "OLDPWD" {
			continue
		}
		t.Errorf("the helper inherited %q", line)
	}
	for line := range want {
		if !got[line] {
			t.Errorf("the helper's environment lacks %q", line)
		}
	}
}

// lingeringHelper writes a helper that leaves a grandchild holding its
// stdout and stderr, writes its credential, says so on the returned FIFO,
// and then either exits or -- block -- waits as a helper waiting for a
// touch does. The grandchild lives for seconds, not forever, so a
// regression ends instead of hanging; it is killed when the test ends
// either way.
func lingeringHelper(t *testing.T, seconds int, block bool) (path, fifo string) {
	t.Helper()
	dir := privateDir(t)
	pidFile := filepath.Join(dir, "grandchild.pid")
	fifo = filepath.Join(dir, "started")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "lingering")
	script := "#!/bin/sh\nsleep " + strconv.Itoa(seconds) + " &\necho $! > " + shellQuote(pidFile) +
		"\necho the-credential\necho started > " + shellQuote(fifo) + "\n"
	if block {
		script += "exec sleep " + strconv.Itoa(seconds) + "\n"
	}
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if b, err := os.ReadFile(pidFile); err == nil { // #nosec G304 -- under t.TempDir()
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	return path, fifo
}

// awaitStarted blocks until the helper has written its credential.
func awaitStarted(t *testing.T, fifo string) {
	t.Helper()
	// Opening the FIFO read-write never blocks, and a FIFO is pollable, so
	// the read below honors a deadline: a helper that never starts (one
	// Command refused, say) fails the test here instead of at -timeout.
	f, err := os.OpenFile(fifo, os.O_RDWR, 0) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := f.SetReadDeadline(time.Now().Add(helperStartBound)); err != nil {
		t.Fatal(err)
	}
	var got []byte
	buf := make([]byte, 64)
	for !strings.Contains(string(got), "\n") {
		n, err := f.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			t.Fatalf("the helper did not write \"started\" to %s within %v: got %q, %v", fifo, helperStartBound, got, err)
		}
	}
	if strings.TrimSpace(string(got)) != "started" {
		t.Fatalf("the helper did not start: %q", got)
	}
}

// helperStartBound is how long awaitStarted waits for a helper to start.
const helperStartBound = 30 * time.Second

// TestCommandEndsWhenItsContextDoes is #246 D6: the stdout read ignored ctx,
// so a helper whose grandchild kept stdout open held Passphrase past
// cancellation until the grandchild exited -- for ever, for a daemon. Here
// the helper is still waiting (for a touch, say) when ctx ends; the call
// returns the context's error. (A regression returns a helper failure once
// the grandchild exits, and fails.)
func TestCommandEndsWhenItsContextDoes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	path, fifo := lingeringHelper(t, 20, true)
	p, err := NewCommand(path, WithLine(1))
	if err != nil {
		t.Fatal(err)
	}
	p.sys.waitDelay = time.Millisecond // not package state: this Command's own seam

	done := make(chan error, 1)
	go func() {
		credential, err := p.Passphrase(ctx)
		if credential != nil {
			_ = credential.Destroy()
		}
		done <- err
	}()
	awaitStarted(t, fifo)
	cancel()

	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Passphrase() after cancel = %v, want context.Canceled", err)
	}
}

// TestCommandStopsWaitingForAnExitedHelpersOutput is D6 with no deadline in
// ctx at all -- what an unattended unlock at boot passes. The helper
// exited; a process it started still holds the pipe; the read is cut off
// after sys.waitDelay and refused, not trusted. (A regression returns the
// credential once the grandchild exits, and fails.)
func TestCommandStopsWaitingForAnExitedHelpersOutput(t *testing.T) {
	path, fifo := lingeringHelper(t, 20, false)
	p, err := NewCommand(path, WithLine(1))
	if err != nil {
		t.Fatal(err)
	}
	p.sys.waitDelay = time.Millisecond

	done := make(chan error, 1)
	go func() {
		credential, err := p.Passphrase(context.Background())
		if credential != nil {
			_ = credential.Destroy()
		}
		done <- err
	}()
	awaitStarted(t, fifo)

	if err := <-done; !errors.Is(err, ErrHelperOutput) || !strings.Contains(err.Error(), "still held open") {
		t.Fatalf("Passphrase() = %v, want ErrHelperOutput naming the held pipe", err)
	}
}

// TestFIDO2HelpersRequireADeviceAndEndTheirOptions is #246 D7: an empty
// device went to the helper as an empty-string argument, and a device was
// not separated from the options, so a name starting with "-" was parsed as
// one.
func TestFIDO2HelpersRequireADeviceAndEndTheirOptions(t *testing.T) {
	params := fido2TestParams(t)
	if _, err := NewFIDO2(params); !errors.Is(err, ErrNoDevice) {
		t.Fatalf("NewFIDO2 with no device = %v, want ErrNoDevice", err)
	}
	if _, err := NewFIDO2Credential(context.Background(), FIDO2CredentialParams{}); !errors.Is(err, ErrNoDevice) {
		t.Fatalf("NewFIDO2Credential with no device = %v, want ErrNoDevice", err)
	}

	p, err := NewFIDO2(params, WithDevice("-r"))
	if err != nil {
		t.Fatal(err)
	}
	args := p.cmd.args
	if len(args) < 2 || args[len(args)-2] != "--" || args[len(args)-1] != "-r" {
		t.Fatalf("assert argv = %q, want it to end with -- and the device", args)
	}

	helper, argsFile, _ := echoingHelper(t, "fido2-cred", "1\n2\n3\n4\naWQ=\n")
	if _, err := NewFIDO2Credential(context.Background(), FIDO2CredentialParams{}, WithFIDO2Tools(helper, ""), WithDevice("-v")); err != nil {
		t.Fatal(err)
	}
	if got := readFixture(t, argsFile); !strings.HasSuffix(got, "--\n-v\nes256\n") {
		t.Fatalf("cred argv = %q, want -- before the device", got)
	}
}

// TestFIDO2TokenRoundTripsEveryRequirement is #246 D9: fido2Token wrote only
// the user-presence requirement, so a binding enrolled with a PIN or user
// verification was rebuilt from its token -- FromToken, what an unlock from
// the header uses -- into one that asked for neither.
func TestFIDO2TokenRoundTripsEveryRequirement(t *testing.T) {
	for _, params := range []FIDO2Params{
		{CredentialID: []byte("c"), Salt: []byte("s"), ClientPIN: true, UserVerification: true},
		{CredentialID: []byte("c"), Salt: []byte("s"), UserPresence: true},
	} {
		token := fido2Token(params)
		encoded, err := json.Marshal(token)
		if err != nil {
			t.Fatal(err)
		}
		var back luks2.Token
		if err := json.Unmarshal(encoded, &back); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{
			`"fido2-clientPin-required":` + strconv.FormatBool(params.ClientPIN),
			`"fido2-uv-required":` + strconv.FormatBool(params.UserVerification),
		} {
			if !strings.Contains(string(encoded), field) {
				t.Errorf("token %s does not record %s", encoded, field)
			}
		}

		round, err := fido2ParamsFromToken(back)
		if err != nil {
			t.Fatal(err)
		}
		if round.ClientPIN != params.ClientPIN || round.UserVerification != params.UserVerification || round.UserPresence != params.UserPresence {
			t.Fatalf("round trip = %+v, want the requirements of %+v", round, params)
		}

		p, err := FromToken(back, WithDevice("/dev/hidraw9"))
		if err != nil {
			t.Fatal(err)
		}
		args := strings.Join(p.(*FIDO2).cmd.args, " ")
		if strings.Contains(args, "pin=true") != params.ClientPIN || strings.Contains(args, " -v") != params.UserVerification {
			t.Fatalf("argv from the token = %q, want the requirements of %+v", args, params)
		}
	}
}
