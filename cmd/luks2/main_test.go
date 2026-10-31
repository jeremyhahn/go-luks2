// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/cli"
)

// cliChildEnv names the variable that turns this test binary, re-executed by
// inCLIChild, into the child that runs one test against the real CLI. cli.Run
// hardens the process it runs in, and RLIMIT_CORE 0/0 is permanent for an
// unprivileged process: run in the test binary itself, the real CLI would
// leave TestRunHardensBeforeFirstSecret unable to start its probe from a
// process that would dump core, on a second -count or in a shuffled order.
const cliChildEnv = "LUKS2_CLI_CHILD"

// cliChildDone marks, on the child's output, that the selected test ran to
// its end, so a -test.run that selects nothing cannot pass for it.
const cliChildDone = "cli-child-done:"

// inCLIChild reports whether this process is t's child. In the test binary
// itself it re-executes the binary with only t selected, fails t unless the
// child passed and ran t to its end, and returns false; the caller then
// returns, so its CLI call happens only in the child.
func inCLIChild(t *testing.T) bool {
	t.Helper()
	if os.Getenv(cliChildEnv) == t.Name() {
		t.Cleanup(func() { fmt.Println(cliChildDone, t.Name()) })
		return true
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1") // #nosec G204 -- the test binary re-executing itself
	cmd.Env = append(os.Environ(), cliChildEnv+"="+t.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child %s: %v\n%s", t.Name(), err, out)
	}
	if !strings.Contains(string(out), cliChildDone+" "+t.Name()) {
		t.Fatalf("child %s did not run the test:\n%s", t.Name(), out)
	}
	return false
}

// fakeCLI swaps cliRun for fn until t ends, so a test of main's own wiring
// does not harden the test binary.
func fakeCLI(t *testing.T, fn func(context.Context, []string, io.Reader, io.Writer, io.Writer) int) {
	t.Helper()
	old := cliRun
	cliRun = fn
	t.Cleanup(func() { cliRun = old })
}

func TestRunHelp(t *testing.T) {
	if !inCLIChild(t) {
		return
	}
	stdout := &bytes.Buffer{}
	code := run([]string{"luks2", "help"}, &bytes.Buffer{}, stdout, &bytes.Buffer{})
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if stdout.Len() == 0 {
		t.Error("stdout should carry the usage text")
	}
}

// TestRunHandsOffToCLI checks run's own wiring against a fake CLI: Version
// set first, the arguments and streams passed through unchanged, a live
// context that is canceled once run returns, and the CLI's exit code.
func TestRunHandsOffToCLI(t *testing.T) {
	oldVersion, oldCLIVersion := version, cli.Version
	version = "wiring-version-marker"
	defer func() { version, cli.Version = oldVersion, oldCLIVersion }()

	args := []string{"luks2", "status", "vol"}
	stdin, stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}, &bytes.Buffer{}
	var gotCtx context.Context
	called := false
	fakeCLI(t, func(ctx context.Context, a []string, in io.Reader, out, errOut io.Writer) int {
		called = true
		gotCtx = ctx
		if cli.Version != "wiring-version-marker" {
			t.Errorf("cli.Version = %q at the call, want %q", cli.Version, "wiring-version-marker")
		}
		if strings.Join(a, " ") != strings.Join(args, " ") {
			t.Errorf("args = %q, want %q", a, args)
		}
		if in != stdin || out != stdout || errOut != stderr {
			t.Error("run did not pass its streams through unchanged")
		}
		if ctx.Err() != nil {
			t.Errorf("context already done at the call: %v", ctx.Err())
		}
		return 3
	})

	if code := run(args, stdin, stdout, stderr); code != 3 {
		t.Errorf("code = %d, want the CLI's 3", code)
	}
	if !called {
		t.Fatal("run did not call the CLI")
	}
	if gotCtx.Err() == nil {
		t.Error("run returned with its signal context still live")
	}
}

func TestMainCallsOSExitWithRunsCode(t *testing.T) {
	oldExit := osExit
	oldArgs := os.Args
	defer func() {
		osExit = oldExit
		os.Args = oldArgs
	}()

	var gotArgs []string
	fakeCLI(t, func(_ context.Context, a []string, in io.Reader, out, errOut io.Writer) int {
		gotArgs = a
		if in != os.Stdin || out != os.Stdout || errOut != os.Stderr {
			t.Error("main did not hand run the process's standard streams")
		}
		return 7
	})

	var gotCode int
	exited := false
	osExit = func(code int) {
		gotCode = code
		exited = true
	}
	os.Args = []string{"luks2", "help"}

	main()

	if !exited {
		t.Fatal("main: want osExit to be called")
	}
	if gotCode != 7 {
		t.Errorf("code = %d, want run's 7", gotCode)
	}
	if strings.Join(gotArgs, " ") != "luks2 help" {
		t.Errorf("args = %q, want os.Args", gotArgs)
	}
}
