// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli_test

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"

	clicmd "github.com/jeremyhahn/go-luks2/internal/cli"
	"github.com/jeremyhahn/go-luks2/test/integration/cli/commands"
)

// TestEveryRegistryVerbHasADefinition is the parity suite's enumerating test:
// it fails when internal/cli's registry answers to a verb commands.Commands
// has no CommandDefinition for, so the table cannot silently fall behind
// the registry it is meant to describe.
func TestEveryRegistryVerbHasADefinition(t *testing.T) {
	defined := make(map[string]bool, len(commands.Commands))
	for _, c := range commands.Commands {
		defined[c.Verb] = true
	}
	for _, verb := range clicmd.RegisteredVerbs() {
		if !defined[verb] {
			t.Errorf("registry verb %q has no CommandDefinition in test/integration/cli/commands", verb)
		}
	}
}

// embeddedRun calls internal/cli.Run in-process, the "embedded" column of
// the parity suite's {CLI binary, embedded} runner.
func embeddedRun(args ...string) (stdout, stderr string, code int) {
	var out, errBuf bytes.Buffer
	code = clicmd.Run(context.Background(), append([]string{"luks2"}, args...), strings.NewReader(""), &out, &errBuf)
	return out.String(), errBuf.String(), code
}

// exitCodeOf extracts the process exit code runCLI's error carries, the
// same way internal/cli's exit-code table is read back in a test: 0 on a nil
// error (the process could still have failed to start, which is reported
// separately).
func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return -1
}

// TestCommandParityRefusesMissingArgumentsIdentically is the parity runner, crossed over the {CLI binary, embedded} columns commands.Commands
// enumerates: every registered verb, called with none of its required
// positional arguments, is refused with the same cryptsetup(8)-compatible
// exit code (1, "wrong parameters") whether dispatched through the built
// CLI binary (cmd/luks2, exec'd as a subprocess) or embedded
// (internal/cli.Run, called in-process). Neither column touches a device:
// every command here returns its UsageError during flag/argument parsing,
// before any I/O, so this runs without root and is the parity case every new
// verb extends rather than replaces.
func TestCommandParityRefusesMissingArgumentsIdentically(t *testing.T) {
	for _, c := range commands.Commands {
		if c.RequiredArgCount() == 0 {
			// "recovery generate" takes no positional argument at all: it
			// generates a key without touching a volume, so calling it
			// with none is the success path, not a usage error.
			continue
		}
		t.Run(c.Verb, func(t *testing.T) {
			verbParts := strings.Fields(c.Verb)

			_, _, embeddedCode := embeddedRun(verbParts...)
			if embeddedCode != 1 {
				t.Errorf("embedded %q with no arguments exited %d, want 1 (UsageError)", c.Verb, embeddedCode)
			}

			_, _, err := runCLI(verbParts...)
			binaryCode := exitCodeOf(err)
			if binaryCode != 1 {
				t.Errorf("CLI binary %q with no arguments exited %d, want 1 (UsageError)", c.Verb, binaryCode)
			}

			if embeddedCode != binaryCode {
				t.Errorf("%q: embedded exited %d but the CLI binary exited %d -- not parity", c.Verb, embeddedCode, binaryCode)
			}
		})
	}
}
