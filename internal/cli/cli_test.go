// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunNoArgsShowsUsage(t *testing.T) {
	stdout := &bytes.Buffer{}
	code := Run(context.Background(), []string{"luks2"}, &bytes.Buffer{}, stdout, &bytes.Buffer{})
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), "USAGE:") {
		t.Errorf("stdout = %q, want usage text", stdout.String())
	}
}

func TestRunHelp(t *testing.T) {
	stdout := &bytes.Buffer{}
	code := Run(context.Background(), []string{"luks2", "help"}, &bytes.Buffer{}, stdout, &bytes.Buffer{})
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "USAGE:") {
		t.Errorf("stdout = %q, want usage text", stdout.String())
	}
}

func TestRunVersion(t *testing.T) {
	stdout := &bytes.Buffer{}
	code := Run(context.Background(), []string{"luks2", "version"}, &bytes.Buffer{}, stdout, &bytes.Buffer{})
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "luks2") {
		t.Errorf("stdout = %q, want it to name luks2", stdout.String())
	}
}

// TestRunVersionFlags locks the existing CLI's documented compat surface
// (docs/volumes/cli.md): --version, -v and version all print "luks2
// version <X>", not just "luks2 <X>".
func TestRunVersionFlags(t *testing.T) {
	for _, arg := range []string{"--version", "-v", "version"} {
		t.Run(arg, func(t *testing.T) {
			stdout := &bytes.Buffer{}
			code := Run(context.Background(), []string{"luks2", arg}, &bytes.Buffer{}, stdout, &bytes.Buffer{})
			if code != 0 {
				t.Errorf("code = %d, want 0", code)
			}
			if !strings.Contains(stdout.String(), "luks2 version") {
				t.Errorf("stdout = %q, want %q", stdout.String(), "luks2 version")
			}
		})
	}
}

func TestRunUnknownCommand(t *testing.T) {
	stderr := &bytes.Buffer{}
	code := Run(context.Background(), []string{"luks2", "frobnicate"}, &bytes.Buffer{}, &bytes.Buffer{}, stderr)
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "Unknown command") {
		t.Errorf("stderr = %q, want it to mention the unknown command", stderr.String())
	}
}

func TestRunGroupWithNoSubcommandShowsUsage(t *testing.T) {
	stdout := &bytes.Buffer{}
	code := Run(context.Background(), []string{"luks2", "header"}, &bytes.Buffer{}, stdout, &bytes.Buffer{})
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), "restore") {
		t.Errorf("stdout = %q, want the header usage", stdout.String())
	}
}

func TestRunGroupWithUnknownSubcommand(t *testing.T) {
	stderr := &bytes.Buffer{}
	code := Run(context.Background(), []string{"luks2", "header", "frobnicate"}, &bytes.Buffer{}, &bytes.Buffer{}, stderr)
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "Unknown command") {
		t.Errorf("stderr = %q, want it to mention the unknown subcommand", stderr.String())
	}
}

func TestRunCommandUsageError(t *testing.T) {
	stderr := &bytes.Buffer{}
	code := Run(context.Background(), []string{"luks2", "close"}, &bytes.Buffer{}, &bytes.Buffer{}, stderr)
	if code != 1 {
		t.Errorf("code = %d, want 1 for a missing argument", code)
	}
	if stderr.Len() == 0 {
		t.Error("stderr should report the usage error")
	}
}

// TestRunMissingArgumentUsagePrintsOnStdout locks the existing CLI's
// documented compat surface: a missing-argument usage message for each of
// these commands is printed on STDOUT (as the pre-rewrite CLI did), not only
// folded into the generic stderr error line.
func TestRunMissingArgumentUsagePrintsOnStdout(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"luks2", "create"}, "Usage: luks2 create"},
		{[]string{"luks2", "open"}, "Usage: luks2 open"},
		{[]string{"luks2", "open", "/dev/sda1"}, "Usage: luks2 open"},
		{[]string{"luks2", "close"}, "Usage: luks2 close"},
		{[]string{"luks2", "mount"}, "Usage: luks2 mount"},
		{[]string{"luks2", "mount", "myvolume"}, "Usage: luks2 mount"},
		{[]string{"luks2", "unmount"}, "Usage: luks2 unmount"},
		{[]string{"luks2", "info"}, "Usage: luks2 info"},
		{[]string{"luks2", "wipe"}, "Usage: luks2 wipe"},
	}
	for _, tc := range tests {
		t.Run(strings.Join(tc.args[1:], " "), func(t *testing.T) {
			stdout := &bytes.Buffer{}
			code := Run(context.Background(), tc.args, &bytes.Buffer{}, stdout, &bytes.Buffer{})
			if code != 1 {
				t.Errorf("code = %d, want 1", code)
			}
			if !strings.Contains(stdout.String(), tc.want) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tc.want)
			}
		})
	}
}

// TestRunCreateFileMissingSizePrintsSizeRequired locks docs/volumes/cli.md's
// "Error: Size required for file volumes" text, which the pre-rewrite CLI
// printed on stdout for a file path given with no size.
func TestRunCreateFileMissingSizePrintsSizeRequired(t *testing.T) {
	stdout := &bytes.Buffer{}
	code := Run(context.Background(), []string{"luks2", "create", filepath.Join(t.TempDir(), "vol.luks")}, &bytes.Buffer{}, stdout, &bytes.Buffer{})
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), "Size required") {
		t.Errorf("stdout = %q, want it to contain %q", stdout.String(), "Size required")
	}
}

func TestRegistryHasEveryImplementedCommand(t *testing.T) {
	reg := registry()
	for _, name := range []string{
		"create", "open", "close", "mount", "unmount", "info", "keyslots", "testkey",
		"addkey", "changekey", "removekey", "killslot", "recovery", "token", "wipe", "header", "isluks",
	} {
		if _, ok := reg[name]; !ok {
			t.Errorf("registry() is missing %q", name)
		}
	}
}

// TestRegisteredVerbs locks RegisteredVerbs to what test/integration/cli's
// parity table (commands.Commands) expects: every top-level command with no
// subcommands reported bare, and "header" reported as its one subcommand
// "header restore" rather than bare "header" -- the two branches
// RegisteredVerbs' loop takes.
func TestRegisteredVerbs(t *testing.T) {
	got := make(map[string]bool)
	for _, v := range RegisteredVerbs() {
		got[v] = true
	}

	want := []string{
		"create", "open", "close", "mount", "unmount", "info", "keyslots",
		"testkey", "addkey", "changekey", "removekey", "killslot",
		"recovery generate", "recovery add", "recovery verify",
		"token list", "token show", "token export", "token import",
		"token remove", "token free", "token exists", "token count",
		"wipe", "header show", "header secondary", "header restore", "isluks",
	}
	if len(got) != len(want) {
		t.Errorf("RegisteredVerbs() = %v, want exactly %v", RegisteredVerbs(), want)
	}
	for _, v := range want {
		if !got[v] {
			t.Errorf("RegisteredVerbs() is missing %q", v)
		}
	}
	if got["header"] {
		t.Error(`RegisteredVerbs() reports bare "header", but it only has a subcommand`)
	}
	if got["recovery"] {
		t.Error(`RegisteredVerbs() reports bare "recovery", but it only has a subcommand`)
	}
	if got["token"] {
		t.Error(`RegisteredVerbs() reports bare "token", but it only has a subcommand`)
	}
}
