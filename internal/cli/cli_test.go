// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"
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

// untouchedReader fails the test if anything reads it.
type untouchedReader struct{ t *testing.T }

func (r untouchedReader) Read([]byte) (int, error) {
	r.t.Error("stdin was read after process hardening failed")
	return 0, errors.New("untouchedReader read")
}

func TestRunFailsClosedWhenHardeningFails(t *testing.T) {
	cause := errors.New("injected hardening failure")
	cases := []struct {
		name   string
		report enclave.ProcessHardening
		err    error
		want   error
	}{
		{"error", enclave.ProcessHardening{}, cause, cause},
		{"unsupported", enclave.ProcessHardening{}, enclave.ErrProcessHardeningUnsupported, enclave.ErrProcessHardeningUnsupported},
		{"still dumpable", enclave.ProcessHardening{CoreDumpsDisabled: true}, nil, errHardeningIncomplete},
		{"core limit not lowered", enclave.ProcessHardening{NotDumpable: true}, nil, errHardeningIncomplete},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := sys
			sys.hardenProcess = func() (enclave.ProcessHardening, error) { return tc.report, tc.err }
			defer func() { sys = old }()

			herr := harden()
			var typed *HardeningError
			if !errors.As(herr, &typed) || !errors.Is(herr, tc.want) {
				t.Fatalf("harden() = %v, want a *HardeningError wrapping %v", herr, tc.want)
			}

			vol := filepath.Join(t.TempDir(), "vol.luks")
			stderr := &bytes.Buffer{}
			code := Run(context.Background(), []string{"luks2", "create", "--key-file", "-", vol, "1M"}, untouchedReader{t}, &bytes.Buffer{}, stderr)
			if code == 0 {
				t.Fatal("code = 0, want a non-zero exit when hardening fails")
			}
			if !strings.Contains(stderr.String(), "cannot disable core dumps") || !strings.Contains(stderr.String(), tc.want.Error()) {
				t.Errorf("stderr = %q, want the hardening failure and its cause", stderr.String())
			}
			if _, err := os.Stat(vol); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("stat %s: %v, want no volume created", vol, err)
			}
		})
	}
}

func TestHardeningErrorUnwraps(t *testing.T) {
	cause := errors.New("cause")
	var err error = &HardeningError{Err: cause}
	if !errors.Is(err, cause) {
		t.Error("errors.Is(HardeningError, cause) = false, want true")
	}
	var herr *HardeningError
	if !errors.As(err, &herr) {
		t.Error("errors.As(*HardeningError) = false, want true")
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
