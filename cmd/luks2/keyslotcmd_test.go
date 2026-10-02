// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// Tests for the keyslot, token and header subcommands.
//
// They assert on WHAT THE COMMAND HANDED THE LIBRARY, not merely on the exit
// code. A mock that returns nil for everything makes any command look like it
// worked, so an exit code alone would pass for a command that read the wrong
// argument, sent the passphrase to the wrong parameter, or targeted the wrong
// keyslot -- which on removekey and killslot means destroying the wrong
// credential.

// runCLI builds a CLI over the given arguments with no terminal attached, which
// is the shape every non-interactive test wants. Everything a CLI touches is
// injected through it -- streams, terminal, operations -- so the package's
// tests share no mutable state, and the ones that cost real time (cryptsetup
// round-trips, multi-megabyte key files under -race) run in parallel (#92).
func runCLI(t *testing.T, stdin string, args ...string) (*CLI, *strings.Builder, *strings.Builder) {
	t.Helper()

	stdout := &strings.Builder{}
	stderr := &strings.Builder{}

	cli := &CLI{
		Args:       append([]string{"luks2"}, args...),
		Stdin:      strings.NewReader(stdin),
		Stdout:     stdout,
		Stderr:     stderr,
		Luks:       &MockLuksOperations{},
		Terminal:   &MockTerminal{Password: []byte("testpassword"), NotATerminal: true},
		FS:         &MockFileSystem{Files: make(map[string]bool)},
		ExitFunc:   func(int) {},
		getStdinFd: func() int { return 0 },
	}
	return cli, stdout, stderr
}

func TestTestKeyPassesThePassphraseThrough(t *testing.T) {
	var gotDevice string
	var gotPassphrase []byte

	cli, stdout, _ := runCLI(t, "the-passphrase\n", "testkey", "/dev/sdb1")
	cli.Luks = &MockLuksOperations{
		TestKeyFunc: func(device string, passphrase []byte) error {
			gotDevice = device
			gotPassphrase = append([]byte(nil), passphrase...)
			return nil
		},
	}

	if code := cli.Run(); code != 0 {
		t.Fatalf("testkey exited %d, want 0", code)
	}
	if gotDevice != "/dev/sdb1" {
		t.Errorf("device = %q, want /dev/sdb1", gotDevice)
	}
	if string(gotPassphrase) != "the-passphrase" {
		t.Errorf("passphrase = %q, want the piped line", gotPassphrase)
	}
	if !strings.Contains(stdout.String(), "opens /dev/sdb1") {
		t.Errorf("stdout = %q, want it to report success", stdout.String())
	}
}

// TestTestKeyReportsWhyItFailed: the library distinguishes "wrong passphrase"
// from "this keyslot could not be tried", and flattening that into one message
// sends an operator looking for a typo when the container is damaged.
func TestTestKeyReportsWhyItFailed(t *testing.T) {
	cli, _, stderr := runCLI(t, "wrong\n", "testkey", "/dev/sdb1")
	cli.Luks = &MockLuksOperations{
		TestKeyFunc: func(string, []byte) error { return luks2.ErrNoKeyslots },
	}

	if code := cli.Run(); code != 1 {
		t.Fatalf("testkey exited %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), luks2.ErrNoKeyslots.Error()) {
		t.Errorf("stderr = %q, want it to carry the library's reason", stderr.String())
	}
}

// TestAddKeyKeepsTheTwoCredentialsApart is the bug that matters here: swapping
// the existing and new passphrases would enroll the wrong one, and both are
// plausible []byte arguments to the same call.
func TestAddKeyKeepsTheTwoCredentialsApart(t *testing.T) {
	dir := t.TempDir()
	existingFile := writeFile(t, dir, "existing", "the-existing-one")
	newFile := writeFile(t, dir, "new", "the-new-one")

	var gotExisting, gotNew []byte
	var gotOpts *luks2.AddKeyOptions

	cli, _, stderr := runCLI(t, "", "addkey",
		"--key-file", existingFile, "--new-key-file", newFile, "--slot", "3", "--kdf", "pbkdf2", "/dev/sdb1")
	cli.Luks = &MockLuksOperations{
		AddKeyFunc: func(device string, existing, added []byte, opts *luks2.AddKeyOptions) (int, error) {
			gotExisting = append([]byte(nil), existing...)
			gotNew = append([]byte(nil), added...)
			gotOpts = opts
			return 3, nil
		},
	}

	if code := cli.Run(); code != 0 {
		t.Fatalf("addkey exited %d, want 0: %s", code, stderr.String())
	}
	if string(gotExisting) != "the-existing-one" {
		t.Errorf("existing passphrase = %q", gotExisting)
	}
	if string(gotNew) != "the-new-one" {
		t.Errorf("new passphrase = %q", gotNew)
	}
	if gotOpts == nil || gotOpts.Keyslot == nil || *gotOpts.Keyslot != 3 {
		t.Errorf("keyslot option = %v, want 3", gotOpts)
	}
	if gotOpts.KDFType != "pbkdf2" {
		t.Errorf("kdf = %q, want pbkdf2", gotOpts.KDFType)
	}
}

// TestAddKeyDoesNotClaimAKeyslotNumber pins a deliberate omission: AddKey does
// not report the slot it used, and any number printed here would be an
// inference that is wrong on every container with a gap in its slots (#42).
func TestAddKeyDoesNotClaimAKeyslotNumber(t *testing.T) {
	dir := t.TempDir()
	key := writeFile(t, dir, "key", "passphrase")

	cli, stdout, _ := runCLI(t, "", "addkey", "--key-file", key, "--new-key-file", key, "/dev/sdb1")

	if code := cli.Run(); code != 0 {
		t.Fatalf("addkey exited %d, want 0", code)
	}
	if strings.Contains(stdout.String(), "keyslot 0") || strings.Contains(stdout.String(), "slot 0") {
		t.Errorf("addkey named a keyslot it cannot know: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "luks2 keyslots") {
		t.Errorf("stdout = %q, want it to point at the listing", stdout.String())
	}
}

func TestRemoveKeyTargetsTheSlotItWasGiven(t *testing.T) {
	var gotSlot int
	var gotPassphrase []byte

	cli, stdout, _ := runCLI(t, "slot-two-passphrase\n", "removekey", "/dev/sdb1", "2")
	cli.Luks = &MockLuksOperations{
		RemoveKeyFunc: func(device string, passphrase []byte, keyslot int) error {
			gotSlot = keyslot
			gotPassphrase = append([]byte(nil), passphrase...)
			return nil
		},
	}

	if code := cli.Run(); code != 0 {
		t.Fatalf("removekey exited %d, want 0", code)
	}
	if gotSlot != 2 {
		t.Errorf("keyslot = %d, want 2", gotSlot)
	}
	if string(gotPassphrase) != "slot-two-passphrase" {
		t.Errorf("passphrase = %q", gotPassphrase)
	}
	if !strings.Contains(stdout.String(), "Keyslot 2 removed") {
		t.Errorf("stdout = %q", stdout.String())
	}
}

func TestKillSlotTargetsTheSlotItWasGiven(t *testing.T) {
	var gotSlot int

	cli, stdout, _ := runCLI(t, "any-valid-passphrase\n", "killslot", "/dev/sdb1", "5")
	cli.Luks = &MockLuksOperations{
		KillSlotFunc: func(device string, auth []byte, target int) error {
			gotSlot = target
			return nil
		},
	}

	if code := cli.Run(); code != 0 {
		t.Fatalf("killslot exited %d, want 0", code)
	}
	if gotSlot != 5 {
		t.Errorf("target slot = %d, want 5", gotSlot)
	}
	// The slot number is echoed BEFORE the removal, because the operator named
	// it by number and this is irreversible.
	if !strings.Contains(stdout.String(), "Removing keyslot 5") {
		t.Errorf("stdout = %q, want it to name the slot before removing it", stdout.String())
	}
}

func TestChangeKeyKeepsTheTwoCredentialsApart(t *testing.T) {
	dir := t.TempDir()
	oldFile := writeFile(t, dir, "old", "the-old-one")
	newFile := writeFile(t, dir, "new", "the-new-one")

	var gotOld, gotNew []byte
	var gotSlot int

	cli, _, stderr := runCLI(t, "", "changekey", "--key-file", oldFile, "--new-key-file", newFile, "/dev/sdb1", "1")
	cli.Luks = &MockLuksOperations{
		ChangeKeyFunc: func(device string, old, replacement []byte, keyslot int) error {
			gotOld = append([]byte(nil), old...)
			gotNew = append([]byte(nil), replacement...)
			gotSlot = keyslot
			return nil
		},
	}

	if code := cli.Run(); code != 0 {
		t.Fatalf("changekey exited %d, want 0: %s", code, stderr.String())
	}
	if string(gotOld) != "the-old-one" || string(gotNew) != "the-new-one" {
		t.Errorf("old = %q, new = %q", gotOld, gotNew)
	}
	if gotSlot != 1 {
		t.Errorf("keyslot = %d, want 1", gotSlot)
	}
}

func TestKeyslotCommandsRefuseAnImpossibleSlot(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "removekey, not a number", args: []string{"removekey", "/dev/sdb1", "two"}},
		{name: "removekey, out of range", args: []string{"removekey", "/dev/sdb1", "32"}},
		{name: "killslot, negative", args: []string{"killslot", "/dev/sdb1", "-1"}},
		{name: "changekey, out of range", args: []string{"changekey", "/dev/sdb1", "99"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			cli, _, stderr := runCLI(t, "passphrase\n", tt.args...)
			cli.Luks = &MockLuksOperations{
				RemoveKeyFunc: func(string, []byte, int) error { called = true; return nil },
				KillSlotFunc:  func(string, []byte, int) error { called = true; return nil },
				ChangeKeyFunc: func(string, []byte, []byte, int) error { called = true; return nil },
			}

			if code := cli.Run(); code != 1 {
				t.Fatalf("exited %d, want 1", code)
			}
			if called {
				t.Error("the library was called with a keyslot that cannot exist")
			}
			if !strings.Contains(stderr.String(), "usage") {
				t.Errorf("stderr = %q, want a usage error", stderr.String())
			}
		})
	}
}

func TestKeyslotsListsWhatTheLibraryReports(t *testing.T) {
	cli, stdout, _ := runCLI(t, "", "keyslots", "/dev/sdb1")
	cli.Luks = &MockLuksOperations{
		ListKeyslotsFunc: func(string) ([]luks2.KeyslotInfo, error) {
			return []luks2.KeyslotInfo{
				{ID: 0, Type: "luks2", KeySize: 64, KDFType: "argon2id", Encryption: "aes-xts-plain64"},
				{ID: 4, Type: "luks2", KeySize: 64, KDFType: "pbkdf2", Encryption: "aes-xts-plain64"},
			}, nil
		},
	}

	if code := cli.Run(); code != 0 {
		t.Fatalf("keyslots exited %d, want 0", code)
	}
	for _, want := range []string{"argon2id", "pbkdf2", "aes-xts-plain64"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout = %q, want it to contain %q", stdout.String(), want)
		}
	}
	// The gap matters: an operator reading this listing is deciding what to
	// remove, and a listing that renumbered the slots would be lethal.
	if !strings.Contains(stdout.String(), "4 ") {
		t.Errorf("stdout = %q, want slot 4 reported as 4", stdout.String())
	}
}

// TestKeyslotsRefusesAContainerWithNoKeyslots: an empty table would read as
// "everything is fine" for a volume nothing can open.
func TestKeyslotsRefusesAContainerWithNoKeyslots(t *testing.T) {
	cli, _, stderr := runCLI(t, "", "keyslots", "/dev/sdb1")
	cli.Luks = &MockLuksOperations{
		ListKeyslotsFunc: func(string) ([]luks2.KeyslotInfo, error) { return nil, nil },
	}

	if code := cli.Run(); code != 1 {
		t.Fatalf("keyslots exited %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "NO keyslots") {
		t.Errorf("stderr = %q, want it to say the volume cannot be opened", stderr.String())
	}
}

// --- Tokens ---

func TestTokenListIsOrdered(t *testing.T) {
	cli, stdout, _ := runCLI(t, "", "token", "list", "/dev/sdb1")
	cli.Luks = &MockLuksOperations{
		ListTokensFunc: func(string) (map[int]*luks2.Token, error) {
			return map[int]*luks2.Token{
				5: {Type: "systemd-tpm2", Keyslots: []string{"2"}},
				1: {Type: "systemd-fido2", Keyslots: []string{"1"}},
				0: {Type: "systemd-recovery", Keyslots: []string{"0"}},
			}, nil
		},
	}

	if code := cli.Run(); code != 0 {
		t.Fatalf("token list exited %d, want 0", code)
	}

	out := stdout.String()
	first, second, third := strings.Index(out, "systemd-recovery"), strings.Index(out, "systemd-fido2"), strings.Index(out, "systemd-tpm2")
	if !(first < second && second < third) {
		t.Errorf("tokens were not listed in slot order:\n%s", out)
	}
}

func TestTokenRoundTripsThroughJSON(t *testing.T) {
	dir := t.TempDir()
	exported := dir + "/token.json"

	// The REAL filesystem, under t.TempDir(): this test is about a document
	// written by one command and read back by another, and a mock that quietly
	// wrote somewhere else would prove nothing about that.
	cli, _, stderr := runCLI(t, "", "token", "export", "/dev/sdb1", "0", "--file", exported)
	cli.FS = &DefaultFileSystem{}
	if code := cli.Run(); code != 0 {
		t.Fatalf("token export exited %d, want 0: %s", code, stderr.String())
	}

	var imported []byte
	var importedID int
	cli, _, stderr = runCLI(t, "", "token", "import", "/dev/sdb1", "2", "--file", exported)
	cli.FS = &DefaultFileSystem{}
	cli.Luks = &MockLuksOperations{
		ImportTokenJSONFunc: func(device string, tokenID int, tokenJSON []byte) error {
			imported = append([]byte(nil), tokenJSON...)
			importedID = tokenID
			return nil
		},
	}
	if code := cli.Run(); code != 0 {
		t.Fatalf("token import exited %d, want 0: %s", code, stderr.String())
	}

	if importedID != 2 {
		t.Errorf("imported into token %d, want 2", importedID)
	}
	if !strings.Contains(string(imported), "systemd-fido2") {
		t.Errorf("imported JSON = %q, want the exported document", imported)
	}
}

func TestTokenImportReadsStandardInput(t *testing.T) {
	const document = `{"type":"systemd-fido2","keyslots":["1"]}`

	var imported []byte
	cli, _, stderr := runCLI(t, document, "token", "import", "/dev/sdb1", "1", "--file", "-")
	cli.Luks = &MockLuksOperations{
		ImportTokenJSONFunc: func(device string, tokenID int, tokenJSON []byte) error {
			imported = append([]byte(nil), tokenJSON...)
			return nil
		},
	}

	if code := cli.Run(); code != 0 {
		t.Fatalf("token import exited %d, want 0: %s", code, stderr.String())
	}
	if string(imported) != document {
		t.Errorf("imported = %q, want %q", imported, document)
	}
}

func TestTokenImportRefusesWithoutASource(t *testing.T) {
	cli, _, stderr := runCLI(t, "", "token", "import", "/dev/sdb1", "1")

	if code := cli.Run(); code != 1 {
		t.Fatalf("token import exited %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "--file is required") {
		t.Errorf("stderr = %q, want it to name the missing option", stderr.String())
	}
}

// TestTokenRemoveSaysItRevokedNothing is the misunderstanding this command has
// to prevent: deleting a token leaves the credential working.
func TestTokenRemoveSaysItRevokedNothing(t *testing.T) {
	cli, stdout, _ := runCLI(t, "", "token", "remove", "/dev/sdb1", "1")

	if code := cli.Run(); code != 0 {
		t.Fatalf("token remove exited %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "UNCHANGED") {
		t.Errorf("stdout = %q, want it to say the keyslot still opens the volume", stdout.String())
	}
}

// TestTokenExistsAnswersInItsExitCode: a script branches on this.
func TestTokenExistsAnswersInItsExitCode(t *testing.T) {
	tests := []struct {
		name   string
		exists bool
		want   int
	}{
		{name: "present", exists: true, want: 0},
		{name: "absent", exists: false, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli, _, _ := runCLI(t, "", "token", "exists", "/dev/sdb1", "1")
			cli.Luks = &MockLuksOperations{
				TokenExistsFunc: func(string, int) (bool, error) { return tt.exists, nil },
			}

			if code := cli.Run(); code != tt.want {
				t.Errorf("token exists exited %d, want %d", code, tt.want)
			}
		})
	}
}

func TestTokenCountAndFreeReportBareNumbers(t *testing.T) {
	t.Run("count", func(t *testing.T) {
		cli, stdout, _ := runCLI(t, "", "token", "count", "/dev/sdb1")
		cli.Luks = &MockLuksOperations{CountTokensFunc: func(string) (int, error) { return 3, nil }}

		if code := cli.Run(); code != 0 {
			t.Fatalf("token count exited %d, want 0", code)
		}
		if strings.TrimSpace(stdout.String()) != "3" {
			t.Errorf("stdout = %q, want a bare 3 a script can read", stdout.String())
		}
	})

	t.Run("free", func(t *testing.T) {
		cli, stdout, _ := runCLI(t, "", "token", "free", "/dev/sdb1")
		cli.Luks = &MockLuksOperations{FindFreeTokenSlotFunc: func(string) (int, error) { return 7, nil }}

		if code := cli.Run(); code != 0 {
			t.Fatalf("token free exited %d, want 0", code)
		}
		if strings.TrimSpace(stdout.String()) != "7" {
			t.Errorf("stdout = %q, want a bare 7", stdout.String())
		}
	})
}

func TestTokenRefusesAnImpossibleID(t *testing.T) {
	called := false
	cli, _, stderr := runCLI(t, "", "token", "show", "/dev/sdb1", "32")
	cli.Luks = &MockLuksOperations{
		GetTokenFunc: func(string, int) (*luks2.Token, error) { called = true; return nil, nil },
	}

	if code := cli.Run(); code != 1 {
		t.Fatalf("token show exited %d, want 1", code)
	}
	if called {
		t.Error("the library was called with a token id that cannot exist")
	}
	if !strings.Contains(stderr.String(), "out of range") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestTokenReportsALibraryFailure(t *testing.T) {
	cli, _, stderr := runCLI(t, "", "token", "show", "/dev/sdb1", "1")
	cli.Luks = &MockLuksOperations{
		GetTokenFunc: func(string, int) (*luks2.Token, error) { return nil, luks2.ErrTokenNotFound },
	}

	if code := cli.Run(); code != 1 {
		t.Fatalf("token show exited %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), luks2.ErrTokenNotFound.Error()) {
		t.Errorf("stderr = %q, want the library's reason", stderr.String())
	}
}

// --- Header ---

func TestHeaderShowReportsTheSequenceID(t *testing.T) {
	tests := []struct {
		name string
		args []string
		seq  uint64
	}{
		{name: "primary", args: []string{"header", "show", "/dev/sdb1"}, seq: 9},
		{name: "secondary", args: []string{"header", "secondary", "/dev/sdb1"}, seq: 11},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli, stdout, _ := runCLI(t, "", tt.args...)
			cli.Luks = &MockLuksOperations{
				ReadHeaderFunc: func(string) (*luks2.LUKS2BinaryHeader, *luks2.LUKS2Metadata, error) {
					return mockHeader(2, tt.seq), mockMetadata(), nil
				},
				ReadSecondaryHeaderFunc: func(string) (*luks2.LUKS2BinaryHeader, *luks2.LUKS2Metadata, error) {
					return mockHeader(2, tt.seq), mockMetadata(), nil
				},
			}

			if code := cli.Run(); code != 0 {
				t.Fatalf("exited %d, want 0", code)
			}

			out := stdout.String()
			// The sequence id is the whole reason to look at both copies: the
			// higher one was written last.
			if !strings.Contains(out, "Sequence ID:") || !strings.Contains(out, "12345678-1234-1234-1234-123456789abc") {
				t.Errorf("stdout = %q, want the sequence id and the UUID", out)
			}
		})
	}
}

func TestHeaderShowReportsAnUnreadableHeader(t *testing.T) {
	cli, _, stderr := runCLI(t, "", "header", "show", "/dev/sdb1")
	cli.Luks = &MockLuksOperations{
		ReadHeaderFunc: func(string) (*luks2.LUKS2BinaryHeader, *luks2.LUKS2Metadata, error) {
			return nil, nil, luks2.ErrInvalidHeader
		},
	}

	if code := cli.Run(); code != 1 {
		t.Fatalf("header show exited %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), luks2.ErrInvalidHeader.Error()) {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// TestHeaderRestoreNeedsAnExplicitYes: restoring can lose a keyslot recorded
// only in the primary header.
func TestHeaderRestoreNeedsAnExplicitYes(t *testing.T) {
	tests := []struct {
		name     string
		answer   string
		restored bool
	}{
		{name: "confirmed", answer: "YES\n", restored: true},
		{name: "refused", answer: "no\n", restored: false},
		{name: "empty", answer: "\n", restored: false},
		{name: "lowercase yes is not YES", answer: "yes\n", restored: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restored := false
			cli, _, _ := runCLI(t, tt.answer, "header", "restore", "/dev/sdb1")
			cli.Luks = &MockLuksOperations{
				RestorePrimaryHeaderFunc: func(string) error { restored = true; return nil },
			}

			if code := cli.Run(); code != 0 {
				t.Fatalf("header restore exited %d, want 0", code)
			}
			if restored != tt.restored {
				t.Errorf("restored = %v, want %v", restored, tt.restored)
			}
		})
	}
}

func TestHeaderRestoreReportsAFailure(t *testing.T) {
	cli, _, stderr := runCLI(t, "YES\n", "header", "restore", "/dev/sdb1")
	cli.Luks = &MockLuksOperations{
		RestorePrimaryHeaderFunc: func(string) error { return errors.New("device is read-only") },
	}

	if code := cli.Run(); code != 1 {
		t.Fatalf("header restore exited %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "read-only") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// TestIsLUKSAnswersInItsExitCode mirrors `cryptsetup isLuks`.
func TestIsLUKSAnswersInItsExitCode(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		isLUKS  bool
		isLUKS2 bool
		err     error
		want    int
	}{
		{name: "a LUKS device", args: []string{"isluks", "/dev/sdb1"}, isLUKS: true, want: 0},
		{name: "not a LUKS device", args: []string{"isluks", "/dev/sdb1"}, isLUKS: false, want: 1},
		{name: "a LUKS2 device", args: []string{"isluks", "--luks2", "/dev/sdb1"}, isLUKS2: true, want: 0},
		{name: "LUKS1 asked about LUKS2", args: []string{"isluks", "--luks2", "/dev/sdb1"}, isLUKS: true, isLUKS2: false, want: 1},
		{name: "unreadable", args: []string{"isluks", "/dev/sdb1"}, err: luks2.ErrDeviceNotFound, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli, _, _ := runCLI(t, "", tt.args...)
			cli.Luks = &MockLuksOperations{
				IsLUKSFunc:  func(string) (bool, error) { return tt.isLUKS, tt.err },
				IsLUKS2Func: func(string) (bool, error) { return tt.isLUKS2, tt.err },
			}

			if code := cli.Run(); code != tt.want {
				t.Errorf("isluks exited %d, want %d", code, tt.want)
			}
		})
	}
}

// TestEverySubcommandShowsUsageWithNoArguments: a command that does nothing and
// says nothing is indistinguishable from one that worked.
func TestEverySubcommandShowsUsageWithNoArguments(t *testing.T) {
	commands := [][]string{
		{"testkey"}, {"addkey"}, {"removekey"}, {"killslot"}, {"changekey"}, {"keyslots"},
		{"recovery"}, {"recovery", "add"}, {"recovery", "verify"},
		{"token"}, {"token", "list"}, {"token", "show", "/dev/sdb1"},
		{"header"}, {"header", "show"}, {"isluks"},
	}

	for _, args := range commands {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			cli, stdout, _ := runCLI(t, "", args...)

			if code := cli.Run(); code != 1 {
				t.Fatalf("exited %d, want 1", code)
			}
			if !strings.Contains(stdout.String(), "Usage") && !strings.Contains(stdout.String(), "Subcommands") {
				t.Errorf("stdout = %q, want usage", stdout.String())
			}
		})
	}
}

func TestUnknownSubcommandsAreRefused(t *testing.T) {
	tests := [][]string{
		{"recovery", "destroy"},
		{"token", "frobnicate", "/dev/sdb1"},
		{"header", "rewrite", "/dev/sdb1"},
	}

	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			cli, _, stderr := runCLI(t, "", args...)

			if code := cli.Run(); code != 1 {
				t.Fatalf("exited %d, want 1", code)
			}
			if !strings.Contains(stderr.String(), "Unknown") {
				t.Errorf("stderr = %q, want it to name the unknown subcommand", stderr.String())
			}
		})
	}
}
