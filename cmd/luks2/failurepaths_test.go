// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// The failure paths, gathered.
//
// Each command's happy path is covered where the command is. What is here is
// the half that is easy to leave untested and expensive to get wrong: a command
// that CANNOT READ ITS CREDENTIAL must refuse, and must refuse before it
// touches the volume. A tool that silently fell back to prompting -- with no
// terminal to prompt on -- is how an unattended unlock hangs forever holding a
// device open.

// TestEveryCredentialCommandRefusesAnUnreadableKeyFile walks the whole set,
// because the branch is per-command and a new command that forgets it looks
// exactly like the ones that do not.
func TestEveryCredentialCommandRefusesAnUnreadableKeyFile(t *testing.T) {
	defer parallel(t)()

	absent := filepath.Join(t.TempDir(), "absent.key")

	commands := [][]string{
		{"open", "--key-file", absent, "/dev/sdb1", "backup"},
		{"create", "--batch-mode", "--key-file", absent, "/dev/sdb1"},
		{"testkey", "--key-file", absent, "/dev/sdb1"},
		{"addkey", "--key-file", absent, "/dev/sdb1"},
		{"removekey", "--key-file", absent, "/dev/sdb1", "1"},
		{"killslot", "--key-file", absent, "/dev/sdb1", "1"},
		{"changekey", "--key-file", absent, "/dev/sdb1", "1"},
		{"recovery", "add", "--key-file", absent, "/dev/sdb1"},
	}

	for _, args := range commands {
		t.Run(args[0]+" "+args[1], func(t *testing.T) {
			touched := false
			cli, _, stderr := runCLI(t, "", args...)
			cli.FS = &DefaultFileSystem{}
			cli.Luks = &MockLuksOperations{
				UnlockFunc:    func(string, []byte, string) error { touched = true; return nil },
				FormatFunc:    func(luks2.FormatOptions) error { touched = true; return nil },
				TestKeyFunc:   func(string, []byte) error { touched = true; return nil },
				AddKeyFunc:    func(string, []byte, []byte, *luks2.AddKeyOptions) (int, error) { touched = true; return 0, nil },
				RemoveKeyFunc: func(string, []byte, int) error { touched = true; return nil },
				KillSlotFunc:  func(string, []byte, int) error { touched = true; return nil },
				ChangeKeyFunc: func(string, []byte, []byte, int) error { touched = true; return nil },
				AddRecoveryKeyFunc: func(string, []byte, *luks2.RecoveryKeyOptions) (*luks2.RecoveryKey, error) {
					touched = true
					return nil, nil
				},
			}

			if code := cli.Run(); code != 1 {
				t.Fatalf("exited %d, want 1", code)
			}
			if touched {
				t.Error("the volume was touched even though the credential could not be read")
			}
			if !strings.Contains(stderr.String(), "no such file") {
				t.Errorf("stderr = %q, want it to say which file could not be read", stderr.String())
			}
		})
	}
}

// TestASecondCredentialThatCannotBeReadIsAlsoRefused: addkey and changekey read
// TWO credentials, and the second one has its own branch.
func TestASecondCredentialThatCannotBeReadIsAlsoRefused(t *testing.T) {
	dir := t.TempDir()
	present := writeFile(t, dir, "present.key", "a passphrase")
	absent := filepath.Join(dir, "absent.key")

	commands := [][]string{
		{"addkey", "--key-file", present, "--new-key-file", absent, "/dev/sdb1"},
		{"changekey", "--key-file", present, "--new-key-file", absent, "/dev/sdb1", "1"},
	}

	for _, args := range commands {
		t.Run(args[0], func(t *testing.T) {
			touched := false
			cli, _, stderr := runCLI(t, "", args...)
			cli.FS = &DefaultFileSystem{}
			cli.Luks = &MockLuksOperations{
				AddKeyFunc:    func(string, []byte, []byte, *luks2.AddKeyOptions) (int, error) { touched = true; return 0, nil },
				ChangeKeyFunc: func(string, []byte, []byte, int) error { touched = true; return nil },
			}

			if code := cli.Run(); code != 1 {
				t.Fatalf("exited %d, want 1", code)
			}
			if touched {
				t.Error("a keyslot was written with a credential that could not be read")
			}
			if !strings.Contains(stderr.String(), "no such file") {
				t.Errorf("stderr = %q", stderr.String())
			}
		})
	}
}

// TestEveryCredentialCommandReportsALibraryRefusal: the exit code alone is not
// enough, the operator needs the reason.
func TestEveryCredentialCommandReportsALibraryRefusal(t *testing.T) {
	refusal := errors.New("the device is read-only")

	commands := [][]string{
		{"testkey", "/dev/sdb1"},
		{"addkey", "/dev/sdb1"},
		{"removekey", "/dev/sdb1", "1"},
		{"killslot", "/dev/sdb1", "1"},
		{"changekey", "/dev/sdb1", "1"},
		{"keyslots", "/dev/sdb1"},
	}

	for _, args := range commands {
		t.Run(args[0], func(t *testing.T) {
			cli, _, stderr := runCLI(t, "a passphrase\n", args...)
			cli.Luks = &MockLuksOperations{
				TestKeyFunc:      func(string, []byte) error { return refusal },
				AddKeyFunc:       func(string, []byte, []byte, *luks2.AddKeyOptions) (int, error) { return -1, refusal },
				RemoveKeyFunc:    func(string, []byte, int) error { return refusal },
				KillSlotFunc:     func(string, []byte, int) error { return refusal },
				ChangeKeyFunc:    func(string, []byte, []byte, int) error { return refusal },
				ListKeyslotsFunc: func(string) ([]luks2.KeyslotInfo, error) { return nil, refusal },
			}

			if code := cli.Run(); code != 1 {
				t.Fatalf("exited %d, want 1", code)
			}
			if !strings.Contains(stderr.String(), refusal.Error()) {
				t.Errorf("stderr = %q, want the library's reason", stderr.String())
			}
		})
	}
}

// TestEveryCommandRefusesAnUnknownOption: a misspelled flag that falls through
// to the positional list becomes a device path.
func TestEveryCommandRefusesAnUnknownOption(t *testing.T) {
	commands := [][]string{
		{"testkey", "--keyfile", "/k", "/dev/sdb1"},
		{"addkey", "--slt", "1", "/dev/sdb1"},
		{"removekey", "--force", "/dev/sdb1", "1"},
		{"killslot", "--yes", "/dev/sdb1", "1"},
		{"changekey", "--kdf2", "x", "/dev/sdb1", "1"},
		{"keyslots", "--all", "/dev/sdb1"},
		{"recovery", "generate", "--fmt", "hex"},
		{"recovery", "add", "--fmt", "hex", "/dev/sdb1"},
		{"recovery", "verify", "--from", "/f", "/dev/sdb1"},
		{"token", "list", "--json", "/dev/sdb1"},
		{"header", "show", "--json", "/dev/sdb1"},
		{"isluks", "--luks1", "/dev/sdb1"},
		{"create", "--keyfile", "/k", "/dev/sdb1"},
	}

	for _, args := range commands {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			cli, _, stderr := runCLI(t, "", args...)

			if code := cli.Run(); code != 1 {
				t.Fatalf("exited %d, want 1", code)
			}
			if !strings.Contains(stderr.String(), "unknown option") {
				t.Errorf("stderr = %q, want it to name the unknown option", stderr.String())
			}
		})
	}
}

// TestTokenShowPrintsTheWholeToken: the JSON is the point of the command.
func TestTokenShowPrintsTheWholeToken(t *testing.T) {
	cli, stdout, _ := runCLI(t, "", "token", "show", "/dev/sdb1", "1")
	cli.Luks = &MockLuksOperations{
		GetTokenFunc: func(string, int) (*luks2.Token, error) {
			return &luks2.Token{
				Type:            "systemd-fido2",
				Keyslots:        []string{"2"},
				FIDO2Credential: "Y3JlZGVudGlhbA==",
				FIDO2RP:         "io.systemd.cryptsetup",
			}, nil
		},
	}

	if code := cli.Run(); code != 0 {
		t.Fatalf("token show exited %d, want 0", code)
	}
	for _, want := range []string{"systemd-fido2", "Y3JlZGVudGlhbA==", "io.systemd.cryptsetup", `"2"`} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout = %q, want it to contain %q", stdout.String(), want)
		}
	}
}

// TestTokenExportGoesToStandardOutputByDefault, so it can be piped.
func TestTokenExportGoesToStandardOutputByDefault(t *testing.T) {
	for _, args := range [][]string{
		{"token", "export", "/dev/sdb1", "0"},
		{"token", "export", "/dev/sdb1", "0", "--file", "-"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			cli, stdout, _ := runCLI(t, "", args...)

			if code := cli.Run(); code != 0 {
				t.Fatalf("token export exited %d, want 0", code)
			}
			if !strings.Contains(stdout.String(), "systemd-fido2") {
				t.Errorf("stdout = %q, want the token JSON", stdout.String())
			}
		})
	}
}

// The path below is never opened: cli.FS is replaced with a mock that returns
// CreateErr before Run() executes, so the failure comes from the injected error
// value, not from anything the real filesystem does with this string. It is
// named "unwritable" rather than a directory that looks absent, on purpose --
// a name like the /nowhere paths this file used to use elsewhere would suggest
// a real path is being exercised, which is exactly the permission-bit fault
// injection this file no longer does.
func TestTokenExportReportsAFileItCannotWrite(t *testing.T) {
	cli, _, stderr := runCLI(t, "", "token", "export", "/dev/sdb1", "0", "--file", "unwritable/token.json")
	cli.FS = &MockFileSystem{Files: make(map[string]bool), CreateErr: errors.New("permission denied")}

	if code := cli.Run(); code != 1 {
		t.Fatalf("token export exited %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "permission denied") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestTokenExportReportsALibraryFailure(t *testing.T) {
	cli, _, stderr := runCLI(t, "", "token", "export", "/dev/sdb1", "0")
	cli.Luks = &MockLuksOperations{
		ExportTokenFunc: func(string, int) ([]byte, error) { return nil, luks2.ErrTokenNotFound },
	}

	if code := cli.Run(); code != 1 {
		t.Fatalf("token export exited %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), luks2.ErrTokenNotFound.Error()) {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestTokenImportReportsAFileItCannotRead(t *testing.T) {
	cli, _, stderr := runCLI(t, "", "token", "import", "/dev/sdb1", "0", "--file", filepath.Join(t.TempDir(), "absent.json"))
	cli.FS = &DefaultFileSystem{}

	if code := cli.Run(); code != 1 {
		t.Fatalf("token import exited %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "no such file") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestTokenImportReportsALibraryRefusal(t *testing.T) {
	cli, _, stderr := runCLI(t, `{"not":"a token"}`, "token", "import", "/dev/sdb1", "0", "--file", "-")
	cli.Luks = &MockLuksOperations{
		ImportTokenJSONFunc: func(string, int, []byte) error { return errors.New("token type cannot be empty") },
	}

	if code := cli.Run(); code != 1 {
		t.Fatalf("token import exited %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "token type cannot be empty") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestTokenReportsOtherLibraryFailures(t *testing.T) {
	failure := errors.New("the header could not be read")

	tests := []struct {
		name string
		args []string
		ops  *MockLuksOperations
	}{
		{
			name: "list",
			args: []string{"token", "list", "/dev/sdb1"},
			ops:  &MockLuksOperations{ListTokensFunc: func(string) (map[int]*luks2.Token, error) { return nil, failure }},
		},
		{
			name: "remove",
			args: []string{"token", "remove", "/dev/sdb1", "0"},
			ops:  &MockLuksOperations{RemoveTokenFunc: func(string, int) error { return failure }},
		},
		{
			name: "free",
			args: []string{"token", "free", "/dev/sdb1"},
			ops:  &MockLuksOperations{FindFreeTokenSlotFunc: func(string) (int, error) { return -1, failure }},
		},
		{
			name: "exists",
			args: []string{"token", "exists", "/dev/sdb1", "0"},
			ops:  &MockLuksOperations{TokenExistsFunc: func(string, int) (bool, error) { return false, failure }},
		},
		{
			name: "count",
			args: []string{"token", "count", "/dev/sdb1"},
			ops:  &MockLuksOperations{CountTokensFunc: func(string) (int, error) { return 0, failure }},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli, _, stderr := runCLI(t, "", tt.args...)
			cli.Luks = tt.ops

			if code := cli.Run(); code != 1 {
				t.Fatalf("exited %d, want 1", code)
			}
			if !strings.Contains(stderr.String(), failure.Error()) {
				t.Errorf("stderr = %q, want the library's reason", stderr.String())
			}
		})
	}
}

func TestTokenListSaysSoWhenThereAreNone(t *testing.T) {
	cli, stdout, _ := runCLI(t, "", "token", "list", "/dev/sdb1")

	if code := cli.Run(); code != 0 {
		t.Fatalf("token list exited %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "no tokens") {
		t.Errorf("stdout = %q, want it to say there are none", stdout.String())
	}
}

// TestRecoveryGenerateSavesWhenAsked, and says so when it could not.
func TestRecoveryGenerateSavesWhenAsked(t *testing.T) {
	defer parallel(t)()

	t.Run("saved", func(t *testing.T) {
		saved := filepath.Join(t.TempDir(), "recovery.txt")

		cli, stdout, stderr := runCLI(t, "", "recovery", "generate", "--output", saved)
		cli.Luks = realRecoveryOps()

		if code := cli.Run(); code != 0 {
			t.Fatalf("recovery generate exited %d, want 0: %s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "Saved to "+saved) {
			t.Errorf("stdout = %q, want it to report the path", stdout.String())
		}

		// The saved file must hold the same key that was displayed, or one of
		// the two copies is worthless.
		printed := printedRecoveryKey(t, stdout.String())
		loaded, err := luks2.LoadRecoveryKey(saved)
		if err != nil {
			t.Fatalf("LoadRecoveryKey() error = %v", err)
		}
		defer mustDestroy(t, loaded)

		parsed, err := luks2.ParseRecoveryKey(printed)
		if err != nil {
			t.Fatalf("ParseRecoveryKey() error = %v", err)
		}
		defer mustDestroy(t, parsed)

		if !parsed.EqualTo(mustOpen(t, loaded)) {
			t.Error("the saved file holds a different key from the one that was displayed")
		}
	})

	t.Run("could not be saved", func(t *testing.T) {
		// SaveRecoveryKey calls os.MkdirAll(filepath.Dir(output), 0700) before it
		// writes anything, so a merely-unwritable directory is not a failure CI can
		// rely on: CI runs as root, and root bypasses permission bits -- it would
		// simply create the missing directory and the save would succeed, which is
		// the opposite of what this test asserts. A REGULAR FILE standing where the
		// parent directory needs to be is refused for everyone, root included:
		// MkdirAll finds a name already taken by something that is not a directory
		// and fails with ENOTDIR, a type conflict rather than a permission check.
		blocker := writeFile(t, t.TempDir(), "blocks-the-directory", "")
		output := filepath.Join(blocker, "recovery.txt")

		cli, stdout, stderr := runCLI(t, "", "recovery", "generate", "--output", output)
		cli.Luks = realRecoveryOps()

		if code := cli.Run(); code != 1 {
			t.Fatalf("recovery generate exited %d, want 1", code)
		}
		// The key is on the screen and nowhere else, so it must still be shown.
		if printed := printedRecoveryKey(t, stdout.String()); printed == "" {
			t.Error("the key was not displayed")
		}
		if !strings.Contains(stderr.String(), "NOT saved") {
			t.Errorf("stderr = %q", stderr.String())
		}
	})
}

func TestRecoveryVerifyReportsAKeyItCannotRead(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "a file that is not there", args: []string{"recovery", "verify", "--recovery-file", "/nowhere/key.txt", "/dev/sdb1"}},
		{name: "a string that is not a key", args: []string{"recovery", "verify", "/dev/sdb1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli, _, stderr := runCLI(t, "not a recovery key\n", tt.args...)
			cli.Luks = realRecoveryOps()

			if code := cli.Run(); code != 1 {
				t.Fatalf("exited %d, want 1", code)
			}
			if stderr.Len() == 0 {
				t.Error("nothing was reported for a key that could not be read")
			}
		})
	}
}

func TestRecoveryVerifyReportsALibraryFailure(t *testing.T) {
	cli, _, stderr := runCLI(t, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n", "recovery", "verify", "/dev/sdb1")
	cli.Luks = &MockLuksOperations{
		VerifyRecoveryKeyFunc: func(string, *enclave.MemoryEnclave) (bool, error) { return false, luks2.ErrInvalidHeader },
	}

	if code := cli.Run(); code != 1 {
		t.Fatalf("recovery verify exited %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), luks2.ErrInvalidHeader.Error()) {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// TestReadKeyLineRefusesALineWithoutEnd: a stream with no newline at all must
// not grow this process without bound.
func TestReadKeyLineRefusesALineWithoutEnd(t *testing.T) {
	defer parallel(t)()

	endless := strings.NewReader(strings.Repeat("x", maxKeyFileSize+2))

	if _, err := readKeyLine(endless); !errors.Is(err, ErrKeyFileTooLarge) {
		t.Errorf("error = %v, want errors.Is(_, ErrKeyFileTooLarge)", err)
	}
}

// TestHeaderRefusesAnIncompleteCommand covers the group's own argument
// handling.
func TestHeaderRefusesAnIncompleteCommand(t *testing.T) {
	for _, args := range [][]string{
		{"header"},
		{"header", "show"},
		{"header", "--json", "show", "/dev/sdb1"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			cli, stdout, stderr := runCLI(t, "", args...)

			if code := cli.Run(); code != 1 {
				t.Fatalf("exited %d, want 1", code)
			}
			if stdout.Len() == 0 && stderr.Len() == 0 {
				t.Error("the command failed silently")
			}
		})
	}
}
