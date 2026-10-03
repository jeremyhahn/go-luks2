// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// Tests for the recovery-key subcommands.
//
// The one that matters runs against a REAL container and lets cryptsetup decide
// whether the string this tool printed is any good. A recovery key that is
// displayed once and does not work is worse than no recovery key: the operator
// believes they have a way back into the volume and finds out otherwise on the
// day they need it.

// realRecoveryOps delegates to the library but pins the keyslot KDF to
// something a unit test can afford.
//
// The library is doing the work -- a real keyslot is written to a real
// container and a real cryptsetup is asked about it. What the override changes
// is the COST: AddRecoveryKey's default is argon2id at 1 GiB, and the CLI
// deliberately does not expose the cost knobs, so this is where a test says it.
func realRecoveryOps() *MockLuksOperations {
	return &MockLuksOperations{
		AddRecoveryKeyFunc: func(device string, existing []byte, opts *luks2.RecoveryKeyOptions) (*luks2.RecoveryKey, error) {
			opts.Argon2Time = 1
			opts.Argon2Memory = 65536
			opts.Argon2Parallel = 1
			return luks2.AddRecoveryKey(device, existing, opts)
		},
		VerifyRecoveryKeyFunc: func(device string, key *enclave.MemoryEnclave) (bool, error) {
			return luks2.VerifyRecoveryKey(device, key)
		},
		RecoveryCredentialFunc:     luks2.RecoveryCredential,
		LoadRecoveryCredentialFunc: luks2.LoadRecoveryCredential,
		SaveRecoveryKeyFunc:        luks2.SaveRecoveryKey,
	}
}

// printedRecoveryKey pulls the key out of what the command displayed.
//
// It reads the line after the RECOVERY KEY banner, which is deliberately the
// only place the key appears: displayed once, and nowhere else.
func printedRecoveryKey(t *testing.T, out string) string {
	t.Helper()

	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if strings.Contains(line, "RECOVERY KEY") && i+1 < len(lines) {
			return lines[i+1]
		}
	}
	t.Fatalf("no recovery key was displayed:\n%s", out)
	return ""
}

// TestRecoveryKeyRoundTripsThroughCryptsetup is the acceptance bar.
//
// The printed characters ARE the passphrase. So the test is the operator's own
// workflow with nothing of ours in the middle: run `luks2 recovery add`, take
// what is on the screen verbatim, and hand those exact bytes to cryptsetup.
//
// Both routes an operator has are exercised, because they read a passphrase
// differently and only one of them is obvious:
//
//	--key-file    the file content IS the passphrase, so the printed text is
//	              written with NO trailing newline
//	stdin         cryptsetup reads one line and discards its terminator, which
//	              is what pasting at the prompt does
func TestRecoveryKeyRoundTripsThroughCryptsetup(t *testing.T) {
	defer parallel(t)()

	requireCryptsetupCLI(t)

	formats := []string{
		string(luks2.RecoveryKeyFormatDashed),
		string(luks2.RecoveryKeyFormatHex),
		string(luks2.RecoveryKeyFormatBase64),
	}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			passphrase := writeFile(t, dir, "pw", "the-existing-passphrase")
			image := newLUKSImage(t, passphrase)

			cli, stdout, stderr := runCLI(t, "", "recovery", "add",
				"--key-file", passphrase, "--format", format, image)
			cli.Luks = realRecoveryOps()

			if code := cli.Run(); code != 0 {
				t.Fatalf("recovery add exited %d, want 0: %s", code, stderr.String())
			}

			printed := printedRecoveryKey(t, stdout.String())
			if printed == "" {
				t.Fatal("the recovery key was displayed as an empty string")
			}

			// Route 1: the characters verbatim, no trailing newline.
			keyFile := writeFile(t, dir, "printed", printed)
			if code, out := runCryptsetupCLI(t, "luksOpen", "--test-passphrase", image, "--key-file", keyFile); code != 0 {
				t.Fatalf("cryptsetup rejected the printed recovery key (exit %d): %s", code, out)
			}

			// Route 2: pasted at the prompt.
			cmd := exec.Command("cryptsetup", "luksOpen", "--test-passphrase", image) // #nosec G204 -- t.TempDir() path
			cmd.Stdin = strings.NewReader(printed + "\n")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("cryptsetup rejected the printed recovery key pasted at its prompt: %v: %s", err, out)
			}

			// And the original passphrase still works: adding a recovery key
			// adds a keyslot, it does not replace one.
			if code, out := runCryptsetupCLI(t, "luksOpen", "--test-passphrase", image, "--key-file", passphrase); code != 0 {
				t.Fatalf("cryptsetup rejected the original passphrase (exit %d): %s", code, out)
			}
		})
	}
}

// TestOnlyTheExactPrintedStringOpensTheVolume is the negative control for the
// test above, and it is not decoration: without it that test would pass for a
// tool that enrolled something else and happened to print something cryptsetup
// also accepts.
//
// Three near misses, each of which a person or a script plausibly produces:
//
//	the bytes BEHIND the rendering	what this package used to enroll
//	the same text, dashes removed	what a "tidy it up" step produces
//	the same text, lower-cased	what a shell pipeline through tr produces
func TestOnlyTheExactPrintedStringOpensTheVolume(t *testing.T) {
	defer parallel(t)()

	requireCryptsetupCLI(t)

	dir := t.TempDir()
	passphrase := writeFile(t, dir, "pw", "the-existing-passphrase")
	image := newLUKSImage(t, passphrase)

	cli, stdout, stderr := runCLI(t, "", "recovery", "add", "--key-file", passphrase, image)
	cli.Luks = realRecoveryOps()
	if code := cli.Run(); code != 0 {
		t.Fatalf("recovery add exited %d, want 0: %s", code, stderr.String())
	}
	printed := printedRecoveryKey(t, stdout.String())

	// The decoded material: the OLD credential, which must no longer open it.
	decoded, err := luks2.ParseRecoveryKey(printed)
	if err != nil {
		t.Fatalf("ParseRecoveryKey() error = %v", err)
	}
	defer mustDestroy(t, decoded)

	rawFile := filepath.Join(dir, "decoded.raw")
	if err := decoded.WithBytes(func(b []byte) error {
		return os.WriteFile(rawFile, b, 0o600)
	}); err != nil {
		t.Fatalf("failed to write the decoded key: %v", err)
	}

	misses := []struct {
		name string
		path string
	}{
		{name: "the decoded bytes behind the rendering", path: rawFile},
		{name: "the text with its dashes stripped", path: writeFile(t, dir, "nodashes", strings.ReplaceAll(printed, "-", ""))},
		{name: "the text lower-cased", path: writeFile(t, dir, "lower", strings.ToLower(printed))},
	}

	for _, miss := range misses {
		t.Run(miss.name, func(t *testing.T) {
			if code, _ := runCryptsetupCLI(t, "luksOpen", "--test-passphrase", image, "--key-file", miss.path); code == 0 {
				t.Fatal("cryptsetup accepted something other than the printed string; the round-trip test proves less than it claims")
			}
		})
	}
}

// TestRecoveryAddWritesTheSystemdRecoveryToken: without it the header says a
// keyslot exists and nothing says what it is, which is indistinguishable from
// somebody's forgotten second passphrase.
func TestRecoveryAddWritesTheSystemdRecoveryToken(t *testing.T) {
	defer parallel(t)()

	requireCryptsetupCLI(t)

	dir := t.TempDir()
	passphrase := writeFile(t, dir, "pw", "the-existing-passphrase")
	image := newLUKSImage(t, passphrase)

	cli, stdout, stderr := runCLI(t, "", "recovery", "add", "--key-file", passphrase, image)
	cli.Luks = realRecoveryOps()
	if code := cli.Run(); code != 0 {
		t.Fatalf("recovery add exited %d, want 0: %s", code, stderr.String())
	}

	tokens, err := luks2.ListTokens(image)
	if err != nil {
		t.Fatalf("ListTokens() error = %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("the container carries %d tokens, want 1", len(tokens))
	}

	for id, token := range tokens {
		if token.Type != "systemd-recovery" {
			t.Errorf("token %d has type %q, want systemd-recovery", id, token.Type)
		}
		// The token names the slot the library CHOSE, not an inferred one.
		slots, err := luks2.ListKeyslots(image)
		if err != nil {
			t.Fatalf("ListKeyslots() error = %v", err)
		}
		added := slots[len(slots)-1].ID
		if len(token.Keyslots) != 1 || token.Keyslots[0] != strconv.Itoa(added) {
			t.Errorf("token keyslots = %v, want [%d]", token.Keyslots, added)
		}
		if !strings.Contains(stdout.String(), fmt.Sprintf("token %d", id)) {
			t.Errorf("stdout did not report the token: %q", stdout.String())
		}
	}

	// cryptsetup must still read the container it now shares a token with.
	if code, out := runCryptsetupCLI(t, "luksDump", image); code != 0 {
		t.Fatalf("cryptsetup could not read the container after the token was written (exit %d): %s", code, out)
	} else if !strings.Contains(out, "systemd-recovery") {
		t.Errorf("cryptsetup luksDump does not show the token:\n%s", out)
	}
}

// TestRecoveryVerifyAcceptsWhatWasPrinted closes the loop through the tool
// itself: the string on the screen, typed back, is accepted.
func TestRecoveryVerifyAcceptsWhatWasPrinted(t *testing.T) {
	defer parallel(t)()

	requireCryptsetupCLI(t)

	dir := t.TempDir()
	passphrase := writeFile(t, dir, "pw", "the-existing-passphrase")
	image := newLUKSImage(t, passphrase)

	cli, stdout, stderr := runCLI(t, "", "recovery", "add", "--key-file", passphrase, image)
	cli.Luks = realRecoveryOps()
	if code := cli.Run(); code != 0 {
		t.Fatalf("recovery add exited %d, want 0: %s", code, stderr.String())
	}
	printed := printedRecoveryKey(t, stdout.String())

	// Typed back on standard input, newline and all, as a person or a script
	// would.
	cli, stdout, stderr = runCLI(t, printed+"\n", "recovery", "verify", image)
	cli.Luks = realRecoveryOps()
	if code := cli.Run(); code != 0 {
		t.Fatalf("recovery verify exited %d, want 0: %s%s", code, stdout.String(), stderr.String())
	}

	// And a key that is not this one is refused, so the check above is not
	// vacuous.
	other, err := luks2.GenerateRecoveryKey(luks2.RecoveryKeyLength, luks2.RecoveryKeyFormatDashed)
	if err != nil {
		t.Fatalf("GenerateRecoveryKey() error = %v", err)
	}
	defer other.Clear()
	wrong, err := other.FormattedString()
	if err != nil {
		t.Fatalf("FormattedString() error = %v", err)
	}

	cli, _, _ = runCLI(t, wrong+"\n", "recovery", "verify", image)
	cli.Luks = realRecoveryOps()
	if code := cli.Run(); code == 0 {
		t.Fatal("recovery verify accepted a recovery key the volume does not hold")
	}
}

// TestRecoveryVerifyReadsASavedFile covers the other input path: the file this
// tool wrote, read back by LoadRecoveryKey rather than parsed as a bare string.
func TestRecoveryVerifyReadsASavedFile(t *testing.T) {
	defer parallel(t)()

	requireCryptsetupCLI(t)

	dir := t.TempDir()
	passphrase := writeFile(t, dir, "pw", "the-existing-passphrase")
	image := newLUKSImage(t, passphrase)
	saved := filepath.Join(dir, "recovery.txt")

	cli, _, stderr := runCLI(t, "", "recovery", "add", "--key-file", passphrase, "--output", saved, image)
	cli.Luks = realRecoveryOps()
	if code := cli.Run(); code != 0 {
		t.Fatalf("recovery add exited %d, want 0: %s", code, stderr.String())
	}

	if _, err := os.Stat(saved); err != nil {
		t.Fatalf("the recovery key was not saved: %v", err)
	}

	cli, stdout, stderr := runCLI(t, "", "recovery", "verify", "--recovery-file", saved, image)
	cli.Luks = realRecoveryOps()
	if code := cli.Run(); code != 0 {
		t.Fatalf("recovery verify exited %d, want 0: %s%s", code, stdout.String(), stderr.String())
	}
}

// TestRecoveryGenerateShowsTheKeyExactlyOnce.
func TestRecoveryGenerateShowsTheKeyExactlyOnce(t *testing.T) {
	cli, stdout, _ := runCLI(t, "", "recovery", "generate")

	if code := cli.Run(); code != 0 {
		t.Fatalf("recovery generate exited %d, want 0", code)
	}

	printed := printedRecoveryKey(t, stdout.String())
	if printed == "" {
		t.Fatal("no key was displayed")
	}
	if n := strings.Count(stdout.String(), printed); n != 1 {
		t.Errorf("the recovery key appears %d times in the output, want exactly 1", n)
	}
	// The checksum is not the key and is explicitly labeled so, because an
	// operator copying "the long hex string" off the screen must not copy that
	// one.
	if !strings.Contains(stdout.String(), "not secret") {
		t.Errorf("stdout = %q, want the checksum labeled", stdout.String())
	}
}

// TestRecoveryGenerateHonorsTheFormat: the format decides what the operator
// writes down.
func TestRecoveryGenerateHonorsTheFormat(t *testing.T) {
	tests := []struct {
		format string
		check  func(string) bool
	}{
		{format: "hex", check: func(s string) bool { return !strings.Contains(s, "-") && len(s) == 64 }},
		{format: "dashed", check: func(s string) bool { return strings.Contains(s, "-") }},
		{format: "base64", check: func(s string) bool { return strings.Contains(s, "=") || len(s) == 44 }},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			cli, stdout, _ := runCLI(t, "", "recovery", "generate", "--format", tt.format)

			if code := cli.Run(); code != 0 {
				t.Fatalf("recovery generate exited %d, want 0", code)
			}
			if printed := printedRecoveryKey(t, stdout.String()); !tt.check(printed) {
				t.Errorf("printed %q, which is not %s", printed, tt.format)
			}
		})
	}
}

func TestRecoveryGenerateRefusesAnImpossibleRequest(t *testing.T) {
	cli, _, stderr := runCLI(t, "", "recovery", "generate", "--format", "morse")
	cli.Luks = &MockLuksOperations{
		GenerateRecoveryKeyFunc: func(int, luks2.RecoveryKeyFormat) (*luks2.RecoveryKey, error) {
			return nil, errors.New("unsupported recovery key format")
		},
	}

	if code := cli.Run(); code != 1 {
		t.Fatalf("recovery generate exited %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "unsupported") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// TestRecoveryAddWarnsLoudlyWhenTheKeyWasNotSaved is the dangerous case: the
// credential is LIVE in a keyslot and the operator believes it is on disk.
func TestRecoveryAddWarnsLoudlyWhenTheKeyWasNotSaved(t *testing.T) {
	cli, stdout, stderr := runCLI(t, "passphrase\n", "recovery", "add", "--output", "/nowhere/recovery.txt", "/dev/sdb1")
	cli.Luks = &MockLuksOperations{
		AddRecoveryKeyFunc: func(device string, existing []byte, opts *luks2.RecoveryKeyOptions) (*luks2.RecoveryKey, error) {
			key, err := luks2.GenerateRecoveryKey(opts.Length, opts.Format)
			if err != nil {
				return nil, err
			}
			key.Keyslot = 2
			key.SaveError = errors.New("permission denied")
			return key, nil
		},
	}

	code := cli.Run()
	if code != 1 {
		t.Fatalf("recovery add exited %d, want 1: a key that was not saved is not a success", code)
	}
	// The key must still be on the screen -- it is the only copy that exists.
	if printed := printedRecoveryKey(t, stdout.String()); printed == "" {
		t.Fatal("the key was not displayed even though it is live in a keyslot")
	}
	if !strings.Contains(stderr.String(), "NOT saved") || !strings.Contains(stderr.String(), "keyslot 2") {
		t.Errorf("stderr = %q, want it to say the key is live and unsaved, and in which slot", stderr.String())
	}
}

// TestRecoveryAddReportsTheKeyslotTheLibraryChose: that number is written into
// the saved file and outlives the process (#42).
func TestRecoveryAddReportsTheKeyslotTheLibraryChose(t *testing.T) {
	cli, stdout, _ := runCLI(t, "passphrase\n", "recovery", "add", "/dev/sdb1")
	cli.Luks = &MockLuksOperations{
		AddRecoveryKeyFunc: func(device string, existing []byte, opts *luks2.RecoveryKeyOptions) (*luks2.RecoveryKey, error) {
			key, err := luks2.GenerateRecoveryKey(opts.Length, opts.Format)
			if err != nil {
				return nil, err
			}
			key.Keyslot = 4
			return key, nil
		},
	}

	if code := cli.Run(); code != 0 {
		t.Fatalf("recovery add exited %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "keyslot 4") {
		t.Errorf("stdout = %q, want it to name keyslot 4", stdout.String())
	}
}

func TestRecoveryAddReportsALibraryFailure(t *testing.T) {
	cli, stdout, stderr := runCLI(t, "wrong-passphrase\n", "recovery", "add", "/dev/sdb1")
	cli.Luks = &MockLuksOperations{
		AddRecoveryKeyFunc: func(string, []byte, *luks2.RecoveryKeyOptions) (*luks2.RecoveryKey, error) {
			return nil, luks2.ErrMasterKeyVerification
		},
	}

	if code := cli.Run(); code != 1 {
		t.Fatalf("recovery add exited %d, want 1", code)
	}
	if strings.Contains(stdout.String(), "RECOVERY KEY") {
		t.Error("a recovery key was displayed for an operation that failed")
	}
	if !strings.Contains(stderr.String(), luks2.ErrMasterKeyVerification.Error()) {
		t.Errorf("stderr = %q, want the library's reason", stderr.String())
	}
}

func TestRecoveryVerifyReportsARefusal(t *testing.T) {
	cli, _, stderr := runCLI(t, "not-the-key\n", "recovery", "verify", "/dev/sdb1")
	cli.Luks = &MockLuksOperations{
		VerifyRecoveryKeyFunc: func(string, *enclave.MemoryEnclave) (bool, error) { return false, nil },
	}

	if code := cli.Run(); code != 1 {
		t.Fatalf("recovery verify exited %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "does NOT open") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// verifyCapturing returns a VerifyRecoveryKeyFunc answering valid that records
// the credential it was handed, so a test can check what became of it.
func verifyCapturing(valid bool, got **enclave.MemoryEnclave) func(string, *enclave.MemoryEnclave) (bool, error) {
	return func(_ string, key *enclave.MemoryEnclave) (bool, error) {
		*got = key
		return valid, nil
	}
}

func TestRecoveryVerifyReleasesTheCredentialCleanly(t *testing.T) {
	var key *enclave.MemoryEnclave
	cli, _, stderr := runCLI(t, "the-recovery-key\n", "recovery", "verify", "/dev/sdb1")
	cli.Luks = &MockLuksOperations{VerifyRecoveryKeyFunc: verifyCapturing(true, &key)}

	if code := cli.Run(); code != 0 {
		t.Fatalf("recovery verify exited %d, want 0: %s", code, stderr.String())
	}
	if key == nil {
		t.Fatal("the credential never reached VerifyRecoveryKey")
	}
	if err := key.WithBytes(func([]byte) error { return nil }); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Errorf("credential after the command = %v, want enclave.ErrEnclaveDestroyed", err)
	}
	if strings.Contains(stderr.String(), "Warning") {
		t.Errorf("a clean release produced a warning: %q", stderr.String())
	}
}

// TestRecoveryVerifyReportsAReleaseReport pins releaseCredential: a release
// go-enclave reports as unclean reaches the operator, and does not change the
// answer the command gives about the key.
func TestRecoveryVerifyReportsAReleaseReport(t *testing.T) {
	tests := []struct {
		name     string
		report   error
		is       error
		valid    bool
		wantCode int
	}{
		{
			name:     "released without the in-process wipe",
			report:   &enclave.UnwipedReleaseError{Cause: errors.New("synthetic mprotect EPERM")},
			is:       enclave.ErrReleasedWithoutWipe,
			valid:    true,
			wantCode: 0,
		},
		{
			name:     "release refused on a key that does not open the volume",
			report:   &enclave.LockedMemoryError{Cause: errors.New("synthetic munmap ENOMEM")},
			is:       enclave.ErrLockedMemoryUnavailable,
			valid:    false,
			wantCode: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.report, tt.is) {
				t.Fatalf("fixture %v does not match %v; the case tests nothing", tt.report, tt.is)
			}
			var key, released *enclave.MemoryEnclave
			cli, _, stderr := runCLI(t, "the-recovery-key\n", "recovery", "verify", "/dev/sdb1")
			cli.Luks = &MockLuksOperations{VerifyRecoveryKeyFunc: verifyCapturing(tt.valid, &key)}
			cli.destroyEnclave = func(e *enclave.MemoryEnclave) error {
				released = e
				if err := e.Destroy(); err != nil {
					t.Errorf("the real release under the fake report failed: %v", err)
				}
				return tt.report
			}

			if code := cli.Run(); code != tt.wantCode {
				t.Fatalf("recovery verify exited %d, want %d: %s", code, tt.wantCode, stderr.String())
			}
			if key == nil || released != key {
				t.Fatal("the credential handed to VerifyRecoveryKey was not the one released")
			}
			want := "Warning: the recovery key's protected memory was not released cleanly: " + tt.report.Error()
			if !strings.Contains(stderr.String(), want) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
			}
		})
	}
}
