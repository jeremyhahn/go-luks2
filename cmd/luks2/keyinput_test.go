// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// Tests for non-interactive key input.
//
// The ones that matter are DIFFERENTIAL: they format a container with
// cryptsetup using a key file, read the same key file the way this tool does,
// and hand the result back to cryptsetup. If the two readings disagree by so
// much as a trailing newline the container does not open, which is exactly the
// failure an operator hits and cannot explain.
//
// They run unprivileged. LUKS2 header handling on a file image needs no root,
// and `luksOpen --test-passphrase` verifies a passphrase without asking the
// kernel for a device-mapper target.

// keyInputImageSize is comfortably above the header and keyslot area cryptsetup
// reserves.
const keyInputImageSize = 32 << 20

// requireCryptsetupCLI skips the calling test when cryptsetup is missing, and
// says so loudly: a differential test with nothing to differ from reports
// success while verifying nothing.
func requireCryptsetupCLI(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("cryptsetup"); err != nil {
		t.Skipf("SKIPPING KEY-FILE COMPATIBILITY CHECK -- cryptsetup is NOT INSTALLED (%v). "+
			"Nothing in this test was verified against cryptsetup's own key-file handling. "+
			"Install cryptsetup to actually run it.", err)
	}
}

// newLUKSImage creates a sparse image and formats it with cryptsetup, taking
// the passphrase from keyFile exactly as cryptsetup reads it.
//
// The KDF is forced to the cheapest pbkdf2 setting cryptsetup accepts: these
// tests are about byte handling, not about key derivation, and an argon2id
// default would put seconds on every case.
//
// THE 1000 BELOW IS A TEST-SPEED KNOB AND NOTHING ELSE. systemd also writes
// 1000 pbkdf2 iterations, for its recovery and FIDO2 keyslots, for a completely
// unrelated and principled reason -- those credentials are 256 random bits with
// nothing to enumerate (see RecoveryKeyOptions.KDFType). The two numbers are a
// coincidence, they have been confounded once before in this project, and
// changing this one says nothing about that one.
func newLUKSImage(t *testing.T, keyFile string) string {
	t.Helper()

	image := filepath.Join(t.TempDir(), "container.img")
	f, err := os.Create(image) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to create image: %v", err)
	}
	if err := f.Truncate(keyInputImageSize); err != nil {
		_ = f.Close()
		t.Fatalf("failed to size image: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close image: %v", err)
	}

	code, out := runCryptsetupCLI(t, "luksFormat", "--type", "luks2",
		"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000",
		"--batch-mode", image, "--key-file", keyFile)
	if code != 0 {
		t.Fatalf("cryptsetup luksFormat failed (exit %d): %s", code, out)
	}
	return image
}

// runCryptsetupCLI runs cryptsetup and returns its exit code and output.
func runCryptsetupCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()

	cmd := exec.Command("cryptsetup", args...) // #nosec G204 -- arguments are test constants and t.TempDir() paths
	out, err := cmd.CombinedOutput()

	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, string(out)
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), string(out)
	default:
		t.Fatalf("failed to run cryptsetup %v: %v", args, err)
		return -1, ""
	}
}

// writeFile writes content to a file under dir and returns its path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
	return path
}

// keyFileCases are the shapes of key file that distinguish a correct reader
// from a plausible one.
var keyFileCases = []struct {
	name    string
	content string
}{
	{name: "no trailing newline", content: "hunter2"},
	{
		// The one that breaks tools: `echo secret > key` produces this, and the
		// newline IS part of the passphrase.
		name:    "trailing newline",
		content: "hunter2\n",
	},
	{name: "a second line is part of it too", content: "hunter2\nsecond line\n"},
	{name: "leading and trailing spaces are content", content: "  spaced out  "},
	{name: "a NUL byte is content", content: "abc\x00def"},
	{name: "long", content: strings.Repeat("x", 8000)},
}

// TestKeyFileReadingMatchesCryptsetup is the acceptance bar for --key-file.
//
// cryptsetup formats the container FROM the key file, so the container's
// passphrase is whatever cryptsetup thinks the file holds. This tool then reads
// the same file, writes what it got to a second file, and cryptsetup is asked to
// open with that. It opens only if the two readings are byte-identical.
func TestKeyFileReadingMatchesCryptsetup(t *testing.T) {
	requireCryptsetupCLI(t)

	for _, tc := range keyFileCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			keyFile := writeFile(t, dir, "key", tc.content)
			image := newLUKSImage(t, keyFile)

			f, err := os.Open(keyFile) // #nosec G304 -- path is under t.TempDir()
			if err != nil {
				t.Fatalf("failed to open key file: %v", err)
			}
			defer func() { _ = f.Close() }()

			got, err := readKeyFile(f, keyFile)
			if err != nil {
				t.Fatalf("readKeyFile() error = %v", err)
			}
			if string(got) != tc.content {
				t.Fatalf("readKeyFile() = %q, want the file verbatim %q", got, tc.content)
			}

			ours := writeFile(t, dir, "ours", string(got))
			if code, out := runCryptsetupCLI(t, "luksOpen", "--test-passphrase", image, "--key-file", ours); code != 0 {
				t.Fatalf("cryptsetup rejected what this tool read from the key file (exit %d): %s", code, out)
			}
		})
	}
}

// TestTrimmingAKeyFileWouldBreakIt is the negative control for the test above.
//
// A reader that strips the trailing newline -- the obvious, wrong
// implementation -- produces a credential cryptsetup does not accept. Without
// this case the differential test would pass for a tool that trims, because
// most key files have no trailing newline to trim.
func TestTrimmingAKeyFileWouldBreakIt(t *testing.T) {
	requireCryptsetupCLI(t)

	dir := t.TempDir()
	keyFile := writeFile(t, dir, "key", "hunter2\n")
	image := newLUKSImage(t, keyFile)

	trimmed := writeFile(t, dir, "trimmed", "hunter2")
	if code, _ := runCryptsetupCLI(t, "luksOpen", "--test-passphrase", image, "--key-file", trimmed); code == 0 {
		t.Fatal("cryptsetup accepted a trimmed key file; the differential test above proves nothing")
	}
}

// TestPipedPassphraseMatchesCryptsetup covers the OTHER rule: with no
// --key-file, a passphrase piped to standard input is one line, and the newline
// is not part of it.
//
// It is the opposite convention to a key file, on the same tool, which is
// exactly why both are pinned here rather than described in a comment.
func TestPipedPassphraseMatchesCryptsetup(t *testing.T) {
	requireCryptsetupCLI(t)

	tests := []struct {
		name  string
		piped string
		want  string
	}{
		{name: "line with newline", piped: "hunter2\n", want: "hunter2"},
		{name: "line without newline", piped: "hunter2", want: "hunter2"},
		{name: "everything after the newline is ignored", piped: "hunter2\nGARBAGE\n", want: "hunter2"},
		{name: "spaces are content", piped: "  spaced  \n", want: "  spaced  "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readKeyLine(strings.NewReader(tt.piped))
			if err != nil {
				t.Fatalf("readKeyLine() error = %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("readKeyLine() = %q, want %q", got, tt.want)
			}

			// cryptsetup, reading the same pipe, must reach the same passphrase.
			dir := t.TempDir()
			image := newLUKSImage(t, writeFile(t, dir, "key", tt.want))

			cmd := exec.Command("cryptsetup", "luksOpen", "--test-passphrase", image) // #nosec G204 -- t.TempDir() path
			cmd.Stdin = strings.NewReader(tt.piped)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("cryptsetup read a different passphrase from the same pipe: %v: %s", err, out)
			}
		})
	}
}

// TestReadKeyLineLeavesTheRestOfTheStream is why the line reader does not use
// bufio: `luks2 create` reads a volume label from the same stream immediately
// afterwards.
func TestReadKeyLineLeavesTheRestOfTheStream(t *testing.T) {
	stream := strings.NewReader("the-passphrase\nthe-label\n")

	got, err := readKeyLine(stream)
	if err != nil {
		t.Fatalf("readKeyLine() error = %v", err)
	}
	if string(got) != "the-passphrase" {
		t.Fatalf("readKeyLine() = %q, want %q", got, "the-passphrase")
	}

	rest, err := readKeyLine(stream)
	if err != nil {
		t.Fatalf("second readKeyLine() error = %v", err)
	}
	if string(rest) != "the-label" {
		t.Errorf("the rest of the stream = %q, want %q: the reader consumed ahead", rest, "the-label")
	}
}

func TestReadKeyFileRefusesWhatCryptsetupRefuses(t *testing.T) {
	t.Run("larger than the bound", func(t *testing.T) {
		oversize := strings.NewReader(strings.Repeat("x", maxKeyFileSize+1))

		got, err := readKeyFile(oversize, "oversize")
		if err == nil {
			t.Fatalf("readKeyFile() accepted %d bytes, want a refusal", len(got))
		}
		if !errors.Is(err, ErrKeyFileTooLarge) {
			t.Errorf("error = %v, want errors.Is(_, ErrKeyFileTooLarge)", err)
		}
		if !errors.Is(err, ErrKeyInput) {
			t.Errorf("error = %v, want it to match ErrKeyInput too", err)
		}
	})

	t.Run("exactly the bound is accepted", func(t *testing.T) {
		atLimit := strings.NewReader(strings.Repeat("x", maxKeyFileSize))

		got, err := readKeyFile(atLimit, "at-limit")
		if err != nil {
			t.Fatalf("readKeyFile() refused a file of exactly the maximum size: %v", err)
		}
		if len(got) != maxKeyFileSize {
			t.Errorf("read %d bytes, want %d", len(got), maxKeyFileSize)
		}
	})

	t.Run("a read failure is reported, not swallowed", func(t *testing.T) {
		if _, err := readKeyFile(failingReader{}, "broken"); !errors.Is(err, ErrKeyInput) {
			t.Errorf("error = %v, want errors.Is(_, ErrKeyInput)", err)
		}
	})

	t.Run("a read failure on the line path is reported too", func(t *testing.T) {
		if _, err := readKeyLine(failingReader{}); !errors.Is(err, ErrKeyInput) {
			t.Errorf("error = %v, want errors.Is(_, ErrKeyInput)", err)
		}
	})
}

// failingReader fails on the first read, which is what a closed pipe or a
// removed device does.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("input went away") }

// TestReadPassphraseChoosesTheSource pins the dispatch itself, which is the
// part an operator experiences as "it hung waiting for a prompt that was never
// going to come".
func TestReadPassphraseChoosesTheSource(t *testing.T) {
	dir := t.TempDir()
	keyFile := writeFile(t, dir, "key", "from-the-file\n")

	tests := []struct {
		name       string
		src        KeySource
		stdin      string
		isTerminal bool
		want       string
	}{
		{
			name: "a key file is read whole",
			src:  KeySource{Path: keyFile},
			want: "from-the-file\n",
		},
		{
			name:  "dash means standard input, read whole",
			src:   KeySource{Path: stdinKeyFile},
			stdin: "from-stdin\n",
			want:  "from-stdin\n",
		},
		{
			name:  "a pipe with no flag is one line",
			stdin: "from-a-pipe\nignored\n",
			want:  "from-a-pipe",
		},
		{
			name:       "a terminal is prompted",
			isTerminal: true,
			stdin:      "not read",
			want:       "testpassword",
		},
		{
			// A key file WINS over a terminal: an operator who names one has
			// said where the credential is, and prompting anyway would hang a
			// unit that has a terminal attached for other reasons.
			name:       "a key file wins over a terminal",
			src:        KeySource{Path: keyFile},
			isTerminal: true,
			want:       "from-the-file\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli, _, _ := newTestCLI([]string{"luks2"})
			cli.Stdin = strings.NewReader(tt.stdin)
			cli.Terminal = &MockTerminal{Password: []byte("testpassword"), NotATerminal: !tt.isTerminal}

			got, err := cli.readPassphrase("Enter passphrase: ", false, tt.src)
			if err != nil {
				t.Fatalf("readPassphrase() error = %v", err)
			}
			defer ClearBytes(got)

			if string(got) != tt.want {
				t.Errorf("readPassphrase() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadPassphraseReportsAKeyFileItCannotOpen(t *testing.T) {
	cli, _, _ := newTestCLI([]string{"luks2"})

	_, err := cli.readPassphrase("Enter passphrase: ", false, KeySource{Path: filepath.Join(t.TempDir(), "absent")})
	if !errors.Is(err, ErrKeyInput) {
		t.Fatalf("error = %v, want errors.Is(_, ErrKeyInput)", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error = %v, want the cause to still be reachable", err)
	}
}

// TestOpenUnlocksWithAKeyFile is the workload this exists for: no terminal
// anywhere, and the passphrase handed to the library is the file's bytes
// verbatim.
func TestOpenUnlocksWithAKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyFile := writeFile(t, dir, "key", "backup-script-passphrase\n")

	var handed []byte
	cli, _, stderr := newTestCLI([]string{"luks2", "open", "--key-file", keyFile, "/dev/sdb1", "backup"})
	cli.Terminal = &MockTerminal{Err: errors.New("there is no terminal"), NotATerminal: true}
	cli.Luks = &MockLuksOperations{
		UnlockFunc: func(device string, passphrase []byte, name string) error {
			handed = append([]byte(nil), passphrase...)
			return nil
		},
	}

	if code := cli.Run(); code != 0 {
		t.Fatalf("open exited %d, want 0: %s", code, stderr.String())
	}
	if string(handed) != "backup-script-passphrase\n" {
		t.Errorf("passphrase handed to Unlock = %q, want the key file verbatim", handed)
	}
}

// TestOpenUnlocksFromAPipe covers the other unattended shape.
func TestOpenUnlocksFromAPipe(t *testing.T) {
	var handed []byte
	cli, _, stderr := newTestCLI([]string{"luks2", "open", "/dev/sdb1", "backup"})
	cli.Stdin = strings.NewReader("piped-passphrase\n")
	cli.Terminal = &MockTerminal{Err: errors.New("there is no terminal"), NotATerminal: true}
	cli.Luks = &MockLuksOperations{
		UnlockFunc: func(device string, passphrase []byte, name string) error {
			handed = append([]byte(nil), passphrase...)
			return nil
		},
	}

	if code := cli.Run(); code != 0 {
		t.Fatalf("open exited %d, want 0: %s", code, stderr.String())
	}
	if string(handed) != "piped-passphrase" {
		t.Errorf("passphrase handed to Unlock = %q, want the line without its newline", handed)
	}
}

func TestOpenRefusesAnUnknownOption(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "open", "--key-fil", "/tmp/k", "/dev/sdb1", "backup"})

	if code := cli.Run(); code == 0 {
		t.Fatal("open accepted a misspelled option")
	}
	if !strings.Contains(stderr.String(), "unknown option") {
		t.Errorf("stderr = %q, want it to name the unknown option", stderr.String())
	}
}

// TestCreateDoesNotPromptForALabelWhenUnattended: Fscanln on a script's stdin
// consumes whatever the script sent next.
func TestCreateDoesNotPromptForALabelWhenUnattended(t *testing.T) {
	dir := t.TempDir()
	keyFile := writeFile(t, dir, "key", "create-passphrase")

	var gotLabel string
	cli, stdout, _ := newTestCLI([]string{"luks2", "create", "--key-file", keyFile, filepath.Join(dir, "vol.luks"), "32M"})
	cli.Terminal = &MockTerminal{Err: errors.New("there is no terminal"), NotATerminal: true}
	cli.FS = &MockFileSystem{Files: make(map[string]bool)}
	cli.Luks = &MockLuksOperations{
		FormatFunc: func(opts luks2.FormatOptions) error {
			gotLabel = opts.Label
			return nil
		},
		SetupLoopDeviceFunc: func(string) (string, error) { return "", errors.New("no loop devices in a unit test") },
	}

	if code := cli.Run(); code != 0 {
		t.Fatalf("create exited %d, want 0", code)
	}
	if gotLabel != "" {
		t.Errorf("label = %q, want empty: nobody was there to answer the prompt", gotLabel)
	}
	if strings.Contains(stdout.String(), "Enter volume label") {
		t.Error("create prompted for a label with no terminal attached")
	}
}

// TestOptionsParser covers the shared parser directly, including the shapes the
// subcommands rely on.
func TestOptionsParser(t *testing.T) {
	t.Run("options in any position", func(t *testing.T) {
		o := newOptions("test")
		key := o.String("key-file", "")
		flag := o.Bool("force")

		args, err := o.parse([]string{"first", "--key-file", "/k", "second", "--force"})
		if err != nil {
			t.Fatalf("parse() error = %v", err)
		}
		if *key != "/k" || !*flag {
			t.Errorf("key-file = %q, force = %v", *key, *flag)
		}
		if fmt.Sprint(args) != "[first second]" {
			t.Errorf("positional = %v, want [first second]", args)
		}
	})

	t.Run("inline values", func(t *testing.T) {
		o := newOptions("test")
		key := o.String("key-file", "")
		slot := o.Int("slot", -1)

		if _, err := o.parse([]string{"--key-file=/k", "--slot=3"}); err != nil {
			t.Fatalf("parse() error = %v", err)
		}
		if *key != "/k" || *slot != 3 {
			t.Errorf("key-file = %q, slot = %d", *key, *slot)
		}
	})

	t.Run("a bare dash is a positional argument", func(t *testing.T) {
		o := newOptions("test")
		key := o.String("key-file", "")

		args, err := o.parse([]string{"--key-file", "-", "-"})
		if err != nil {
			t.Fatalf("parse() error = %v", err)
		}
		if *key != "-" {
			t.Errorf("key-file = %q, want -", *key)
		}
		if len(args) != 1 || args[0] != "-" {
			t.Errorf("positional = %v, want [-]", args)
		}
	})

	t.Run("refusals", func(t *testing.T) {
		tests := []struct {
			name string
			args []string
		}{
			{name: "unknown option", args: []string{"--nope"}},
			{name: "missing value", args: []string{"--key-file"}},
			{name: "a number that is not one", args: []string{"--slot", "many"}},
			{name: "a value on a boolean", args: []string{"--force=maybe"}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				o := newOptions("test")
				o.String("key-file", "")
				o.Int("slot", -1)
				o.Bool("force")

				if _, err := o.parse(tt.args); !errors.Is(err, ErrUsage) {
					t.Errorf("error = %v, want errors.Is(_, ErrUsage)", err)
				}
			})
		}
	})
}

// TestReadAllSecretZeroesWhatItOutgrows: an abandoned buffer holding a
// passphrase is a passphrase on the heap.
func TestReadAllSecretZeroesWhatItOutgrows(t *testing.T) {
	// Larger than the 4 KiB the reader starts with, so at least one buffer is
	// outgrown and abandoned.
	content := bytes.Repeat([]byte("s"), 10_000)

	got, err := readAllSecret(bytes.NewReader(content), maxKeyFileSize+1)
	if err != nil {
		t.Fatalf("readAllSecret() error = %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("readAllSecret() returned %d bytes, want %d", len(got), len(content))
	}
}
