// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Key files through the built binary against cryptsetup, both ways: a key
// file is the passphrase byte for byte, trailing newline included, in both
// tools (docs/cli/key-input.md). A tool that stripped the newline would
// enroll a passphrase the other cannot open from the same file.

func cliKeyFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// cliImage is a sparse image cryptsetup formatted with first's key file.
func cliImage(t *testing.T, first string) string {
	t.Helper()
	image := filepath.Join(t.TempDir(), "keyfile.img")
	if err := os.WriteFile(image, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(image, 64<<20); err != nil {
		t.Fatal(err)
	}
	cryptsetup(t, true, "luksFormat", "--type", "luks2", "--batch-mode", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000",
		"--key-file", first, image)
	return image
}

// cryptsetup runs cryptsetup and fails the test unless it succeeded exactly
// when want says it should.
func cryptsetup(t *testing.T, want bool, args ...string) {
	t.Helper()
	out, err := exec.Command("cryptsetup", args...).CombinedOutput() // #nosec G204 -- test constants and files this test made
	if (err == nil) != want {
		t.Fatalf("cryptsetup %v: err %v, want success %v\n%s", args, err, want, out)
	}
}

func TestCLI_KeyFilesAreReadAsCryptsetupReadsThem(t *testing.T) {
	first := cliKeyFile(t, "cli-first-passphrase")

	t.Run("luks2 addkey -> cryptsetup", func(t *testing.T) {
		image := cliImage(t, first)
		withNewline := cliKeyFile(t, "cli-new-passphrase\n")
		if _, stderr, err := runCLI("addkey", "--pbkdf", "pbkdf2", "--iter-time", "100", "--key-file", first, "--new-key-file", withNewline, image); err != nil {
			t.Fatalf("luks2 addkey: %v\n%s", err, stderr)
		}
		cryptsetup(t, true, "open", "--test-passphrase", "--key-file", withNewline, image)
		cryptsetup(t, false, "open", "--test-passphrase", "--key-file", cliKeyFile(t, "cli-new-passphrase"), image)
	})

	t.Run("cryptsetup luksAddKey -> luks2 testkey", func(t *testing.T) {
		image := cliImage(t, first)
		withNewline := cliKeyFile(t, "cli-new-passphrase\n")
		cryptsetup(t, true, "luksAddKey", "--batch-mode", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000",
			"--key-file", first, image, withNewline)
		if _, stderr, err := runCLI("testkey", "--key-file", withNewline, image); err != nil {
			t.Fatalf("luks2 testkey with cryptsetup's key file: %v\n%s", err, stderr)
		}
		if _, _, err := runCLI("testkey", "--key-file", cliKeyFile(t, "cli-new-passphrase"), image); err == nil {
			t.Fatal("luks2 testkey opened the volume without the key file's trailing newline")
		}
	})
}
