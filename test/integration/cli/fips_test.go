// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

// TestCLI_FIPSModeCreateAndRecoveryAddOpenWithCryptsetup is the acceptance
// bar for #237, on the real kernel.
//
// A luks2 binary built with the Go Cryptographic Module and run under
// GODEBUG=fips140=only creates a volume and enrolls a recovery key with NO KDF
// options -- before #237 both were refused, because create hard-coded
// Argon2id and recovery add defaulted to it. Both keyslots must be
// PBKDF2-SHA512, and cryptsetup -- a separate implementation, in no FIPS mode
// of its own -- must open the volume with each credential. An explicit
// --pbkdf argon2id must be refused before the device is touched.
//
// create is given the loop device rather than a file: on a file it also
// unlocks under a fixed mapping name, which is host-global and is not this
// test's subject.
func TestCLI_FIPSModeCreateAndRecoveryAddOpenWithCryptsetup(t *testing.T) {
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		t.Fatalf("cryptsetup is not installed (%v); the integration image declares it, "+
			"and nothing here can be verified without it", err)
	}

	dir := t.TempDir()
	fipsBinary := filepath.Join(dir, "luks2-fips")
	build := exec.Command("go", "build", "-o", fipsBinary, "github.com/jeremyhahn/go-luks2/cmd/luks2")
	build.Env = append(os.Environ(), "GOFIPS140=latest")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the FIPS-mode CLI failed: %v\n%s", err, out)
	}

	image := filepath.Join(dir, "fips.img")
	f, err := os.Create(image)
	if err != nil {
		t.Fatalf("creating the image failed: %v", err)
	}
	if err := f.Truncate(32 * 1024 * 1024); err != nil {
		_ = f.Close()
		t.Fatalf("sizing the image failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing the image failed: %v", err)
	}

	loopOut, err := exec.Command("losetup", "-f", "--show", image).Output()
	if err != nil {
		t.Fatalf("attaching the image failed: %v", err)
	}
	loopDev := strings.TrimSpace(string(loopOut))
	defer detachLoopDevicesBackedBy(t, image)

	keyFile := filepath.Join(dir, "passphrase")
	if err := os.WriteFile(keyFile, []byte("fips-mode-passphrase"), 0o600); err != nil {
		t.Fatalf("writing the key file failed: %v", err)
	}

	runFIPS := func(args ...string) (string, string, error) {
		cmd := exec.Command(fipsBinary, args...)
		cmd.Env = append(os.Environ(), "GODEBUG=fips140=only")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}

	// An explicit Argon2id is refused up front: the device is still blank.
	_, stderr, err := runFIPS("create", "--key-file", keyFile, "--pbkdf", "argon2id", loopDev)
	if err == nil {
		t.Fatal("create --pbkdf argon2id succeeded under fips140=only")
	}
	if !strings.Contains(stderr, luks2.ErrFIPSNotApproved.Error()) {
		t.Fatalf("create --pbkdf argon2id: stderr %q, want the FIPS refusal", stderr)
	}
	contents, err := os.ReadFile(image)
	if err != nil {
		t.Fatalf("reading the image failed: %v", err)
	}
	if !bytes.Equal(contents, make([]byte, len(contents))) {
		t.Fatal("the refused create wrote to the device")
	}

	// The defaults: create, then recovery add, with no KDF option.
	stdout, stderr, err := runFIPS("create", "--batch-mode", "--key-file", keyFile, loopDev)
	if err != nil {
		t.Fatalf("create under fips140=only failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "KDF: PBKDF2-SHA512") {
		t.Errorf("create did not report the FIPS default KDF:\n%s", stdout)
	}

	stdout, stderr, err = runFIPS("recovery", "add", "--key-file", keyFile, loopDev)
	if err != nil {
		t.Fatalf("recovery add under fips140=only failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	recoveryKey := printedRecoveryKey(t, stdout)

	// Both keyslots are PBKDF2-SHA512 at no less than the SHA-512 floor for the
	// default budget.
	_, metadata, err := harness.ReadHeader(image)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if len(metadata.Keyslots) != 2 {
		t.Fatalf("the volume has %d keyslots, want 2", len(metadata.Keyslots))
	}
	for id, keyslot := range metadata.Keyslots {
		kdf := keyslot.KDF
		if kdf.Type != "pbkdf2" || kdf.Hash != "sha512" {
			t.Fatalf("keyslot %s KDF = %s/%s, want pbkdf2/sha512", id, kdf.Type, kdf.Hash)
		}
		if kdf.Iterations == nil || *kdf.Iterations < 210000 {
			t.Fatalf("keyslot %s iterations = %v, want at least the SHA-512 floor 210000", id, kdf.Iterations)
		}
	}

	// cryptsetup opens the volume with each credential: the passphrase, and
	// the recovery key exactly as printed.
	recoveryFile := filepath.Join(dir, "recovery")
	if err := os.WriteFile(recoveryFile, []byte(recoveryKey), 0o600); err != nil {
		t.Fatalf("writing the recovery key file failed: %v", err)
	}
	for i, credential := range []string{keyFile, recoveryFile} {
		name := runVolume(t, "test-cli-fips-"+strconv.Itoa(i))
		if out, err := exec.Command("cryptsetup", "open", "--key-file", credential, loopDev, name).CombinedOutput(); err != nil {
			t.Fatalf("cryptsetup could not open the volume with credential %d: %v\n%s", i, err, out)
		}
		if out, err := exec.Command("cryptsetup", "close", name).CombinedOutput(); err != nil {
			t.Fatalf("cryptsetup could not close %s: %v\n%s", name, err, out)
		}
	}
}

// printedRecoveryKey pulls the key out of what `recovery add` displayed: the
// line after the RECOVERY KEY banner.
func printedRecoveryKey(t *testing.T, out string) string {
	t.Helper()

	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if strings.Contains(line, "RECOVERY KEY") && i+1 < len(lines) && lines[i+1] != "" {
			return lines[i+1]
		}
	}
	t.Fatalf("no recovery key was displayed:\n%s", out)
	return ""
}
