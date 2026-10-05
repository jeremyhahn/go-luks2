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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// #246 against the built binary and real block devices: create on a block
// device asks, refuses existing data, and reports a cancel in its exit
// status (D10, D12); a relative path works (D14).

// blankLoop attaches a zeroed image and returns the loop device and image.
func blankLoop(t *testing.T) (string, string) {
	t.Helper()
	image := filepath.Join(t.TempDir(), "blank.img")
	if err := os.WriteFile(image, make([]byte, 32<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("losetup", "-f", "--show", image).Output()
	if err != nil {
		t.Fatalf("losetup: %v", err)
	}
	t.Cleanup(func() { detachLoopDevicesBackedBy(t, image) })
	return strings.TrimSpace(string(out)), image
}

// TestCLI_CreateOnABlockDeviceAsksAndRefusesData is #246 D10: create formatted
// a block device without asking and over whatever was on it.
func TestCLI_CreateOnABlockDeviceAsksAndRefusesData(t *testing.T) {
	loop, image := blankLoop(t)
	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte("lane-d-cli-passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}

	// No answer: refused, non-zero, nothing written.
	if _, stderr, err := runCLIWithInput("", "create", "--key-file", keyFile, loop); err == nil || !strings.Contains(stderr, "canceled") {
		t.Fatalf("create with no confirmation: %v, stderr %q", err, stderr)
	}
	if got, _ := os.ReadFile(image); !bytes.Equal(got, make([]byte, len(got))) {
		t.Fatal("an unconfirmed create wrote to the device")
	}

	// YES: formatted.
	if _, stderr, err := runCLIWithInput("YES\n", "create", "--key-file", keyFile, loop); err != nil {
		t.Fatalf("create with YES: %v\n%s", err, stderr)
	}
	if ok, err := luks2.IsLUKS2(loop); err != nil || !ok {
		t.Fatalf("the confirmed create left no LUKS2 header (%v)", err)
	}
	_, before, err := luks2.ReadHeader(loop)
	if err != nil {
		t.Fatal(err)
	}

	// A LUKS header is there now: refused even in batch mode, without --force.
	if _, stderr, err := runCLI("create", "--batch-mode", "--key-file", keyFile, loop); err == nil || !strings.Contains(stderr, "a LUKS header") {
		t.Fatalf("create over a LUKS header: %v, stderr %q", err, stderr)
	}
	_, after, err := luks2.ReadHeader(loop)
	if err != nil || after.Config == nil || before.Config == nil {
		t.Fatalf("the refused create damaged the header: %v", err)
	}

	// --force: formatted again.
	if _, stderr, err := runCLI("create", "--batch-mode", "--force", "--key-file", keyFile, loop); err != nil {
		t.Fatalf("create --force: %v\n%s", err, stderr)
	}
}

// TestCLI_RelativePathsWork is #246 D14: the documented `luks2 ... vol.luks`
// form failed for every command, because the library takes absolute paths.
func TestCLI_RelativePathsWork(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join(dir, "vol.luks")
	if err := os.WriteFile(image, make([]byte, 32<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := luks2.Format(luks2.FormatOptions{Device: image, Passphrase: []byte("lane-d-cli-passphrase"), KDFType: luks2.KDFTypePBKDF2, PBKDFIterTime: 1}); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binaryPath, "isluks", "--luks2", "vol.luks")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isluks with a relative path: %v\n%s", err, out)
	}
	cmd = exec.Command(binaryPath, "testkey", "vol.luks")
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader("lane-d-cli-passphrase\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("testkey with a relative path: %v\n%s", err, out)
	}
}
