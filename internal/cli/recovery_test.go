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

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// fastKDFArgs are the shared KDF flags recovery add and create tests pass
// to avoid the library's default (a multi-second PBKDF2 calibration, or a
// 1 GiB Argon2id derivation): Argon2id at the cheapest cost the library
// writes, or PBKDF2 at its iteration floor in FIPS mode, which refuses Argon2.
var fastKDFArgs = func() []string {
	if fipsProcess {
		return []string{"--pbkdf", "pbkdf2", "--iter-time", "1"}
	}
	return []string{"--pbkdf", "argon2id", "--pbkdf-force-iterations", "1", "--pbkdf-memory", "65536", "--pbkdf-parallel", "1"}
}()

func TestRunRecoveryGenerate(t *testing.T) {
	e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})

	if err := runRecoveryGenerate(context.Background(), e, nil); err != nil {
		t.Fatalf("runRecoveryGenerate: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "RECOVERY KEY") {
		t.Errorf("stdout = %q, want the recovery key banner", out)
	}
	if !strings.Contains(out, "Checksum") {
		t.Errorf("stdout = %q, want the checksum line", out)
	}
}

func TestRunRecoveryGenerateWithOutput(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "gen.txt")
	e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})

	if err := runRecoveryGenerate(context.Background(), e, []string{"--output", outputPath}); err != nil {
		t.Fatalf("runRecoveryGenerate: %v", err)
	}
	if !strings.Contains(stdout.String(), "Saved to") {
		t.Errorf("stdout = %q, want save confirmation", stdout.String())
	}
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("Stat output: %v", err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Errorf("output mode = %v, want 0400", info.Mode().Perm())
	}
}

func TestRunRecoveryGenerateBadFormat(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})

	err := runRecoveryGenerate(context.Background(), e, []string{"--format", "nope"})
	var ue *UsageError
	if !asUsageError(err, &ue) {
		t.Fatalf("runRecoveryGenerate error = %T, want *UsageError", err)
	}
}

func TestRunRecoveryAddAndVerify(t *testing.T) {
	path := newTestVolumeImage(t, "recovery-add.img")
	outputPath := filepath.Join(t.TempDir(), "recovery.txt")

	addE, _, _, addStdout, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
	args := append(append([]string{}, fastKDFArgs...), "--output", outputPath, path)
	if err := runRecoveryAdd(context.Background(), addE, args); err != nil {
		t.Fatalf("runRecoveryAdd: %v", err)
	}
	out := addStdout.String()
	if !strings.Contains(out, "RECOVERY KEY") {
		t.Errorf("stdout = %q, want the recovery key banner", out)
	}
	if !strings.Contains(out, "Added to keyslot") {
		t.Errorf("stdout = %q, want it to report the keyslot", out)
	}
	if !strings.Contains(out, "Saved to") {
		t.Errorf("stdout = %q, want save confirmation", out)
	}

	verifyE, _, _, verifyStdout, _ := newTestEnv(&bytes.Buffer{})
	if err := runRecoveryVerify(context.Background(), verifyE, []string{"--recovery-file", outputPath, path}); err != nil {
		t.Fatalf("runRecoveryVerify: %v", err)
	}
	if !strings.Contains(verifyStdout.String(), "opens") {
		t.Errorf("stdout = %q, want confirmation", verifyStdout.String())
	}
}

func TestRunRecoveryVerifyWrongKey(t *testing.T) {
	path := newTestVolumeImage(t, "recovery-verify-wrong.img")
	e, _, _, _, stderr := newTestEnv(bytes.NewBufferString(
		"ABCDEF-ABCDEF-ABCDEF-ABCDEF-ABCDEF-ABCDEF-ABCDEF-ABCDEF-ABCDEF-ABCDEF-AB\n"))

	err := runRecoveryVerify(context.Background(), e, []string{path})
	if err == nil {
		t.Fatal("runRecoveryVerify: want an error for a key that does not open the volume")
	}
	if got := exitCode(err); got != 2 {
		t.Errorf("exit status = %d, want 2 (a key that does not open the volume)", got)
	}
	if !strings.Contains(stderr.String(), "does NOT open") {
		t.Errorf("stderr = %q, want the verdict line", stderr.String())
	}

	// The help text must state the status the command exits with.
	usage := recoveryCommand().sub["verify"].usage
	if !strings.Contains(usage, "2 if it does not") || strings.Contains(usage, "1 otherwise") {
		t.Errorf("recovery verify help = %q, does not say a key that does not open the volume exits 2", usage)
	}
}

// A failure that never tried the key is not a verdict on it: no "does NOT
// open" line, and the status is the failure's own, not the wrong-key 2.
func TestRunRecoveryVerifyOperationalFailureIsNotAVerdict(t *testing.T) {
	path := newTestVolumeImage(t, "recovery-verify-unreadable.img")
	// Cut the image inside the keyslots area: the header still opens, but the
	// keyslot cannot be read.
	if err := os.Truncate(path, 32*1024); err != nil {
		t.Fatal(err)
	}
	e, _, _, stdout, stderr := newTestEnv(bytes.NewBufferString(
		"ABCDEF-ABCDEF-ABCDEF-ABCDEF-ABCDEF-ABCDEF-ABCDEF-ABCDEF-ABCDEF-ABCDEF-AB\n"))

	err := runRecoveryVerify(context.Background(), e, []string{path})
	if err == nil {
		t.Fatal("runRecoveryVerify: want an error for a volume whose keyslot cannot be read")
	}
	if errors.Is(err, luks2.ErrWrongKey) {
		t.Fatalf("runRecoveryVerify = %v, want a failure other than a wrong key", err)
	}
	if strings.Contains(stderr.String(), "does NOT open") || strings.Contains(stdout.String(), "does NOT open") {
		t.Errorf("stdout = %q, stderr = %q, want no verdict on a key that was never tried", stdout.String(), stderr.String())
	}
	if got := exitCode(err); got != 4 {
		t.Errorf("exit status = %d, want 4 (an unreadable keyslot is an invalid header, not the wrong-key 2)", got)
	}
}

func TestRunRecoveryAddMissingArgs(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runRecoveryAdd(context.Background(), e, fastKDFArgs); err == nil {
		t.Fatal("runRecoveryAdd: want a usage error with no device")
	}
}

func TestRunRecoveryVerifyMissingArgs(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runRecoveryVerify(context.Background(), e, nil); err == nil {
		t.Fatal("runRecoveryVerify: want a usage error with no device")
	}
}

func TestParseRecoveryFormatRejectsEmpty(t *testing.T) {
	if _, err := parseRecoveryFormat("recovery generate", ""); err == nil {
		t.Fatal("parseRecoveryFormat: want an error for an empty format")
	}
	var ue *UsageError
	_, err := parseRecoveryFormat("recovery generate", "")
	if !errors.As(err, &ue) {
		t.Fatalf("parseRecoveryFormat error = %T, want *UsageError", err)
	}
}
