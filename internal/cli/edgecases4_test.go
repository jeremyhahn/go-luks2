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

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func TestKDFFlagsArgon2InvalidMemoryAndParallel(t *testing.T) {
	f := newFlags("create")
	kdf := declareKDFFlags(f)
	if _, err := f.parse([]string{"--pbkdf-memory", "not-a-number"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, _, err := kdf.resolve(); err == nil {
		t.Fatal("resolve: want an error for a non-numeric --pbkdf-memory")
	}

	f2 := newFlags("create")
	kdf2 := declareKDFFlags(f2)
	if _, err := f2.parse([]string{"--pbkdf-parallel", "not-a-number"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, _, err := kdf2.resolve(); err == nil {
		t.Fatal("resolve: want an error for a non-numeric --pbkdf-parallel")
	}
}

func TestKDFFlagsPBKDF2InvalidHash(t *testing.T) {
	f := newFlags("create")
	kdf := declareKDFFlags(f)
	if _, err := f.parse([]string{"--pbkdf", "pbkdf2", "--hash", "sha1"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, _, err := kdf.resolve(); err == nil {
		t.Fatal("resolve: want an error for --hash sha1")
	}
}

func TestRunRecoveryGenerateLengthTooShort(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runRecoveryGenerate(context.Background(), e, []string{"--length", "4"}); err == nil {
		t.Fatal("runRecoveryGenerate: want an error for a length below the minimum")
	}
}

func TestRunRecoveryGenerateOutputSaveFailure(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "nonexistent-dir", "key.txt")
	e, _, _, _, stderr := newTestEnv(&bytes.Buffer{})

	if err := runRecoveryGenerate(context.Background(), e, []string{"--output", outputPath}); err == nil {
		t.Fatal("runRecoveryGenerate: want an error when the output directory does not exist")
	}
	if stderr.Len() == 0 {
		t.Error("stderr should report the save failure")
	}
}

func TestRunRecoveryAddOutputSaveFailure(t *testing.T) {
	path := newTestVolumeImage(t, "recovery-add-savefail.img")
	outputPath := filepath.Join(t.TempDir(), "nonexistent-dir", "key.txt")

	e, _, _, stdout, stderr := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
	args := append(append([]string{}, fastKDFArgs...), "--output", outputPath, path)
	if err := runRecoveryAdd(context.Background(), e, args); err == nil {
		t.Fatal("runRecoveryAdd: want an error when the output directory does not exist")
	}
	if !strings.Contains(stdout.String(), "RECOVERY KEY") {
		t.Errorf("stdout = %q, want the key to still have been shown", stdout.String())
	}
	if stderr.Len() == 0 {
		t.Error("stderr should warn that the key was not saved")
	}
}

func TestRunTokenCountOnNonLUKSDevice(t *testing.T) {
	path := newPlainImage(t, "token-count-plain.img")
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runTokenCount(context.Background(), e, []string{path}); err == nil {
		t.Fatal("runTokenCount: want an error for a non-LUKS2 device")
	}
}

func TestRunTokenShowOnNonLUKSDevice(t *testing.T) {
	path := newPlainImage(t, "token-show-plain.img")
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runTokenShow(context.Background(), e, []string{path, "0"}); err == nil {
		t.Fatal("runTokenShow: want an error for a non-LUKS2 device")
	}
}

func TestRunRecoveryVerifyBadFile(t *testing.T) {
	path := newTestVolumeImage(t, "recovery-verify-badfile.img")
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	err := runRecoveryVerify(context.Background(), e, []string{"--recovery-file", filepath.Join(t.TempDir(), "nope"), path})
	if err == nil {
		t.Fatal("runRecoveryVerify: want an error for a missing --recovery-file")
	}
}

func TestUnshownRecoveryKeyRollbackFailure(t *testing.T) {
	path := newTestVolumeImage(t, "unshown-recovery-fail.img")
	ctx := context.Background()

	v, err := luks2.Open(ctx, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	pass := newTestPassphraseEnclave(t)
	defer pass.Destroy()
	key, err := v.Unlock(ctx, pass)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer key.Destroy()
	rk, err := luks2.NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey: %v", err)
	}
	defer rk.Destroy()
	enrollment, err := v.AddRecoveryKey(ctx, key, rk, luks2.KeyslotParams{Priority: luks2.PriorityNormal, KDF: fastKDF})
	if err != nil {
		t.Fatalf("AddRecoveryKey: %v", err)
	}

	// Closing the volume first makes the rollback's own RemoveKeyslot
	// fail (ErrClosed), covering unshownRecoveryKey's own failure path.
	if err := v.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	e, _, _, _, stderr := newTestEnv(&bytes.Buffer{})
	if got := unshownRecoveryKey(ctx, e, v, path, enrollment, errSentinel); got != errSentinel {
		t.Errorf("unshownRecoveryKey = %v, want the cause back", got)
	}
	if stderr.Len() == 0 {
		t.Error("stderr should warn that the rollback itself failed")
	}
}
