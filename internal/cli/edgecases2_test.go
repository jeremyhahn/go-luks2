// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestRunWithFileStdin(t *testing.T) {
	stdin, err := os.Open("/dev/null")
	if err != nil {
		t.Fatalf("Open /dev/null: %v", err)
	}
	defer func() { _ = stdin.Close() }()

	stdout := &bytes.Buffer{}
	code := Run(context.Background(), []string{"luks2", "help"}, stdin, stdout, &bytes.Buffer{})
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
}

func TestCreatePathKindStatError(t *testing.T) {
	regular := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	bogus := filepath.Join(regular, "sub")

	if _, err := createPathKind(bogus); err == nil {
		t.Fatal("createPathKind: want an error when a path component is not a directory")
	}
}

func TestClaimDeviceStatError(t *testing.T) {
	regular := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	bogus := filepath.Join(regular, "sub")

	if _, _, err := claimDevice(bogus); err == nil {
		t.Fatal("claimDevice: want an error when a path component is not a directory")
	}
}

func TestStillCreatedFileNilHandle(t *testing.T) {
	if stillCreatedFile("/nonexistent", nil) {
		t.Error("stillCreatedFile(nil): want false")
	}
}

func TestStillCreatedFileLstatFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() { _ = f.Close() }()

	if stillCreatedFile(filepath.Join(t.TempDir(), "elsewhere-does-not-exist"), f) {
		t.Error("stillCreatedFile: want false when the path cannot be statted")
	}
}

func TestPromptPassphraseConfirmationMismatch(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	e.term = &fakeTerminal{isTerm: true, answers: [][]byte{[]byte("one"), []byte("two")}}
	e.getStdinFd = func() int { return 0 }

	if _, err := promptPassphrase(e, "Enter: ", true); err == nil {
		t.Fatal("promptPassphrase: want an error when the confirmation does not match")
	}
}

func TestPromptPassphraseReadFailure(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	e.term = &fakeTerminal{isTerm: true, failAt: 1}
	e.getStdinFd = func() int { return 0 }

	if _, err := promptPassphrase(e, "Enter: ", false); err == nil {
		t.Fatal("promptPassphrase: want an error when reading the terminal fails")
	}
}

func TestPromptPassphraseConfirmationReadFailure(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	e.term = &fakeTerminal{isTerm: true, answers: [][]byte{[]byte("one")}, failAt: 2}
	e.getStdinFd = func() int { return 0 }

	if _, err := promptPassphrase(e, "Enter: ", true); err == nil {
		t.Fatal("promptPassphrase: want an error when reading the confirmation fails")
	}
}

func TestRunIsLUKS2Flag(t *testing.T) {
	path := newTestVolumeImage(t, "isluks2.img")
	e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})

	if err := runIsLUKS(context.Background(), e, []string{"--luks2", path}); err != nil {
		t.Fatalf("runIsLUKS: %v", err)
	}
	if !strings.Contains(stdout.String(), "LUKS2") {
		t.Errorf("stdout = %q, want it to mention LUKS2", stdout.String())
	}
}

func TestKeyslotCommandsRejectUnknownFlags(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runKeyslots(context.Background(), e, []string{"--bogus", "/dev/sdb1"}); err == nil {
		t.Error("runKeyslots: want an error for an unknown flag")
	}
	if err := runAddKey(context.Background(), e, []string{"--bogus", "/dev/sdb1"}); err == nil {
		t.Error("runAddKey: want an error for an unknown flag")
	}
	if err := runChangeKey(context.Background(), e, []string{"--bogus", "/dev/sdb1", "0"}); err == nil {
		t.Error("runChangeKey: want an error for an unknown flag")
	}
	if err := runRemoveKey(context.Background(), e, []string{"--bogus", "/dev/sdb1", "0"}); err == nil {
		t.Error("runRemoveKey: want an error for an unknown flag")
	}
	if err := runKillSlot(context.Background(), e, []string{"--bogus", "/dev/sdb1", "0"}); err == nil {
		t.Error("runKillSlot: want an error for an unknown flag")
	}
}

func TestRunAddKeyWrongExistingPassphrase(t *testing.T) {
	path := newTestVolumeImage(t, "addkey-wrong.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("not it\nsecond-pass\n"))

	if err := runAddKey(context.Background(), e, []string{"--kdf", "pbkdf2-sha256", path}); err == nil {
		t.Fatal("runAddKey: want an error for the wrong existing passphrase")
	}
}

func TestRunChangeKeyWrongSlotPassphrase(t *testing.T) {
	path := newTestVolumeImage(t, "changekey-wrong.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("not it\nreplacement\n"))

	if err := runChangeKey(context.Background(), e, []string{path, "0"}); err == nil {
		t.Fatal("runChangeKey: want an error for the wrong passphrase")
	}
}

func TestRunRemoveKeyWrongSlotPassphrase(t *testing.T) {
	path := newTestVolumeImage(t, "removekey-wrong.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("not it\n"))

	if err := runRemoveKey(context.Background(), e, []string{path, "0"}); err == nil {
		t.Fatal("runRemoveKey: want an error for the wrong passphrase")
	}
}

func TestRunKillSlotWrongPassphrase(t *testing.T) {
	path := newTestVolumeImage(t, "killslot-wrong.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("not it\n"))

	if err := runKillSlot(context.Background(), e, []string{path, "0"}); err == nil {
		t.Fatal("runKillSlot: want an error for a passphrase that opens nothing")
	}
}

func TestRunTokenImportInvalidJSON(t *testing.T) {
	path := newTestVolumeImage(t, "token-badjson.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("not json"))

	err := runTokenImport(context.Background(), e, []string{"--file", "-", path, "0"})
	var ue *UsageError
	if !asUsageError(err, &ue) {
		t.Fatalf("runTokenImport error = %T, want *UsageError", err)
	}
}

func TestReadBoundedRejectsOverLimit(t *testing.T) {
	if _, err := readBounded(bytes.NewReader(make([]byte, 10)), 5); err == nil {
		t.Fatal("readBounded: want an error over the limit")
	}
}

func TestReadFileBoundedMissingFile(t *testing.T) {
	if _, err := readFileBounded(filepath.Join(t.TempDir(), "nope"), 1024); err == nil {
		t.Fatal("readFileBounded: want an error for a missing file")
	}
}

func TestTokenDeviceAndIDBadPath(t *testing.T) {
	if _, _, err := tokenDeviceAndID("token show", []string{"", "0"}); err == nil {
		t.Fatal("tokenDeviceAndID: want an error for an empty device path")
	}
}

func TestRunTokenCountWrongArgCount(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runTokenCount(context.Background(), e, nil); err == nil {
		t.Fatal("runTokenCount: want a usage error with no arguments")
	}
}

func TestRunTokenFreeAllSlotsUsed(t *testing.T) {
	path := newTestVolumeImage(t, "token-allused.img")
	ctx := context.Background()

	for id := 0; id < 32; id++ {
		e, _, _, _, _ := newTestEnv(bytes.NewBufferString(`{"type":"user-defined","keyslots":["0"]}`))
		if err := runTokenImport(ctx, e, []string{"--file", "-", path, strconv.Itoa(id)}); err != nil {
			t.Fatalf("runTokenImport(%d): %v", id, err)
		}
	}

	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runTokenFree(ctx, e, []string{path}); err == nil {
		t.Fatal("runTokenFree: want an error when every slot is used")
	}
}
