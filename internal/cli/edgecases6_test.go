// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEmptyDeviceAcrossCommands drives absPath's "an empty path" branch
// for every command whose first positional argument is a device, which a
// happy-path test (a real temp-file device) never reaches.
func TestEmptyDeviceAcrossCommands(t *testing.T) {
	cases := []struct {
		name string
		run  func(context.Context, *env, []string) error
		args []string
	}{
		{"keyslots", runKeyslots, []string{""}},
		{"testkey", runTestKey, []string{""}},
		{"addkey", runAddKey, []string{""}},
		{"changekey", runChangeKey, []string{"", "0"}},
		{"removekey", runRemoveKey, []string{"", "0"}},
		{"killslot", runKillSlot, []string{"", "0"}},
		{"recovery add", runRecoveryAdd, []string{""}},
		{"recovery verify", runRecoveryVerify, []string{""}},
		{"token list", runTokenList, []string{""}},
		{"token show", runTokenShow, []string{"", "0"}},
		{"token export", runTokenExport, []string{"", "0"}},
		{"token import", runTokenImport, []string{"", "0"}},
		{"token remove", runTokenRemove, []string{"", "0"}},
		{"token free", runTokenFree, []string{""}},
		{"token exists", runTokenExists, []string{"", "0"}},
		{"token count", runTokenCount, []string{""}},
		{"header show", runHeaderShow, []string{""}},
		{"header secondary", runHeaderSecondary, []string{""}},
		{"header restore", runHeaderRestore, []string{""}},
		{"info", runInfo, []string{""}},
		{"isluks", runIsLUKS, []string{""}},
		{"wipe", runWipe, []string{""}},
		{"create", runCreate, []string{""}},
		{"open", runOpen, []string{"", "name"}},
	}
	for _, c := range cases {
		e, _, _, _, _ := newTestEnv(bytes.NewBufferString("YES\n"))
		if err := c.run(context.Background(), e, c.args); err == nil {
			t.Errorf("%s: want an error for an empty device path", c.name)
		}
	}
}

func TestRunCreateKDFResolveFailure(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	err := runCreate(context.Background(), e, []string{"--pbkdf", "pbkdf2", "--hash", "sha1", "/dev/sdb1"})
	var ue *UsageError
	if !asUsageError(err, &ue) {
		t.Fatalf("runCreate error = %T, want *UsageError for an invalid --hash", err)
	}
}

func TestRunRecoveryAddKDFResolveFailure(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	err := runRecoveryAdd(context.Background(), e, []string{"--pbkdf", "pbkdf2", "--hash", "sha1", "/dev/sdb1"})
	var ue *UsageError
	if !asUsageError(err, &ue) {
		t.Fatalf("runRecoveryAdd error = %T, want *UsageError for an invalid --hash", err)
	}
}

func TestRunWipeHeaderOnlyCanceled(t *testing.T) {
	path := newTestVolumeImage(t, "wipe-header-cancel.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("no\n"))

	if err := runWipe(context.Background(), e, []string{path}); err == nil {
		t.Fatal("runWipe: want an error when the confirmation is refused")
	}
}

func TestRunIsLUKSUnknownFlag(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runIsLUKS(context.Background(), e, []string{"--bogus", "/dev/sdb1"}); err == nil {
		t.Fatal("runIsLUKS: want an error for an unknown flag")
	}
}

func TestRemoveCreatedFileSourceMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gone.img")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() { _ = f.Close() }()
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if err := removeCreatedFile(path, f); err == nil {
		t.Fatal("removeCreatedFile: want an error when the path no longer exists to rename")
	}
}

func TestRunCreateFileVolumeOpenLoopDeviceFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vol.luks")
	e, _, _, _, stderr := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
	lp := e.host.looper.(*fakeLooper)
	lp.device.devPath = filepath.Join(t.TempDir(), "nonexistent-loop-target")

	args := []string{"--pbkdf", "pbkdf2", "--hash", "sha256", "--iter-time", "1", path, "24M"}
	if err := runCreate(context.Background(), e, args); err == nil {
		t.Fatal("runCreate: want an error when the loop device cannot be opened")
	}
	if len(lp.detached) != 1 {
		t.Errorf("detached = %v, want one call", lp.detached)
	}
	if stderr.Len() == 0 {
		t.Error("stderr should report the failure")
	}
}

func TestRunCreateFileVolumeMkfsFailureDeactivateAlsoFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vol.luks")
	e, act, mnt, _, stderr := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
	mnt.makeErr = errMkfsFailed
	act.deactivateErr = errSentinel

	args := []string{"--pbkdf", "pbkdf2", "--hash", "sha256", "--iter-time", "1", path, "24M"}
	if err := runCreate(context.Background(), e, args); err == nil {
		t.Fatal("runCreate: want an error when mkfs fails")
	}
	if !strings.Contains(stderr.String(), "Failed to close") {
		t.Errorf("stderr = %q, want it to report the failed deactivate", stderr.String())
	}
}

func TestCreatePathKindAndClaimDeviceOnEmptyPath(t *testing.T) {
	// runCreate's own createPathKind error branch, reached with a path
	// that absPath accepts (non-empty) but that cannot be statted for a
	// reason other than "does not exist" -- a NUL byte is rejected by the
	// syscall outright.
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runCreate(context.Background(), e, []string{"/tmp/has\x00nul"}); err == nil {
		t.Fatal("runCreate: want an error for a path the OS refuses to stat")
	}
}
