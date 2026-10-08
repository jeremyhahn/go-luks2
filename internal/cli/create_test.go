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
)

// fastKDF is the cheapest KDFParams the library writes, the one
// newTestVolumeImage formats with.
var fastKDF = fastTestKDF

func TestCreatePathKind(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "f")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	absent := filepath.Join(dir, "nope")

	if kind, err := createPathKind(regular); err != nil || kind != pathRegular {
		t.Errorf("createPathKind(regular) = %v, %v; want pathRegular, nil", kind, err)
	}
	if kind, err := createPathKind(absent); err != nil || kind != pathAbsent {
		t.Errorf("createPathKind(absent) = %v, %v; want pathAbsent, nil", kind, err)
	}
}

func TestClaimDeviceFindsKnownSignature(t *testing.T) {
	path := filepath.Join(t.TempDir(), "luks.img")
	data := make([]byte, signatureScanSize)
	copy(data, []byte("LUKS\xba\xbe"))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	found, release, err := claimDevice(path)
	if err != nil {
		t.Fatalf("claimDevice: %v", err)
	}
	defer release()
	if found != "a LUKS header" {
		t.Errorf("found = %q, want %q", found, "a LUKS header")
	}
}

func TestClaimDeviceNoSignature(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.img")
	if err := os.WriteFile(path, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	found, release, err := claimDevice(path)
	if err != nil {
		t.Fatalf("claimDevice: %v", err)
	}
	defer release()
	if found != "" {
		t.Errorf("found = %q, want none", found)
	}
}

func TestCreateBlockDeviceFormatsSuccessfully(t *testing.T) {
	path := filepath.Join(t.TempDir(), "block.img")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := f.Truncate(testVolumeImageSize); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	e, _, _, stdout, _ := newTestEnv(bytes.NewBufferString("YES\n" + testPassphrase + "\n"))

	if err := createBlockDevice(context.Background(), e, path, keySource{}, fastKDF, fastTestKDFLabel, false, false); err != nil {
		t.Fatalf("createBlockDevice: %v", err)
	}
	if !strings.Contains(stdout.String(), "created successfully") {
		t.Errorf("stdout = %q, want success message", stdout.String())
	}
}

func TestCreateBlockDeviceRefusesExistingSignatureWithoutForce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signed.img")
	data := make([]byte, testVolumeImageSize)
	copy(data, []byte("LUKS\xba\xbe"))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})

	err := createBlockDevice(context.Background(), e, path, keySource{}, fastKDF, fastTestKDFLabel, true, false)
	if err == nil {
		t.Fatal("createBlockDevice: want an error for an existing signature without --force")
	}
	if !strings.Contains(err.Error(), "LUKS header") {
		t.Errorf("err = %v, want it to name the signature", err)
	}
}

func TestCreateBlockDeviceForceOverwritesExistingSignature(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signed-force.img")
	data := make([]byte, testVolumeImageSize)
	copy(data, []byte("LUKS\xba\xbe"))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	e, _, _, stdout, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))

	if err := createBlockDevice(context.Background(), e, path, keySource{}, fastKDF, fastTestKDFLabel, true, true); err != nil {
		t.Fatalf("createBlockDevice: %v", err)
	}
	if !strings.Contains(stdout.String(), "created successfully") {
		t.Errorf("stdout = %q, want success message", stdout.String())
	}
}

// TestCreateBlockDeviceRefusesWithoutConfirmation is #246 D10/D12 against
// createBlockDevice directly: no answer on stdin cancels, and the refusal
// is reported on stderr naming the operation ("Create canceled"), matching
// docs/volumes/cli.md's documented confirmation prompt.
func TestCreateBlockDeviceRefusesWithoutConfirmation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "block-noconfirm.img")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := f.Truncate(testVolumeImageSize); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	e, _, _, _, stderr := newTestEnv(&bytes.Buffer{})

	if err := createBlockDevice(context.Background(), e, path, keySource{}, fastKDF, fastTestKDFLabel, false, false); err == nil {
		t.Fatal("createBlockDevice: want an error when nothing confirms the prompt")
	}
	if !strings.Contains(stderr.String(), "canceled") {
		t.Errorf("stderr = %q, want it to report the operation as canceled", stderr.String())
	}
}

func TestRunCreateFileVolumeEndToEnd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vol.luks")
	e, act, mnt, stdout, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))

	args := append(append([]string{}, fastKDFArgs...), path, "24M")
	if err := runCreate(context.Background(), e, args); err != nil {
		t.Fatalf("runCreate: %v", err)
	}

	if len(act.activated) != 1 || act.activated[0] != "luks-auto" {
		t.Errorf("activated = %v, want [luks-auto]", act.activated)
	}
	if len(mnt.makeCalls) != 1 {
		t.Errorf("makeCalls = %v, want exactly one", mnt.makeCalls)
	}
	if !strings.Contains(stdout.String(), "created successfully") {
		t.Errorf("stdout = %q, want success message", stdout.String())
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the container file should still exist: %v", err)
	}
}

func TestRunCreateFileVolumeUnsupportedFilesystem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vol.luks")
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})

	err := runCreate(context.Background(), e, []string{path, "16M", "btrfs"})
	var ue *UsageError
	if err == nil {
		t.Fatal("runCreate: want an error for an unsupported filesystem")
	} else if !asUsageError(err, &ue) {
		t.Errorf("err = %T, want *UsageError", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("no file should have been created for a rejected filesystem")
	}
}

func TestRunCreateFileVolumeLoopAttachFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vol.luks")
	e, _, _, _, stderr := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
	lp := e.host.looper.(*fakeLooper)
	lp.attachErr = errAttachFailed

	args := append(append([]string{}, fastKDFArgs...), path, "24M")
	if err := runCreate(context.Background(), e, args); err == nil {
		t.Fatal("runCreate: want an error when the loop device cannot be attached")
	}
	if !strings.Contains(stderr.String(), "loop device") {
		t.Errorf("stderr = %q, want it to mention the loop device", stderr.String())
	}
	// The formatted container is left in place for the operator to finish
	// by hand.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the container file should still exist: %v", err)
	}
}

func TestRunCreateFileVolumeMkfsFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vol.luks")
	e, act, mnt, _, stderr := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
	mnt.makeErr = errMkfsFailed

	args := append(append([]string{}, fastKDFArgs...), path, "24M")
	if err := runCreate(context.Background(), e, args); err == nil {
		t.Fatal("runCreate: want an error when mkfs fails")
	}
	if !strings.Contains(stderr.String(), "filesystem") {
		t.Errorf("stderr = %q, want it to mention the filesystem", stderr.String())
	}
	if len(act.deactivated) != 1 {
		t.Errorf("deactivated = %v, want the mapping to be torn down", act.deactivated)
	}
}

// TestRunCreateCleanupSurvivesACanceledCtx is S2: an interrupt that cancels
// the caller's ctx must not stop the teardown of the mapping and loop device
// create itself set up, or they would be left behind.
func TestRunCreateCleanupSurvivesACanceledCtx(t *testing.T) {
	args := func() []string {
		return append(append([]string{}, fastKDFArgs...),
			filepath.Join(t.TempDir(), "vol.luks"), "24M")
	}

	t.Run("mkfs failure", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		e, act, mnt, _, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
		lp := e.host.looper.(*fakeLooper)
		mnt.makeErr = errMkfsFailed
		mnt.onMake = cancel

		if err := runCreate(ctx, e, args()); err == nil {
			t.Fatal("runCreate: want an error when mkfs fails")
		}
		if len(act.deactivated) != 1 || act.deactivateCtxErr != nil {
			t.Errorf("deactivated = %v with ctx error %v, want one call on a live ctx", act.deactivated, act.deactivateCtxErr)
		}
		if len(lp.detached) != 1 || lp.detachCtxErr != nil {
			t.Errorf("detached = %v with ctx error %v, want one call on a live ctx", lp.detached, lp.detachCtxErr)
		}
	})

	t.Run("activate failure", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		e, act, _, _, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
		lp := e.host.looper.(*fakeLooper)
		act.activateErr = errors.New("activate failed")
		act.onActivate = cancel

		if err := runCreate(ctx, e, args()); err == nil {
			t.Fatal("runCreate: want an error when activation fails")
		}
		if len(lp.detached) != 1 || lp.detachCtxErr != nil {
			t.Errorf("detached = %v with ctx error %v, want one call on a live ctx", lp.detached, lp.detachCtxErr)
		}
	})
}

func TestRunCreateMissingArgs(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runCreate(context.Background(), e, nil); err == nil {
		t.Fatal("runCreate: want a usage error with no arguments")
	}
}

func TestRunCreateFileVolumeMissingSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vol.luks")
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runCreate(context.Background(), e, []string{path}); err == nil {
		t.Fatal("runCreate: want a usage error with no size for a file volume")
	}
}

func asUsageError(err error, target **UsageError) bool {
	ue, ok := err.(*UsageError)
	if ok {
		*target = ue
	}
	return ok
}

var (
	errAttachFailed = &testFailure{"loop attach failed"}
	errMkfsFailed   = &testFailure{"mkfs failed"}
)

type testFailure struct{ msg string }

func (e *testFailure) Error() string { return e.msg }
