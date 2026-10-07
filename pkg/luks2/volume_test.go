// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"errors"
	"testing"
	"time"
)

// formattedVolumeImage formats a fresh temp image with minimum legal cost
// and the given label/subsystem, returning its path.
func formattedVolumeImage(t *testing.T, name, label, subsystem string) string {
	t.Helper()

	path := newImage(t, name)
	if err := formatForTest(formatOptionsForTest{
		Device:        path,
		Passphrase:    []byte("correct horse battery staple"),
		Cipher:        "aes",
		CipherMode:    "xts-plain64",
		KeySize:       512,
		HashAlgo:      "sha256",
		SectorSize:    512,
		KDFType:       kdfTypePBKDF2,
		PBKDFIterTime: 1,
		Label:         label,
		Subsystem:     subsystem,
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}
	return path
}

func TestOpenPinsTheGivenPath(t *testing.T) {
	path := newImage(t, "open.img")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if got := v.Path(); got != path {
		t.Errorf("Path() = %q, want %q", got, path)
	}
}

func TestOpenOnAMissingPathFailsWithErrDeviceNotFound(t *testing.T) {
	_, err := Open(context.Background(), "/nonexistent/go-luks2-test-path")
	if err == nil {
		t.Fatal("Open on a missing path succeeded, want an error")
	}
	if !errors.Is(err, ErrDeviceNotFound) {
		t.Errorf("Open error = %v, want ErrDeviceNotFound", err)
	}
}

func TestOpenRefusesAnAlreadyCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	path := newImage(t, "canceled.img")
	_, err := Open(ctx, path, withTestSys(testVolumeSys()))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Open(canceled ctx) = %v, want context.Canceled", err)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	path := newImage(t, "close.img")
	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if err := v.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
}

func TestMethodsOnAClosedVolumeReturnErrClosed(t *testing.T) {
	path := newImage(t, "closed.img")
	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if _, err := v.Header(context.Background()); !errors.Is(err, ErrClosed) {
		t.Errorf("Header on a closed Volume = %v, want ErrClosed", err)
	}
	if err := v.RestorePrimaryHeader(context.Background()); !errors.Is(err, ErrClosed) {
		t.Errorf("RestorePrimaryHeader on a closed Volume = %v, want ErrClosed", err)
	}
}

func TestWithReadOnlyRefusesAMutatingMethod(t *testing.T) {
	path := formattedVolumeImage(t, "readonly.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()), WithReadOnly())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if err := v.RestorePrimaryHeader(context.Background()); !errors.Is(err, ErrReadOnly) {
		t.Errorf("RestorePrimaryHeader on a read-only Volume = %v, want ErrReadOnly", err)
	}

	// A read-only Volume can still read its header.
	if _, err := v.Header(context.Background()); err != nil {
		t.Errorf("Header on a read-only Volume failed: %v", err)
	}
}

func TestWithLockWaitOverridesTheDefault(t *testing.T) {
	path := newImage(t, "lockwait.img")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()), WithLockWait(5*time.Second))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if v.sys.lockWait != 5*time.Second {
		t.Errorf("lockWait = %v, want 5s", v.sys.lockWait)
	}
}

func TestOpenWithoutWithLockWaitUsesTheDefault(t *testing.T) {
	path := newImage(t, "defaultlockwait.img")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if v.sys.lockWait != DefaultLockWait {
		t.Errorf("lockWait = %v, want the default %v", v.sys.lockWait, DefaultLockWait)
	}
}
