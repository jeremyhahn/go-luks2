// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
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

// volumeMethodCalls is every *Volume method but Path and Close, each called
// with arguments that would do work on an open, writable handle. The bool
// marks the methods volumes/engineering.md lists as writes.
func volumeMethodCalls(t *testing.T) []struct {
	name  string
	write bool
	call  func(ctx context.Context, v *Volume) error
} {
	t.Helper()
	pass := newTestPassphrase(t)
	t.Cleanup(func() { _ = pass.Destroy() })
	provider := &fakeKeyProvider{credential: []byte("a-provider-credential"), token: Token{Type: "x-provider", Keyslots: []int{0}}}
	return []struct {
		name  string
		write bool
		call  func(ctx context.Context, v *Volume) error
	}{
		{"Format", true, func(ctx context.Context, v *Volume) error { return v.Format(ctx, pass, FormatParams{}) }},
		{"Erase", true, func(ctx context.Context, v *Volume) error { return v.Erase(ctx) }},
		{"AddKeyslot", true, func(ctx context.Context, v *Volume) error {
			_, err := v.AddKeyslot(ctx, nil, pass, KeyslotParams{})
			return err
		}},
		{"ChangeKeyslot", true, func(ctx context.Context, v *Volume) error {
			_, err := v.ChangeKeyslot(ctx, nil, pass, KeyslotParams{})
			return err
		}},
		{"RemoveKeyslot", true, func(ctx context.Context, v *Volume) error { return v.RemoveKeyslot(ctx, 0) }},
		{"AddToken", true, func(ctx context.Context, v *Volume) error {
			_, err := v.AddToken(ctx, Token{Type: "x-test"})
			return err
		}},
		{"SetToken", true, func(ctx context.Context, v *Volume) error { return v.SetToken(ctx, 0, Token{Type: "x-test"}) }},
		{"RemoveToken", true, func(ctx context.Context, v *Volume) error { return v.RemoveToken(ctx, 0) }},
		{"Enroll", true, func(ctx context.Context, v *Volume) error {
			_, err := v.Enroll(ctx, nil, provider, KeyslotParams{})
			return err
		}},
		{"AddRecoveryKey", true, func(ctx context.Context, v *Volume) error {
			_, err := v.AddRecoveryKey(ctx, nil, nil, KeyslotParams{})
			return err
		}},
		{"RestorePrimaryHeader", true, func(ctx context.Context, v *Volume) error { return v.RestorePrimaryHeader(ctx) }},
		{"ReplacePrimaryHeader", true, func(ctx context.Context, v *Volume) error { return v.ReplacePrimaryHeader(ctx) }},
		{"MigrateToFIPS", true, func(ctx context.Context, v *Volume) error {
			_, err := v.MigrateToFIPS(ctx, pass, MigrateParams{})
			return err
		}},
		{"Header", false, func(ctx context.Context, v *Volume) error {
			_, err := v.Header(ctx)
			return err
		}},
		{"SecondaryHeader", false, func(ctx context.Context, v *Volume) error {
			_, err := v.SecondaryHeader(ctx)
			return err
		}},
		{"Unlock", false, func(ctx context.Context, v *Volume) error {
			k, err := v.Unlock(ctx, pass)
			if k != nil {
				k.Destroy()
			}
			return err
		}},
		{"UnlockKeyslot", false, func(ctx context.Context, v *Volume) error {
			k, err := v.UnlockKeyslot(ctx, 0, pass)
			if k != nil {
				k.Destroy()
			}
			return err
		}},
		{"UnlockWithProvider", false, func(ctx context.Context, v *Volume) error {
			k, err := v.UnlockWithProvider(ctx, provider)
			if k != nil {
				k.Destroy()
			}
			return err
		}},
		{"UnlockWithVolumeKey", false, func(ctx context.Context, v *Volume) error {
			k, err := v.UnlockWithVolumeKey(ctx, pass)
			if k != nil {
				k.Destroy()
			}
			return err
		}},
		{"Target", false, func(ctx context.Context, v *Volume) error {
			_, err := v.Target(ctx, nil)
			return err
		}},
	}
}

// TestEveryVolumeMethodHonoursErrClosedAndErrReadOnly pins volumes/
// engineering.md's two handle sentinels for every method, not a sample: after
// Close every method but Path and Close returns an *Error whose Kind is
// ErrClosed and whose Op names the method; Close is idempotent; on a
// WithReadOnly handle every write method returns ErrReadOnly; a closed
// read-only handle reports ErrClosed first; and no refusal touches the device.
func TestEveryVolumeMethodHonoursErrClosedAndErrReadOnly(t *testing.T) {
	ctx := context.Background()
	path := formattedVolumeImage(t, "sentinels.img", "", "")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the image failed: %v", err)
	}
	calls := volumeMethodCalls(t)

	refusedAs := func(t *testing.T, name string, err, want error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Errorf("%s = %v, want %v", name, err, want)
			return
		}
		var e *Error
		if !errors.As(err, &e) {
			t.Errorf("%s returned %T, want an *Error", name, err)
			return
		}
		if !strings.Contains(e.Op, name) {
			t.Errorf("%s's error has Op %q, want the method's name", name, e.Op)
		}
	}

	t.Run("closed", func(t *testing.T) {
		v, err := Open(ctx, path, withTestSys(testVolumeSys()))
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		if err := v.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
		if err := v.Close(); err != nil {
			t.Fatalf("a second Close = %v, want nil", err)
		}
		if v.Path() == "" {
			t.Error("Path on a closed Volume is empty")
		}
		for _, c := range calls {
			refusedAs(t, c.name, c.call(ctx, v), ErrClosed)
		}
	})

	t.Run("read-only", func(t *testing.T) {
		v, err := Open(ctx, path, withTestSys(testVolumeSys()), WithReadOnly())
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		for _, c := range calls {
			if c.write {
				refusedAs(t, c.name, c.call(ctx, v), ErrReadOnly)
			}
		}
		if err := v.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
		for _, c := range calls {
			if c.write {
				refusedAs(t, c.name, c.call(ctx, v), ErrClosed)
			}
		}
	})

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the image back failed: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a refused call changed the device")
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

// WithTestSysForTest hands the external luks2_test package the Option the
// in-package tests get from cheapOpts: Open with testVolumeSys, whose KDF and
// digest floors are the minimum, not the production calibration. It exists
// only in the test build, so it is no part of the package API.
func WithTestSysForTest() Option {
	return withTestSys(testVolumeSys())
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

// TestTheDefaultLockIsCryptsetups pins what the cryptsetup-interop metadata
// lock table measures: a Volume locks in cryptsetup's directory,
// /run/cryptsetup, and waits DefaultLockWait, 30 s, before ErrLockContended.
func TestTheDefaultLockIsCryptsetups(t *testing.T) {
	if DefaultLockWait != 30*time.Second {
		t.Errorf("DefaultLockWait = %v, want 30s", DefaultLockWait)
	}
	s := defaultVolumeSys()
	if s.lockDir != "/run/cryptsetup" {
		t.Errorf("lockDir = %q, want cryptsetup's /run/cryptsetup", s.lockDir)
	}
	if s.lockWait != DefaultLockWait {
		t.Errorf("lockWait = %v, want DefaultLockWait", s.lockWait)
	}
}
