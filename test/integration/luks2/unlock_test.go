// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// Unlock without activation: Volume.Unlock derives the master key from a
// real on-disk header and a passphrase, which is as far as this package's
// own API reaches now that activation moved to pkg/dmcrypt (#268,
// test/integration/dmcrypt's own activation_test.go covers the rest of the
// old luks2.Unlock's work -- creating the device-mapper mapping).

func TestVolumeUnlockDerivesTheKey(t *testing.T) {
	tmpfile := "/tmp/test-luks-unlock.img"
	defer os.Remove(tmpfile)

	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(50 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	passphrase := []byte("test-password")
	opts := FormatOptions{
		Device:        tmpfile,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1,
	}
	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	ctx := context.Background()
	v, err := luks2.Open(ctx, tmpfile)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy(passphrase)
	if err != nil {
		t.Fatalf("could not hold the test passphrase in protected memory: %v", err)
	}
	defer func() { _ = pass.Destroy() }()

	key, err := v.Unlock(ctx, pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	if key.Size() == 0 {
		t.Fatal("Unlock returned an empty master key")
	}
}

func TestVolumeUnlockWithWrongPassphraseFails(t *testing.T) {
	tmpfile := "/tmp/test-luks-wrong-pass.img"
	defer os.Remove(tmpfile)

	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(50 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	opts := FormatOptions{
		Device:        tmpfile,
		Passphrase:    []byte("correct-password"),
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1,
	}
	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	ctx := context.Background()
	v, err := luks2.Open(ctx, tmpfile)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy([]byte("wrong-password"))
	if err != nil {
		t.Fatalf("could not hold the test passphrase in protected memory: %v", err)
	}
	defer func() { _ = pass.Destroy() }()

	if _, err := v.Unlock(ctx, pass); !errors.Is(err, luks2.ErrWrongKey) {
		t.Fatalf("Unlock with the wrong passphrase = %v, want ErrWrongKey", err)
	}
}

func TestVolumeOpenErrors(t *testing.T) {
	if _, err := luks2.Open(context.Background(), "/dev/nonexistent"); err == nil {
		t.Fatal("Open of a nonexistent device returned no error")
	}
}
