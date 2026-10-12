// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package dmcrypt_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"github.com/jeremyhahn/go-luks2/pkg/loop"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// This file drives Activate, Deactivate and Lookup against a REAL
// device-mapper target and a REAL kernel keyring, over a loop device. It
// needs root (device-mapper and the loop-control ioctls both do) and runs
// in the devcontainer only, with make integration-test.

const integrationPassphrase = "dmcrypt-integration-test-passphrase"

func formatOnLoopDevice(t *testing.T) (*luks2.Volume, *luks2.Key, string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "dmcrypt-integration.img")
	f, err := os.Create(path) //nolint:gosec // path is under t.TempDir()
	if err != nil {
		t.Fatalf("creating the backing file failed: %v", err)
	}
	if err := f.Truncate(64 << 20); err != nil {
		t.Fatalf("sizing the backing file failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing the backing file failed: %v", err)
	}

	loopDev, err := loop.Attach(context.Background(), path)
	if err != nil {
		t.Fatalf("loop.Attach failed (this test needs root): %v", err)
	}
	t.Cleanup(func() { _, _ = loopDev.Detach(context.Background()) })

	passphrase := []byte(integrationPassphrase)
	pass, err := enclave.NewMemoryCopy(passphrase)
	if err != nil {
		t.Fatalf("could not hold the test passphrase in protected memory: %v", err)
	}
	defer func() { _ = pass.Destroy() }()

	v, err := luks2.Open(context.Background(), loopDev.Path())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })

	if err := v.Format(context.Background(), pass, luks2.FormatParams{
		KDF: luks2.KDFParams{Type: luks2.KDFPBKDF2, IterTime: time.Millisecond},
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	t.Cleanup(key.Destroy)

	return v, key, loopDev.Path()
}

// TestActivateDeactivateLookupRoundTrip is the end-to-end happy path: a
// real dm-crypt target is created, named, found by Lookup, read from and
// written to through its mapped path, and torn down again -- with nothing
// left behind in the kernel keyring or at /dev/mapper.
func TestActivateDeactivateLookupRoundTrip(t *testing.T) {
	v, key, _ := formatOnLoopDevice(t)
	name := "dmcrypt-it-roundtrip"

	mapping, err := dmcrypt.Activate(context.Background(), v, key, name)
	if err != nil {
		t.Fatalf("Activate failed: %v", err)
	}
	t.Cleanup(func() { _ = dmcrypt.Deactivate(context.Background(), name) })

	if mapping.Name != name {
		t.Fatalf("mapping.Name = %q, want %q", mapping.Name, name)
	}
	if mapping.Path() != "/dev/mapper/"+name {
		t.Fatalf("mapping.Path() = %q", mapping.Path())
	}

	looked, err := dmcrypt.Lookup(context.Background(), name)
	if err != nil {
		t.Fatalf("Lookup failed right after Activate: %v", err)
	}
	if looked.UUID != mapping.UUID || looked.Major != mapping.Major || looked.Minor != mapping.Minor {
		t.Fatalf("Lookup = %+v, want the identity Activate reported: %+v", looked, mapping)
	}

	// The mapped device is really usable: a write through it and a
	// read-back agree, which only holds if the kernel really resolved the
	// keyring reference and decrypts with the right key.
	written := bytes.Repeat([]byte{0xA5}, 4096)
	dev, err := os.OpenFile(mapping.Path(), os.O_RDWR, 0) //nolint:gosec // path is the mapping just created
	if err != nil {
		t.Fatalf("opening the mapped device failed: %v", err)
	}
	if _, err := dev.WriteAt(written, 0); err != nil {
		_ = dev.Close()
		t.Fatalf("writing through the mapping failed: %v", err)
	}
	if err := dev.Close(); err != nil {
		t.Fatalf("closing the mapped device failed: %v", err)
	}
	dev, err = os.Open(mapping.Path()) //nolint:gosec // path is the mapping just created
	if err != nil {
		t.Fatalf("reopening the mapped device failed: %v", err)
	}
	readBack := make([]byte, len(written))
	if _, err := dev.ReadAt(readBack, 0); err != nil {
		_ = dev.Close()
		t.Fatalf("reading through the mapping failed: %v", err)
	}
	_ = dev.Close()
	if !bytes.Equal(written, readBack) {
		t.Fatal("the mapped device did not read back what was written to it")
	}

	if err := dmcrypt.Deactivate(context.Background(), name); err != nil {
		t.Fatalf("Deactivate failed: %v", err)
	}
	if _, err := dmcrypt.Lookup(context.Background(), name); !errors.Is(err, dmcrypt.ErrNotActive) {
		t.Fatalf("Lookup after Deactivate = %v, want ErrNotActive", err)
	}
}

// TestActivateRefusesAnAlreadyActiveNameOnTheRealKernel confirms the
// early, cheap refusal reaches the real device-mapper control node, not
// only this package's fakes.
func TestActivateRefusesAnAlreadyActiveNameOnTheRealKernel(t *testing.T) {
	v, key, _ := formatOnLoopDevice(t)
	name := "dmcrypt-it-already-active"

	if _, err := dmcrypt.Activate(context.Background(), v, key, name); err != nil {
		t.Fatalf("the first Activate failed: %v", err)
	}
	t.Cleanup(func() { _ = dmcrypt.Deactivate(context.Background(), name) })

	if _, err := dmcrypt.Activate(context.Background(), v, key, name); !errors.Is(err, dmcrypt.ErrActive) {
		t.Fatalf("a second Activate under the same name = %v, want ErrActive", err)
	}
}

// TestDeactivateReportsErrNotActiveOnTheRealKernel is Lookup's refusal
// sibling, against the real control node.
func TestDeactivateReportsErrNotActiveOnTheRealKernel(t *testing.T) {
	if err := dmcrypt.Deactivate(context.Background(), "dmcrypt-it-never-activated"); !errors.Is(err, dmcrypt.ErrNotActive) {
		t.Fatalf("Deactivate of a name nothing opened = %v, want ErrNotActive", err)
	}
}

// TestCheckKeyringPassesOnARealKernel is the preflight's own claim: that
// it exercises the same syscalls, key type and ring resolution an
// activation does, and passes wherever activation would succeed.
func TestCheckKeyringPassesOnARealKernel(t *testing.T) {
	if err := dmcrypt.CheckKeyring(context.Background()); err != nil {
		t.Fatalf("CheckKeyring failed on a kernel where Activate is expected to work: %v", err)
	}
}
