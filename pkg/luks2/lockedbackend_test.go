// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"
)

// otherBackend is a backend that is not go-enclave locked memory.
type otherBackend struct{}

func (otherBackend) Name() string { return "heap" }

// foreignHandle is a caller's handle that reports otherBackend. It holds
// real bytes, so an entry point that read it anyway would succeed; reads
// counts every WithBytes and EqualTo, which a refusal must leave at zero.
type foreignHandle struct {
	enclave.ByteAccess
	reads atomic.Int32
}

func (h *foreignHandle) Backend() enclave.Backend { return otherBackend{} }

func (h *foreignHandle) WithBytes(fn func([]byte) error) error {
	h.reads.Add(1)
	return h.ByteAccess.WithBytes(fn)
}

func (h *foreignHandle) EqualTo(b []byte) (bool, error) {
	h.reads.Add(1)
	return h.ByteAccess.EqualTo(b)
}

func newForeignHandle(t *testing.T, content []byte) *foreignHandle {
	t.Helper()
	e, err := enclave.NewMemoryCopy(content)
	if err != nil {
		t.Fatalf("could not build the handle: %v", err)
	}
	t.Cleanup(func() { _ = e.Destroy() })
	return &foreignHandle{ByteAccess: e}
}

// foreignProvider hands over a handle that reports otherBackend.
type foreignProvider struct{ h *foreignHandle }

func (p foreignProvider) Passphrase(context.Context) (enclave.ByteAccess, error) { return p.h, nil }
func (p foreignProvider) Token() Token                                           { return Token{Type: "test", Keyslots: []int{0}} }

func assertRefusedUnread(t *testing.T, err error, h *foreignHandle, alive bool) {
	t.Helper()
	if !errors.Is(err, ErrNotLockedMemory) {
		t.Fatalf("got %v, want ErrNotLockedMemory", err)
	}
	var nle *NotLockedMemoryError
	if !errors.As(err, &nle) || nle.Backend != "heap" {
		t.Fatalf("got %v, want a *NotLockedMemoryError naming backend %q", err, "heap")
	}
	if n := h.reads.Load(); n != 0 {
		t.Fatalf("the refused handle was read %d time(s)", n)
	}
	if alive && !h.IsAlive() {
		t.Fatal("the refused handle was destroyed; it is the caller's")
	}
}

// TestHandlesNotInLockedMemoryAreRefusedUnread: every entry point that takes
// a caller's handle refuses one reporting a backend other than go-enclave
// locked memory with ErrNotLockedMemory, before reading it and without
// destroying it.
func TestHandlesNotInLockedMemoryAreRefusedUnread(t *testing.T) {
	defer parallel(t)()
	ctx := context.Background()
	open := func(t *testing.T, path string) *Volume {
		t.Helper()
		v, err := Open(ctx, path, withTestSys(testVolumeSys()))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { _ = v.Close() })
		return v
	}
	pass := []byte(testPassphraseText)

	t.Run("Unlock", func(t *testing.T) {
		v := open(t, formattedVolumeImage(t, "foreign-unlock.img", "", ""))
		h := newForeignHandle(t, pass)
		key, err := v.Unlock(ctx, h)
		if key != nil {
			t.Fatal("Unlock returned a key for a refused handle")
		}
		assertRefusedUnread(t, err, h, true)
	})

	t.Run("UnlockKeyslot", func(t *testing.T) {
		v := open(t, formattedVolumeImage(t, "foreign-unlockslot.img", "", ""))
		h := newForeignHandle(t, pass)
		_, err := v.UnlockKeyslot(ctx, 0, h)
		assertRefusedUnread(t, err, h, true)
	})

	t.Run("Format", func(t *testing.T) {
		v := open(t, newImage(t, "foreign-format.img"))
		h := newForeignHandle(t, pass)
		err := v.Format(ctx, h, FormatParams{KDF: KDFParams{Type: KDFPBKDF2, IterTime: 50 * time.Millisecond}})
		assertRefusedUnread(t, err, h, true)
	})

	t.Run("UnlockWithVolumeKey", func(t *testing.T) {
		v := open(t, formattedVolumeImage(t, "foreign-vk.img", "", ""))
		h := newForeignHandle(t, make([]byte, 64))
		_, err := v.UnlockWithVolumeKey(ctx, h)
		assertRefusedUnread(t, err, h, true)
	})

	t.Run("UnlockWithProvider", func(t *testing.T) {
		v := open(t, formattedVolumeImage(t, "foreign-provider.img", "", ""))
		h := newForeignHandle(t, pass)
		_, err := v.UnlockWithProvider(ctx, foreignProvider{h: h})
		// A provider's result is handed over to the library, so it may be
		// released; it must still never be read.
		assertRefusedUnread(t, err, h, false)
	})

	t.Run("ValidatePassphrase", func(t *testing.T) {
		h := newForeignHandle(t, pass)
		assertRefusedUnread(t, ValidatePassphrase(h), h, true)
	})

	t.Run("ParseRecoveryKey", func(t *testing.T) {
		h := newForeignHandle(t, []byte("not a recovery key"))
		_, err := ParseRecoveryKey(h)
		assertRefusedUnread(t, err, h, true)
	})
}
