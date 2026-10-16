// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// heapBackend is a backend that is not go-enclave locked memory.
type heapBackend struct{}

func (heapBackend) Name() string { return "heap" }

// foreignHandle reports heapBackend and counts every read.
type foreignHandle struct {
	enclave.ByteAccess
	reads int
}

func (h *foreignHandle) Backend() enclave.Backend { return heapBackend{} }

func (h *foreignHandle) WithBytes(fn func([]byte) error) error {
	h.reads++
	return h.ByteAccess.WithBytes(fn)
}

func (h *foreignHandle) EqualTo(b []byte) (bool, error) {
	h.reads++
	return h.ByteAccess.EqualTo(b)
}

func newForeignHandle(t *testing.T) *foreignHandle {
	t.Helper()
	e, err := enclave.NewMemoryCopy([]byte("caller's credential"))
	if err != nil {
		t.Fatalf("NewMemoryCopy: %v", err)
	}
	t.Cleanup(func() { _ = e.Destroy() })
	return &foreignHandle{ByteAccess: e}
}

func assertNotLocked(t *testing.T, err error, h *foreignHandle) {
	t.Helper()
	if !errors.Is(err, ErrNotLockedMemory) {
		t.Fatalf("err = %v, want ErrNotLockedMemory", err)
	}
	var nle *NotLockedMemoryError
	if !errors.As(err, &nle) || nle.Backend != "heap" {
		t.Fatalf("err = %v, want a *NotLockedMemoryError naming %q", err, "heap")
	}
	if h.reads != 0 {
		t.Fatalf("the refused handle was read %d time(s)", h.reads)
	}
	if !h.IsAlive() {
		t.Fatal("the refused handle was destroyed; it is the caller's")
	}
}

func TestLockedLeavesANilHandleToTheCaller(t *testing.T) {
	if err := Locked("test", nil); err != nil {
		t.Fatalf("Locked(nil) = %v, want nil", err)
	}
}

func TestLockedAdmitsLockedMemory(t *testing.T) {
	e, err := enclave.NewMemoryCopy([]byte("locked"))
	if err != nil {
		t.Fatalf("NewMemoryCopy: %v", err)
	}
	defer mustDestroy(t, e)
	if err := Locked("test", e); err != nil {
		t.Fatalf("Locked(locked memory) = %v, want nil", err)
	}
}

func TestLockedRefusesAnotherBackendUnread(t *testing.T) {
	h := newForeignHandle(t)
	assertNotLocked(t, Locked("test", h), h)
}

func TestBorrowReportsANilHandleDestroyed(t *testing.T) {
	called := false
	err := Borrow("test", nil, func([]byte) error { called = true; return nil })
	if !errors.Is(err, ErrProtectedMemory) || !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("err = %v, want ErrProtectedMemory wrapping enclave.ErrEnclaveDestroyed", err)
	}
	if called {
		t.Fatal("fn ran for a nil handle")
	}
}

func TestBorrowRefusesAnotherBackendUnread(t *testing.T) {
	h := newForeignHandle(t)
	called := false
	err := Borrow("test", h, func([]byte) error { called = true; return nil })
	assertNotLocked(t, err, h)
	if called {
		t.Fatal("fn ran for a refused handle")
	}
}

func TestNotLockedMemoryErrorNamesTheBackend(t *testing.T) {
	e := &NotLockedMemoryError{Backend: "heap"}
	if got, want := e.Error(), `luks2: handle backend "heap" is not go-enclave locked memory`; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if e.Unwrap() != ErrNotLockedMemory {
		t.Fatalf("Unwrap() = %v, want ErrNotLockedMemory", e.Unwrap())
	}
}

// unwritable fails every WithBytes, as a handle released under it would.
type unwritable struct{ enclave.ByteAccess }

var errUnwritable = errors.New("test: handle cannot be written")

func (unwritable) WithBytes(func([]byte) error) error { return errUnwritable }

// freezeRefused has the Freezer capability, and its Freeze fails.
type freezeRefused struct{ enclave.ByteAccess }

var errFreezeRefused = errors.New("test: freeze refused")

func (freezeRefused) Freeze() error { return errFreezeRefused }

// TestCopiedFailsClosedWhenTheCopyOrFreezeFails: a copy that cannot be
// written, or a handle whose Freeze fails, fails the Clone and destroys the
// enclave rather than handing it out.
func TestCopiedFailsClosedWhenTheCopyOrFreezeFails(t *testing.T) {
	for _, tc := range []struct {
		name string
		wrap func(enclave.ByteAccess) enclave.ByteAccess
		want error
	}{
		{"write", func(e enclave.ByteAccess) enclave.ByteAccess { return unwritable{e} }, errUnwritable},
		{"freeze", func(e enclave.ByteAccess) enclave.ByteAccess { return freezeRefused{e} }, errFreezeRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var held []enclave.ByteAccess
			sized := func(n int) (enclave.ByteAccess, error) {
				e, err := system.Sized(n)
				if err != nil {
					return nil, err
				}
				held = append(held, e)
				return tc.wrap(e), nil
			}
			c := system
			c.Copied = copiedInto(sized)

			e, err := c.Clone("test", []byte("MATERIAL that must not be handed out"))
			if e != nil {
				mustDestroy(t, e)
				t.Fatal("a failed Clone returned an enclave")
			}
			if !errors.Is(err, ErrProtectedMemory) || !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want ErrProtectedMemory wrapping %v", err, tc.want)
			}
			if len(held) != 1 {
				t.Fatalf("sized was called %d times, want 1", len(held))
			}
			if held[0].IsAlive() {
				_ = held[0].Destroy()
				t.Fatal("the enclave was not destroyed")
			}
		})
	}
}
