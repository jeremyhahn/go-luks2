// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package volkey

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

func newTestEnclave(tb testing.TB, data []byte) *enclave.Memory {
	tb.Helper()
	e, err := enclave.NewMemoryCopy(data)
	if err != nil {
		tb.Fatalf("could not build a test enclave: %v", err)
	}
	return e
}

func TestNewReportsTheGivenKeyslot(t *testing.T) {
	e := newTestEnclave(t, []byte("0123456789abcdef"))
	k := New(e, 3)
	defer k.Destroy()

	if got := k.Keyslot(); got != 3 {
		t.Fatalf("Keyslot() = %d, want 3", got)
	}
}

func TestNewReportsMinusOneForASuppliedKey(t *testing.T) {
	e := newTestEnclave(t, []byte("0123456789abcdef"))
	k := New(e, -1)
	defer k.Destroy()

	if got := k.Keyslot(); got != -1 {
		t.Fatalf("Keyslot() = %d, want -1", got)
	}
}

func TestSizeReportsTheEnclaveLength(t *testing.T) {
	data := []byte("a 32-byte volume key, exactly!!!")
	if len(data) != 32 {
		t.Fatalf("fixture is %d bytes, want 32", len(data))
	}
	e := newTestEnclave(t, data)
	k := New(e, 0)
	defer k.Destroy()

	if got := k.Size(); got != 32 {
		t.Fatalf("Size() = %d, want 32", got)
	}
}

func TestBorrowSeesExactlyTheWrappedBytes(t *testing.T) {
	data := []byte("the master key material")
	e := newTestEnclave(t, data)
	k := New(e, 1)
	defer k.Destroy()

	var seen []byte
	err := Borrow("test borrow", k, func(b []byte) error {
		seen = append([]byte(nil), b...)
		return nil
	})
	if err != nil {
		t.Fatalf("Borrow returned an error: %v", err)
	}
	if !bytes.Equal(seen, data) {
		t.Fatalf("Borrow saw %q, want %q", seen, data)
	}
}

func TestBorrowPropagatesTheCallbacksError(t *testing.T) {
	e := newTestEnclave(t, []byte("0123456789abcdef"))
	k := New(e, 0)
	defer k.Destroy()

	sentinel := errors.New("callback failure")
	err := Borrow("test borrow", k, func([]byte) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("Borrow error = %v, want %v", err, sentinel)
	}
}

func TestBorrowAfterDestroyFailsClosed(t *testing.T) {
	e := newTestEnclave(t, []byte("0123456789abcdef"))
	k := New(e, 0)
	k.Destroy()

	err := Borrow("test borrow after destroy", k, func([]byte) error {
		t.Fatal("fn must not run against a destroyed key")
		return nil
	})
	if err == nil {
		t.Fatal("Borrow after Destroy returned nil, want an error")
	}
	if !errors.Is(err, secret.ErrProtectedMemory) {
		t.Fatalf("Borrow after Destroy = %v, want secret.ErrProtectedMemory", err)
	}
}

func TestDestroyOnANilKeyDoesNotPanic(t *testing.T) {
	var k *Key
	k.Destroy()
}

func TestDestroyIsIdempotent(t *testing.T) {
	e := newTestEnclave(t, []byte("0123456789abcdef"))
	k := New(e, 0)
	k.Destroy()
	k.Destroy()
}

func TestVerifyRefusesANilKeyWithoutCallingVerify(t *testing.T) {
	err := Verify(nil, func(*enclave.Memory) error {
		t.Fatal("verify must not run for a nil key")
		return nil
	})
	if !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("Verify(nil) = %v, want errs.ErrInvalidArgument", err)
	}
}

func TestVerifyRefusesAKeyWithNoEnclaveWithoutCallingVerify(t *testing.T) {
	err := Verify(&Key{}, func(*enclave.Memory) error {
		t.Fatal("verify must not run for a key with no enclave")
		return nil
	})
	if !errors.Is(err, errs.ErrInvalidArgument) {
		t.Fatalf("Verify(empty key) = %v, want errs.ErrInvalidArgument", err)
	}
}

func TestVerifyPassesTheKeysOwnEnclaveAndReturnsItsErrorUnchanged(t *testing.T) {
	e := newTestEnclave(t, []byte("0123456789abcdef"))
	k := New(e, 0)
	defer k.Destroy()

	sentinel := errors.New("verify failure")
	var got *enclave.Memory
	err := Verify(k, func(m *enclave.Memory) error {
		got = m
		return sentinel
	})
	if got != e {
		t.Fatal("verify was not handed the key's own enclave")
	}
	if err != sentinel {
		t.Fatalf("Verify error = %v, want the callback's error unchanged", err)
	}
}
