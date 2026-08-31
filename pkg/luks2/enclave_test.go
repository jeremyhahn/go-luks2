// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// enclaveFrom returns an enclave holding a COPY of b, registered for cleanup.
//
// It copies rather than adopting because enclave.NewMemoryEnclave takes
// ownership and wipes its argument, and a test that hands over a fixture and
// then asserts against it would be asserting against zeros.
func enclaveFrom(t *testing.T, b []byte) *enclave.MemoryEnclave {
	t.Helper()

	e, err := enclave.NewMemoryEnclaveSized(len(b))
	if err != nil {
		t.Fatalf("could not allocate a test enclave: %v", err)
	}
	t.Cleanup(e.Destroy)

	if err := e.WithBytes(func(dst []byte) error {
		copy(dst, b)
		return nil
	}); err != nil {
		t.Fatalf("could not fill a test enclave: %v", err)
	}

	return e
}

// openSecret copies the material out of an enclave so a test can assert on it.
// Production code must never do this; a test has to look at the bytes to prove
// anything about them.
func openSecret(t *testing.T, e *enclave.MemoryEnclave) []byte {
	t.Helper()

	var out []byte
	if err := e.WithBytes(func(b []byte) error {
		out = append([]byte(nil), b...)
		return nil
	}); err != nil {
		t.Fatalf("could not read a test enclave: %v", err)
	}
	return out
}

// lockedKiB reports the process's currently mlock'd memory, in kibibytes, from
// /proc/self/status.
//
// It is how the custody tests below assert that locked pages are RELEASED and
// not merely dropped: a leak of enclave regions is invisible to any assertion
// about return values, because the leaked handle is exactly the one nobody
// holds any more.
func lockedKiB(t *testing.T) int {
	t.Helper()

	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Skipf("/proc/self/status is unavailable: %v", err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmLck:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil {
			break
		}
		return n
	}

	t.Skip("/proc/self/status does not report VmLck")
	return 0
}

// lockedSlackKiB is the tolerance the leak assertions allow. Locked pages are
// released explicitly by Destroy, with no finalizer or collector in the way, so
// VmLck returns to its starting value exactly; one page of slack absorbs
// nothing more than a rounding difference.
const lockedSlackKiB = 4

func TestNewSecretEnclaveReturnsLockedZeroedMemory(t *testing.T) {
	e, err := newSecretEnclave("test", 64)
	if err != nil {
		t.Fatalf("newSecretEnclave failed: %v", err)
	}
	defer e.Destroy()

	if !e.IsAlive() {
		t.Fatal("a freshly allocated enclave reports itself destroyed")
	}
	if e.Size() != 64 {
		t.Fatalf("enclave holds %d bytes, want 64", e.Size())
	}

	// Sized enclaves are handed over zeroed, which is what makes it safe to
	// fill them in place without first clearing whatever the kernel supplied.
	if got := openSecret(t, e); !bytes.Equal(got, make([]byte, 64)) {
		t.Fatal("a freshly allocated enclave is not zeroed")
	}
}

func TestNewSecretEnclaveRefusesAnImpossibleSize(t *testing.T) {
	for _, size := range []int{0, -1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			e, err := newSecretEnclave("test", size)
			if err == nil {
				e.Destroy()
				t.Fatalf("newSecretEnclave(%d) succeeded", size)
			}
			if e != nil {
				t.Fatal("newSecretEnclave returned both an enclave and an error")
			}
			if !errors.Is(err, ErrProtectedMemory) {
				t.Fatalf("error does not match ErrProtectedMemory: %v", err)
			}

			// The underlying cause stays reachable, so a caller can tell an
			// impossible request from a resource limit without reading text.
			var pme *ProtectedMemoryError
			if !errors.As(err, &pme) {
				t.Fatalf("error is not a *ProtectedMemoryError: %v", err)
			}
			if !errors.Is(err, enclave.ErrInvalidSize) {
				t.Fatalf("go-enclave's cause is not reachable through the wrapper: %v", err)
			}
		})
	}
}

func TestProtectedMemoryErrorDoesNotNameSizes(t *testing.T) {
	// An error string is a place key facts leak. This one names the operation
	// and nothing measurable about the material.
	err := &ProtectedMemoryError{Op: "master key", Err: enclave.ErrLockedMemoryUnavailable}

	msg := err.Error()
	if !strings.Contains(msg, "master key") {
		t.Fatalf("error does not name the operation: %q", msg)
	}
	for _, digit := range []string{"32", "64", "256"} {
		if strings.Contains(msg, digit) {
			t.Fatalf("error text contains what looks like a key length: %q", msg)
		}
	}
}

func TestRandomSecretGeneratesInsideTheEnclave(t *testing.T) {
	a, err := randomSecret("test", 32)
	if err != nil {
		t.Fatalf("randomSecret failed: %v", err)
	}
	defer a.Destroy()

	b, err := randomSecret("test", 32)
	if err != nil {
		t.Fatalf("randomSecret failed: %v", err)
	}
	defer b.Destroy()

	first, second := openSecret(t, a), openSecret(t, b)

	if bytes.Equal(first, make([]byte, 32)) {
		t.Fatal("randomSecret produced all zeros, so nothing was written into the locked pages")
	}
	if bytes.Equal(first, second) {
		t.Fatal("two randomSecret calls produced identical material")
	}
}

func TestRandomSecretRefusesAZeroLengthDraw(t *testing.T) {
	e, err := randomSecret("test", 0)
	if err == nil {
		e.Destroy()
		t.Fatal("randomSecret(0) succeeded; an enclave over nothing protects nothing")
	}
	if !errors.Is(err, ErrProtectedMemory) {
		t.Fatalf("error does not match ErrProtectedMemory: %v", err)
	}
}

func TestAdoptSecretWipesTheSourceSlice(t *testing.T) {
	original := []byte("this is key material that must not survive the move")
	source := append([]byte(nil), original...)

	e, err := adoptSecret("test", source)
	if err != nil {
		t.Fatalf("adoptSecret failed: %v", err)
	}
	defer e.Destroy()

	// The whole point of adopting rather than copying: the caller's slice is
	// zeroed, so the material does not survive in unprotected memory.
	if !bytes.Equal(source, make([]byte, len(source))) {
		t.Fatal("adoptSecret left the source slice readable")
	}
	if got := openSecret(t, e); !bytes.Equal(got, original) {
		t.Fatal("adoptSecret did not move the material into the enclave intact")
	}
}

func TestAdoptSecretRefusesEmptyMaterial(t *testing.T) {
	e, err := adoptSecret("test", nil)
	if err == nil {
		e.Destroy()
		t.Fatal("adoptSecret(nil) succeeded")
	}
	if !errors.Is(err, ErrProtectedMemory) {
		t.Fatalf("error does not match ErrProtectedMemory: %v", err)
	}
	if !errors.Is(err, enclave.ErrEmptyEnclave) {
		t.Fatalf("go-enclave's cause is not reachable: %v", err)
	}
}

func TestBorrowSecretReportsADestroyedEnclaveAsAProtectedMemoryError(t *testing.T) {
	e, err := randomSecret("test", 32)
	if err != nil {
		t.Fatalf("randomSecret failed: %v", err)
	}
	e.Destroy()

	called := false
	err = borrowSecret("test", e, func([]byte) error {
		called = true
		return nil
	})
	if called {
		t.Fatal("the borrow ran against a destroyed enclave")
	}
	if !errors.Is(err, ErrProtectedMemory) {
		t.Fatalf("error does not match ErrProtectedMemory: %v", err)
	}
}

func TestBorrowSecretPassesTheCallersErrorThrough(t *testing.T) {
	e, err := randomSecret("test", 32)
	if err != nil {
		t.Fatalf("randomSecret failed: %v", err)
	}
	defer e.Destroy()

	sentinel := errors.New("the caller's own failure")
	if err := borrowSecret("test", e, func([]byte) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("borrowSecret reclassified the caller's error: %v", err)
	}
	// A caller's failure must NOT be reported as a custody failure, or an
	// operator goes looking at RLIMIT_MEMLOCK for a bad passphrase.
	if errors.Is(err, ErrProtectedMemory) {
		t.Fatal("a caller error was reported as a protected-memory failure")
	}
}

func TestBorrowWindowClosesWhenTheBorrowReturns(t *testing.T) {
	e, err := randomSecret("test", 32)
	if err != nil {
		t.Fatalf("randomSecret failed: %v", err)
	}

	// Destroy takes the write lock and therefore BLOCKS until every in-flight
	// borrow has returned. If a borrow window were still open here, this would
	// deadlock rather than complete -- which is what makes the completion
	// itself the assertion.
	if err := borrowSecret("test", e, func(b []byte) error {
		if len(b) != 32 {
			t.Errorf("borrow saw %d bytes, want 32", len(b))
		}
		return nil
	}); err != nil {
		t.Fatalf("borrowSecret failed: %v", err)
	}

	e.Destroy()

	if e.IsAlive() {
		t.Fatal("the enclave survived Destroy")
	}
}

func TestDestroySecretsIsNilSafeAndIdempotent(t *testing.T) {
	e, err := randomSecret("test", 32)
	if err != nil {
		t.Fatalf("randomSecret failed: %v", err)
	}

	// A nil in the middle must not stop the rest from being released, and a
	// second pass must not panic: error paths call this after some of the
	// enclaves have already been destroyed.
	destroySecrets(e, nil, nil)
	destroySecrets(e, nil)

	if e.IsAlive() {
		t.Fatal("the enclave survived destroySecrets")
	}
}

func TestLockedMemoryIsReleasedByDestroySecrets(t *testing.T) {
	before := lockedKiB(t)

	const rounds = 16
	for i := 0; i < rounds; i++ {
		e, err := randomSecret("test", 64<<10)
		if err != nil {
			t.Fatalf("randomSecret failed: %v", err)
		}
		destroySecrets(e)
	}

	// Sixteen 64 KiB regions is a megabyte of locked memory. If Destroy were
	// dropping the handle without unmapping, VmLck would carry all of it.
	//
	// The slack is one page rather than a fraction of the total, because
	// release here is EXPLICIT -- no finalizer, no collector -- so VmLck comes
	// back to exactly where it started, and a leak of even one region would be
	// 64 KiB. A generous tolerance would let single leaks through, which is
	// precisely what this is looking for.
	if after := lockedKiB(t); after > before+lockedSlackKiB {
		t.Fatalf("locked memory grew from %d KiB to %d KiB across %d allocate/destroy rounds", before, after, rounds)
	}
}
