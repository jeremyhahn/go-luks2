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
// then asserts against it would be asserting against zeros. That is exactly the
// case enclave.NewMemoryEnclaveCopy was added for (go-enclave v0.5.0-alpha),
// replacing the Sized + WithBytes + Destroy-on-error composition this helper
// used to carry. The result is FROZEN read-only, like every enclave built from
// existing material: a test that needs to write into its fixture must build a
// sized enclave itself.
func enclaveFrom(t *testing.T, b []byte) *enclave.MemoryEnclave {
	t.Helper()

	e, err := enclave.NewMemoryEnclaveCopy(b)
	if err != nil {
		t.Fatalf("could not allocate a test enclave: %v", err)
	}
	destroyOnCleanup(t, e)

	return e
}

// mustDestroy destroys e now and fails the test if go-enclave reports the
// release as anything but clean. Every test-side Destroy goes through it, for
// the reason destroyOnCleanup gives: on a healthy host every release is clean,
// so a report means the suite ran somewhere that refuses part of the teardown
// contract, and that is worth a red test rather than a silent drop. It uses
// Errorf, not Fatalf, so it is safe from a deferred call and from a goroutine.
func mustDestroy(tb testing.TB, e *enclave.MemoryEnclave) {
	tb.Helper()
	if err := e.Destroy(); err != nil {
		tb.Errorf("releasing a test enclave was reported: %v", err)
	}
}

// destroyOnCleanup destroys e when the test ends and fails the test if the
// release is reported as anything but clean. A fixture's release report is
// the one a test CAN act on: on a healthy host every release succeeds, so a
// report here means the suite ran somewhere that refuses part of the teardown
// contract, which is worth a red test rather than a silent drop.
func destroyOnCleanup(t *testing.T, e *enclave.MemoryEnclave) {
	t.Helper()
	t.Cleanup(func() { mustDestroy(t, e) })
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
	defer mustDestroy(t, e)

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
				mustDestroy(t, e)
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
	defer mustDestroy(t, a)

	b, err := randomSecret("test", 32)
	if err != nil {
		t.Fatalf("randomSecret failed: %v", err)
	}
	defer mustDestroy(t, b)

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
		mustDestroy(t, e)
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
	defer mustDestroy(t, e)

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
		mustDestroy(t, e)
		t.Fatal("adoptSecret(nil) succeeded")
	}
	if !errors.Is(err, ErrProtectedMemory) {
		t.Fatalf("error does not match ErrProtectedMemory: %v", err)
	}
	if !errors.Is(err, enclave.ErrEmptyEnclave) {
		t.Fatalf("go-enclave's cause is not reachable: %v", err)
	}
}

func TestCopySecretLeavesTheSourceIntact(t *testing.T) {
	original := []byte("MATERIAL that is not the caller's to wipe")
	source := append([]byte(nil), original...)

	e, err := copySecret("test", source)
	if err != nil {
		t.Fatalf("copySecret failed: %v", err)
	}
	defer mustDestroy(t, e)

	// The whole point of copying rather than adopting: the source belongs to
	// someone else -- a line inside another enclave's locked pages -- and must
	// still read as it did.
	if !bytes.Equal(source, original) {
		t.Fatal("copySecret disturbed the source slice")
	}
	if got := openSecret(t, e); !bytes.Equal(got, original) {
		t.Fatal("copySecret did not copy the material into the enclave intact")
	}
}

func TestCopySecretRefusesEmptyMaterial(t *testing.T) {
	for _, name := range []string{"copySecret", "copySecretWritable"} {
		t.Run(name, func(t *testing.T) {
			var (
				e   *enclave.MemoryEnclave
				err error
			)
			if name == "copySecret" {
				e, err = copySecret("test", nil)
			} else {
				e, err = copySecretWritable("test", nil)
			}
			if err == nil {
				mustDestroy(t, e)
				t.Fatalf("%s(nil) succeeded", name)
			}
			if !errors.Is(err, ErrProtectedMemory) {
				t.Fatalf("error does not match ErrProtectedMemory: %v", err)
			}
			if !errors.Is(err, enclave.ErrEmptyEnclave) {
				t.Fatalf("go-enclave's cause is not reachable: %v", err)
			}
		})
	}
}

// copySecret is built through go-enclave's copy constructor, which is reached
// through its own seam variable. If that seam were left out of
// withFailingProtectedMemory, a copy would succeed while every other
// allocation in the same test was being refused -- a fail-closed path with a
// hole in it that only the copying callers would fall through.
func TestCopySecretFailsClosedWhenLockedMemoryIsUnavailable(t *testing.T) {
	withFailingProtectedMemory(t)

	for _, name := range []string{"copySecret", "copySecretWritable"} {
		t.Run(name, func(t *testing.T) {
			source := []byte("material that never reaches locked memory")
			var (
				e   *enclave.MemoryEnclave
				err error
			)
			if name == "copySecret" {
				e, err = copySecret("test", source)
			} else {
				e, err = copySecretWritable("test", source)
			}
			if err == nil {
				mustDestroy(t, e)
				t.Fatalf("%s succeeded while locked memory was being refused", name)
			}
			if e != nil {
				t.Fatalf("%s returned both an enclave and an error", name)
			}
			if !errors.Is(err, ErrProtectedMemory) {
				t.Fatalf("error does not match ErrProtectedMemory: %v", err)
			}
			if !errors.Is(err, enclave.ErrLockedMemoryUnavailable) {
				t.Fatalf("go-enclave's refusal is not reachable: %v", err)
			}
		})
	}
}

// copySecretWritable exists for one reason: the copy is normalised IN PLACE.
// The enclaves go-enclave builds from existing material are frozen read-only
// and a write through them faults the process, so the writable variant has to
// keep handing back pages a borrow may write to. This is the property
// parseRecoveryKeySecret depends on when it lower-cases a candidate body.
func TestCopySecretWritableHandsBackPagesABorrowMayWrite(t *testing.T) {
	source := []byte("ABCDEF0123")

	e, err := copySecretWritable("test", source)
	if err != nil {
		t.Fatalf("copySecretWritable failed: %v", err)
	}
	defer mustDestroy(t, e)

	if err := borrowSecret("test", e, func(b []byte) error {
		lowerASCII(b)
		return nil
	}); err != nil {
		t.Fatalf("writing into a writable copy failed: %v", err)
	}

	if got, want := openSecret(t, e), []byte("abcdef0123"); !bytes.Equal(got, want) {
		t.Fatalf("copy reads %q after an in-place lower-case, want %q", got, want)
	}
	// The source is untouched by both the copy and the write into the copy.
	if !bytes.Equal(source, []byte("ABCDEF0123")) {
		t.Fatalf("source reads %q after a write into the copy", source)
	}
}

func TestBorrowSecretReportsADestroyedEnclaveAsAProtectedMemoryError(t *testing.T) {
	e, err := randomSecret("test", 32)
	if err != nil {
		t.Fatalf("randomSecret failed: %v", err)
	}
	mustDestroy(t, e)

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
	defer mustDestroy(t, e)

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

	mustDestroy(t, e)

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

// reportingDestroy installs a destroyEnclave that really releases each enclave
// and then reports report for it, the way go-enclave does when the kernel or a
// sandbox refuses part of the teardown. It records every enclave it was given,
// in order, so a test can prove the release reached each one.
func reportingDestroy(t *testing.T, report error) *[]*enclave.MemoryEnclave {
	t.Helper()
	var seen []*enclave.MemoryEnclave
	saved := destroyEnclave
	t.Cleanup(func() { destroyEnclave = saved })
	destroyEnclave = func(e *enclave.MemoryEnclave) error {
		seen = append(seen, e)
		if err := e.Destroy(); err != nil {
			t.Errorf("the real release under the fake report failed: %v", err)
		}
		return report
	}
	return &seen
}

// requireReleased fails unless e's material is gone.
func requireReleased(t *testing.T, name string, e *enclave.MemoryEnclave) {
	t.Helper()
	if err := e.WithBytes(func([]byte) error { return nil }); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Errorf("%s: borrow after release = %v, want enclave.ErrEnclaveDestroyed", name, err)
	}
}

func TestReleaseSecretDestroysTheEnclave(t *testing.T) {
	e, err := enclave.NewMemoryEnclaveCopy([]byte("volume key material"))
	if err != nil {
		t.Fatalf("could not allocate a test enclave: %v", err)
	}

	releaseSecret(e)

	requireReleased(t, "releaseSecret", e)
}

// TestReleaseSecretDropsEveryReleaseReport pins the decision documented on
// releaseSecret: neither report go-enclave can return is turned into a panic or
// leaks out of the helper, and the enclave is released either way.
func TestReleaseSecretDropsEveryReleaseReport(t *testing.T) {
	tests := []struct {
		name   string
		report error
		is     error
	}{
		{
			name:   "released without the in-process wipe",
			report: &enclave.UnwipedReleaseError{Cause: errors.New("synthetic mprotect EPERM")},
			is:     enclave.ErrReleasedWithoutWipe,
		},
		{
			name:   "release refused, pages still held",
			report: &enclave.LockedMemoryError{Cause: errors.New("synthetic munmap ENOMEM")},
			is:     enclave.ErrLockedMemoryUnavailable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.report, tt.is) {
				t.Fatalf("fixture %v does not match %v; the case tests nothing", tt.report, tt.is)
			}
			seen := reportingDestroy(t, tt.report)
			e, err := enclave.NewMemoryEnclaveCopy([]byte("volume key material"))
			if err != nil {
				t.Fatalf("could not allocate a test enclave: %v", err)
			}

			releaseSecret(e)

			if len(*seen) != 1 || (*seen)[0] != e {
				t.Fatalf("release saw %d enclaves, want exactly the one given", len(*seen))
			}
			requireReleased(t, tt.name, e)
		})
	}
}

// TestDestroySecretsReleasesPastAReport proves one enclave's report does not
// stop the others being released: the material after it would otherwise
// outlive the function that deferred the call.
func TestDestroySecretsReleasesPastAReport(t *testing.T) {
	seen := reportingDestroy(t, &enclave.LockedMemoryError{Cause: errors.New("synthetic munmap ENOMEM")})
	first, err := enclave.NewMemoryEnclaveCopy([]byte("passphrase key"))
	if err != nil {
		t.Fatalf("could not allocate a test enclave: %v", err)
	}
	second, err := enclave.NewMemoryEnclaveCopy([]byte("af stripes"))
	if err != nil {
		t.Fatalf("could not allocate a test enclave: %v", err)
	}

	destroySecrets(first, nil, second)

	if len(*seen) != 3 || (*seen)[0] != first || (*seen)[2] != second {
		t.Fatalf("release saw %v, want first, nil, second in order", *seen)
	}
	requireReleased(t, "first", first)
	requireReleased(t, "second", second)
}

// TestReleaseSecretDoesNotSwallowCorruption pins the other half of the
// decision: detected corruption is go-enclave's one panic, and releaseSecret
// must let it reach the caller rather than recover it into a dropped report.
func TestReleaseSecretDoesNotSwallowCorruption(t *testing.T) {
	saved := destroyEnclave
	t.Cleanup(func() { destroyEnclave = saved })
	e, err := enclave.NewMemoryEnclaveCopy([]byte("volume key material"))
	if err != nil {
		t.Fatalf("could not allocate a test enclave: %v", err)
	}
	destroyOnCleanup(t, e)
	destroyEnclave = func(*enclave.MemoryEnclave) error {
		panic(enclave.ErrEnclaveCorrupted)
	}

	defer func() {
		r := recover()
		perr, ok := r.(error)
		if !ok || !errors.Is(perr, enclave.ErrEnclaveCorrupted) {
			t.Fatalf("recovered %v, want a panic matching enclave.ErrEnclaveCorrupted", r)
		}
	}()
	releaseSecret(e)
	t.Fatal("releaseSecret returned normally from a corrupted release")
}
