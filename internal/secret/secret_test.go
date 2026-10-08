// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/jeremyhahn/go-enclave"
)

// system is the production custody the tests exercise.
var system = System()

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
		// Linux always has it; a host without it cannot run this package.
		t.Fatalf("/proc/self/status is unavailable, so locked memory cannot be measured: %v", err)
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

	t.Fatalf("/proc/self/status reports no VmLck line, so locked memory cannot be measured:\n%s", data)
	return 0
}

// lockedSlackKiB is the tolerance the leak assertions allow. Locked pages are
// released explicitly by Destroy, with no finalizer or collector in the way, so
// VmLck returns to its starting value exactly; one page of slack absorbs
// nothing more than a rounding difference.
const lockedSlackKiB = 4

func TestNewReturnsLockedZeroedMemory(t *testing.T) {
	e, err := system.New("test", 64)
	if err != nil {
		t.Fatalf("New failed: %v", err)
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

func TestNewRefusesAnImpossibleSize(t *testing.T) {
	for _, size := range []int{0, -1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			e, err := system.New("test", size)
			if err == nil {
				mustDestroy(t, e)
				t.Fatalf("system.New(%d) succeeded", size)
			}
			if e != nil {
				t.Fatal("New returned both an enclave and an error")
			}
			if !errors.Is(err, ErrProtectedMemory) {
				t.Fatalf("error does not match ErrProtectedMemory: %v", err)
			}

			// The underlying cause stays reachable, so a caller can tell an
			// impossible request from a resource limit without reading text.
			if !errors.Is(err, enclave.ErrInvalidSize) {
				t.Fatalf("go-enclave's cause is not reachable through the wrapper: %v", err)
			}
		})
	}
}

func TestRandomGeneratesInsideTheEnclave(t *testing.T) {
	a, err := system.Random("test", 32, rand.Reader)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}
	defer mustDestroy(t, a)

	b, err := system.Random("test", 32, rand.Reader)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}
	defer mustDestroy(t, b)

	first, second := openSecret(t, a), openSecret(t, b)

	if bytes.Equal(first, make([]byte, 32)) {
		t.Fatal("Random produced all zeros, so nothing was written into the locked pages")
	}
	if bytes.Equal(first, second) {
		t.Fatal("two Random calls produced identical material")
	}
}

func TestRandomRefusesAZeroLengthDraw(t *testing.T) {
	e, err := system.Random("test", 0, rand.Reader)
	if err == nil {
		mustDestroy(t, e)
		t.Fatal("Random(0) succeeded; an enclave over nothing protects nothing")
	}
	if !errors.Is(err, ErrProtectedMemory) {
		t.Fatalf("error does not match ErrProtectedMemory: %v", err)
	}
}

func TestAdoptWipesTheSourceSlice(t *testing.T) {
	original := []byte("this is key material that must not survive the move")
	source := append([]byte(nil), original...)

	e, err := system.Adopt("test", source)
	if err != nil {
		t.Fatalf("Adopt failed: %v", err)
	}
	defer mustDestroy(t, e)

	// The whole point of adopting rather than copying: the caller's slice is
	// zeroed, so the material does not survive in unprotected memory.
	if !bytes.Equal(source, make([]byte, len(source))) {
		t.Fatal("Adopt left the source slice readable")
	}
	if got := openSecret(t, e); !bytes.Equal(got, original) {
		t.Fatal("Adopt did not move the material into the enclave intact")
	}
}

func TestAdoptRefusesEmptyMaterial(t *testing.T) {
	e, err := system.Adopt("test", nil)
	if err == nil {
		mustDestroy(t, e)
		t.Fatal("system.Adopt(nil) succeeded")
	}
	if !errors.Is(err, ErrProtectedMemory) {
		t.Fatalf("error does not match ErrProtectedMemory: %v", err)
	}
	if !errors.Is(err, enclave.ErrEmptyEnclave) {
		t.Fatalf("go-enclave's cause is not reachable: %v", err)
	}
}

func TestCloneLeavesTheSourceIntact(t *testing.T) {
	original := []byte("MATERIAL that is not the caller's to wipe")
	source := append([]byte(nil), original...)

	e, err := system.Clone("test", source)
	if err != nil {
		t.Fatalf("Clone failed: %v", err)
	}
	defer mustDestroy(t, e)

	// The whole point of copying rather than adopting: the source belongs to
	// someone else -- a line inside another enclave's locked pages -- and must
	// still read as it did.
	if !bytes.Equal(source, original) {
		t.Fatal("Clone disturbed the source slice")
	}
	if got := openSecret(t, e); !bytes.Equal(got, original) {
		t.Fatal("Clone did not copy the material into the enclave intact")
	}
}

func TestCloneRefusesEmptyMaterial(t *testing.T) {
	for _, name := range []string{"Clone", "CloneWritable"} {
		t.Run(name, func(t *testing.T) {
			var (
				e   *enclave.MemoryEnclave
				err error
			)
			if name == "Clone" {
				e, err = system.Clone("test", nil)
			} else {
				e, err = system.CloneWritable("test", nil)
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

// CloneWritable exists for one reason: the copy is normalised IN PLACE.
// The enclaves go-enclave builds from existing material are frozen read-only
// and a write through them faults the process, so the writable variant has to
// keep handing back pages a borrow may write to. This is the property
// recoverykey.Decode depends on when it lower-cases a candidate body.
func TestCloneWritableHandsBackPagesABorrowMayWrite(t *testing.T) {
	source := []byte("ABCDEF0123")

	e, err := system.CloneWritable("test", source)
	if err != nil {
		t.Fatalf("CloneWritable failed: %v", err)
	}
	defer mustDestroy(t, e)

	if err := Borrow("test", e, func(b []byte) error {
		copy(b, bytes.ToLower(b))
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

func TestBorrowReportsADestroyedEnclaveAsErrProtectedMemory(t *testing.T) {
	e, err := system.Random("test", 32, rand.Reader)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}
	mustDestroy(t, e)

	called := false
	err = Borrow("test", e, func([]byte) error {
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

func TestBorrowPassesTheCallersErrorThrough(t *testing.T) {
	e, err := system.Random("test", 32, rand.Reader)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}
	defer mustDestroy(t, e)

	sentinel := errors.New("the caller's own failure")
	if err := Borrow("test", e, func([]byte) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("Borrow reclassified the caller's error: %v", err)
	}
	// A caller's failure must NOT be reported as a custody failure, or an
	// operator goes looking at RLIMIT_MEMLOCK for a bad passphrase.
	if errors.Is(err, ErrProtectedMemory) {
		t.Fatal("a caller error was reported as a protected-memory failure")
	}
}

func TestBorrowWindowClosesWhenTheBorrowReturns(t *testing.T) {
	e, err := system.Random("test", 32, rand.Reader)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}

	// Destroy takes the write lock and therefore BLOCKS until every in-flight
	// borrow has returned. If a borrow window were still open here, this would
	// deadlock rather than complete -- which is what makes the completion
	// itself the assertion.
	if err := Borrow("test", e, func(b []byte) error {
		if len(b) != 32 {
			t.Errorf("borrow saw %d bytes, want 32", len(b))
		}
		return nil
	}); err != nil {
		t.Fatalf("Borrow failed: %v", err)
	}

	mustDestroy(t, e)

	if e.IsAlive() {
		t.Fatal("the enclave survived Destroy")
	}
}

func TestReleaseIsNilSafeAndIdempotent(t *testing.T) {
	e, err := system.Random("test", 32, rand.Reader)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}

	// A nil in the middle must not stop the rest from being released, and a
	// second pass must not panic: error paths call this after some of the
	// enclaves have already been destroyed.
	system.Release(e, nil, nil)
	system.Release(e, nil)

	if e.IsAlive() {
		t.Fatal("the enclave survived Release")
	}
}

func TestLockedMemoryIsReleasedByRelease(t *testing.T) {
	before := lockedKiB(t)

	const rounds = 16
	for i := 0; i < rounds; i++ {
		e, err := system.Random("test", 64<<10, rand.Reader)
		if err != nil {
			t.Fatalf("Random failed: %v", err)
		}
		system.Release(e)
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

// reportingCustody is the system custody whose Destroy really releases each
// enclave and then reports report for it, the way go-enclave does when the
// kernel or a sandbox refuses part of the teardown. It records every enclave
// it was given, in order, so a test can prove the release reached each one.
func reportingCustody(t *testing.T, report error) (Custody, *[]*enclave.MemoryEnclave) {
	t.Helper()
	var seen []*enclave.MemoryEnclave
	c := System()
	c.Destroy = func(e *enclave.MemoryEnclave) error {
		seen = append(seen, e)
		if err := e.Destroy(); err != nil {
			t.Errorf("the real release under the fake report failed: %v", err)
		}
		return report
	}
	return c, &seen
}

// requireReleased fails unless e's material is gone.
func requireReleased(t *testing.T, name string, e *enclave.MemoryEnclave) {
	t.Helper()
	if err := e.WithBytes(func([]byte) error { return nil }); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Errorf("%s: borrow after release = %v, want enclave.ErrEnclaveDestroyed", name, err)
	}
}

// TestReleaseDropsEveryReleaseReport pins the decision documented on Release:
// neither report go-enclave can return stops the release or reaches the
// caller.
func TestReleaseDropsEveryReleaseReport(t *testing.T) {
	for _, tt := range []struct {
		name   string
		report error
		is     error
	}{
		{"released without the in-process wipe", &enclave.UnwipedReleaseError{Cause: errors.New("synthetic mprotect EPERM")}, enclave.ErrReleasedWithoutWipe},
		{"release refused, pages still held", &enclave.LockedMemoryError{Cause: errors.New("synthetic munmap ENOMEM")}, enclave.ErrLockedMemoryUnavailable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.report, tt.is) {
				t.Fatalf("fixture %v does not match %v; the case tests nothing", tt.report, tt.is)
			}
			c, seen := reportingCustody(t, tt.report)
			e, err := enclave.NewMemoryEnclaveCopy([]byte("volume key material"))
			if err != nil {
				t.Fatalf("could not allocate a test enclave: %v", err)
			}

			c.Release(e)

			if len(*seen) != 1 || (*seen)[0] != e {
				t.Fatalf("release saw %d enclaves, want exactly the one given", len(*seen))
			}
			requireReleased(t, tt.name, e)
		})
	}
}

// TestReleaseReleasesPastAReport proves one enclave's report does not stop
// the others being released: the material after it would otherwise outlive
// the function that deferred the call. A nil is skipped, not handed to
// Destroy.
func TestReleaseReleasesPastAReport(t *testing.T) {
	c, seen := reportingCustody(t, &enclave.LockedMemoryError{Cause: errors.New("synthetic munmap ENOMEM")})
	first, err := enclave.NewMemoryEnclaveCopy([]byte("passphrase key"))
	if err != nil {
		t.Fatalf("could not allocate a test enclave: %v", err)
	}
	second, err := enclave.NewMemoryEnclaveCopy([]byte("af stripes"))
	if err != nil {
		t.Fatalf("could not allocate a test enclave: %v", err)
	}

	c.Release(first, nil, second)

	if len(*seen) != 2 || (*seen)[0] != first || (*seen)[1] != second {
		t.Fatalf("release saw %v, want first then second", *seen)
	}
	requireReleased(t, "first", first)
	requireReleased(t, "second", second)
}

// TestReleaseDropsCorruptionReportAndKeepsReleasing pins the other half of the
// decision: Destroy reports detected corruption as enclave.ErrEnclaveCorrupted
// (it no longer panics), after wiping, and the next WipeAll reports it again.
// Release drops the report like any other and still releases what follows.
func TestReleaseDropsCorruptionReportAndKeepsReleasing(t *testing.T) {
	first, err := enclave.NewMemoryEnclaveCopy([]byte("volume key material"))
	if err != nil {
		t.Fatalf("could not allocate a test enclave: %v", err)
	}
	second, err := enclave.NewMemoryEnclaveCopy([]byte("more volume key material"))
	if err != nil {
		t.Fatalf("could not allocate a test enclave: %v", err)
	}
	destroyOnCleanup(t, first)
	destroyOnCleanup(t, second)
	c := System()
	var seen []*enclave.MemoryEnclave
	c.Destroy = func(e *enclave.MemoryEnclave) error {
		seen = append(seen, e)
		return enclave.ErrEnclaveCorrupted
	}

	c.Release(first, second)

	if len(seen) != 2 || seen[0] != first || seen[1] != second {
		t.Fatalf("release saw %v, want first then second", seen)
	}
}

// refusingCustody is a custody every constructor of which refuses, as a
// process out of RLIMIT_MEMLOCK does.
func refusingCustody() Custody {
	refusal := &enclave.LockedMemoryError{Cause: errors.New("synthetic RLIMIT_MEMLOCK exhaustion")}
	return Admitted(func() (*enclave.Allocator, error) { return nil, refusal })
}

// TestEveryConstructorFailsClosedWhenLockedMemoryIsUnavailable: no
// constructor has a path around the custody's refusal -- a fail-closed path
// with a hole in it is one only some callers would fall through.
func TestEveryConstructorFailsClosedWhenLockedMemoryIsUnavailable(t *testing.T) {
	c := refusingCustody()
	source := []byte("material that never reaches locked memory")
	for name, construct := range map[string]func() (*enclave.MemoryEnclave, error){
		"New":           func() (*enclave.MemoryEnclave, error) { return c.New("test", 32) },
		"Random":        func() (*enclave.MemoryEnclave, error) { return c.Random("test", 32, rand.Reader) },
		"Clone":         func() (*enclave.MemoryEnclave, error) { return c.Clone("test", source) },
		"CloneWritable": func() (*enclave.MemoryEnclave, error) { return c.CloneWritable("test", source) },
		"CloneFiltered": func() (*enclave.MemoryEnclave, error) {
			return c.CloneFiltered("test", source, func(b byte) bool { return b != ' ' })
		},
		"Adopt": func() (*enclave.MemoryEnclave, error) { return c.Adopt("test", append([]byte(nil), source...)) },
	} {
		t.Run(name, func(t *testing.T) {
			e, err := construct()
			if err == nil {
				mustDestroy(t, e)
				t.Fatalf("%s succeeded while locked memory was being refused", name)
			}
			if e != nil {
				t.Fatalf("%s returned both an enclave and an error", name)
			}
			if !errors.Is(err, ErrProtectedMemory) || !errors.Is(err, enclave.ErrLockedMemoryUnavailable) {
				t.Fatalf("%s = %v, want ErrProtectedMemory carrying go-enclave's refusal", name, err)
			}
		})
	}
	if !bytes.Equal(source, []byte("material that never reaches locked memory")) {
		t.Fatal("a refused copy disturbed its source")
	}
	material := []byte("owned-even-on-failure")
	if _, err := c.Adopt("test", material); err == nil {
		t.Fatal("Adopt succeeded while locked memory was being refused")
	}
	if !bytes.Equal(material, make([]byte, len(material))) {
		t.Fatal("a refused Adopt left the material it owns on the heap")
	}
}

// TestRandomReportsAFailedDraw: a reader that fails leaves no enclave behind
// and names the draw.
func TestRandomReportsAFailedDraw(t *testing.T) {
	broken := errors.New("entropy source unavailable")
	e, err := System().Random("volume key", 32, iotest.ErrReader(broken))
	if err == nil {
		mustDestroy(t, e)
		t.Fatal("Random succeeded from a reader that fails")
	}
	if !errors.Is(err, broken) || !strings.Contains(err.Error(), "volume key") {
		t.Fatalf("Random = %v, want the reader's failure naming the draw", err)
	}
}

// TestCloneFilteredKeepsOnlyWhatSurvives: the filter runs inside locked
// memory and the result is sized to what it kept.
func TestCloneFilteredKeepsOnlyWhatSurvives(t *testing.T) {
	e, err := System().CloneFiltered("test", []byte("ab-cd-ef"), func(b byte) bool { return b != '-' })
	if err != nil {
		t.Fatal(err)
	}
	defer mustDestroy(t, e)
	if got := openSecret(t, e); !bytes.Equal(got, []byte("abcdef")) {
		t.Fatalf("filtered copy reads %q, want %q", got, "abcdef")
	}
	if _, err := System().CloneFiltered("test", []byte("---"), func(b byte) bool { return b != '-' }); !errors.Is(err, enclave.ErrEmptyEnclave) {
		t.Fatalf("filtering everything out = %v, want ErrEmptyEnclave", err)
	}
}

// TestEnclavesAreAdmittedThroughTheAllocator: the three constructors charge
// the allocator, and give the charge back when the enclave is destroyed.
func TestEnclavesAreAdmittedThroughTheAllocator(t *testing.T) {
	a, err := enclave.NewAllocator(enclave.LockedSize(4096) * 8)
	if err != nil {
		t.Fatal(err)
	}
	c := Admitted(func() (*enclave.Allocator, error) { return a, nil })

	sized, err := c.Sized(32)
	if err != nil {
		t.Fatal(err)
	}
	moved, err := c.Moved([]byte("moved-into-locked-memory"))
	if err != nil {
		t.Fatal(err)
	}
	copied, err := c.Copied([]byte("copied-into-locked-memory"))
	if err != nil {
		t.Fatal(err)
	}
	if a.InUse() != 3*enclave.LockedSize(32) {
		t.Fatalf("in use %d after three enclaves, want %d", a.InUse(), 3*enclave.LockedSize(32))
	}
	if ok, err := copied.EqualTo([]byte("copied-into-locked-memory")); err != nil || !ok {
		t.Fatal("the copy does not hold its source")
	}
	c.Release(sized, moved, copied)
	if a.InUse() != 0 {
		t.Fatalf("in use %d after every enclave was destroyed", a.InUse())
	}
	if _, err := c.Copied(nil); !errors.Is(err, enclave.ErrEmptyEnclave) {
		t.Fatalf("Copied(nil) = %v", err)
	}
}

// TestAdmissibleMeasuresAgainstTheAllocatorsWholeLimit: a peak above the
// limit is refused before anything is allocated, one at it is not, and an
// allocator that cannot be had refuses everything.
func TestAdmissibleMeasuresAgainstTheAllocatorsWholeLimit(t *testing.T) {
	a, err := enclave.NewAllocator(enclave.LockedSize(4096))
	if err != nil {
		t.Fatal(err)
	}
	c := Admitted(func() (*enclave.Allocator, error) { return a, nil })
	if err := c.Admissible("scan", a.Limit()); err != nil {
		t.Fatalf("a peak at the limit was refused: %v", err)
	}
	err = c.Admissible("scan", a.Limit()+1)
	if !errors.Is(err, ErrProtectedMemory) || !errors.Is(err, enclave.ErrBudgetExhausted) {
		t.Fatalf("a peak over the limit = %v, want ErrProtectedMemory matching enclave.ErrBudgetExhausted", err)
	}
	if err := refusingCustody().Admissible("scan", 1); !errors.Is(err, ErrProtectedMemory) {
		t.Fatalf("Admissible with no allocator = %v", err)
	}
}

// TestSystemAdmitsThroughTheProcessAllocator: production custody is
// go-enclave's process allocator, not one this module built.
func TestSystemAdmitsThroughTheProcessAllocator(t *testing.T) {
	process, err := enclave.ProcessAllocator()
	if err != nil {
		t.Fatal(err)
	}
	got, err := System().Allocator()
	if err != nil || got != process {
		t.Fatalf("System().Allocator() = %p, %v; want the process allocator %p", got, err, process)
	}
}

// TestARefusalNamesTheMaterialAndNotItsSize: an error string is a place key
// facts leak. A refusal names the material that needed protected memory and
// nothing measurable about it.
func TestARefusalNamesTheMaterialAndNotItsSize(t *testing.T) {
	_, err := refusingCustody().New("master key", 64)
	if err == nil {
		t.Fatal("a refusing custody allocated")
	}
	msg := err.Error()
	if !strings.Contains(msg, "master key") {
		t.Fatalf("error does not name the material: %q", msg)
	}
	if strings.Contains(msg, "64") {
		t.Fatalf("error text contains the key length: %q", msg)
	}
}
