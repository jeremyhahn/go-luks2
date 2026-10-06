// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
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
