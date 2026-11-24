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

// enclaveFrom returns a frozen enclave holding a copy of b, registered for cleanup.
func enclaveFrom(t *testing.T, b []byte) enclave.ByteAccess {
	t.Helper()

	e, err := enclave.NewMemoryCopy(b)
	if err != nil {
		t.Fatalf("could not allocate a test enclave: %v", err)
	}
	destroyOnCleanup(t, e)

	return e
}

// mustDestroy destroys e and fails the test (Errorf) unless the release is clean.
func mustDestroy(tb testing.TB, e enclave.ByteAccess) {
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
func destroyOnCleanup(t *testing.T, e enclave.ByteAccess) {
	t.Helper()
	t.Cleanup(func() { mustDestroy(t, e) })
}

// openSecret copies the material out of an enclave so a test can assert on it.
// Production code must never do this; a test has to look at the bytes to prove
// anything about them.
func openSecret(t *testing.T, e enclave.ByteAccess) []byte {
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

// lockedKiB reports the process's mlock'd memory in KiB from /proc/self/status.
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
