// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const (
	// frozenCopyMarker selects the child half of TestCopySecretPagesAreReadOnly.
	frozenCopyMarker = "GO_LUKS2_COPYSECRET_FROZEN_CHILD"

	// frozenCopyRead is printed by the child once it has READ the copy back
	// intact through a borrow, immediately before the write. The parent
	// requires it: a child that died for any other reason -- a refused
	// allocation, a copy that did not match, a panic on the way -- exits
	// non-zero too, and without this marker every one of those would read as
	// proof of a fault the test never observed.
	frozenCopyRead = "copySecret read back intact; writing through the borrow now"

	// frozenCopySurvived is printed by the child if that write RETURNED. Seeing
	// it is the failure this test exists to catch: copySecret handed back
	// writable pages, so a stray write corrupts a credential silently instead
	// of faulting.
	frozenCopySurvived = "wrote through a copySecret borrow and lived"
)

// TestCopySecretPagesAreReadOnly is the execution evidence for copySecret's
// read-only contract. The other copySecret tests -- contents, source
// preservation, refusal, the writable scratch variant -- would all still pass
// if copySecret were reverted to the old sized-and-filled composition, because
// none of them touches the one property that changed: a write through its
// pages FAULTS. A property about faults is not established by a bool.
//
// The two halves run in different processes because they have different
// success conditions. The write into copySecretWritable's result must RETURN
// -- that is the in-place normalisation path parseRecoveryKeySecret relies on
// -- so it runs here, in-process, and is the control in the strict sense: the
// same material, the same borrow and the same store, differing only in which
// constructor built the enclave. The write into copySecret's result must kill
// the process: the fault is at a mapped-but-read-only address outside the Go
// heap, which the runtime reports as an unrecoverable fault rather than a
// catchable panic. So the child's evidence is inverted -- it must die, it must
// have reported the successful read first, and it must not have printed the
// survival marker on its way.
//
// Setup failures are told apart from the fault three ways: the child fails
// its own test (never a skip -- a skipped child is a gate that cannot fail)
// so its output carries the reason; the parent refuses a child that never
// printed the read marker; and the death itself must carry the runtime's
// fault signature, so a child killed by anything other than the write is not
// mistaken for one killed by it.
func TestCopySecretPagesAreReadOnly(t *testing.T) {
	if os.Getenv(frozenCopyMarker) == "1" {
		frozenCopyChild(t)
		return
	}

	// Control: the same store into a WRITABLE copy returns, and takes.
	src := []byte("MATERIAL-that-a-borrow-may-rewrite")
	writable, err := copySecretWritable("test", src)
	if err != nil {
		t.Fatalf("copySecretWritable: %v", err)
	}
	defer mustDestroy(t, writable)
	if err := borrowSecret("test", writable, func(b []byte) error {
		b[0] = 'm'
		return nil
	}); err != nil {
		t.Fatalf("the control write into a writable copy failed: %v", err)
	}
	if got := openSecret(t, writable); got[0] != 'm' {
		t.Fatalf("the control write into a writable copy did not take: %q", got)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestCopySecretPagesAreReadOnly$", "-test.v")
	cmd.Env = append(os.Environ(), frozenCopyMarker+"=1")
	out, cerr := cmd.CombinedOutput()
	output := string(out)

	if !strings.Contains(output, frozenCopyRead) {
		t.Fatalf("the child never reported reading the copy back, so whatever killed it was not the write; child output:\n%s", output)
	}
	if strings.Contains(output, frozenCopySurvived) {
		t.Fatalf("a write through a copySecret borrow returned instead of faulting; copySecret handed back writable pages:\n%s", output)
	}
	if cerr == nil {
		t.Fatalf("the child exited cleanly after writing to copySecret's pages; it should have faulted:\n%s", output)
	}
	// The runtime names the fault it died of. Anything else -- a panic, a
	// test failure after the read marker, a signal from outside -- is a death
	// this test did not cause and must not take credit for.
	if !strings.Contains(output, "unexpected fault address") &&
		!strings.Contains(output, "SIGSEGV") && !strings.Contains(output, "SIGBUS") {
		t.Fatalf("the child died (%v) without the runtime's fault signature, so the death is not evidence of read-only pages:\n%s", cerr, output)
	}
}

func frozenCopyChild(t *testing.T) {
	t.Helper()

	src := []byte("MATERIAL-that-a-borrow-may-rewrite")
	e, err := copySecret("test", src)
	if err != nil {
		t.Fatalf("copySecret: %v", err)
	}
	// Not deferred: after the write below nothing runs. The process is gone,
	// and the kernel reclaims the mlock'd pages with it.

	if err := borrowSecret("test", e, func(b []byte) error {
		if !bytes.Equal(b, src) {
			return fmt.Errorf("copy reads %q, want %q", b, src)
		}
		return nil
	}); err != nil {
		t.Fatalf("reading the copy back: %v", err)
	}
	fmt.Println(frozenCopyRead)

	// The store the read-only contract exists to stop. The same store into a
	// writable copy is the control in the parent.
	if err := borrowSecret("test", e, func(b []byte) error {
		b[0] = 'm'
		return nil
	}); err != nil {
		t.Fatalf("the borrow itself failed before the write: %v", err)
	}
	fmt.Println(frozenCopySurvived)
	mustDestroy(t, e)
}
