// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package secret

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const (
	// frozenCopyMarker selects the child half of TestClonePagesAreReadOnly.
	frozenCopyMarker = "GO_LUKS2_CLONE_FROZEN_CHILD"

	// frozenCopyRead is printed once the child has read the copy back intact, just before the write.
	frozenCopyRead = "Clone read back intact; writing through the borrow now"

	// frozenCopySurvived is printed if the write returned: Clone handed back writable pages.
	frozenCopySurvived = "wrote through a Clone borrow and lived"
)

// TestClonePagesAreReadOnly: a write into CloneWritable's result returns in-process; one into Clone's must kill a child with the runtime's fault signature after its read marker.
func TestClonePagesAreReadOnly(t *testing.T) {
	if os.Getenv(frozenCopyMarker) == "1" {
		frozenCopyChild(t)
		return
	}

	// Control: the same store into a WRITABLE copy returns, and takes.
	src := []byte("MATERIAL-that-a-borrow-may-rewrite")
	writable, err := system.CloneWritable("test", src)
	if err != nil {
		t.Fatalf("CloneWritable: %v", err)
	}
	defer mustDestroy(t, writable)
	if err := Borrow("test", writable, func(b []byte) error {
		b[0] = 'm'
		return nil
	}); err != nil {
		t.Fatalf("the control write into a writable copy failed: %v", err)
	}
	if got := openSecret(t, writable); got[0] != 'm' {
		t.Fatalf("the control write into a writable copy did not take: %q", got)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestClonePagesAreReadOnly$", "-test.v")
	cmd.Env = append(os.Environ(), frozenCopyMarker+"=1")
	out, cerr := cmd.CombinedOutput()
	output := string(out)

	if !strings.Contains(output, frozenCopyRead) {
		t.Fatalf("the child never reported reading the copy back, so whatever killed it was not the write; child output:\n%s", output)
	}
	if strings.Contains(output, frozenCopySurvived) {
		t.Fatalf("a write through a Clone borrow returned instead of faulting; Clone handed back writable pages:\n%s", output)
	}
	if cerr == nil {
		t.Fatalf("the child exited cleanly after writing to Clone's pages; it should have faulted:\n%s", output)
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
	e, err := system.Clone("test", src)
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	// Not deferred: after the write below nothing runs. The process is gone,
	// and the kernel reclaims the mlock'd pages with it.

	if err := Borrow("test", e, func(b []byte) error {
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
	if err := Borrow("test", e, func(b []byte) error {
		b[0] = 'm'
		return nil
	}); err != nil {
		t.Fatalf("the borrow itself failed before the write: %v", err)
	}
	fmt.Println(frozenCopySurvived)
	mustDestroy(t, e)
}
