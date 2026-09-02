// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package pkg_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/test/harness"
)

// TestMain records the host state this suite is about to create (#96).
//
// # What it covers, and what it does not
//
// COVERED: loop devices. The run creates its own temp root, records it before
// anything allocates there, and points TMPDIR at it, so every backing file this
// suite creates through os.CreateTemp("") or t.TempDir() sits underneath a path
// the reaper was told about. That holds through a SIGKILL, because the record
// is on disk and outlives the container.
//
// NOT COVERED: dm mappings, on the kill path specifically. This package is
// pkg_test -- an EXTERNAL test package -- so it cannot reach luks2's
// dm.createAndLoad seam, which is unexported and is what gives the pkg/luks2
// suite write-ahead mapping records with no call-site changes. The tests here
// still remove their mappings through testCleanup on pass, fail and panic; what
// is missing is the SIGKILL window, where a mapping created a moment before the
// kill has no record.
//
// # Why the gap is accepted rather than closed here (ruled 2026-09-01)
//
// Three things close it between them, which is why leaving it is not a punt:
//
//   - All four leak names measured in #96 originate in pkg/luks2, which the
//     dm.createAndLoad seam covers completely. The external suites are not
//     where the observed damage came from.
//   - Both external suites already clean up on pass, fail AND panic. Only the
//     SIGKILL window is open.
//   - #105 -- concurrent jobs docker-rm-f'ing each other's containers through a
//     fixed name -- is the dominant PRODUCER of those kills, and it is
//     dispatched. Closing it shrinks the window rather than merely narrowing
//     it. #80 then removes the class entirely by denying the container host
//     device-mapper access, at which point this gap cannot exist.
//
// Two alternatives were considered and refused. Building the CLI with a
// recording hook compiled in tests a binary we do not ship, which is a worse
// defect than the gap. An integration-build-tagged EXPORTED observer on the
// library would work, but new exported surface on a Layer-0 library is an
// owner's decision rather than a lane's -- **if #80 stalls, that proposal goes
// back to the owner rather than being adopted quietly here.**
func TestMain(m *testing.M) {
	suite, err := harness.BeginSuite(os.Stderr)
	if err != nil {
		// Fatal by design: running unrecorded is running with the leak this
		// exists to stop, and the failure would surface later as some other
		// run's refusal on a host nobody can attribute.
		os.Stderr.WriteString("integration suite: " + err.Error() + "\n")
		os.Exit(1)
	}

	// Exit with what the CLEANUP concluded: a green run that could not remove
	// its own host state must not report success.
	os.Exit(suite.Finish(m.Run(), os.Stderr))
}

// TestSuiteAllocatesUnderTheRecordedTempRoot is the assertion that the covered
// half is actually wired.
//
// A recorded root nothing allocates under is a record of nothing: the reaper
// would find no loop devices beneath it and report a clean pass while the
// leaked devices sat somewhere else entirely.
func TestSuiteAllocatesUnderTheRecordedTempRoot(t *testing.T) {
	root := filepath.Clean(os.Getenv("TMPDIR"))
	if root == "" || root == "." {
		t.Fatal("TMPDIR is unset; the suite is allocating outside any recorded root")
	}

	got := filepath.Clean(t.TempDir())
	if !strings.HasPrefix(got, root+string(filepath.Separator)) {
		t.Fatalf("t.TempDir() returned %q, which is not under the recorded root %q", got, root)
	}

	// os.CreateTemp("") is the other allocator this suite uses, and it reads
	// TMPDIR independently of testing's own bookkeeping -- so it is asserted
	// separately rather than assumed to follow.
	f, err := os.CreateTemp("", "leakledger-*.img")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	name := f.Name()
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(name) })

	if !strings.HasPrefix(filepath.Clean(name), root+string(filepath.Separator)) {
		t.Fatalf("os.CreateTemp(\"\") returned %q, which is not under the recorded root %q", name, root)
	}
}
