// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/test/harness"
)

// runLedger and dmCreateInner are package-level so the wiring can be ASSERTED
// rather than trusted. TestLedgerRecordsAMappingBeforeTheKernelIsAsked
// substitutes dmCreateInner and reads runLedger from inside it, which proves
// the record is durable before the kernel call -- the one property this whole
// change rests on -- and does it without creating any host state.
var (
	runLedger     *harness.Ledger
	dmCreateInner func(name, uuid string) (uint64, error)
)

// TestMain records every piece of HOST state this suite is about to create, so
// a later run can remove exactly that state and nothing else (#96).
//
// # Why here and not in each test
//
// 33 test functions in this package create dm mappings or loop devices, across
// nine files, and the suite spells 28 distinct volume names. Cleanup added test
// by test is cleanup that the next test to be written will not have, and a
// cleanup keyed to the list of names is wrong the moment someone adds the
// twenty-ninth. So the record is taken at the one place every mapping in this
// package passes through.
//
// devicemapper.go already exposes that place: `dm.create` is the single
// seam between this package and the kernel's device mapper, and it exists
// because a failure that only ever runs against a real kernel is a failure
// nothing checks. Wrapping it here means no test call site changes and no test
// can opt out by forgetting.
//
// # The ordering is the design
//
// The record is written and fsynced BEFORE the mapping is created, and a record
// that fails REFUSES the creation. Anything weaker leaks the one thing nothing
// knows about: a mapping created a moment before the process died with its
// record still in the page cache.
//
// # Loop devices are recorded differently, and cannot be recorded the same way
//
// LOOP_CTL_GET_FREE allocates the device and returns its minor, so there is no
// name to record until after the resource exists -- the exact ordering this
// cannot accept. What IS knowable beforehand is where the backing file will
// live: this suite allocates through t.TempDir() and os.CreateTemp(""), both of
// which land under TMPDIR. So the run creates its own directory, points TMPDIR
// at it, and records THAT before a single test runs. Every loop device the
// suite attaches is backed by a file underneath it, by construction.
//
// SetupLoopDevice itself is deliberately untouched: the node-allocation defect
// in it is #104 and belongs to another change.
func TestMain(m *testing.M) {
	// The exit code comes from the CLEANUP, not from m.Run(): a green suite
	// that could not remove its own host state must not report success.
	os.Exit(runWithLedger(m))
}

func runWithLedger(m *testing.M) int {
	// The parts every integration suite in this repo needs -- ledger, recorded
	// temp root, TMPDIR, reap -- live in harness.BeginSuite, because setup
	// copied into three test processes is setup that drifts in two of them.
	suite, err := harness.BeginSuite(os.Stderr)
	if err != nil {
		// Fatal by design. Running unrecorded is running with the leak this
		// exists to stop, and the failure would surface later as some other
		// run's refusal on a host nobody can attribute.
		fmt.Fprintf(os.Stderr, "integration suite: %v\n", err)
		return 1
	}

	// Every device-mapper name this suite creates is scoped to this run (#109).
	// dm names are a flat host-wide namespace, so a constant name collides with
	// any concurrent run of the same suite -- and the collision is destructive,
	// not merely a failure. Set BEFORE m.Run so no test can allocate a name
	// without it; runVolume fails closed if it is still empty.
	runSuite = suite

	// Keyslots whose cost is not under test stay as cheap as they were before
	// a calibrated count was held to the OWASP floor (#249, A8); see
	// calibratedCountFloor and the unit suite's TestMain.
	calibratedCountFloor = func(string, keyslotCostPolicy) int { return minPBKDF2Iterations }

	// What this package adds on top, and what the external suites cannot have:
	// WRITE-AHEAD records for dm mappings, taken at the one seam every mapping
	// in this package passes through. The record is durable before the kernel
	// is asked, and a failed record REFUSES the creation rather than proceeding
	// unrecorded.
	previous := dm.create
	runLedger = suite.Ledger
	dmCreateInner = previous
	dm.create = func(name, uuid string) (uint64, error) {
		if err := suite.Ledger.Record(harness.KindMapping, name, uuid); err != nil {
			return 0, fmt.Errorf("refusing to create dm mapping %q: %w", name, err)
		}
		return dmCreateInner(name, uuid)
	}

	code := m.Run()
	dm.create = previous
	return suite.Finish(code, os.Stderr)
}

// TestLedgerRecordsAMappingBeforeTheKernelIsAsked is the ordering property the
// whole of #96 rests on, asserted at the seam.
//
// A record written after the mapping exists is worthless: the window it leaves
// is exactly where the measured debris came from -- a container killed between
// the create and the append leaves a mapping nothing knows about, and the #85
// guard then blocks every later run on that host.
//
// So this substitutes the kernel side of the seam and reads the ledger FROM
// INSIDE it. If the record were taken afterwards, or buffered rather than
// fsynced, the read would come up empty. Nothing is created: the substitute
// returns an error instead of calling the kernel, so this runs anywhere.
func TestLedgerRecordsAMappingBeforeTheKernelIsAsked(t *testing.T) {
	if runLedger == nil {
		t.Fatal("TestMain did not install a run ledger; the suite is running unrecorded")
	}

	const name = "luks2-ledger-selftest"
	const uuid = "CRYPT-LUKS2-selftest-luks2-ledger-selftest"

	var recordedAtCallTime []harness.Entry
	saved := dmCreateInner
	t.Cleanup(func() { dmCreateInner = saved })

	sentinel := fmt.Errorf("selftest: deliberately not creating a mapping")
	dmCreateInner = func(gotName, gotUUID string) (uint64, error) {
		entries, err := harness.ReadLedger(runLedger.Path())
		if err != nil {
			t.Errorf("reading the ledger from inside the create call: %v", err)
			return 0, sentinel
		}
		recordedAtCallTime = entries
		if gotName != name || gotUUID != uuid {
			t.Errorf("seam received (%q, %q), want (%q, %q)", gotName, gotUUID, name, uuid)
		}
		return 0, sentinel
	}

	_, err := dm.create(name, uuid)
	if err == nil || !strings.Contains(err.Error(), "deliberately not creating") {
		t.Fatalf("create error = %v, want the substitute's sentinel", err)
	}

	var found bool
	for _, e := range recordedAtCallTime {
		if e.Kind == harness.KindMapping && e.Value == name {
			found = true
			if e.Identity != uuid {
				t.Errorf("recorded identity = %q, want the dm uuid %q; without it the reaper cannot tell our mapping from a reused name",
					e.Identity, uuid)
			}
		}
	}
	if !found {
		t.Fatalf("the ledger did not yet contain %q when the kernel was called; the record is not write-ahead", name)
	}
}

// TestSuiteTempRootIsRecordedBeforeAnyTestRuns covers the loop-device half.
//
// Loop devices cannot be recorded before they exist, so what is recorded is the
// directory their backing files will live in. That only works if TMPDIR
// actually points there -- otherwise t.TempDir() and os.CreateTemp("") allocate
// somewhere the reaper was never told about, and every loop device the suite
// attaches is invisible to it.
func TestSuiteTempRootIsRecordedBeforeAnyTestRuns(t *testing.T) {
	if runLedger == nil {
		t.Fatal("TestMain did not install a run ledger")
	}

	entries, err := harness.ReadLedger(runLedger.Path())
	if err != nil {
		t.Fatalf("ReadLedger: %v", err)
	}

	var roots []string
	for _, e := range entries {
		if e.Kind == harness.KindLoopRoot {
			roots = append(roots, e.Value)
		}
	}
	if len(roots) != 1 {
		t.Fatalf("ledger holds %d loop-root entries, want exactly 1: %v", len(roots), roots)
	}

	// The assertion that matters: where the suite actually allocates.
	got := filepath.Clean(t.TempDir())
	want := filepath.Clean(roots[0])
	if !strings.HasPrefix(got, want+string(filepath.Separator)) {
		t.Fatalf("t.TempDir() returned %q, which is not under the recorded root %q; "+
			"loop devices backed there would be invisible to the reaper", got, want)
	}
}
