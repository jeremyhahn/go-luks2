// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Suite is one integration test process's participation in the ledger: it holds
// the run's record open, points TMPDIR at a directory the run owns, and reaps
// what previous runs left behind.
//
// It exists because the separate test processes (pkg/luks2 and each
// test/integration/<package> directory) need identical setup, and setup copied
// into each of them is setup that drifts in all but one.
type Suite struct {
	Ledger  *Ledger
	TempDir string
	RunID   string

	// Scope identifies the CONTAINER rather than this process, so the three
	// test binaries that run inside one container agree on it and two
	// containers never do. See volumename.go for why a name needs both terms.
	Scope string

	// Remover is the kernel side of Finish. It is a field rather than a
	// hardcoded SystemRemover because Finish is where the measured defect
	// LIVED -- it trusted the exit code -- and a path that has already been
	// wrong once must be reachable by a test.
	Remover Remover
}

// BeginSuite prepares a run: it opens the ledger, creates and RECORDS a temp
// root before anything can allocate in it, points TMPDIR there, and reaps the
// ledgers of runs that are already dead.
//
// The order is deliberate. The temp root is recorded before TMPDIR points at
// it, so there is no instant at which the suite could allocate a backing file
// somewhere unrecorded. The reap comes last, after this run has its own id, so
// it cannot mistake this run's ledger for a stale one.
func BeginSuite(w io.Writer) (*Suite, error) {
	stateDir := StateDir()
	runID := NewRunID(os.Getpid(), time.Now().UnixNano())

	// Before the ledger: a suite that cannot name its volumes uniquely must not
	// start, and failing here costs nothing. Proceeding would hand every test a
	// host-global name under a guard that no longer refuses them.
	scope, err := NewScope()
	if err != nil {
		return nil, err
	}

	ledger, err := OpenLedger(stateDir, runID)
	if err != nil {
		return nil, err
	}

	// The run id is IN the name (#247): a run root is told apart from another
	// container's by name alone, and the reaper detaches under a root only for
	// the run whose ledger carries that id. See reapLoopRoot.
	tmpRoot, err := os.MkdirTemp("", runRootPrefix+runID+"-")
	if err != nil {
		_ = ledger.Close()
		return nil, fmt.Errorf("creating the run temp root: %w", err)
	}
	if err := ledger.Record(KindLoopRoot, tmpRoot, ""); err != nil {
		_ = ledger.Close()
		return nil, err
	}
	if err := os.Setenv("TMPDIR", tmpRoot); err != nil {
		_ = ledger.Close()
		return nil, fmt.Errorf("pointing TMPDIR at the run temp root: %w", err)
	}

	// PROVE THE REDIRECTION TOOK EFFECT. Do not assume it.
	//
	// The loop-device half of the ledger rests entirely on this: the recorded
	// root is worth something only if the suite's backing files actually land
	// underneath it. os.TempDir() reads $TMPDIR on every call and t.TempDir()
	// allocates through it, so the redirection holds -- but "holds, as
	// documented" is an assumption about the environment, and an assumption the
	// mechanism's correctness depends on is one the mechanism should check.
	//
	// Checked here rather than only in a test, because a test asserts it where
	// the test runs while this asserts it where the SUITE runs. If some future
	// toolchain, sandbox or wrapper ever breaks the redirection, this fails the
	// run at startup with a diagnosis -- instead of every run quietly recording
	// a root that covers nothing and leaking every loop device it attaches.
	if err := verifyAllocationsLandUnder(tmpRoot); err != nil {
		_ = ledger.Close()
		return nil, err
	}

	// In the container this has already run in the entrypoint, before the #85
	// guard, and finds nothing. It runs here too for the host path
	// (`make host-integration-test`), which has no entrypoint.
	//
	// The three suites run SEQUENTIALLY from the entrypoint, and each discards
	// its ledger on a clean exit, so what is left for this to reap is only ever
	// a run that is already dead. They must not be made concurrent without
	// revisiting this: a live sibling's ledger would look stale.
	if _, err := Reap(stateDir, runID, SystemRemover{}, w); err != nil {
		_ = ledger.Close()
		return nil, err
	}

	return &Suite{Ledger: ledger, TempDir: tmpRoot, RunID: runID, Scope: scope, Remover: SystemRemover{}}, nil
}

// verifyAllocationsLandUnder confirms that a temp allocation made the way the
// suite makes them ends up under root.
//
// It probes os.CreateTemp("") rather than t.TempDir() because there is no
// *testing.T here, and because both resolve through os.TempDir() -- the probe
// therefore exercises the same lookup the suite's own allocations use, which is
// the property in question. TestSuiteTempRootIsRecordedBeforeAnyTestRuns covers
// t.TempDir() specifically, from inside a test.
func verifyAllocationsLandUnder(root string) error {
	f, err := os.CreateTemp("", "ledger-probe-*")
	if err != nil {
		return fmt.Errorf("probing where temp allocations land: %w", err)
	}
	name := f.Name()
	_ = f.Close()
	defer func() { _ = os.Remove(name) }()

	prefix := filepath.Clean(root) + string(filepath.Separator)
	if !strings.HasPrefix(filepath.Clean(name), prefix) {
		return fmt.Errorf(
			"%w: temp allocations land in %q, not under the recorded root %q -- "+
				"every loop device this suite attaches would be backed outside the ledger and "+
				"invisible to the next run's reaper",
			ErrLedgerUnavailable, filepath.Dir(name), root)
	}
	return nil
}

// Finish closes out the run: it removes what this run recorded and left behind,
// and discards the ledger only if nothing is outstanding.
//
// # A passing run is not evidence of a clean host
//
// An earlier version discarded the ledger whenever the tests passed. That is
// wrong, and it was wrong in the most expensive way -- MEASURED on a privileged
// CI runner,
// 2026-09-01: pkg/luks2 reported `ok` in 87.6s while TestLoopDeviceCleanup left
// /dev/loop1 attached. Finish saw exit 0, discarded the ledger and deleted the
// temp root, destroying the only record of the device the run had just leaked.
// The next run then reaped a ledger describing nothing and honestly reported
// "1 already gone" while the device sat on the host.
//
// That is the failure shape this repository keeps meeting: the danger path is
// the one that looks like normal completion. A green suite and a leaked device
// are not mutually exclusive, and the exit code cannot tell them apart.
//
// So the record is checked against the HOST rather than against the verdict.
// Whatever this run recorded and has not cleaned up is removed here, by exactly
// the same identity rules the cross-run reaper uses, and the ledger survives
// unless there is nothing left outstanding.
//
// # It returns the exit code the process must use
//
// A cleanup failure FAILS THE RUN. An earlier version logged and returned, so a
// green suite that could not remove its own dm mapping still exited 0 -- CI
// reported success while the host kept the state and the ledger. That is the
// fail-open path this whole harness exists to close, reintroduced at the last
// step of it.
//
// A non-zero test result is preserved as-is; a clean run whose cleanup failed
// becomes 1. The caller must exit with what this returns.
func (s *Suite) Finish(code int, w io.Writer) int {
	report, err := ReapOwn(s.Ledger, s.Remover, w)
	if err != nil {
		// Keep the ledger. Something this run created is still on the host and
		// could not be removed, and the record is what lets the next run try
		// again.
		_ = s.Ledger.Close()
		fmt.Fprintf(w, "suite: could not remove everything this run created: %v\n", err)
		fmt.Fprintf(w, "suite: keeping %s and %s so the next run can finish the job\n",
			s.Ledger.Path(), s.TempDir)
		return failedExit(code)
	}

	if len(report.NotOurs) > 0 {
		// A name we recorded is now held by something else. There is nothing to
		// do about it and nothing of ours left under it, so the ledger goes --
		// but it is reported rather than passed over in silence.
		fmt.Fprintf(w, "suite: %d recorded name(s) are now held by something else and were left alone\n",
			len(report.NotOurs))
	}
	if len(report.Removed) > 0 {
		fmt.Fprintf(w, "suite: this run leaked %d resource(s) and cleaned them up itself (tests exited %d)\n",
			len(report.Removed), code)
	}

	// THE DIRECTORY GOES BEFORE THE RECORD OF IT DOES, and its failure is
	// reported.
	//
	// The previous order discarded the ledger and then ignored os.RemoveAll:
	// a removal that failed left tens of megabytes of disk images behind, with
	// the run exiting 0 and the only record of where they were already
	// destroyed. Repeated, that exhausts the runner's filesystem -- and my own
	// sweep classified this as cosmetic because it looked only at host DEVICE
	// state and never asked what else the ledger was the record of.
	if err := s.Remover.RemoveDir(s.TempDir); err != nil {
		_ = s.Ledger.Close()
		fmt.Fprintf(w, "suite: could not remove the run temp root %s: %v\n", s.TempDir, err)
		fmt.Fprintf(w, "suite: keeping %s so the next run can finish the job\n", s.Ledger.Path())
		return failedExit(code)
	}

	if err := s.Ledger.Discard(); err != nil {
		// A ledger that cannot be discarded will be reaped by the next run as
		// though this one had died. That is safe, but it is not nothing, and a
		// silent pass would hide a state directory nobody can write to.
		fmt.Fprintf(w, "suite: could not discard the run ledger: %v\n", err)
		return failedExit(code)
	}
	return code
}

// failedExit preserves an existing failure and turns a clean run into one.
func failedExit(code int) int {
	if code != 0 {
		return code
	}
	return 1
}
