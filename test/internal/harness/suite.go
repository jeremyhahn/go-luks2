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

// Suite is one integration test process's ledger participation: it holds the run's record, points TMPDIR at a run-owned directory, and reaps dead runs.
type Suite struct {
	Ledger  *Ledger
	TempDir string
	RunID   string

	// Scope identifies the container, shared by its test binaries (see volumename.go).
	Scope string

	// Remover is the kernel side of Finish; a field so tests can reach it.
	Remover Remover
}

// BeginSuite opens the ledger, records a temp root before pointing TMPDIR at it, then reaps the ledgers of dead runs.
func BeginSuite(w io.Writer) (*Suite, error) {
	stateDir := StateDir()
	runID := NewRunID(os.Getpid(), time.Now().UnixNano())

	// Refuse to start if volumes cannot be named uniquely.
	scope, err := NewScope()
	if err != nil {
		return nil, err
	}

	ledger, err := OpenLedger(stateDir, runID)
	if err != nil {
		return nil, err
	}

	// The run id is in the name, so the reaper detaches under a root only for its own run (reapLoopRoot).
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

	// Prove allocations land under the recorded root; otherwise the ledger covers nothing.
	if err := verifyAllocationsLandUnder(tmpRoot); err != nil {
		_ = ledger.Close()
		return nil, err
	}
	recordedRunRoot = tmpRoot

	// The suites run sequentially, so only dead runs' ledgers remain; do not make them concurrent without revisiting this.
	if _, err := Reap(stateDir, runID, SystemRemover{}, w); err != nil {
		_ = ledger.Close()
		return nil, err
	}

	return &Suite{Ledger: ledger, TempDir: tmpRoot, RunID: runID, Scope: scope, Remover: SystemRemover{}}, nil
}

// verifyAllocationsLandUnder confirms an os.CreateTemp allocation lands under root.
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

// Finish removes what this run recorded and left, keeps the ledger if anything is outstanding, and returns the exit code to use (a cleanup failure makes a clean run 1).
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

	// Remove the directory before discarding its record, and report the failure.
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
