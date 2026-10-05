// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Regression tests for #247's harness findings: (a) a loop detach bounded by
// run-root name, (b) a state directory used through the handle it was
// validated by, (c) run roots bound to the run that recorded them.

// (a) A damaged or forged loop-root line must not be able to aim a detach at
// every loop device under an arbitrary directory. Only "" and "/" used to be
// refused, so /var/lib/snapd would have detached every snap.
func TestLoopDevicesUnderRefusesARootNotNamedLikeARunRoot(t *testing.T) {
	sys := t.TempDir()
	d := filepath.Join(sys, "loop7", "loop")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "backing_file"), []byte("/var/lib/snapd/snaps/core_1.snap\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, root := range []string{"/var/lib/snapd", "/var/lib", "relative/go-luks2-run-x", "/tmp/luks2-run-abc", ".", ""} {
		got, err := loopDevicesUnderIn(sys, root, stubBoundIdentity)
		var refused *RunRootError
		if !errors.As(err, &refused) {
			t.Errorf("loopDevicesUnderIn(%q) = %v, %v; want a *RunRootError", root, got, err)
			continue
		}
		if !strings.Contains(err.Error(), "match loop devices under") {
			t.Errorf("message %q does not say what was refused", err)
		}
	}

	// The accept side: a run root's name matches, and only its devices.
	if err := os.WriteFile(filepath.Join(d, "backing_file"), []byte("/tmp/go-luks2-run-r-1/x.img\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loopDevicesUnderIn(sys, "/tmp/go-luks2-run-r-1", stubBoundIdentity)
	if err != nil || !slices.Equal(loopPaths(got), []string{"/dev/loop7"}) {
		t.Fatalf("loopDevicesUnderIn(run root) = %v, %v; want /dev/loop7", got, err)
	}
}

// swapDir moves dir aside and puts a FORGED state directory in its place: one
// that would pass validation on its own, holding a ledger that aims the reaper
// at a mapping nobody recorded.
func swapDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.Rename(dir, dir+".validated"); err != nil {
		t.Fatalf("moving the validated directory aside: %v", err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("creating the forged directory: %v", err)
	}
	forged := "dm\tsomeones-root\tuuid-someones-root\n"
	if err := os.WriteFile(filepath.Join(dir, "forged-run.ledger"), []byte(forged), 0o600); err != nil {
		t.Fatalf("planting the forged ledger: %v", err)
	}
}

func withStateDirHook(t *testing.T, hook func(stage, dir string)) {
	t.Helper()
	saved := stateDirHook
	stateDirHook = hook
	t.Cleanup(func() { stateDirHook = saved })
}

// (b) The reaper validated the state directory by PATH and then re-resolved
// that path for every listing, lock and read. A directory swapped in after the
// check -- possible wherever a parent is writable by someone else -- was then
// believed. Now everything after the check goes through the validated handle,
// so a swap after validation is invisible to the reap.
func TestReapUsesTheDirectoryItValidatedNotWhateverThePathNamesNow(t *testing.T) {
	dir := stateDir(t)
	writeLedger(t, dir, "dead-run", Entry{Kind: KindMapping, Value: "ours", Identity: "uuid-ours"})

	rm := newFakeRemover()
	rm.mappings["ours"] = "uuid-ours"
	rm.mappings["someones-root"] = "uuid-someones-root"

	withStateDirHook(t, func(stage, d string) {
		if stage == stateDirValidated && d == dir {
			swapDir(t, dir)
		}
	})
	report, err := Reap(dir, "live-run", rm, io.Discard)
	if err != nil {
		t.Fatalf("Reap: %v", err)
	}

	if _, ok := rm.mappings["someones-root"]; !ok {
		t.Fatal("the reaper removed a mapping named only by a ledger in a directory swapped in after validation")
	}
	if _, ok := rm.mappings["ours"]; ok {
		t.Fatal("the validated directory's own ledger was not reaped")
	}
	if len(report.LedgersProcessed) != 1 || filepath.Base(report.LedgersProcessed[0]) != "dead-run.ledger" {
		t.Fatalf("processed %v, want only the validated directory's dead-run.ledger", report.LedgersProcessed)
	}
	// The ledger was consumed in the directory that was validated, and the
	// forged one was never touched.
	if _, err := os.Stat(filepath.Join(dir+".validated", "dead-run.ledger")); !os.IsNotExist(err) {
		t.Errorf("the reaped ledger is still in the validated directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "forged-run.ledger")); err != nil {
		t.Errorf("the forged ledger was touched: %v", err)
	}
}

// The writer side of (b): a ledger is created and discarded through the handle,
// so a swap after validation cannot redirect where the record is written.
func TestLedgerIsWrittenAndDiscardedInTheDirectoryItValidated(t *testing.T) {
	dir := stateDir(t)
	withStateDirHook(t, func(stage, d string) {
		if stage == stateDirValidated && d == dir {
			swapDir(t, dir)
		}
	})
	ledger, err := OpenLedger(dir, "run-1")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	if err := ledger.Record(KindMapping, "m", "u"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir+".validated", "run-1.ledger")); err != nil {
		t.Fatalf("the ledger is not in the validated directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "run-1.ledger")); !os.IsNotExist(err) {
		t.Fatalf("the ledger was written into the swapped-in directory: %v", err)
	}
	entries, err := ledger.entries()
	if err != nil || len(entries) != 1 || entries[0].Value != "m" {
		t.Fatalf("entries = %v, %v; want the recorded mapping", entries, err)
	}
	if err := ledger.Discard(); err != nil {
		t.Fatalf("Discard: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir+".validated", "run-1.ledger")); !os.IsNotExist(err) {
		t.Fatalf("Discard did not remove the ledger it wrote: %v", err)
	}
}

// A swap between inspecting the name and opening it is refused, not raced:
// the opened directory must be the one the name showed.
func TestStateDirSwappedWhileBeingOpenedIsRefused(t *testing.T) {
	dir := stateDir(t)
	withStateDirHook(t, func(stage, d string) {
		if stage == stateDirNamed && d == dir {
			swapDir(t, dir)
		}
	})
	_, err := openTrustedStateDir(dir)
	var sde *StateDirError
	if !errors.As(err, &sde) || !errors.Is(err, ErrLedgerUnavailable) {
		t.Fatalf("openTrustedStateDir = %v; want a *StateDirError that is ErrLedgerUnavailable", err)
	}
	if !strings.Contains(err.Error(), "replaced while it was being opened") {
		t.Errorf("message %q does not say what happened", err)
	}
}

func TestOpenLedgerRefusesARunIDThatIsNotAName(t *testing.T) {
	dir := stateDir(t)
	for _, id := range []string{"", ".", "..", "../escape", "a/b"} {
		if l, err := OpenLedger(dir, id); !errors.Is(err, ErrLedgerUnavailable) {
			if l != nil {
				_ = l.Close()
			}
			t.Errorf("OpenLedger(%q) = %v; want ErrLedgerUnavailable", id, err)
		}
	}
}

func TestStateDirErrorMessage(t *testing.T) {
	cause := errors.New("EIO")
	err := &StateDirError{Dir: "/var/tmp/s", Problem: "opening it", Err: cause}
	if !errors.Is(err, cause) || !errors.Is(err, ErrLedgerUnavailable) {
		t.Fatalf("errors.Is does not reach the cause and the sentinel: %v", err)
	}
	for _, want := range []string{"/var/tmp/s", "opening it", "EIO"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q lacks %q", err, want)
		}
	}
	if msg := (&StateDirError{Problem: "no state directory was configured"}).Error(); strings.Contains(msg, "directory  ") {
		t.Errorf("message without a directory is malformed: %q", msg)
	}
}

// (c) The run root carries the run id, and the reaper requires that match.
func TestRootBelongsToRun(t *testing.T) {
	cases := []struct {
		root, run string
		want      bool
	}{
		{"/tmp/go-luks2-run-1-abc-123456", "1-abc", true},
		{"/tmp/go-luks2-run-1-abc-123456/", "1-abc", true},
		{"/tmp/go-luks2-run-1-abc-123456", "1-abd", false},
		// A run id that is a prefix of another's must not claim its root.
		{"/tmp/go-luks2-run-1-abc-123456", "1", false},
		{"/tmp/go-luks2-run-1-abc-123456", "1-ab", false},
		// The pre-#247 name: no run id at all.
		{"/tmp/go-luks2-run-123456", "1-abc", false},
		{"/tmp/go-luks2-run-1-abc-", "1-abc", false},
		{"/tmp/go-luks2-run-1-abc-12x", "1-abc", false},
		{"/tmp/go-luks2-run-1-abc-123", "", false},
	}
	for _, tc := range cases {
		if got := rootBelongsToRun(tc.root, tc.run); got != tc.want {
			t.Errorf("rootBelongsToRun(%q, %q) = %v, want %v", tc.root, tc.run, got, tc.want)
		}
	}
}

// Two containers each create /tmp/go-luks2-run-<n> in their own /tmp; with a
// 32-bit suffix a dead run's root and a live sibling's can share a name, and
// the kernel reports both runs' backing files under it. The reaper must not
// detach under a root that is not named for the run whose ledger recorded it.
func TestReapLeavesAnUnboundRunRootsDevicesAlone(t *testing.T) {
	dir := stateDir(t)
	const shared = "/tmp/go-luks2-run-1405067156" // pre-#247 shape: no run id
	path := writeLedger(t, dir, "dead-run", Entry{Kind: KindLoopRoot, Value: shared})

	rm := newFakeRemover()
	rm.loops[shared+"/TestLive/001/x.img"] = []string{"/dev/loop9"} // a live sibling's device

	report, err := Reap(dir, "next-run", rm, io.Discard)
	var unbound *UnboundRunRootError
	if !errors.As(err, &unbound) || !errors.Is(err, ErrReapIncomplete) {
		t.Fatalf("Reap = %v; want ErrReapIncomplete carrying an *UnboundRunRootError", err)
	}
	if !strings.Contains(err.Error(), "may belong to another, live run") {
		t.Errorf("message %q does not explain the refusal", err)
	}
	if len(rm.detached) != 0 {
		t.Fatalf("detached %v under a root not named for the run that recorded it", rm.detached)
	}
	if len(rm.removedDirs) != 0 {
		t.Fatalf("removed %v: the directory may be a live run's", rm.removedDirs)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the ledger was consumed while its state was left on the host: %v", err)
	}
	if len(report.Unremoved) != 1 {
		t.Fatalf("report.Unremoved = %v, want the unbound root", report.Unremoved)
	}
}

// With nothing backed under it, an unbound root does not latch the runner: the
// record is consumed, and the directory -- possibly someone else's -- is left.
func TestReapConsumesAnUnboundRootWithNothingUnderIt(t *testing.T) {
	dir := stateDir(t)
	const legacy = "/tmp/go-luks2-run-77"
	path := writeLedger(t, dir, "dead-run", Entry{Kind: KindLoopRoot, Value: legacy})

	rm := newFakeRemover()
	var out strings.Builder
	report, err := Reap(dir, "next-run", rm, &out)
	if err != nil {
		t.Fatalf("Reap: %v", err)
	}
	if len(rm.removedDirs) != 0 {
		t.Fatalf("removed %v: an unbound root's directory is not provably ours", rm.removedDirs)
	}
	if len(report.AlreadyGone) != 1 {
		t.Fatalf("report.AlreadyGone = %v, want the unbound root", report.AlreadyGone)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the ledger was kept: %v", err)
	}
	if !strings.Contains(out.String(), "is not named for run dead-run") {
		t.Errorf("output does not say why the directory was left: %s", out.String())
	}
}

// BeginSuite names the run root for its run, so its own reaper -- and the next
// run's -- can tell it from another container's.
func TestBeginSuiteNamesTheRunRootForTheRun(t *testing.T) {
	t.Setenv(StateDirEnv, stateDir(t))
	t.Setenv("TMPDIR", t.TempDir())

	suite, err := BeginSuite(io.Discard)
	if err != nil {
		t.Fatalf("BeginSuite: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(suite.TempDir) })

	if !rootBelongsToRun(suite.TempDir, suite.RunID) {
		t.Errorf("run root %q is not named for run %q", suite.TempDir, suite.RunID)
	}
	if suite.Ledger.RunID() != suite.RunID {
		t.Errorf("ledger run id %q, suite run id %q", suite.Ledger.RunID(), suite.RunID)
	}

	// Its own Finish reaps it as its own: the root is removed.
	rm := newFakeRemover()
	suite.Remover = rm
	if code := suite.Finish(0, io.Discard); code != 0 {
		t.Fatalf("Finish = %d", code)
	}
	if !slices.Contains(rm.removedDirs, suite.TempDir) {
		t.Errorf("Finish did not remove the run's own root: %v", rm.removedDirs)
	}
}

func TestLockErrorsAreTyped(t *testing.T) {
	cause := errors.New("EIO")
	lockErr := &LockFileError{Action: "locking", Path: "/s/.reap.lock", Err: cause}
	if !errors.Is(lockErr, ErrLedgerUnavailable) || !errors.Is(lockErr, cause) {
		t.Fatalf("LockFileError does not reach the sentinel and the cause: %v", lockErr)
	}
	for _, want := range []string{"locking", "/s/.reap.lock", "EIO"} {
		if !strings.Contains(lockErr.Error(), want) {
			t.Errorf("message %q lacks %q", lockErr, want)
		}
	}
	busy := &ReaperBusyError{Path: "/s/.reap.lock", Waited: 5}
	if !errors.Is(busy, ErrReapIncomplete) || !strings.Contains(busy.Error(), "another reaper has held") {
		t.Fatalf("ReaperBusyError = %v", busy)
	}

	// A ledger whose run id names an existing directory cannot be opened as a
	// file: the failure is a typed LockFileError.
	dir := stateDir(t)
	if err := os.Mkdir(filepath.Join(dir, "taken.ledger"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := OpenLedger(dir, "taken")
	var lfe *LockFileError
	if !errors.As(err, &lfe) || lfe.Action != "opening" {
		t.Fatalf("OpenLedger over a directory = %v; want a *LockFileError(opening)", err)
	}
}

// Discard unlinks the ledger while its lock is still held: at the moment the
// lock is released, no other run's reaper can see the ledger, so it cannot
// consume a clean run's record and fail that run's own Discard.
func TestDiscardUnlinksTheLedgerBeforeReleasingItsLock(t *testing.T) {
	dir := stateDir(t)
	ledger, err := OpenLedger(dir, "clean-run")
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}

	saved := ledgerCloseHook
	t.Cleanup(func() { ledgerCloseHook = saved })
	checked := false
	ledgerCloseHook = func(l *Ledger) {
		checked = true
		if _, err := os.Stat(l.Path()); !os.IsNotExist(err) {
			t.Errorf("the ledger is still visible as its lock is released: %v", err)
		}
		// Another run's reaper, at exactly this moment, finds nothing to take.
		report, err := Reap(dir, "sibling-run", newFakeRemover(), io.Discard)
		if err != nil || len(report.LedgersProcessed) != 0 {
			t.Errorf("a sibling reaper consumed %v (err %v) while the ledger was being discarded",
				report.LedgersProcessed, err)
		}
	}

	if err := ledger.Discard(); err != nil {
		t.Fatalf("Discard: %v", err)
	}
	if !checked {
		t.Fatal("the close hook never ran")
	}
}
