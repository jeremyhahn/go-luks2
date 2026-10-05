// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Remover is the seam between the reaper and the kernel.
//
// It exists for the same reason devicemapper.go's deviceMapper does: the
// behavior that has to be right here -- removing exactly the recorded
// resource, and refusing when the live one is not it -- cannot be exercised
// against a real kernel outside a privileged container, and a decision that
// only ever runs there is a decision nothing checks.
type Remover interface {
	// MappingIdentity returns the dm UUID of the live mapping called name.
	// It reports ok=false when no mapping by that name exists, which is the
	// ordinary case for a ledger entry whose test cleaned up properly.
	MappingIdentity(name string) (uuid string, ok bool, err error)

	// RemoveMapping removes the dm target called name.
	RemoveMapping(name string) error

	// LoopDevicesFor returns the loop devices whose backing file is the given
	// path, in a stable order.
	LoopDevicesFor(backingFile string) ([]LoopDevice, error)

	// LoopDevicesUnder returns the loop devices whose backing file lives under
	// the given directory, in a stable order.
	LoopDevicesUnder(dir string) ([]LoopDevice, error)

	// RemoveDir removes a directory this suite created, recursively.
	//
	// It is on the Remover rather than a direct os.RemoveAll because it can
	// FAIL, and a failure has to be reportable: the run temp root holds
	// multi-megabyte disk images, so a removal that quietly does not happen
	// exhausts the runner's filesystem one run at a time.
	RemoveDir(path string) error

	// DetachLoop releases a loop device, refusing unless it still carries the
	// binding it was ENUMERATED with -- never one re-read afterwards.
	// Re-reading would return whatever the device is bound to now, which is
	// precisely what a reassignment changes, so the check would agree with the
	// reassignment and defeat itself.
	//
	// It takes the whole [LoopDevice] rather than a path, because the
	// enumerated identity travels with it: a check the caller makes and then
	// acts on separately is the race this signature exists to remove.
	// /dev/loopN is a reusable name, and between enumerating it and clearing it
	// the number can be reassigned to something else entirely.
	//
	// An implementation MUST refuse a device whose identity was never captured
	// (LoopDevice.IdentityKnown false). "I could not find out what this is" is
	// not a license to detach it.
	DetachLoop(dev LoopDevice) error
}

// Report describes what a reap did, so a caller can print it and a test can
// assert on it.
type Report struct {
	// LedgersProcessed are the ledger files this reap consumed.
	LedgersProcessed []string

	// Removed is the state that was still present and has been removed.
	Removed []Entry

	// AlreadyGone is recorded state that no longer existed -- the ordinary
	// outcome for a run that cleaned up after itself before dying.
	AlreadyGone []Entry

	// NotOurs is recorded state whose live identity does not match what was
	// recorded, meaning the name was reused by something else. It is REPORTED
	// AND LEFT ALONE, which is the whole reason identity is recorded.
	NotOurs []Entry

	// LedgersSkippedAlive are ledgers whose owning run is still running. They
	// are left completely untouched -- not read, not reaped, not deleted.
	LedgersSkippedAlive []string

	// DirsLeft are recorded directories whose devices are all gone but which
	// could not be removed. Reported, retried on a later run, and deliberately
	// NOT a failure: disk is not a device.
	DirsLeft []Entry

	// Unremoved is recorded state the reaper tried and failed to remove. The
	// ledger is kept and a later run retries. It is REPORTED, never fatal --
	// see the exit-code policy in Reap.
	Unremoved []ReapFailure
}

// Reap removes host state recorded by previous runs of this suite.
//
// It processes every ledger in dir except selfRunID's, which is the live run's
// own and whose resources are in use. Each entry is removed only where the
// resource is still present AND still carries the identity that was recorded
// for it; anything else is left alone and reported.
//
// A ledger is deleted only after every entry in it has been dealt with. A
// partial reap leaves the file, so the next run tries again rather than
// forgetting state that is still on the host.
func Reap(dir, selfRunID string, rm Remover, w io.Writer) (Report, error) {
	var report Report

	// ONE REAPER AT A TIME ON THIS HOST.
	//
	// Without this, two reapers starting together are indistinguishable from a
	// reaper and a live suite: reaper A takes a stale ledger's lock, reaper B
	// gets EWOULDBLOCK and classifies it as "the owner is still alive". B then
	// returns success and proceeds -- even though A may still be working, or
	// may have FAILED and left the recorded state exactly where it was. The
	// fail-closed path would have been defeated by a lock B misread.
	//
	// Serializing the reapers removes the ambiguity at its source: while this
	// lock is held, a ledger lock can only be a live SUITE, which is the one
	// thing it is supposed to mean. B waits for A, then does its own pass over
	// whatever A left -- so if A failed, B fails too, which is the required
	// direction.
	sd, unlock, err := lockReaper(dir)
	if err != nil {
		return report, err
	}
	defer unlock()

	// Every ledger is listed, locked, read and deleted through the handle
	// lockReaper validated, never by path again (#247).
	names, err := staleLedgers(sd, selfRunID)
	if err != nil {
		return report, err
	}
	if len(names) == 0 {
		fmt.Fprintln(w, "reap: no ledgers from previous runs; nothing recorded to remove")
		return report, nil
	}

	for _, name := range names {
		path := filepath.Join(sd.path, name)
		// LIVENESS FIRST, before the file is even read.
		//
		// Several jobs run concurrently on one runner, so a ledger in this
		// directory may belong to a suite that is running right now. Its
		// mappings and loop devices are in USE, and removing them fails a
		// different run in a way that reads as a flaky test on a host that
		// looks clean -- strictly worse than the leak, which at least fails
		// loudly and is recoverable by a human.
		//
		// The owner's lock is the only trustworthy signal. Nothing about the
		// device distinguishes a live job's from an orphan: measured
		// 2026-09-01 on a shared CI runner, a live job's loop device showed empty
		// holders and empty fuser, exactly like the orphans swept minutes
		// before.
		// Cannot establish whether the owner is alive: that is UNKNOWN state,
		// and unknown still fails closed. See the exit-code policy below for
		// why a failure to REMOVE does not.
		dead, release, err := tryLockIn(sd, name)
		if err != nil {
			return report, fmt.Errorf("%w: could not establish whether the run owning %s is alive: %v",
				ErrReapIncomplete, path, err)
		}
		if !dead {
			fmt.Fprintf(w, "reap: leaving %s alone; the run that owns it is still alive\n", path)
			report.LedgersSkippedAlive = append(report.LedgersSkippedAlive, path)
			continue
		}
		// Released at the end of THIS iteration rather than deferred to the
		// end of Reap: a host that has accumulated many dead runs would
		// otherwise hold one open descriptor and one lock per ledger for the
		// whole sweep, which is a leak in the code whose entire job is to stop
		// leaks.
		outcome := reapLedger(sd, name, rm, w, &report)
		release()

		if outcome.err != nil {
			return report, outcome.err
		}
		report.Unremoved = append(report.Unremoved, outcome.failures...)
	}

	fmt.Fprintf(w, "reap: %d ledger(s) consumed, %d skipped (owner alive), %d removed, %d already gone, %d left alone (name reused), %d director(ies) left, %d NOT REMOVED\n",
		len(report.LedgersProcessed), len(report.LedgersSkippedAlive),
		len(report.Removed), len(report.AlreadyGone), len(report.NotOurs),
		len(report.DirsLeft), len(report.Unremoved))

	// EXIT-CODE POLICY: a DEVICE left behind refuses the run; a DIRECTORY does
	// not. The line is between live host state and disk.
	//
	// I softened this to non-fatal for both, on the evidence that a stuck
	// device had latched a runner permanently. That evidence was my own defect:
	// an empty lo_file_name was read as "already free", so LOOP_CLR_FD was
	// never called and the device could never clear. Fixed and proven on the
	// live device. With that gone, no case we can actually produce makes a
	// device permanently unremovable -- a live holder sets LO_FLAGS_AUTOCLEAR
	// and resolves when it exits, and a leaked holder needs a human either way.
	// So the reversal was correct about disk and wrong about devices, and it
	// was wrong because it generalised from a bug.
	//
	// The substance is that the #85 guard CANNOT cover this. It inventories
	// `dmsetup ls`, so a retained dm mapping is caught there -- but a retained
	// LOOP device passes it untouched, goes on to consume minors toward #104's
	// threshold, and reaches the suite as a resource the host quietly no longer
	// has. Continuing on that is running on a contaminated host.
	//
	// A DIRECTORY is different in kind: the guard never looks at it, no run
	// trips over it, and the only cost is space. It is reported, the record is
	// kept, and a later run retries -- see reapLoopRoot.
	//
	// UNKNOWN still fails closed and always did: an untrusted state directory,
	// an unreadable ledger, or a liveness check that cannot answer return an
	// error above, because then the reaper does not know what is on the host.
	for _, f := range report.Unremoved {
		fmt.Fprintf(w, "reap: NOT REMOVED: %s %q: %v -- record kept, will retry\n",
			f.Entry.Kind, f.Entry.Value, f.Err)
	}
	for _, e := range report.DirsLeft {
		fmt.Fprintf(w, "reap: directory left: %q -- record kept, will retry; disk, not a device\n", e.Value)
	}

	if len(report.Unremoved) > 0 {
		return report, &ReapError{Failures: report.Unremoved}
	}
	return report, nil
}

// ledgerOutcome separates a fatal error -- one that stops the whole sweep --
// from per-entry failures, which do not.
type ledgerOutcome struct {
	err      error
	failures []ReapFailure
}

// reapLedger deals with one stale ledger. The caller holds its lock.
func reapLedger(sd *trustedDir, name string, rm Remover, w io.Writer, report *Report) ledgerOutcome {
	var out ledgerOutcome
	path := filepath.Join(sd.path, name)
	runID := strings.TrimSuffix(name, ledgerSuffix)

	entries, err := readLedgerIn(sd, name)
	if err != nil {
		// A ledger that cannot be read is NOT skipped and NOT deleted. Its
		// contents are unknown, so the host cannot be declared clean.
		out.err = err
		return out
	}

	clean := true
	for _, entry := range inRemovalOrder(entries) {
		res, err := reapEntry(entry, runID, rm, w)
		if err != nil {
			out.failures = append(out.failures, ReapFailure{Entry: entry, Err: err})
			clean = false
			continue
		}
		switch res {
		case outcomeRemoved:
			report.Removed = append(report.Removed, entry)
		case outcomeAlreadyGone:
			report.AlreadyGone = append(report.AlreadyGone, entry)
		case outcomeNotOurs:
			report.NotOurs = append(report.NotOurs, entry)
		case outcomeDirLeft:
			// Not a failure -- but the ledger stays, so a later run retries.
			report.DirsLeft = append(report.DirsLeft, entry)
			clean = false
		}
	}

	if !clean {
		fmt.Fprintf(w, "reap: keeping %s; some recorded state is still on the host\n", path)
		return out
	}
	if err := sd.root.Remove(name); err != nil {
		out.failures = append(out.failures, ReapFailure{
			Entry: Entry{Kind: "ledger", Value: path},
			Err:   err,
		})
		return out
	}
	report.LedgersProcessed = append(report.LedgersProcessed, path)
	return out
}

// ReapOwn removes what THIS run recorded and has not already cleaned up,
// against its own still-locked ledger.
//
// It exists because of a defect measured on real hardware (a privileged CI
// runner, 2026-09-01)
// that no amount of local reasoning had surfaced: a suite can PASS and still
// leak. TestLoopDeviceCleanup left /dev/loop1 attached while `go test` reported
// ok, and the run then discarded its ledger on the strength of the exit code --
// destroying the only record of the device it had just leaked. The next run
// reaped a ledger describing nothing and honestly reported "already gone" while
// the device sat there.
//
// So an exit code is not evidence that the host is clean. The record is checked
// against the host instead: the run removes anything it recorded that is still
// present, and only a ledger with nothing left outstanding may be discarded.
//
// There is no liveness check here, and there must not be: the caller IS the
// owner and holds the lock, so TryLock would refuse its own ledger.
func ReapOwn(ledger *Ledger, rm Remover, w io.Writer) (Report, error) {
	var report Report

	entries, err := ledger.entries()
	if err != nil {
		return report, err
	}

	var failures []ReapFailure
	// Holder-first, for the same reason the cross-run reaper needs it: the
	// ledger's write order is the reverse of the removal order, so a run that
	// leaked a dm mapping AND its loop backing would try to detach a device its
	// own mapping still holds. Missing it here while fixing it in Reap was the
	// same defect in the sibling function.
	for _, entry := range inRemovalOrder(entries) {
		out, err := reapEntry(entry, ledger.runID, rm, w)
		if err != nil {
			failures = append(failures, ReapFailure{Entry: entry, Err: err})
			continue
		}
		switch out {
		case outcomeRemoved:
			report.Removed = append(report.Removed, entry)
		case outcomeAlreadyGone:
			report.AlreadyGone = append(report.AlreadyGone, entry)
		case outcomeNotOurs:
			report.NotOurs = append(report.NotOurs, entry)
		}
	}

	if len(report.Removed) > 0 {
		fmt.Fprintf(w, "suite: removed %d resource(s) this run recorded and left behind\n", len(report.Removed))
	}
	if len(failures) > 0 {
		return report, &ReapError{Failures: failures}
	}
	return report, nil
}

// LoopDevice is a loop device together with everything observed about it WHEN
// IT WAS ENUMERATED.
//
// The parts travel together on purpose. The backing path is what made the
// device ours; the identity is what the detach re-validates against. Splitting
// them and re-reading either one later would hand the check whatever the device
// is bound to now, which is exactly what a reassignment changes.
//
// Ownership and identity are deliberately answered by two different sources.
// Only sysfs can say "backed by a file under the root this run recorded", and
// only the ioctl can be re-asked through the same descriptor the detach uses.
// So sysfs decides whether the device is ours, once, and the identity carries
// that decision forward onto the file descriptor.
type LoopDevice struct {
	Path    string // /dev/loopN
	Backing string // what it was backed by when enumerated

	// Identity is the kernel's own name for the binding at enumeration time --
	// the backing file's device and inode, not its path. Only meaningful when
	// IdentityKnown; see loopIdentity for why the path is unfit for this.
	Identity loopIdentity

	// IdentityKnown reports whether Identity was actually captured.
	//
	// It is a separate field rather than a zero-value convention because the
	// zero identity is indistinguishable from a real one that failed to read,
	// and those two must not be confused: a device whose identity is unknown is
	// REFUSED by the detach, not detached on the enumeration's word. Converting
	// "I could not verify this" into a destructive action is the defect this
	// field exists to make impossible to write by accident.
	IdentityKnown bool

	// IdentityErr is why the capture failed, carried so the refusal can say
	// what went wrong instead of just that something did.
	IdentityErr error
}

// String keeps the device readable when a report formats a list of them: the
// path and what it was backed by are the two facts a reader needs, and the
// identity is a pair of numbers that means nothing without a kernel to ask.
func (d LoopDevice) String() string {
	return fmt.Sprintf("%s (backing %q)", d.Path, d.Backing)
}

type outcome int

const (
	outcomeRemoved outcome = iota
	outcomeAlreadyGone
	outcomeNotOurs

	// outcomeDirLeft: the devices are gone, the directory is not. The ledger is
	// kept so a later run retries, but the reap does not fail -- see
	// reapLoopRoot for why a directory must not be treated like a device.
	outcomeDirLeft
)

// reapEntry removes one recorded resource. runID is the run whose ledger
// recorded it.
func reapEntry(entry Entry, runID string, rm Remover, w io.Writer) (outcome, error) {
	switch entry.Kind {
	case KindMapping:
		return reapMapping(entry, rm, w)
	case KindLoopBacking:
		return reapLoop(entry, rm, w)
	case KindLoopRoot:
		return reapLoopRoot(entry, runID, rm, w)
	default:
		return outcomeNotOurs, fmt.Errorf("unknown record kind %q", entry.Kind)
	}
}

// reapMapping removes a dm target only where the live one is the one recorded.
//
// The identity check is the difference between this and a name sweep. dm names
// are a flat, host-wide namespace, so between the record and this reap another
// process can have removed our mapping and created its own under the same name.
// Removing "the target called test-mount" would then destroy a stranger's
// device on the strength of a name we happen to also use.
func reapMapping(entry Entry, rm Remover, w io.Writer) (outcome, error) {
	uuid, present, err := rm.MappingIdentity(entry.Value)
	if err != nil {
		return outcomeNotOurs, err
	}
	if !present {
		return outcomeAlreadyGone, nil
	}

	if entry.Identity == "" || uuid != entry.Identity {
		fmt.Fprintf(w, "reap: LEAVING dm %q alone: it carries uuid %q, not the recorded %q\n",
			entry.Value, uuid, entry.Identity)
		return outcomeNotOurs, nil
	}

	if err := rm.RemoveMapping(entry.Value); err != nil {
		return outcomeNotOurs, err
	}

	// Removal is confirmed rather than assumed. A remove that returns nil and
	// leaves the target live would otherwise be reported as a successful reap,
	// and the next run would fail on the guard with this one claiming success.
	//
	// A verification that ERRORS is a failure, not a pass. It is the difference
	// between "the mapping is gone" and "I could not find out", and treating
	// the second as the first is a check that reports clean precisely when it
	// cannot see -- which then lets the ledger be deleted, destroying the only
	// record of state nobody has confirmed is gone.
	stillThere, err := confirmMappingGone(rm, entry.Value)
	if err != nil {
		return outcomeNotOurs, fmt.Errorf("removed dm %q but could not confirm it is gone: %w", entry.Value, err)
	}
	if stillThere {
		return outcomeNotOurs, fmt.Errorf("dm %q is still present after removal returned no error", entry.Value)
	}

	fmt.Fprintf(w, "reap: removed dm %q (uuid %q)\n", entry.Value, entry.Identity)
	return outcomeRemoved, nil
}

// reapLoop releases every loop device still backed by the recorded file.
//
// The path is what was recorded before the device existed, and the kernel is
// what says which device carries it -- so ownership here is by record AND
// observation, never by device number. The kernel keeps reporting the path
// after the file itself is gone, marked "(deleted)", which is what makes this
// work at all for a container that has since been torn down.
func reapLoop(entry Entry, rm Remover, w io.Writer) (outcome, error) {
	devices, err := rm.LoopDevicesFor(entry.Value)
	if err != nil {
		return outcomeNotOurs, err
	}
	if len(devices) == 0 {
		return outcomeAlreadyGone, nil
	}

	for _, d := range devices {
		if err := rm.DetachLoop(d); err != nil {
			return outcomeNotOurs, fmt.Errorf("detaching %s (backing %s): %w", d.Path, entry.Value, err)
		}
		fmt.Fprintf(w, "reap: detached loop %s (backing %q)\n", d.Path, entry.Value)
	}

	remaining, err := waitForNoDevices(func() ([]LoopDevice, error) {
		return rm.LoopDevicesFor(entry.Value)
	})
	if err != nil {
		return outcomeNotOurs, fmt.Errorf("detached the loop device(s) backing %q but could not confirm they are gone: %w",
			entry.Value, err)
	}
	if len(remaining) > 0 {
		return outcomeNotOurs, fmt.Errorf("loop device(s) %v still back %q %s after detach returned no error",
			remaining, entry.Value, detachSettleTimeout)
	}

	return outcomeRemoved, nil
}

// detachSettleTimeout bounds how long a detach is given to become observable in
// sysfs, and detachSettlePoll is how often that is re-checked.
//
// A successful LOOP_CLR_FD is not necessarily visible immediately: the kernel
// finishes the release asynchronously, and loopdev.go's DetachLoopDevice waits
// for this exact race with a measurement behind it (~0.5ms on an idle host,
// generous bound because CI runners are not idle). Re-querying instantly here
// would turn a successful cleanup into ErrReapIncomplete and fail the NEXT
// integration run over a device that was already on its way out.
//
// Reaching the bound therefore means something still HOLDS the device, not that
// the host is slow -- which is why it is reported rather than waited out
// further.
var (
	detachSettleTimeout = 10 * time.Second
	detachSettlePoll    = 50 * time.Millisecond
)

// waitForNoDevices polls until the query returns nothing or the bound expires,
// and returns whatever it saw last.
func waitForNoDevices(query func() ([]LoopDevice, error)) ([]LoopDevice, error) {
	deadline := waitClock.Now().Add(detachSettleTimeout)
	for {
		devices, err := query()
		if err != nil || len(devices) == 0 {
			return devices, err
		}
		if waitClock.Now().After(deadline) {
			return devices, nil
		}
		waitClock.Sleep(detachSettlePoll)
	}
}

// reapLoopRoot releases every loop device backed by a file under a directory
// this suite created.
//
// The prefix is not a heuristic. The recorded value is a directory made by
// os.MkdirTemp for one run, so a backing file underneath it was put there by
// that run and by nothing else. What the kernel supplies is which device
// carries it -- observation again, against a path recorded first.
//
// THE NAME MUST CARRY THE RUN'S ID (#247). Each container has its own /tmp,
// and the kernel reports a backing file by the path its container saw, so two
// containers' run roots are told apart by NAME alone. MkdirTemp's suffix is 32
// random bits, so a dead run's root and a live sibling's could share a name,
// and reaping the dead one would detach the live one's devices. BeginSuite now
// names the root go-luks2-run-<run id>-<n>, and a root is reaped only for the
// run whose ledger carries that id. A root that is not (an older ledger, or a
// damaged one) with devices under it is left alone and fails the reap; with
// none, the record is consumed and the directory, which may be someone
// else's, is left where it is.
func reapLoopRoot(entry Entry, runID string, rm Remover, w io.Writer) (outcome, error) {
	devices, err := rm.LoopDevicesUnder(entry.Value)
	if err != nil {
		return outcomeNotOurs, err
	}

	if !rootBelongsToRun(entry.Value, runID) {
		if len(devices) > 0 {
			return outcomeNotOurs, &UnboundRunRootError{Root: entry.Value, RunID: runID, Devices: devices}
		}
		fmt.Fprintf(w, "reap: %q is not named for run %s, so it may be another run's; nothing is backed under "+
			"it -- consuming the record and leaving the directory alone\n", entry.Value, runID)
		return outcomeAlreadyGone, nil
	}

	// NO DEVICES DOES NOT MEAN NOTHING TO DO. An early return here left a dead
	// run's temp root -- and the disk images in it -- on the runner whenever
	// its loop devices had already been released, which is the ordinary way a
	// killed run looks once the kernel has autocleared. The devices were the
	// urgent half; the directory is the half that accumulates.
	for _, d := range devices {
		// The expectation is the backing observed during ENUMERATION -- what
		// made this device ours -- not a value re-read now. The root is what
		// establishes ownership; the observed path is what identifies THIS
		// device, and a re-read would simply report the reassignment and agree
		// with it.
		if err := rm.DetachLoop(d); err != nil {
			return outcomeNotOurs, fmt.Errorf("detaching %s (backed under %s): %w", d.Path, entry.Value, err)
		}
		fmt.Fprintf(w, "reap: detached loop %s (backed under %q)\n", d.Path, entry.Value)
	}

	remaining, err := waitForNoDevices(func() ([]LoopDevice, error) {
		if len(devices) == 0 {
			return nil, nil
		}
		return rm.LoopDevicesUnder(entry.Value)
	})
	if err != nil {
		return outcomeNotOurs, fmt.Errorf("detached the loop device(s) under %q but could not confirm they are gone: %w",
			entry.Value, err)
	}
	if len(remaining) > 0 {
		return outcomeNotOurs, fmt.Errorf("loop device(s) %v are still backed under %q %s after detach returned no error",
			remaining, entry.Value, detachSettleTimeout)
	}

	// The DIRECTORY goes too, and only now that nothing is backed by anything
	// inside it. A killed run's temp root holds the disk images its tests
	// created -- tens of megabytes each -- and detaching the devices while
	// leaving the files behind fills the runner one dead run at a time. The
	// devices were the urgent half; this is the half that accumulates.
	// A DIRECTORY THAT WILL NOT DIE MUST NOT POISON THE RUNNER.
	//
	// This is deliberately NOT fatal, and the asymmetry with the device paths
	// above is the whole point. A device left behind is invisible to attribution
	// and blocks the #85 guard, so failing to remove one means the host is not
	// safe and the run must refuse. A directory is disk: the guard never looks
	// at it, no other run trips over it, and the only cost is space.
	//
	// Treating them the same latches. Trace it: an immutable file or a busy
	// mount makes RemoveDir fail permanently; a fatal return keeps the ledger
	// "so the next run can finish the job"; the next run reads the same ledger,
	// fails on the same directory, keeps it again -- and the entrypoint refuses
	// every integration job on that host from then on. That is precisely the
	// runner-poisoning this package exists to remove, reintroduced by the
	// cleanup that removes it, and it is the same shape as the unbound-loop
	// refusal that actually did poison a runner for hours, until a human cleared
	// it by hand.
	//
	// So: report it, KEEP the ledger so a later run retries, and let the run
	// proceed. The record survives, the operator is told, and nothing is
	// blocked on a condition that endangers nothing.
	dirLeft := false
	if err := rm.RemoveDir(entry.Value); err != nil {
		fmt.Fprintf(w, "reap: WARNING: every loop device under %q is gone, but the directory could not be "+
			"removed: %v -- keeping the record so a later run retries; this is disk, not a device, so it "+
			"does not block\n", entry.Value, err)
		dirLeft = true
	}

	switch {
	case dirLeft:
		return outcomeDirLeft, nil
	case len(devices) == 0:
		return outcomeAlreadyGone, nil
	default:
		return outcomeRemoved, nil
	}
}

// confirmMappingGone reports whether the mapping is still present, and errors
// when it cannot tell. The three-way answer is the point: "present", "absent"
// and "unknown" are different, and only the second permits the ledger entry to
// be discarded.
func confirmMappingGone(rm Remover, name string) (stillThere bool, err error) {
	_, present, err := rm.MappingIdentity(name)
	if err != nil {
		return false, err
	}
	return present, nil
}

// inRemovalOrder returns entries with HOLDERS before the things they hold: dm
// mappings first, then the loop devices underneath them.
//
// The ledger's write order is the opposite, and not by accident. BeginSuite
// records the run's loop root before a single test runs -- that is what makes
// the record precede the resource -- while dm mappings are recorded later, as
// each test creates one. So a killed run that left a LUKS mapping stacked on a
// loop device produces a ledger whose loop entry comes first.
//
// Reaping in that order tries to detach a loop device while a dm target is
// still sitting on it. The kernel defers the release, the verification a moment
// later still sees the device, and the reaper reports ErrReapIncomplete for
// state it is perfectly capable of removing -- the entrypoint then exits
// non-zero and the stale run needs a second pass to clear. Removing the holder
// first makes one pass enough.
//
// The sort is stable, so entries of the same kind keep their ledger order.
func inRemovalOrder(entries []Entry) []Entry {
	ordered := make([]Entry, len(entries))
	copy(ordered, entries)
	sort.SliceStable(ordered, func(i, j int) bool {
		return removalRank(ordered[i].Kind) < removalRank(ordered[j].Kind)
	})
	return ordered
}

// removalRank orders kinds by what holds what. A dm mapping can hold a loop
// device open; nothing this package records holds a dm mapping.
func removalRank(k Kind) int {
	if k == KindMapping {
		return 0
	}
	return 1
}

// reaperLockName is the file the host-wide reaper mutex lives on. It is not a
// ledger, and staleLedgers ignores it: it carries no .ledger suffix.
const reaperLockName = ".reap.lock"

// reaperLockTimeoutForTest bounds the wait for another reaper. It is a var so
// the timeout path itself can be tested; nothing outside tests reassigns it.
//
// It is generous because the thing being waited for is a full reap of a
// poisoned host, not a fast path, and because giving up early is the failure
// this exists to avoid -- a reaper that times out and proceeds is a reaper that
// runs on a host in an unknown state. Reaching the bound means something is
// wedged, which is reported rather than assumed away.
var reaperLockTimeoutForTest = 5 * time.Minute

// rootBelongsToRun reports whether root is named the way BeginSuite names
// runID's run root: go-luks2-run-<run id>-<decimal MkdirTemp suffix>.
func rootBelongsToRun(root, runID string) bool {
	if runID == "" {
		return false
	}
	rest, ok := strings.CutPrefix(filepath.Base(filepath.Clean(root)), runRootPrefix+runID+"-")
	return ok && rest != "" && strings.Trim(rest, "0123456789") == ""
}

// lockReaper validates and opens the state directory, then takes the host-wide
// reaper mutex in it, waiting for any other reaper. The returned function
// releases the mutex and closes the directory.
func lockReaper(dir string) (*trustedDir, func(), error) {
	// Validated here too, not only in OpenLedger: this is the privileged side,
	// it runs before the #85 guard, and it acts on whatever the ledgers say.
	sd, err := openTrustedStateDir(dir)
	if err != nil {
		return nil, nil, err
	}

	path := filepath.Join(dir, reaperLockName)
	f, err := sd.root.OpenFile(reaperLockName, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		_ = sd.Close()
		return nil, nil, &LockFileError{Action: "opening", Path: path, Err: err}
	}

	deadline := waitClock.Now().Add(reaperLockTimeoutForTest)
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return sd, func() {
				_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
				_ = f.Close()
				_ = sd.Close()
			}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			_ = f.Close()
			_ = sd.Close()
			return nil, nil, &LockFileError{Action: "locking", Path: path, Err: err}
		}
		if waitClock.Now().After(deadline) {
			_ = f.Close()
			_ = sd.Close()
			return nil, nil, &ReaperBusyError{Path: path, Waited: reaperLockTimeoutForTest}
		}
		waitClock.Sleep(reaperLockPoll)
	}
}

// reaperLockPoll is how often the wait for another reaper is retried. flock's
// blocking mode would avoid the poll but cannot be bounded, and an unbounded
// wait here would hang a CI job rather than fail it.
var reaperLockPoll = 200 * time.Millisecond

// staleLedgers lists, by name, the ledgers in the validated state directory
// belonging to runs other than selfRunID, oldest first so output reads
// chronologically. It reads the directory through its handle.
func staleLedgers(sd *trustedDir, selfRunID string) ([]string, error) {
	f, err := sd.root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := f.ReadDir(-1)
	_ = f.Close()
	if err != nil {
		return nil, err
	}

	self := selfRunID + ledgerSuffix
	var paths []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ledgerSuffix {
			continue
		}
		if e.Name() == self {
			continue
		}
		paths = append(paths, e.Name())
	}
	sort.Strings(paths)
	return paths, nil
}
