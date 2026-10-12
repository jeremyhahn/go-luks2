// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !integration

package loop

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/clock"
	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// The waiting logic is exercised here without a loop device; the
// kernel-facing path is covered by the integration suite in test/integration/loop,
// which drives a real detach. Both halves are needed:
// a seam only ever met through a double proves nothing about the plane it
// stands in for, and a test that needs root proves nothing on a developer's
// machine.

const (
	testDetachTimeout = 20 * time.Millisecond
	testDetachPoll    = 200 * time.Microsecond
)

func attachedTo(path string) loopState { return loopState{backing: path} }

func reader(states ...loopState) loopStateReader {
	i := 0
	return func(string) (loopState, error) {
		st := states[min(i, len(states)-1)]
		i++
		return st, nil
	}
}

func failingReader(err error) loopStateReader {
	return func(string) (loopState, error) { return loopState{}, err }
}

// TestWaitForDetachReturnsOnceTheAssociationIsGone is the property the fix
// exists for: LOOP_CLR_FD can report success before the kernel has released
// the device, so the wait must keep looking until sysfs agrees rather than
// returning on the syscall's word.
func TestWaitForDetachReturnsOnceTheAssociationIsGone(t *testing.T) {
	calls := 0
	backing := func(string) (loopState, error) {
		calls++
		if calls < 4 {
			return attachedTo("/tmp/volume.img"), nil // still held, as the kernel briefly reports
		}
		return loopState{}, nil // released
	}

	state, err := waitForDetach(context.Background(), "/dev/loop0", attachedTo("/tmp/volume.img"), true, testDetachTimeout, testDetachPoll, backing, clock.NewFake(t))
	if err != nil {
		t.Fatalf("waitForDetach returned error: %v", err)
	}
	if state != Released {
		t.Errorf("state = %v, want Released", state)
	}
	if calls < 4 {
		t.Errorf("returned after %d checks; it cannot have observed the release", calls)
	}
}

// TestWaitForDetachAcceptsADeviceReattachedElsewhere guards a flake the fix
// would otherwise INTRODUCE. The loop-device namespace is host-global: once
// our detach completes the device is free, and another process can claim it
// before the next poll. A wait that looked for the backing file to merely
// become unreadable would sit watching someone else's attachment until it
// timed out -- reporting failure for a detach that succeeded, most often
// exactly when the machine is busy.
func TestWaitForDetachAcceptsADeviceReattachedElsewhere(t *testing.T) {
	backing := reader(attachedTo("/tmp/somebody-elses.img"))

	if _, err := waitForDetach(context.Background(), "/dev/loop0", attachedTo("/tmp/volume.img"), true, testDetachTimeout, testDetachPoll, backing, clock.NewFake(t)); err != nil {
		t.Fatalf("waitForDetach reported a failure for a device that was released and reclaimed: %v", err)
	}
}

// TestWaitForDetachReportsADeferredReleaseAsSuccess covers the case that
// made the first version of this wait a BREAKING change, and it is also
// what holds the line against a change that has now been proposed twice.
//
// When something else still holds the device -- a mounted filesystem, a
// dm-crypt mapping -- LOOP_CLR_FD sets the autoclear flag and returns 0. The
// kernel has accepted the request and will complete it when the last user
// goes away; this is what `losetup -d` does on a busy device. Waiting out
// the full timeout and then reporting failure would tell a caller their
// detach did not work when it did.
func TestWaitForDetachReportsADeferredReleaseAsSuccess(t *testing.T) {
	deferred := loopState{backing: "/tmp/volume.img", autoclear: true}

	clk := clock.NewFake(t)
	state, err := waitForDetach(context.Background(), "/dev/loop0", attachedTo("/tmp/volume.img"), true, testDetachTimeout, testDetachPoll, reader(deferred), clk)

	if err != nil {
		t.Fatalf("a deferred release was reported as a failure: %v", err)
	}
	if state != Deferred {
		t.Errorf("state = %v, want Deferred", state)
	}

	// And it does NOT exit early on seeing autoclear. An earlier version
	// did, and the consequence showed up in CI: a device held only
	// momentarily was reported as deferred, and a caller that immediately
	// asked whether the association was gone was told it was not. Waiting
	// turns most of those into observed releases; only a device still held
	// at the bound comes back deferred. On a controlled clock (go-luks2
	// #233) the wait is exact: past the bound, by no more than one poll.
	if elapsed := clk.Elapsed(); elapsed <= testDetachTimeout || elapsed > testDetachTimeout+testDetachPoll {
		t.Errorf("returned after %s; want just past the %s bound -- a momentary holder would "+
			"be reported as deferred rather than waited out", elapsed, testDetachTimeout)
	}
}

// TestWaitForDetachOutlastsAMomentaryHolder is the case the CI failure was,
// and the reason deferred stopped being an early exit.
//
// The device is held with autoclear set for the first few polls and then
// released -- a neighboring process letting go, a udev settle finishing, a
// dm teardown completing. The wait must come back Released, because it saw
// the release, rather than Deferred, which would tell a caller the device
// might still be attached when it demonstrably is not.
func TestWaitForDetachOutlastsAMomentaryHolder(t *testing.T) {
	calls := 0
	backing := func(string) (loopState, error) {
		calls++
		if calls < 4 {
			return loopState{backing: "/tmp/volume.img", autoclear: true}, nil
		}
		return loopState{}, nil // the holder let go
	}

	state, err := waitForDetach(context.Background(), "/dev/loop0", attachedTo("/tmp/volume.img"), true, testDetachTimeout, testDetachPoll, backing, clock.NewFake(t))
	if err != nil {
		t.Fatalf("waitForDetach returned error: %v", err)
	}
	if state != Released {
		t.Errorf("state = %v, want Released -- the release was observed, so reporting "+
			"it as deferred would understate what is known", state)
	}
}

// TestWaitForDetachTimesOutWithATypedError covers the bound. Reaching it
// means something still holds the device open without autoclear set -- not
// that the detach failed, and not that the host is slow -- so it is its own
// condition.
func TestWaitForDetachTimesOutWithATypedError(t *testing.T) {
	backing := reader(attachedTo("/tmp/volume.img")) // never released, never deferred

	clk := clock.NewFake(t)
	_, err := waitForDetach(context.Background(), "/dev/loop0", attachedTo("/tmp/volume.img"), true, testDetachTimeout, testDetachPoll, backing, clk)

	if err == nil {
		t.Fatal("waitForDetach returned no error for a device that was never released")
	}
	if !errors.Is(err, ErrDetachIncomplete) {
		t.Errorf("error = %v, want it to wrap ErrDetachIncomplete", err)
	}

	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("error %v is not a *Error", err)
	}
	if !strings.Contains(e.Detail, "/dev/loop0") {
		t.Errorf("Error.Detail = %q, want it to name %q", e.Detail, "/dev/loop0")
	}

	// The wait waited out its bound and no further: just past it, by at
	// most one poll, on a clock only the wait moves (go-luks2 #233).
	if elapsed := clk.Elapsed(); elapsed <= testDetachTimeout || elapsed > testDetachTimeout+testDetachPoll {
		t.Errorf("gave up after %s, want just past the %s bound", elapsed, testDetachTimeout)
	}
}

// TestWaitForDetachDoesNothingWhenNothingWasAttached checks the short
// circuit by observing that sysfs is never consulted: a device with no
// backing file has nothing to wait for.
func TestWaitForDetachDoesNothingWhenNothingWasAttached(t *testing.T) {
	consulted := false
	backing := func(string) (loopState, error) {
		consulted = true
		return loopState{}, nil
	}

	if _, err := waitForDetach(context.Background(), "/dev/loop0", loopState{}, true, testDetachTimeout, testDetachPoll, backing, clock.NewFake(t)); err != nil {
		t.Fatalf("waitForDetach returned error: %v", err)
	}
	if consulted {
		t.Error("waitForDetach polled sysfs for a device that was not attached")
	}
}

// TestWaitForDetachRecoversWhenTheReadStartsWorking checks a read failure is
// treated as transient rather than fatal: a read that fails and then
// succeeds must still end in success, or every momentary sysfs hiccup
// becomes a spurious detach failure. Retrying is what makes fail-closed
// affordable.
func TestWaitForDetachRecoversWhenTheReadStartsWorking(t *testing.T) {
	calls := 0
	backing := func(string) (loopState, error) {
		calls++
		if calls < 3 {
			return loopState{}, errors.New("sysfs unavailable")
		}
		return loopState{}, nil // readable again, and authoritatively detached
	}

	if _, err := waitForDetach(context.Background(), "/dev/loop0", attachedTo("/tmp/volume.img"), true, testDetachTimeout, testDetachPoll, backing, clock.NewFake(t)); err != nil {
		t.Fatalf("waitForDetach gave up on a transient read failure: %v", err)
	}
}

// TestWaitForDetachNeverSucceedsWithoutAnAuthoritativeObservation states the
// guarantee as one property instead of as a list of cases, and asserts it
// in the direction that cannot be satisfied by accident: for every reader
// that never produces an authoritative released-or-deferred reading, the
// wait must NOT report success.
func TestWaitForDetachNeverSucceedsWithoutAnAuthoritativeObservation(t *testing.T) {
	t.Parallel()

	unreadable := failingReader(errors.New("sysfs unavailable"))
	stillHeld := reader(attachedTo("/tmp/volume.img"))
	heldByAnother := reader(attachedTo("/tmp/other.img"))

	tests := []struct {
		name        string
		before      loopState
		knownBefore bool
		read        loopStateReader
	}{
		{"unreadable throughout, baseline known", attachedTo("/tmp/volume.img"), true, unreadable},
		{"still held throughout", attachedTo("/tmp/volume.img"), true, stillHeld},
		{"unreadable before the detach and after it", loopState{}, false, unreadable},
		{"no baseline, and the device is attached to something", loopState{}, false, heldByAnother},
		{"no baseline, and it is attached to what we were watching", loopState{}, false, stillHeld},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := waitForDetach(context.Background(), "/dev/loop0", tt.before, tt.knownBefore, testDetachTimeout, testDetachPoll, tt.read, clock.NewFake(t))
			if err == nil {
				t.Fatal("waitForDetach reported a release it never observed")
			}
			if !errors.Is(err, ErrDetachIncomplete) {
				t.Errorf("error = %v, want it to wrap ErrDetachIncomplete", err)
			}
		})
	}
}

// TestWaitForDetachSucceedsOnlyOnAnAuthoritativeObservation is the mirror.
// Without it the property above would also pass against a wait that never
// returned success at all.
func TestWaitForDetachSucceedsOnlyOnAnAuthoritativeObservation(t *testing.T) {
	tests := []struct {
		name        string
		before      loopState
		knownBefore bool
		read        loopStateReader
		want        DetachState
	}{
		{"released, baseline known", attachedTo("/tmp/volume.img"), true, reader(loopState{}), Released},
		{"reclaimed by another process", attachedTo("/tmp/volume.img"), true, reader(attachedTo("/tmp/other.img")), Released},
		{"released, no baseline", loopState{}, false, reader(loopState{}), Released},
		{"deferred by the kernel", attachedTo("/tmp/volume.img"), true,
			reader(loopState{backing: "/tmp/volume.img", autoclear: true}), Deferred},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, err := waitForDetach(context.Background(), "/dev/loop0", tt.before, tt.knownBefore, testDetachTimeout, testDetachPoll, tt.read, clock.NewFake(t))
			if err != nil {
				t.Fatalf("waitForDetach returned error: %v", err)
			}
			if state != tt.want {
				t.Errorf("state = %v, want %v", state, tt.want)
			}
		})
	}
}

// TestDetachTimeoutCauseUsesTheDominantObservation pins the classification,
// and it is asserted on a wait that was MOSTLY blind but read cleanly at
// the end -- the shape that inverts a last-sample classifier.
//
// The two causes exist to route an operator differently: a device held by
// something else is a process to find, an unreadable sysfs is a host to
// fix. Blaming a holder that does not exist, because the final poll
// happened to succeed, sends them hunting for nothing.
func TestDetachTimeoutCauseUsesTheDominantObservation(t *testing.T) {
	readFailure := errors.New("sysfs unavailable")

	mostlyBlind := detachTimeoutCause(attachedTo("/tmp/volume.img"), true, time.Second, 9, 1, readFailure)
	if !errors.Is(mostlyBlind, readFailure) {
		t.Errorf("a wait that was blind for 9 of 10 checks reported %v, want the read failure", mostlyBlind)
	}

	mostlyHeld := detachTimeoutCause(attachedTo("/tmp/volume.img"), true, time.Second, 1, 9, readFailure)
	if errors.Is(mostlyHeld, readFailure) {
		t.Errorf("a wait that saw the device held for 9 of 10 checks blamed an unreadable host: %v", mostlyHeld)
	}
	if !errors.Is(mostlyHeld, ErrDetachIncomplete) {
		t.Errorf("error = %v, want it to wrap ErrDetachIncomplete", mostlyHeld)
	}
}

// TestWaitForDetachStopsOnceContextIsCancelled is the cancellation
// requirement (a wait gives up once ctx is done), the detach-side twin of
// TestWaitForLoopNodeStopsOnceContextIsCancelled.
func TestWaitForDetachStopsOnceContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clk := clock.NewFake(t)
	clk.OnWait(func(time.Time) { cancel() })

	_, err := waitForDetach(ctx, "/dev/loop0", attachedTo("/tmp/volume.img"), true, testDetachTimeout, testDetachPoll, reader(attachedTo("/tmp/volume.img")), clk)
	if err == nil {
		t.Fatal("waitForDetach() after cancellation = nil, want an error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) = false for %v", err)
	}
}

// TestDetachDeviceRefusesAnAlreadyCancelledContext pins the ctx-first
// boundary check every exported function makes.
func TestDetachDeviceRefusesAnAlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := detachDevice(ctx, "/dev/loop0", backingIdentity{}, detachSys(t, nil, nil), reader(loopState{})); !errors.Is(err, context.Canceled) {
		t.Errorf("detachDevice() with a canceled context = %v, want context.Canceled", err)
	}
}

// detachSys is a sys whose loop device is a temporary file, whose
// LOOP_GET_STATUS64 answers identity, and whose LOOP_CLR_FD only counts
// itself into cleared.
func detachSys(t *testing.T, identity func(*os.File) (uint64, uint64, error), cleared *int) sys {
	t.Helper()
	node := filepath.Join(t.TempDir(), "loop0")
	if err := os.WriteFile(node, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := defaultSys()
	s.clk = clock.NewFake(t)
	s.detachTimeout, s.detachPoll = testDetachTimeout, testDetachPoll
	s.openFile = func(string, int, os.FileMode) (*os.File, error) { return os.OpenFile(node, os.O_RDWR, 0) } // #nosec G304 -- a test fixture under t.TempDir()
	s.fdBackingIdentity = identity
	s.clearFD = func(*os.File) error {
		*cleared++
		return nil
	}
	return s
}

// TestDetachRefusesADeviceNoLongerBackedByItsFile is the reassignment race:
// between obtaining a Device and detaching it, the loop device was released
// and attached to someone else's file. Detach must refuse BEFORE LOOP_CLR_FD.
func TestDetachRefusesADeviceNoLongerBackedByItsFile(t *testing.T) {
	ours := backingIdentity{dev: 2049, ino: 12, known: true}
	tests := []struct {
		name     string
		want     backingIdentity
		identity func(*os.File) (uint64, uint64, error)
		kind     error
	}{
		{
			name:     "another file's inode",
			want:     ours,
			identity: func(*os.File) (uint64, uint64, error) { return 2049, 13, nil },
			kind:     ErrDeviceReassigned,
		},
		{
			name:     "another filesystem's device",
			want:     ours,
			identity: func(*os.File) (uint64, uint64, error) { return 2050, 12, nil },
			kind:     ErrDeviceReassigned,
		},
		{
			name:     "looked up unattached, attached since",
			want:     backingIdentity{},
			identity: func(*os.File) (uint64, uint64, error) { return 2049, 12, nil },
			kind:     ErrDeviceReassigned,
		},
		{
			name:     "nothing attached any more",
			want:     ours,
			identity: func(*os.File) (uint64, uint64, error) { return 0, 0, unix.ENXIO },
			kind:     errs.ErrIO,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleared := 0
			s := detachSys(t, tt.identity, &cleared)
			_, err := detachDevice(context.Background(), "/dev/loop0", tt.want, s, reader(attachedTo("/img")))
			if !errors.Is(err, tt.kind) {
				t.Errorf("detachDevice() = %v, want errors.Is(_, %v)", err, tt.kind)
			}
			if cleared != 0 {
				t.Errorf("LOOP_CLR_FD sent %d time(s), want none", cleared)
			}
		})
	}

	// The control: the same file, and the device is cleared.
	cleared := 0
	s := detachSys(t, func(*os.File) (uint64, uint64, error) { return ours.dev, ours.ino, nil }, &cleared)
	state, err := detachDevice(context.Background(), "/dev/loop0", ours, s, reader(attachedTo("/img"), loopState{}))
	if err != nil || state != Released {
		t.Fatalf("detachDevice() = %v, %v; want Released, nil", state, err)
	}
	if cleared != 1 {
		t.Errorf("LOOP_CLR_FD sent %d time(s), want 1", cleared)
	}
}
