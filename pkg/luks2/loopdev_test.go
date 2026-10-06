// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/internal/clock"
	"golang.org/x/sys/unix"
)

// The waiting logic is exercised here without a loop device; the kernel-facing
// path is covered by the integration suite, which drives a real detach. Both
// halves are needed: a seam only ever met through a double proves nothing about
// the plane it stands in for, and a test that needs root proves nothing on a
// developer's machine.

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
// exists for: LOOP_CLR_FD can report success before the kernel has released the
// device, so the wait must keep looking until sysfs agrees rather than
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

	state, err := waitForDetach("/dev/loop0", attachedTo("/tmp/volume.img"), true, testDetachTimeout, testDetachPoll, backing, clock.NewFake(t))
	if err != nil {
		t.Fatalf("waitForDetach returned error: %v", err)
	}
	if state != DetachReleased {
		t.Errorf("state = %v, want DetachReleased", state)
	}
	if calls < 4 {
		t.Errorf("returned after %d checks; it cannot have observed the release", calls)
	}
}

// TestWaitForDetachAcceptsADeviceReattachedElsewhere guards a flake the fix
// would otherwise INTRODUCE. The loop-device namespace is host-global: once our
// detach completes the device is free, and another process can claim it before
// the next poll. A wait that looked for the backing file to merely become
// unreadable would sit watching someone else's attachment until it timed out —
// reporting failure for a detach that succeeded, most often exactly when the
// machine is busy.
func TestWaitForDetachAcceptsADeviceReattachedElsewhere(t *testing.T) {
	backing := reader(attachedTo("/tmp/somebody-elses.img"))

	if _, err := waitForDetach("/dev/loop0", attachedTo("/tmp/volume.img"), true, testDetachTimeout, testDetachPoll, backing, clock.NewFake(t)); err != nil {
		t.Fatalf("waitForDetach reported a failure for a device that was released and reclaimed: %v", err)
	}
}

// TestWaitForDetachReportsADeferredReleaseAsSuccess covers the case that made
// the first version of this wait a BREAKING change, and it is also what holds
// the line against a change that has now been proposed twice.
//
// When something else still holds the device — a mounted filesystem, a dm-crypt
// mapping — LOOP_CLR_FD sets the autoclear flag and returns 0. The kernel has
// accepted the request and will complete it when the last user goes away; this
// is what `losetup -d` does on a busy device. Waiting out the full timeout and
// then reporting failure would tell a caller their detach did not work when it
// did.
//
// A review asked for the opposite: that DetachLoopDevice return
// ErrDetachIncomplete on a deferred release. That is stricter than this package
// has ever been — before the wait existed it returned nil whenever the ioctl
// returned 0, which includes this path — and the consumer it would break is on
// a SUCCESS path. go-xkms/xkey/pkg/luks/volume.go's Volume.Create tears down
// its dm-crypt mapping and then detaches, failing the whole creation if the
// detach errors; a dm teardown is precisely what leaves a device briefly held,
// so that call site would start reporting failure for volumes it had just
// successfully created, intermittently. That is this package's own defect class
// reintroduced one level up, in a consumer.
//
// DetachLoopDevice returns this error unchanged — its body is a single
// delegation to DetachLoopDeviceState — so nil here is nil there. That
// one-line pass-through is verified by reading rather than by a second test:
// asserting it separately would duplicate this one, which is the vacuous
// duplicate the same review series already caught once.
func TestWaitForDetachReportsADeferredReleaseAsSuccess(t *testing.T) {
	deferred := loopState{backing: "/tmp/volume.img", autoclear: true}

	clk := clock.NewFake(t)
	state, err := waitForDetach("/dev/loop0", attachedTo("/tmp/volume.img"), true, testDetachTimeout, testDetachPoll, reader(deferred), clk)

	if err != nil {
		t.Fatalf("a deferred release was reported as a failure: %v", err)
	}
	if state != DetachDeferred {
		t.Errorf("state = %v, want DetachDeferred", state)
	}

	// And it does NOT exit early on seeing autoclear. An earlier version did,
	// and the consequence showed up in CI: a device held only momentarily was
	// reported as deferred, and a caller that immediately asked whether the
	// association was gone was told it was not. Waiting turns most of those
	// into observed releases; only a device still held at the bound comes back
	// deferred. On a controlled clock (#233) the wait is exact: past the bound,
	// by no more than one poll.
	if elapsed := clk.Elapsed(); elapsed <= testDetachTimeout || elapsed > testDetachTimeout+testDetachPoll {
		t.Errorf("returned after %s; want just past the %s bound -- a momentary holder would "+
			"be reported as deferred rather than waited out", elapsed, testDetachTimeout)
	}
}

// TestWaitForDetachOutlastsAMomentaryHolder is the case the CI failure was, and
// the reason deferred stopped being an early exit.
//
// The device is held with autoclear set for the first few polls and then
// released — a neighboring process letting go, a udev settle finishing, a dm
// teardown completing. The wait must come back DetachReleased, because it saw
// the release, rather than DetachDeferred, which would tell a caller the device
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

	state, err := waitForDetach("/dev/loop0", attachedTo("/tmp/volume.img"), true, testDetachTimeout, testDetachPoll, backing, clock.NewFake(t))
	if err != nil {
		t.Fatalf("waitForDetach returned error: %v", err)
	}
	if state != DetachReleased {
		t.Errorf("state = %v, want DetachReleased — the release was observed, so reporting "+
			"it as deferred would understate what is known", state)
	}
}

// TestWaitForDetachTimesOutWithATypedError covers the bound. Reaching it means
// something still holds the device open without autoclear set — not that the
// detach failed, and not that the host is slow — so it is its own condition.
func TestWaitForDetachTimesOutWithATypedError(t *testing.T) {
	backing := reader(attachedTo("/tmp/volume.img")) // never released, never deferred

	clk := clock.NewFake(t)
	_, err := waitForDetach("/dev/loop0", attachedTo("/tmp/volume.img"), true, testDetachTimeout, testDetachPoll, backing, clk)

	if err == nil {
		t.Fatal("waitForDetach returned no error for a device that was never released")
	}
	if !errors.Is(err, ErrDetachIncomplete) {
		t.Errorf("error = %v, want it to wrap ErrDetachIncomplete", err)
	}

	var devErr *DeviceError
	if !errors.As(err, &devErr) {
		t.Fatalf("error %v is not a *DeviceError", err)
	}
	if devErr.Device != "/dev/loop0" {
		t.Errorf("DeviceError.Device = %q, want %q", devErr.Device, "/dev/loop0")
	}

	// The wait waited out its bound and no further: just past it, by at most
	// one poll, on a clock only the wait moves (#233).
	if elapsed := clk.Elapsed(); elapsed <= testDetachTimeout || elapsed > testDetachTimeout+testDetachPoll {
		t.Errorf("gave up after %s, want just past the %s bound", elapsed, testDetachTimeout)
	}
}

// TestWaitForDetachDoesNothingWhenNothingWasAttached checks the short circuit
// by observing that sysfs is never consulted: a device with no backing file has
// nothing to wait for.
func TestWaitForDetachDoesNothingWhenNothingWasAttached(t *testing.T) {
	consulted := false
	backing := func(string) (loopState, error) {
		consulted = true
		return loopState{}, nil
	}

	if _, err := waitForDetach("/dev/loop0", loopState{}, true, testDetachTimeout, testDetachPoll, backing, clock.NewFake(t)); err != nil {
		t.Fatalf("waitForDetach returned error: %v", err)
	}
	if consulted {
		t.Error("waitForDetach polled sysfs for a device that was not attached")
	}
}

// TestWaitForDetachRecoversWhenTheReadStartsWorking checks a read failure is
// treated as transient rather than fatal: a read that fails and then succeeds
// must still end in success, or every momentary sysfs hiccup becomes a spurious
// detach failure. Retrying is what makes fail-closed affordable.
func TestWaitForDetachRecoversWhenTheReadStartsWorking(t *testing.T) {
	calls := 0
	backing := func(string) (loopState, error) {
		calls++
		if calls < 3 {
			return loopState{}, errors.New("sysfs unavailable")
		}
		return loopState{}, nil // readable again, and authoritatively detached
	}

	if _, err := waitForDetach("/dev/loop0", attachedTo("/tmp/volume.img"), true, testDetachTimeout, testDetachPoll, backing, clock.NewFake(t)); err != nil {
		t.Fatalf("waitForDetach gave up on a transient read failure: %v", err)
	}
}

// TestWaitForDetachNeverSucceedsWithoutAnAuthoritativeObservation states the
// guarantee as one property instead of as a list of cases, and asserts it in
// the direction that cannot be satisfied by accident: for every reader that
// never produces an authoritative released-or-deferred reading, the wait must
// NOT report success.
//
// A test that checked "the error is such-and-such" would pass against a version
// that failed for an unrelated reason. This one fails against any version that
// reports success it did not observe — which is the whole contract, and which
// the first implementation broke in two separate places.
//
// The last case is the one most easily left out: the read failing BEFORE the
// detach and continuing to fail afterwards, so there is neither a baseline nor
// an authoritative reading at any point.
func TestWaitForDetachNeverSucceedsWithoutAnAuthoritativeObservation(t *testing.T) {
	defer parallel(t)()

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
			_, err := waitForDetach("/dev/loop0", tt.before, tt.knownBefore, testDetachTimeout, testDetachPoll, tt.read, clock.NewFake(t))
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
		{"released, baseline known", attachedTo("/tmp/volume.img"), true, reader(loopState{}), DetachReleased},
		{"reclaimed by another process", attachedTo("/tmp/volume.img"), true, reader(attachedTo("/tmp/other.img")), DetachReleased},
		{"released, no baseline", loopState{}, false, reader(loopState{}), DetachReleased},
		{"deferred by the kernel", attachedTo("/tmp/volume.img"), true,
			reader(loopState{backing: "/tmp/volume.img", autoclear: true}), DetachDeferred},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, err := waitForDetach("/dev/loop0", tt.before, tt.knownBefore, testDetachTimeout, testDetachPoll, tt.read, clock.NewFake(t))
			if err != nil {
				t.Fatalf("waitForDetach returned error: %v", err)
			}
			if state != tt.want {
				t.Errorf("state = %v, want %v", state, tt.want)
			}
		})
	}
}

// TestDetachTimeoutCauseUsesTheDominantObservation pins the classification, and
// it is asserted on a wait that was MOSTLY blind but read cleanly at the end —
// the shape that inverts a last-sample classifier.
//
// The two causes exist to route an operator differently: a device held by
// something else is a process to find, an unreadable sysfs is a host to fix.
// Blaming a holder that does not exist, because the final poll happened to
// succeed, sends them hunting for nothing.
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

// TestReadLoopStateInReportsAnAttachedDevice is the positive control for the
// reader: without it the negative tests below would also pass against a reader
// that reported an error for everything.
func TestReadLoopStateInReportsAnAttachedDevice(t *testing.T) {
	root := sysfsFixture(t, "loop0", "/tmp/volume.img\n", "0\n")

	st, err := readLoopStateIn(root, "/dev/loop0")
	if err != nil {
		t.Fatalf("readLoopStateIn returned error: %v", err)
	}
	if st.backing != "/tmp/volume.img" {
		t.Errorf("backing = %q, want %q", st.backing, "/tmp/volume.img")
	}
	if st.autoclear {
		t.Error("autoclear = true for a device whose flag reads 0")
	}
}

// TestReadLoopStateInReportsAutoclear pins the flag the deferred-release case
// depends on.
func TestReadLoopStateInReportsAutoclear(t *testing.T) {
	root := sysfsFixture(t, "loop0", "/tmp/volume.img\n", "1\n")

	st, err := readLoopStateIn(root, "/dev/loop0")
	if err != nil {
		t.Fatalf("readLoopStateIn returned error: %v", err)
	}
	if !st.autoclear {
		t.Error("autoclear = false for a device whose flag reads 1")
	}
}

// TestReadLoopStateInTreatsMissingLoopAttributesAsDetached is the authoritative
// negative: the loop attributes exist only while a device is attached, so their
// absence — with the block device still present — is a positive answer and must
// NOT come back as an error.
func TestReadLoopStateInTreatsMissingLoopAttributesAsDetached(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "loop0"), 0o755); err != nil {
		t.Fatalf("failed to build the fixture: %v", err)
	}

	st, err := readLoopStateIn(root, "/dev/loop0")
	if err != nil {
		t.Fatalf("a detached device reported an error rather than 'not attached': %v", err)
	}
	if st.backing != "" {
		t.Errorf("backing = %q, want %q", st.backing, "")
	}
}

// TestReadLoopStateInDoesNotTreatAnAbsentBlockDeviceAsDetached is the
// fail-open this reader got wrong twice, in two different disguises.
//
// A name that is not a top-level /sys/block entry — a udev symlink,
// /dev/block/7:0, or a PARTITION like /dev/loop0p1, which lives at
// /sys/block/loop0/loop0p1 — makes the whole path absent. Reading that as "not
// attached" would let the wait conclude a release it never observed, for a
// device it was never able to look at. Absence of the BLOCK DEVICE and absence
// of its LOOP ATTRIBUTES are different facts.
func TestReadLoopStateInDoesNotTreatAnAbsentBlockDeviceAsDetached(t *testing.T) {
	root := t.TempDir()

	for _, device := range []string{"/dev/loop0p1", "/dev/block/7:0", "/dev/disk/by-id/some-symlink"} {
		t.Run(device, func(t *testing.T) {
			st, err := readLoopStateIn(root, device)
			if err == nil {
				t.Fatal("a device that could not be observed was reported as 'not attached'")
			}
			if st.backing != "" {
				t.Errorf("backing = %q, want %q alongside the error", st.backing, "")
			}
		})
	}
}

// TestReadLoopStateInPropagatesAnUnreadableEntry covers the branch the real
// sysfs path cannot provide: under /sys/block every path either exists or does
// not, so the error that must NOT be mistaken for "detached" is unreachable
// from a real device name. A directory where the attribute belongs produces
// exactly that class.
func TestReadLoopStateInPropagatesAnUnreadableEntry(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "loop0", "loop", "backing_file"), 0o755); err != nil {
		t.Fatalf("failed to build the fixture: %v", err)
	}

	st, err := readLoopStateIn(root, "/dev/loop0")
	if err == nil {
		t.Fatal("an unreadable sysfs entry was reported as 'not attached'")
	}
	if st.backing != "" {
		t.Errorf("backing = %q, want %q alongside the error", st.backing, "")
	}
}

// sysfsFixture builds a sysfs tree for one attached loop device.
func sysfsFixture(t *testing.T, name, backing, autoclear string) string {
	t.Helper()

	root := t.TempDir()
	dir := filepath.Join(root, name, "loop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("failed to build the fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "backing_file"), []byte(backing), 0o644); err != nil {
		t.Fatalf("failed to build the fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "autoclear"), []byte(autoclear), 0o644); err != nil {
		t.Fatalf("failed to build the fixture: %v", err)
	}
	return root
}

// TestWaitForLoopNodeReturnsAsSoonAsTheNodeAppears is the success path, and it
// covers the case the defect actually was: the node arrives LATE, not never.
//
// LOOP_CTL_GET_FREE allocates a minor and returns; creating /dev/loop<N> is
// udev's or devtmpfs's job and races this code. Asserting only that the call
// eventually returns nil would be satisfied by a version that slept out the
// whole budget, so this also asserts it returned near the creation rather than
// near the deadline.
func TestWaitForLoopNodeReturnsAsSoonAsTheNodeAppears(t *testing.T) {
	dir := t.TempDir()
	node := filepath.Join(dir, "loop8")

	// udev creates the node 100ms into the wait, on a clock only the wait
	// moves (#233), so "as soon as" is a property of the code, not of the
	// scheduler.
	const appearsAfter = 100 * time.Millisecond
	const poll = time.Millisecond
	clk := clock.NewFake(t)
	clk.OnWait(func(time.Time) {
		if clk.Elapsed() == appearsAfter {
			if err := os.WriteFile(node, nil, 0600); err != nil {
				t.Errorf("could not create the stand-in node: %v", err)
			}
		}
	})

	if err := waitForLoopNode(node, 10*time.Second, poll, clk); err != nil {
		t.Fatalf("waitForLoopNode() error = %v, want it to wait for the node and succeed", err)
	}
	if waited := clk.Elapsed(); waited != appearsAfter {
		t.Errorf("returned after %s; the node appeared at %s and is polled every %s", waited, appearsAfter, poll)
	}
}

// TestWaitForLoopNodeTimesOutWithATypedError is the other side: a node nothing
// will ever create must produce a bounded, typed refusal.
//
// The distinction this error carries is the point. The bare ENOENT it replaces
// read as "there is no such loop device", when the truth is that the minor IS
// ours and only the path is missing -- which sends an operator to look at loop
// device exhaustion instead of at udev.
func TestWaitForLoopNodeTimesOutWithATypedError(t *testing.T) {
	node := filepath.Join(t.TempDir(), "loop9999")

	const budget = 80 * time.Millisecond
	const poll = time.Millisecond
	clk := clock.NewFake(t)
	err := waitForLoopNode(node, budget, poll, clk)

	if err == nil {
		t.Fatal("waitForLoopNode() on a node that never appears = nil, want a timeout")
	}
	if !errors.Is(err, ErrLoopNodeAbsent) {
		t.Errorf("errors.Is(err, ErrLoopNodeAbsent) = false for %v", err)
	}
	var devErr *DeviceError
	if !errors.As(err, &devErr) {
		t.Fatalf("errors.As(err, *DeviceError) = false for %v", err)
	}
	if devErr.Device != node {
		t.Errorf("DeviceError.Device = %q, want %q", devErr.Device, node)
	}
	if waited := clk.Elapsed(); waited <= budget || waited > budget+poll {
		t.Errorf("waited %s against a %s budget polled every %s -- the deadline is not being honored", waited, budget, poll)
	}
}

// TestWaitForLoopNodeDoesNotRetryANonExistenceFailure separates the two
// classes. Retrying a permission or I/O failure for the whole budget would
// report it as a missing node and send an operator to the wrong subsystem.
func TestWaitForLoopNodeDoesNotRetryANonExistenceFailure(t *testing.T) {
	// A path whose PARENT is a regular file: stat fails with ENOTDIR, which is
	// not os.IsNotExist and is uid-independent, so this holds for root too --
	// the project's rule against building failure cases out of permission bits.
	dir := t.TempDir()
	notADir := filepath.Join(dir, "file")
	if err := os.WriteFile(notADir, nil, 0600); err != nil {
		t.Fatal(err)
	}
	node := filepath.Join(notADir, "loop0")

	clk := clock.NewFake(t)
	err := waitForLoopNode(node, 10*time.Second, time.Millisecond, clk)
	if err == nil {
		t.Fatal("waitForLoopNode() on an unstatable path = nil, want an error")
	}
	if errors.Is(err, ErrLoopNodeAbsent) {
		t.Errorf("an unstatable path is reported as an absent node: %v", err)
	}
	// It must not have spent any of the budget on a condition that cannot
	// improve: not one sleep.
	if len(clk.Waits()) != 0 {
		t.Errorf("slept %v before refusing a non-existence failure -- it is being retried", clk.Waits())
	}
}

// TestWaitForLoopNodeAcceptsAnExistingNodeImmediately is the ordinary case: a
// node in the pre-created range is already there, and the wait must cost
// nothing. Without this, a version that always slept one poll interval would
// pass every other case here.
func TestWaitForLoopNodeAcceptsAnExistingNodeImmediately(t *testing.T) {
	node := filepath.Join(t.TempDir(), "loop0")
	if err := os.WriteFile(node, nil, 0600); err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFake(t)
	if err := waitForLoopNode(node, 10*time.Second, time.Second, clk); err != nil {
		t.Fatalf("waitForLoopNode() on an existing node = %v, want nil", err)
	}
	if len(clk.Waits()) != 0 {
		t.Errorf("an existing node slept %v -- the first check is not happening before the first sleep", clk.Waits())
	}
}

// TestLoopAttributeSaysUnboundOnEveryKernelsAnswer: the answers that mean a
// loop device is attached to nothing -- the attribute gone (ENOENT), or the
// read refused with ENODEV as the CI runner's kernel does for a released device
// (#141) -- against the ones that mean the state could not be read, which
// readLoopStateIn must keep as errors.
func TestLoopAttributeSaysUnboundOnEveryKernelsAnswer(t *testing.T) {
	for _, tc := range []struct {
		errno   error
		unbound bool
	}{
		{unix.ENOENT, true},
		{unix.ENODEV, true},
		{unix.ENXIO, true},
		{unix.EIO, false},
		{unix.EACCES, false},
		{unix.EISDIR, false},
	} {
		err := &os.PathError{Op: "read", Path: "/sys/block/loop0/loop/backing_file", Err: tc.errno}
		if got := loopAttributeSaysUnbound(err); got != tc.unbound {
			t.Errorf("loopAttributeSaysUnbound(%v) = %v, want %v", tc.errno, got, tc.unbound)
		}
	}
}
