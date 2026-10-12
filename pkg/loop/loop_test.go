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
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/clock"
	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// The waiting logic is exercised here without a loop device; the
// kernel-facing path is covered by the integration suite in test/integration/loop,$!1 which drives a real attach. Both halves are needed: a seam
// only ever met through a double proves nothing about the plane it stands in
// for, and a test that needs root proves nothing on a developer's machine.

// TestWaitForLoopNodeReturnsAsSoonAsTheNodeAppears is the success path, and
// it covers the case the defect actually was: the node arrives LATE, not
// never.
//
// LOOP_CTL_GET_FREE allocates a minor and returns; creating /dev/loop<N> is
// udev's or devtmpfs's job and races this code. Asserting only that the call
// eventually returns nil would be satisfied by a version that slept out the
// whole budget, so this also asserts it returned near the creation rather
// than near the deadline.
func TestWaitForLoopNodeReturnsAsSoonAsTheNodeAppears(t *testing.T) {
	dir := t.TempDir()
	node := filepath.Join(dir, "loop8")

	// udev creates the node 100ms into the wait, on a clock only the wait
	// moves (go-luks2 #233), so "as soon as" is a property of the code, not
	// of the scheduler.
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

	if err := waitForLoopNode(context.Background(), node, 10*time.Second, poll, clk); err != nil {
		t.Fatalf("waitForLoopNode() error = %v, want it to wait for the node and succeed", err)
	}
	if waited := clk.Elapsed(); waited != appearsAfter {
		t.Errorf("returned after %s; the node appeared at %s and is polled every %s", waited, appearsAfter, poll)
	}
}

// TestWaitForLoopNodeTimesOutWithATypedError is the other side: a node
// nothing will ever create must produce a bounded, typed refusal.
//
// The distinction this error carries is the point. The bare ENOENT it
// replaces read as "there is no such loop device", when the truth is that
// the minor IS ours and only the path is missing -- which sends an operator
// to look at loop device exhaustion instead of at udev.
func TestWaitForLoopNodeTimesOutWithATypedError(t *testing.T) {
	node := filepath.Join(t.TempDir(), "loop9999")

	const budget = 80 * time.Millisecond
	const poll = time.Millisecond
	clk := clock.NewFake(t)
	err := waitForLoopNode(context.Background(), node, budget, poll, clk)

	if err == nil {
		t.Fatal("waitForLoopNode() on a node that never appears = nil, want a timeout")
	}
	if !errors.Is(err, ErrNodeAbsent) {
		t.Errorf("errors.Is(err, ErrNodeAbsent) = false for %v", err)
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("errors.As(err, *Error) = false for %v", err)
	}
	if !strings.Contains(e.Detail, node) {
		t.Errorf("Error.Detail = %q, want it to name %q", e.Detail, node)
	}
	if waited := clk.Elapsed(); waited <= budget || waited > budget+poll {
		t.Errorf("waited %s against a %s budget polled every %s -- the deadline is not being honored", waited, budget, poll)
	}
}

// TestWaitForLoopNodeDoesNotRetryANonExistenceFailure separates the two
// classes. Retrying a permission or I/O failure for the whole budget would
// report it as a missing node and send an operator to the wrong subsystem.
func TestWaitForLoopNodeDoesNotRetryANonExistenceFailure(t *testing.T) {
	// A path whose PARENT is a regular file: stat fails with ENOTDIR, which
	// is not os.IsNotExist and is uid-independent, so this holds for root
	// too -- the project's rule against building failure cases out of
	// permission bits.
	dir := t.TempDir()
	notADir := filepath.Join(dir, "file")
	if err := os.WriteFile(notADir, nil, 0600); err != nil {
		t.Fatal(err)
	}
	node := filepath.Join(notADir, "loop0")

	clk := clock.NewFake(t)
	err := waitForLoopNode(context.Background(), node, 10*time.Second, time.Millisecond, clk)
	if err == nil {
		t.Fatal("waitForLoopNode() on an unstatable path = nil, want an error")
	}
	if errors.Is(err, ErrNodeAbsent) {
		t.Errorf("an unstatable path is reported as an absent node: %v", err)
	}
	// It must not have spent any of the budget on a condition that cannot
	// improve: not one sleep.
	if len(clk.Waits()) != 0 {
		t.Errorf("slept %v before refusing a non-existence failure -- it is being retried", clk.Waits())
	}
}

// TestWaitForLoopNodeAcceptsAnExistingNodeImmediately is the ordinary case:
// a node in the pre-created range is already there, and the wait must cost
// nothing. Without this, a version that always slept one poll interval
// would pass every other case here.
func TestWaitForLoopNodeAcceptsAnExistingNodeImmediately(t *testing.T) {
	node := filepath.Join(t.TempDir(), "loop0")
	if err := os.WriteFile(node, nil, 0600); err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFake(t)
	if err := waitForLoopNode(context.Background(), node, 10*time.Second, time.Second, clk); err != nil {
		t.Fatalf("waitForLoopNode() on an existing node = %v, want nil", err)
	}
	if len(clk.Waits()) != 0 {
		t.Errorf("an existing node slept %v -- the first check is not happening before the first sleep", clk.Waits())
	}
}

// TestWaitForLoopNodeStopsOnceContextIsCancelled is the cancellation
// requirement: a wait is a select on ctx.Done() and a clock
// timer, so a caller that gives up is not held past its own cancellation.
//
// The context is canceled from the fake clock's OnWait hook, which runs
// after a poll has already fired -- so the NEXT iteration's ctx check, not
// the select, is what the test can assert on deterministically: a fired
// timer and an already-canceled context are both ready at once, and
// select's choice between two ready cases is not something a test should
// depend on.
func TestWaitForLoopNodeStopsOnceContextIsCancelled(t *testing.T) {
	node := filepath.Join(t.TempDir(), "loop0")

	ctx, cancel := context.WithCancel(context.Background())
	clk := clock.NewFake(t)
	clk.OnWait(func(time.Time) { cancel() })

	err := waitForLoopNode(ctx, node, 10*time.Second, time.Millisecond, clk)
	if err == nil {
		t.Fatal("waitForLoopNode() after cancellation = nil, want an error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) = false for %v", err)
	}
}

// TestAttachRefusesAnAlreadyCancelledContext pins the ctx-first boundary
// check every exported function makes: a caller that
// hands Attach a context canceled before the call gets ctx.Err() back
// without the function touching the filesystem or a device.
func TestAttachRefusesAnAlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := attach(ctx, "/nonexistent/should-not-be-opened.img", defaultSys()); !errors.Is(err, context.Canceled) {
		t.Errorf("attach() with a canceled context = %v, want context.Canceled", err)
	}
}

// attachSys is a sys whose loop driver is a pair of doubles: getFree hands
// out minors 0, 1, 2… and creates each node in a temporary /dev, and setFD
// answers from setFDErrs, one error per call, succeeding once they run out.
// It records how many LOOP_SET_FD calls were made.
func attachSys(t *testing.T, setFDErrs ...error) (sys, *int) {
	t.Helper()
	dev := t.TempDir()
	control := filepath.Join(dev, "loop-control")
	if err := os.WriteFile(control, nil, 0600); err != nil {
		t.Fatalf("could not create the stand-in loop-control: %v", err)
	}

	s := defaultSys()
	s.clk = clock.NewFake(t)
	s.devDir = dev
	s.openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		if name == "/dev/loop-control" {
			name = control
		}
		return os.OpenFile(name, flag, perm) // #nosec G304 -- test paths under t.TempDir
	}
	var minor uintptr
	s.getFree = func(*os.File) (uintptr, error) {
		n := minor
		minor++
		node := filepath.Join(dev, "loop"+strconv.FormatUint(uint64(n), 10))
		if err := os.WriteFile(node, nil, 0600); err != nil {
			return 0, err
		}
		return n, nil
	}
	calls := new(int)
	s.setFD = func(*os.File, *os.File) error {
		*calls++
		if *calls <= len(setFDErrs) {
			return setFDErrs[*calls-1]
		}
		return nil
	}
	return s, calls
}

// backingImage is a file attach can open read-write.
func backingImage(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "disk.img")
	if err := os.WriteFile(path, make([]byte, 4096), 0600); err != nil {
		t.Fatalf("could not create the backing image: %v", err)
	}
	return path
}

// TestAttachRetriesALoopDeviceTakenByAnotherCaller covers the race
// LOOP_CTL_GET_FREE leaves open: it names a free device without reserving
// it, so a concurrent caller can bind it first and LOOP_SET_FD fails with
// EBUSY. Attach must ask for another device rather than fail. A real attach
// meets this only when two attaches collide, so the integration suite
// covers it on some runs and not others; this test covers it on every one.
func TestAttachRetriesALoopDeviceTakenByAnotherCaller(t *testing.T) {
	s, calls := attachSys(t, unix.EBUSY)
	file := backingImage(t)

	d, err := attach(context.Background(), file, s)
	if err != nil {
		t.Fatalf("attach() error = %v, want the retry to bind the next free device", err)
	}
	if want := filepath.Join(s.devDir, "loop1"); d.Path() != want {
		t.Errorf("attach() bound %s, want %s: the busy loop0 must be passed over", d.Path(), want)
	}
	if d.BackingFile() != file {
		t.Errorf("BackingFile() = %s, want %s", d.BackingFile(), file)
	}
	if *calls != 2 {
		t.Errorf("LOOP_SET_FD sent %d times, want 2", *calls)
	}
}

// TestAttachGivesUpAfterItsAttempts bounds that retry: a device that is
// busy on every attempt yields the EBUSY, after exactly attachAttempts
// tries.
func TestAttachGivesUpAfterItsAttempts(t *testing.T) {
	busy := make([]error, loopAttachAttempts)
	for i := range busy {
		busy[i] = unix.EBUSY
	}
	s, calls := attachSys(t, busy...)

	_, err := attach(context.Background(), backingImage(t), s)
	if !errors.Is(err, unix.EBUSY) {
		t.Fatalf("attach() error = %v, want EBUSY once every attempt is busy", err)
	}
	if *calls != loopAttachAttempts {
		t.Errorf("LOOP_SET_FD sent %d times, want %d", *calls, loopAttachAttempts)
	}
}

// TestAttachDoesNotRetryAnotherFailure keeps the retry to the race it is
// for: any other LOOP_SET_FD failure is returned at once.
func TestAttachDoesNotRetryAnotherFailure(t *testing.T) {
	s, calls := attachSys(t, unix.EINVAL)

	_, err := attach(context.Background(), backingImage(t), s)
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("attach() error = %v, want EINVAL", err)
	}
	if *calls != 1 {
		t.Errorf("LOOP_SET_FD sent %d times, want 1", *calls)
	}
}

// TestAttachReportsAFailedGetFree types a LOOP_CTL_GET_FREE failure, the
// answer of a host whose loop devices are exhausted.
func TestAttachReportsAFailedGetFree(t *testing.T) {
	s, calls := attachSys(t)
	s.getFree = func(*os.File) (uintptr, error) { return 0, unix.ENOSPC }

	_, err := attach(context.Background(), backingImage(t), s)
	if !errors.Is(err, errs.ErrIO) || !strings.Contains(err.Error(), "LOOP_CTL_GET_FREE") {
		t.Fatalf("attach() error = %v, want an ErrIO naming LOOP_CTL_GET_FREE", err)
	}
	if *calls != 0 {
		t.Errorf("LOOP_SET_FD sent %d times without a device, want 0", *calls)
	}
}
