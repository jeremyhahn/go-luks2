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

	"github.com/jeremyhahn/go-luks2/internal/clock"
)

// The waiting logic is exercised here without a loop device; the
// kernel-facing path is covered by the integration suite in pkg/luks2 (moved
// there by H12), which drives a real attach. Both halves are needed: a seam
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

// TestWaitForLoopNodeStopsOnceContextIsCancelled is DESIGN.md D.2's
// cancellation requirement: a wait is a select on ctx.Done() and a clock
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
// check DESIGN.md D rules every new exported function to: a caller that
// hands Attach a context canceled before the call gets ctx.Err() back
// without the function touching the filesystem or a device.
func TestAttachRefusesAnAlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := attach(ctx, "/nonexistent/should-not-be-opened.img", defaultSys()); !errors.Is(err, context.Canceled) {
		t.Errorf("attach() with a canceled context = %v, want context.Canceled", err)
	}
}
