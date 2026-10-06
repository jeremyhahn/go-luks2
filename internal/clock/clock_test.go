// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package clock

import (
	"fmt"
	"testing"
	"time"
)

// TestSystemIsTheRealClock checks System against the time package: Now falls
// between two direct reads, and a timer fires no sooner than it was asked.
// Both are lower bounds on the real clock, so a loaded machine cannot fail
// them.
func TestSystemIsTheRealClock(t *testing.T) {
	var c Clock = System{}
	before := time.Now()
	now := c.Now()
	if now.Before(before) || now.After(time.Now()) {
		t.Fatalf("System.Now() = %v, outside the reads around it", now)
	}

	start := time.Now()
	timer := c.NewTimer(2 * time.Millisecond)
	fired := <-timer.C()
	if waited := time.Since(start); waited < 2*time.Millisecond {
		t.Fatalf("a 2ms timer fired after %v", waited)
	}
	if fired.Before(start) {
		t.Fatalf("the timer fired at %v, before it was started at %v", fired, start)
	}
	if timer.Stop() {
		t.Fatal("Stop reported stopping a timer that had already fired")
	}
	if !c.NewTimer(time.Hour).Stop() {
		t.Fatal("Stop did not stop a pending timer")
	}
}

// recorder is a TB that records a fatal report instead of ending the test, so
// the Fake's deadline guard can itself be tested.
type recorder struct{ fatal string }

func (*recorder) Helper() {}

func (r *recorder) Fatalf(format string, args ...any) { r.fatal = fmt.Sprintf(format, args...) }

// TestFakeMovesOnlyWhenWaitedOn pins the double the wait tests rely on: a fake
// that advanced on Now, or not at all, would make every bound asserted on it
// meaningless.
func TestFakeMovesOnlyWhenWaitedOn(t *testing.T) {
	f := NewFake(t)
	if f.Elapsed() != 0 || !f.Now().Equal(f.Start()) {
		t.Fatal("the fake moved without a wait")
	}

	var seen []time.Duration
	f.OnWait(func(now time.Time) { seen = append(seen, now.Sub(f.Start())) })
	timer := f.NewTimer(3 * time.Millisecond)
	if at := <-timer.C(); !at.Equal(f.Start().Add(3 * time.Millisecond)) {
		t.Fatalf("the timer fired at %v, want 3ms after the start", at)
	}
	if timer.Stop() {
		t.Fatal("Stop reported stopping a fired timer")
	}
	f.NewTimer(4 * time.Millisecond)
	f.NewTimer(-time.Second)
	f.Advance(time.Second)

	if got := f.Elapsed(); got != time.Second+7*time.Millisecond {
		t.Fatalf("elapsed %v, want 1.007s", got)
	}
	if got := f.Waits(); len(got) != 3 || got[0] != 3*time.Millisecond || got[1] != 4*time.Millisecond || got[2] != -time.Second {
		t.Fatalf("waits %v, want [3ms 4ms -1s]", got)
	}
	if len(seen) != 3 || seen[0] != 3*time.Millisecond || seen[1] != 7*time.Millisecond || seen[2] != 7*time.Millisecond {
		t.Fatalf("OnWait saw %v, want [3ms 7ms 7ms]", seen)
	}
}

// TestFakeFailsAWaitThatNeverEnds: a wait that ignores its deadline is
// reported once it has waited more than the bound, instead of hanging.
func TestFakeFailsAWaitThatNeverEnds(t *testing.T) {
	r := &recorder{}
	f := NewFake(r)
	f.SetMaxWaits(2)
	f.NewTimer(time.Millisecond)
	f.NewTimer(time.Millisecond)
	if r.fatal != "" {
		t.Fatalf("failed within the bound: %s", r.fatal)
	}
	timer := f.NewTimer(time.Millisecond)
	if r.fatal == "" {
		t.Fatal("a third wait past a bound of two was not reported")
	}
	if f.Elapsed() != 2*time.Millisecond {
		t.Fatalf("the reported wait advanced the clock to %v", f.Elapsed())
	}
	select {
	case <-timer.C():
	default:
		t.Fatal("the reported wait's timer never fires, so the wait would hang")
	}
}
