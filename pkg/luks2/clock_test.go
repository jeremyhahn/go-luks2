// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// No build constraint: release_test.go, shared by both tiers, waits on a
// fakeClock in its unit tests.

package luks2

import (
	"testing"
	"time"
)

// fakeClock is a clock that only moves when the code under test sleeps, so a
// test can assert exactly how long a wait waited and how it paced itself,
// whatever else the machine is doing (#233).
//
// onSleep runs after each sleep with the new time, which is how a test makes
// the world change at a chosen moment -- a lock released, a node created --
// without a goroutine racing the wait.
//
// A wait that ignores its deadline would sleep forever on a clock like this,
// so the number of sleeps is bounded and exceeding it fails the test rather
// than hanging it.
type fakeClock struct {
	t         *testing.T
	start     time.Time
	now       time.Time
	slept     []time.Duration
	maxSleeps int
	onSleep   func(now time.Time)
}

func newFakeClock(t *testing.T) *fakeClock {
	t.Helper()
	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	return &fakeClock{t: t, start: start, now: start, maxSleeps: 100_000}
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) Sleep(d time.Duration) {
	c.slept = append(c.slept, d)
	if len(c.slept) > c.maxSleeps {
		c.t.Fatalf("slept %d times without returning: the wait is not honoring its deadline", len(c.slept))
	}
	c.now = c.now.Add(d)
	if c.onSleep != nil {
		c.onSleep(c.now)
	}
}

// elapsed is how much controlled time has passed.
func (c *fakeClock) elapsed() time.Duration { return c.now.Sub(c.start) }

// TestFakeClockMovesOnlyWhenSlept pins the double the wait tests rely on: a
// fake that advanced on Now, or not at all, would make every bound assertion
// built on it meaningless.
func TestFakeClockMovesOnlyWhenSlept(t *testing.T) {
	c := newFakeClock(t)
	first := c.Now()
	if c.Now() != first || c.elapsed() != 0 {
		t.Fatal("the fake clock moved without a sleep")
	}
	var seen time.Time
	c.onSleep = func(now time.Time) { seen = now }
	c.Sleep(3 * time.Millisecond)
	c.Sleep(4 * time.Millisecond)
	if c.elapsed() != 7*time.Millisecond || seen != first.Add(7*time.Millisecond) || len(c.slept) != 2 {
		t.Fatalf("after sleeping 3ms and 4ms: elapsed %v, onSleep saw %v, %d sleeps recorded", c.elapsed(), seen.Sub(first), len(c.slept))
	}
}

// BenchmarkSystemClockIsTheRealClock checks the production clock against the
// time package: Now falls between two direct reads, and Sleep pauses for at
// least what it was asked. Both are statements about the real clock, so no
// unit test makes them -- whether a mutation of them is caught would depend on
// scheduling (#233). `make test-calibration` runs this once and fails the
// build on it.
func BenchmarkSystemClockIsTheRealClock(b *testing.B) {
	var c clock = systemClock{}
	for b.Loop() {
		before := time.Now()
		got := c.Now()
		after := time.Now()
		if got.Before(before) || got.After(after) {
			b.Fatalf("systemClock.Now() = %v, not between %v and %v", got, before, after)
		}
		start := time.Now()
		c.Sleep(2 * time.Millisecond)
		if slept := time.Since(start); slept < 2*time.Millisecond {
			b.Fatalf("systemClock.Sleep(2ms) returned after %v", slept)
		}
	}
}
