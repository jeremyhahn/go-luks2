// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"sync"
	"testing"
	"time"
)

// fakeClock is a clock that only moves when a wait sleeps, so a test asserts
// exactly how long the wait waited, whatever else the machine is doing (#233).
// onSleep runs after each sleep with the new time; it is how a test changes
// the world at a chosen moment, or holds a wait still while it looks.
//
// A wait that ignored its deadline would sleep forever on a clock like this,
// so the number of sleeps is bounded and exceeding it fails the test.
type fakeClock struct {
	t         *testing.T
	mu        sync.Mutex
	start     time.Time
	now       time.Time
	sleeps    int
	maxSleeps int
	onSleep   func(now time.Time)
}

// useFakeClock installs a fakeClock as waitClock for the test.
func useFakeClock(t *testing.T) *fakeClock {
	t.Helper()
	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	c := &fakeClock{t: t, start: start, now: start, maxSleeps: 100_000}
	previous := waitClock
	t.Cleanup(func() { waitClock = previous })
	waitClock = c
	return c
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(d time.Duration) {
	c.mu.Lock()
	c.sleeps++
	if c.sleeps > c.maxSleeps {
		c.mu.Unlock()
		c.t.Errorf("slept %d times without returning: the wait is not honoring its deadline", c.sleeps)
		panic("fakeClock: deadline not honored")
	}
	c.now = c.now.Add(d)
	now, hook := c.now, c.onSleep
	c.mu.Unlock()
	if hook != nil {
		hook(now)
	}
}

// elapsed is how much controlled time has passed.
func (c *fakeClock) elapsed() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now.Sub(c.start)
}

// TestFakeClockMovesOnlyWhenSlept pins the double the wait tests rely on.
func TestFakeClockMovesOnlyWhenSlept(t *testing.T) {
	c := useFakeClock(t)
	if waitClock != clock(c) {
		t.Fatal("useFakeClock did not install the fake")
	}
	if c.elapsed() != 0 {
		t.Fatal("the fake clock moved without a sleep")
	}
	var seen time.Duration
	c.onSleep = func(now time.Time) { seen = now.Sub(c.start) }
	c.Sleep(5 * time.Millisecond)
	if c.elapsed() != 5*time.Millisecond || seen != 5*time.Millisecond {
		t.Fatalf("after a 5ms sleep: elapsed %v, onSleep saw %v", c.elapsed(), seen)
	}
}

// TestWaitClockDefaultsToTheSystemClock: outside a test that substitutes it,
// every wait in the package runs on systemClock, a two-line delegation to the
// time package that the integration tier's real waits exercise. Nothing here
// reads the real clock: a unit verdict must not depend on it (#233).
func TestWaitClockDefaultsToTheSystemClock(t *testing.T) {
	if _, ok := waitClock.(systemClock); !ok {
		t.Fatalf("waitClock is %T, want the system clock outside a test that substitutes it", waitClock)
	}
}
