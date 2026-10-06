// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package clock

import (
	"sync"
	"time"
)

// TB is the part of testing.TB a Fake reports through. It is an interface so
// that this package, which production code imports, does not import testing.
type TB interface {
	Helper()
	Fatalf(format string, args ...any)
}

// DefaultMaxWaits bounds how many timers a Fake hands out before it fails the
// test. A wait that ignores its deadline would otherwise wait forever on a
// clock that moves only when it waits.
const DefaultMaxWaits = 100_000

// Fake is a Clock that moves only when the code under test waits on it.
//
// NewTimer advances the clock by the timer's duration and returns a timer
// that has already fired, so a wait on a Fake runs on the caller's goroutine
// and a test asserts exactly how long it waited and how it paced itself.
// OnWait runs after each such advance with the new time: it is how a test
// changes the world at a chosen moment -- a lock released, a node created --
// without a goroutine racing the wait.
//
// A Fake is safe for concurrent use.
type Fake struct {
	tb       TB
	mu       sync.Mutex
	start    time.Time
	now      time.Time
	waits    []time.Duration
	maxWaits int
	onWait   func(now time.Time)
}

// NewFake returns a Fake that fails tb after DefaultMaxWaits waits. It starts
// at a fixed instant, so nothing a test asserts depends on when it ran.
func NewFake(tb TB) *Fake {
	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	return &Fake{tb: tb, start: start, now: start, maxWaits: DefaultMaxWaits}
}

// Now returns the fake's current time.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// NewTimer advances the clock by d, runs the OnWait hook, and returns a timer
// that has fired at the new time. A non-positive d advances nothing, as a
// time.Timer of that duration fires at once.
func (f *Fake) NewTimer(d time.Duration) Timer {
	f.mu.Lock()
	f.waits = append(f.waits, d)
	if len(f.waits) > f.maxWaits {
		n := len(f.waits)
		f.mu.Unlock()
		f.tb.Helper()
		f.tb.Fatalf("waited %d times without returning: the wait is not honoring its deadline", n)
		return newFiredTimer(f.Now())
	}
	if d > 0 {
		f.now = f.now.Add(d)
	}
	now, hook := f.now, f.onWait
	f.mu.Unlock()
	if hook != nil {
		hook(now)
	}
	return newFiredTimer(now)
}

// Advance moves the clock forward by d without a wait.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// OnWait installs fn to run after every wait, with the time the wait ended.
func (f *Fake) OnWait(fn func(now time.Time)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onWait = fn
}

// SetMaxWaits changes how many waits the Fake allows before it fails the test.
func (f *Fake) SetMaxWaits(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.maxWaits = n
}

// Start returns the instant the Fake started at.
func (f *Fake) Start() time.Time { return f.start }

// Elapsed returns how much fake time has passed since the Fake started.
func (f *Fake) Elapsed() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now.Sub(f.start)
}

// Waits returns the duration of every wait so far, in order.
func (f *Fake) Waits() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Duration(nil), f.waits...)
}

// firedTimer is a Timer that has already fired.
type firedTimer struct{ c chan time.Time }

func newFiredTimer(at time.Time) Timer {
	c := make(chan time.Time, 1)
	c <- at
	return firedTimer{c}
}

func (t firedTimer) C() <-chan time.Time { return t.c }

// Stop reports false: the timer has already fired.
func (firedTimer) Stop() bool { return false }
