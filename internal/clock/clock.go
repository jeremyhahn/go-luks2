// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package clock is how code that waits sees time.
//
// A wait asks a Clock for the time and for a timer, never the time package
// directly, so its bound can be tested on a clock the test controls. Asserted
// on the wall clock, a deadline test's verdict depends on what else the
// machine is doing (#233); on a Fake it depends only on the code.
//
// There is no Sleep. A wait selects on a Timer's channel, which is the form
// that can also select on a context.
package clock

import "time"

// Clock is a source of the current time and of timers.
type Clock interface {
	// Now returns the current time.
	Now() time.Time

	// NewTimer returns a Timer that fires once, d from now.
	NewTimer(d time.Duration) Timer
}

// Timer fires once on its channel.
type Timer interface {
	// C returns the channel the timer fires on.
	C() <-chan time.Time

	// Stop prevents the timer from firing. It reports whether it did so, as
	// time.Timer.Stop does.
	Stop() bool
}

// System is the real clock.
type System struct{}

// Now returns time.Now().
func (System) Now() time.Time { return time.Now() }

// NewTimer returns a time.Timer.
func (System) NewTimer(d time.Duration) Timer { return systemTimer{time.NewTimer(d)} }

type systemTimer struct{ t *time.Timer }

func (s systemTimer) C() <-chan time.Time { return s.t.C }

func (s systemTimer) Stop() bool { return s.t.Stop() }
