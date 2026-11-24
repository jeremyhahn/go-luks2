// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package clock is how waiting code sees time, so tests can bound waits on a clock they control; waits select on a Timer, never Sleep.
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
