// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import "time"

// clock is how the code that WAITS sees time: when it started, how long it
// has been, and how to pause before trying again.
//
// It is a parameter of those functions -- the lock acquisition, the loop node
// and loop detach waits -- rather than a direct use of the time package, so
// that their bounds can be tested on a clock the test controls. Asserted on
// the wall clock, a deadline test's verdict depends on what else the machine
// is doing (#233); on a controlled clock it depends only on the code.
type clock interface {
	Now() time.Time
	Sleep(d time.Duration)
}

// systemClock is the real clock, which every exported entry point uses.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) Sleep(d time.Duration) { time.Sleep(d) }
