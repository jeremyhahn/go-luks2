// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import "time"

// clock is how the harness's waits see time: the reaper's wait for another
// reaper, its wait for a detach to settle, and DetachLoop's wait for a release.
type clock interface {
	Now() time.Time
	Sleep(d time.Duration)
}

// systemClock is the real clock.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) Sleep(d time.Duration) { time.Sleep(d) }

// waitClock is the clock every wait in this package uses. Tests substitute a
// controlled one so that a bound is asserted on the code rather than on how
// busy the machine running it is (#233). The package has no parallel tests,
// which is what makes a package-level clock safe to substitute.
var waitClock clock = systemClock{}
