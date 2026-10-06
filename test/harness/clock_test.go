// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/clock"
)

// useFakeClock installs a clock.Fake as waitClock for the test.
func useFakeClock(t *testing.T) *clock.Fake {
	t.Helper()
	c := clock.NewFake(t)
	previous := waitClock
	t.Cleanup(func() { waitClock = previous })
	waitClock = c
	return c
}

// TestWaitClockDefaultsToTheSystemClock: outside a test that substitutes it,
// every wait in the package runs on the system clock, which the integration
// tier's real waits exercise. Nothing here reads the real clock: a unit
// verdict must not depend on it (#233).
func TestWaitClockDefaultsToTheSystemClock(t *testing.T) {
	if _, ok := waitClock.(clock.System); !ok {
		t.Fatalf("waitClock is %T, want the system clock outside a test that substitutes it", waitClock)
	}
}
