// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// No build constraint: parallel tests live in files of both tiers.

package luks2

import (
	"runtime"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// Parallel tests share the RLIMIT_MEMLOCK budget: `defer parallel(t)()` runs the body while holding one of a fixed number of slots.

// lockedMemoryPerTest is one running test's peak locked memory, page-rounded.
const lockedMemoryPerTest = 1 << 20

// lockedMemoryReserve is left for everything that is not a running parallel
// test: the runtime, and a sequential test's own enclaves.
const lockedMemoryReserve = 1 << 20

var (
	lockedMemorySlotsOnce sync.Once
	lockedMemorySlotsChan chan struct{}
)

// lockedMemorySlots returns the semaphore, sized on first use.
func lockedMemorySlots() chan struct{} {
	lockedMemorySlotsOnce.Do(func() {
		lockedMemorySlotsChan = make(chan struct{}, parallelSlotsFor(memlockLimit(), runtime.GOMAXPROCS(0)))
	})
	return lockedMemorySlotsChan
}

// memlockLimit is this process's soft RLIMIT_MEMLOCK, or unix.RLIM_INFINITY
// when it cannot be read: a limit nothing reports is not one to plan around.
func memlockLimit() uint64 {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		return unix.RLIM_INFINITY
	}
	return lim.Cur
}

// parallelSlotsFor is how many tests may run at once under a memlock limit
// with procs processors: as many as the limit affords after the reserve, never
// fewer than one and never more than there are processors to run them.
func parallelSlotsFor(limit uint64, procs int) int {
	if procs < 1 {
		procs = 1
	}
	if limit == unix.RLIM_INFINITY {
		return procs
	}
	if limit <= lockedMemoryReserve+lockedMemoryPerTest {
		return 1
	}
	if n := (limit - lockedMemoryReserve) / lockedMemoryPerTest; n < uint64(procs) {
		return int(n)
	}
	return procs
}

// parallel marks t parallel and holds a locked-memory slot until the returned function is called; not for a body that runs a sequential subtest with parallel subtests.
func parallel(t *testing.T) func() {
	t.Helper()
	t.Parallel()
	slots := lockedMemorySlots()
	slots <- struct{}{}
	var once sync.Once
	return func() { once.Do(func() { <-slots }) }
}

func TestParallelSlotsForFitsTheMemlockLimit(t *testing.T) {
	const mib = 1 << 20
	for _, tc := range []struct {
		name  string
		limit uint64
		procs int
		want  int
	}{
		{"docker's default 8 MiB on a 112-core runner", 8 * mib, 112, 7},
		{"a limit that affords more than the processors", 4096 * mib, 8, 8},
		{"no limit", unix.RLIM_INFINITY, 112, 112},
		{"a limit too small for two", 2 * mib, 64, 1},
		{"a 64 KiB limit, where nothing locks much at all", 64 << 10, 8, 1},
		{"no processors reported", 8 * mib, 0, 1},
	} {
		if got := parallelSlotsFor(tc.limit, tc.procs); got != tc.want {
			t.Errorf("%s: parallelSlotsFor(%d, %d) = %d, want %d", tc.name, tc.limit, tc.procs, got, tc.want)
		}
	}
}

// TestParallelHoldsASlotUntilReleased: the slot is taken when the test is
// released to run and given back exactly once, however often the release is
// called.
func TestParallelHoldsASlotUntilReleased(t *testing.T) {
	slots := lockedMemorySlots()
	t.Run("holder", func(t *testing.T) {
		release := parallel(t)
		if len(slots) < 1 {
			t.Fatal("parallel returned without holding a slot")
		}
		held := len(slots)
		release()
		release()
		if len(slots) != held-1 {
			t.Fatalf("releasing twice gave back %d slots, want exactly one", held-len(slots))
		}
	})
}
