// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import "testing"

// The integration suite leaves device-mapper mappings on the HOST, and until
// this helper existed it did so silently (#100).
//
// # What actually went wrong
//
// Every teardown in this suite was a bare deferred close with the error
// discarded. `Lock` removes the mapping; when it fails, the mapping stays on
// the machine, the test says nothing, and the run reports success. The next
// integration job on that runner then refuses to start, because the container
// entrypoint correctly declines to touch a host holding mappings it did not
// create. A green run poisons the host for the next one.
//
// MEASURED, on 2026-09-01, and this is the case that matters because it
// contradicts the obvious explanation:
//
//	23:13:49Z  pool clean, dm=none on all four runners
//	23:30:53Z  job 34559 starts on that runner; its entrypoint guard does NOT
//	           refuse, so the host was still clean
//	23:31:28Z  --- PASS: TestMakeFilesystemExt3 (3.40s)
//	23:34:44Z  job 34559 completes, conclusion: SUCCESS
//	23:37:40Z  the next job on that runner refuses: test-fs-ext3 (252:0)
//
// It was the only integration job on that runner in the window. Clean when it
// started, dirty when it finished, and it PASSED.
//
// # So the defect is not what it first looked like
//
// The first diagnosis was that `t.Fatal` after a mount left `Lock` running
// against a busy device. That is real, and it is not what happened here:
// TestMakeFilesystemExt3 never mounts anything, nothing failed, and its defer
// order is correct — `defer Lock` is registered after `defer DetachLoopDevice`,
// and defers run LIFO, so the close runs first.
//
// What remains is the clause common to every instance: THE ERROR IS DISCARDED.
// The likely cause on a healthy path is a transient EBUSY — `mkfs`, and the
// udev/blkid activity it triggers, can still hold the device open for a moment
// after MakeFilesystem returns, and `dmsetup remove` fails while that lasts.
//
//	The defect is not "cleanup that cannot run".
//	It is "cleanup whose failure is not reported."
//
// # What this helper asserts, and why it is the END STATE
//
// It asserts that no mapping is left, NOT that Lock returned nil. The two are
// different, and asserting the call would be wrong in both directions:
//
//   - `Lock` returns ErrVolumeNotUnlocked when there is no mapping. That is the
//     desired end state, not a failure — a test that already closed explicitly
//     would fail on a bare error check.
//   - A `Lock` that returns nil while the mapping survives would pass a call
//     check and still leak.
//
// The property the host cares about is "is the mapping gone", so that is what
// is checked.
//
// The retry is the other half and neither half is sufficient alone. The retry
// stops the healthy-path leak; the report stops the next one being invisible.
// Shipping only the retry would fix today's instance and restore the silence.
// It is a poll-until-condition on external state — the sanctioned form — not a
// fixed sleep standing in for synchronization.
//
// It never gives up quietly: exhausting the deadline is a test FAILURE naming
// the mapping and the last error. A retry that eventually gives up silently is
// the same defect wearing a delay.

// releaseVolume closes name and fails the test if a device-mapper mapping is
// left behind on the host. Safe to defer on a volume that is already closed.
//
// The decision lives in releaseVolumeErr (release_test.go), which is UNTAGGED
// and therefore compiled and unit-tested in both build configurations. That
// split is deliberate: the property this helper exists for -- that a mapping
// which cannot be released is REPORTED rather than swallowed -- must itself be
// tested, and it cannot be tested by running the integration suite, because
// reproducing a stuck mapping on demand is exactly what nobody can do. Driving
// the injectable device-mapper seam proves it in milliseconds and without root.
// The real unmount is enabled HERE, in the integration build only.
//
// releaseVolumeErr lives in the untagged tier so its decision can be
// unit-tested, and that tier must never run `umount` against the developer's
// own /proc/self/mountinfo -- a unit test driving the helper with a name like
// "clean" would otherwise unmount whatever the host had mounted from
// /dev/mapper/clean. Review caught that; it is the `losetup -D` class of
// teardown, reintroduced by me inside the fix for its sibling.
//
// Turning it on here rather than stubbing it off in each unit test is
// deliberate: the safe state is the default, so a unit test written later is
// safe without its author knowing this seam exists.
func init() { releaseUnmount = unmountVolume }

func releaseVolume(t *testing.T, name string) {
	t.Helper()
	if err := releaseVolumeErr(name); err != nil {
		t.Errorf("%v", err)
	}
}
