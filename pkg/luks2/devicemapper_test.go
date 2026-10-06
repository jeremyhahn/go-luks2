// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/anatol/devmapper.go"
	"github.com/jeremyhahn/go-luks2/internal/clock"
	"golang.org/x/sys/unix"
)

// Removing a device-mapper target intermittently fails with EBUSY because
// something holds it open for a moment after the activity that preceded the
// close -- in practice a process started by a udev rule (#122).
//
// This is not our diagnosis to defend: dmsetup(8) documents the same condition
// and ships a flag for it.
//
//	remove [--retry] ... "If an attempt to remove a device fails, perhaps
//	because a process run from a udev rule is temporarily using the device,
//	the --retry option will cause the operation to be retried for a few
//	seconds before failing."
//
// So the remedy is device-mapper's own, and the bound below is anchored to
// "a few seconds" rather than to a number someone liked.
//
// # What these tests are really about
//
// A retry is three lines. The reviewable part is what happens when it gives
// up, because a retry that ends in silence is worse than the flake it
// replaces: it converts a fast, visible failure into a slow one that says the
// same unhelpful thing. So the exhaustion cases are written first and asserted
// hardest, and the two call sites are asserted SEPARATELY because they must
// answer differently.

// countingRemove replaces the device-mapper remove with one that fails with
// EBUSY for the first failures calls and then succeeds, and records how many
// times it was called.
//
// It overrides the field on the installed fake rather than extending the fake
// itself, so no other lane's tests change shape.
func countingRemove(t *testing.T, fake *fakeDeviceMapper, failures int) *int {
	t.Helper()

	fake.install(t)

	calls := 0
	previous := dm.remove
	t.Cleanup(func() { dm.remove = previous })
	dm.remove = func(name string) error {
		calls++
		if calls <= failures {
			return os.NewSyscallError("dm ioctl", unix.EBUSY)
		}
		return previous(name)
	}
	return &calls
}

// recordRetryWaits runs the device-mapper waits on a fake clock, which records
// every sleep it is asked for and returns at once, and returns that record.
//
// The test therefore asserts the retry's BUDGET rather than spending it. A
// test that actually slept would be asserting the same property at a hundred
// times the cost, and a loaded runner would make it flaky on top -- exactly
// the "never use a sleep as a synchronization primitive" rule.
func recordRetryWaits(t *testing.T) *clock.Fake {
	t.Helper()

	clk := clock.NewFake(t)
	previous := dmClock
	t.Cleanup(func() { dmClock = previous })
	dmClock = clk
	return clk
}

// TestLockRetriesATransientBusyAndSucceeds is the defect itself: the mapping
// is held for a moment and then free, and the close must ride that out.
//
// Before #122 this failed on the first EBUSY.
func TestLockRetriesATransientBusyAndSucceeds(t *testing.T) {
	withDevDir(t, t.TempDir())

	fake := newFakeDeviceMapper()
	fake.targets["busy-then-free"] = "CRYPT-LUKS2-transient"
	calls := countingRemove(t, fake, 2)
	recordRetryWaits(t)

	if err := Lock("busy-then-free"); err != nil {
		t.Fatalf("Lock = %v, want success once the transient hold clears", err)
	}
	if *calls != 3 {
		t.Fatalf("device-mapper remove was called %d times, want 3 (two busy, one that succeeds)", *calls)
	}
	if _, live := fake.targets["busy-then-free"]; live {
		t.Fatal("Lock reported success but the target is still present")
	}
}

// TestLockGivesUpBoundedWhenSomethingGenuinelyHoldsTheDevice is the case the
// retry must not turn into a hang, and the one this issue is really about.
func TestLockGivesUpBoundedWhenSomethingGenuinelyHoldsTheDevice(t *testing.T) {
	withDevDir(t, t.TempDir())

	fake := newFakeDeviceMapper()
	fake.targets["genuinely-held"] = "CRYPT-LUKS2-held"
	calls := countingRemove(t, fake, 1<<30) // never clears
	waits := recordRetryWaits(t)

	err := Lock("genuinely-held")
	if err == nil {
		t.Fatal("Lock reported success against a device that is never released")
	}

	// It says WHICH condition, so an operator is not left with a bare errno
	// and no idea whether anything was tried.
	if !errors.Is(err, ErrMappingBusy) {
		t.Fatalf("Lock = %v, want an error wrapping ErrMappingBusy", err)
	}
	// The cause stays reachable: a caller that already branches on the errno
	// does not have to change.
	if !errors.Is(err, unix.EBUSY) {
		t.Fatalf("the underlying EBUSY is no longer reachable: %v", err)
	}
	// It must NOT claim the rollback's meaning. ErrMappingStillLive is about a
	// plaintext target the caller does not know exists; here the caller asked
	// for the close and is being told it failed.
	if errors.Is(err, ErrMappingStillLive) {
		t.Fatalf("an ordinary close reported the rollback's sentinel: %v", err)
	}

	// BOUNDED, asserted on the budget rather than on elapsed time.
	if len(waits.Waits()) == 0 {
		t.Fatal("no backoff was recorded, so nothing was actually retried")
	}
	var total time.Duration
	for _, w := range waits.Waits() {
		total += w
	}
	// EXACTLY the budget, not merely within it. Asserting only the upper bound
	// let an early give-up through: the loop stopped as soon as the next
	// doubling would overshoot, spending 2.54s of 3s while the error claimed
	// the full budget. A one-sided assertion on a bound checks one of the two
	// ways it can be wrong (caught in review of #122).
	if total != dmRemoveRetryBudget {
		t.Fatalf("the backoff totalled %v; the budget is %v and the give-up error claims all of it was spent",
			total, dmRemoveRetryBudget)
	}
	if *calls < 2 {
		t.Fatalf("remove was attempted %d times; a retry that never retries is not a retry", *calls)
	}
}

// TestLockGiveUpErrorNamesTheRemedy pins the half of the fix that is not the
// loop. An operator who reads this message has to be able to act on it.
func TestLockGiveUpErrorNamesTheRemedy(t *testing.T) {
	withDevDir(t, t.TempDir())

	fake := newFakeDeviceMapper()
	fake.targets["held"] = "CRYPT-LUKS2-held"
	countingRemove(t, fake, 1<<30)
	recordRetryWaits(t)

	err := Lock("held")
	if err == nil {
		t.Fatal("Lock reported success against a device that is never released")
	}
	for _, want := range []string{
		"held",     // the name, so it is actionable at all
		"attempts", // that we tried, and how many
		"lsof",     // how to find the holder
		"deferred", // dmsetup remove --deferred, for a device that frees later
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the give-up error does not mention %q: %v", want, err)
		}
	}
}

// TestRollbackStillFailsClosedWhenTheDeviceIsNeverReleased is the constraint
// the retry must not break.
//
// removeCreatedMapping is the rollback after a FAILED unlock. Its contract is
// that a plaintext target which cannot be confirmed gone is reported loudly,
// because the caller has been told the unlock failed and would otherwise
// assume no decrypted device exists. Retrying is fine; quietly succeeding, or
// downgrading to the ordinary busy error, is not.
func TestRollbackStillFailsClosedWhenTheDeviceIsNeverReleased(t *testing.T) {
	withDevDir(t, t.TempDir())

	fake := newFakeDeviceMapper()
	fake.targets["rollback-held"] = "CRYPT-LUKS2-rollback"
	countingRemove(t, fake, 1<<30)
	recordRetryWaits(t)

	err := removeCreatedMapping("rollback-held", "CRYPT-LUKS2-rollback", fakeDefaultDevNo)
	if err == nil {
		t.Fatal("the rollback reported success for a target it could not remove")
	}
	if !errors.Is(err, ErrMappingStillLive) {
		t.Fatalf("removeCreatedMapping = %v, want ErrMappingStillLive; the rollback must still fail closed", err)
	}
}

// TestRollbackRidesOutATransientBusy is the benefit the shared helper gives
// the rollback: a udev hold no longer produces a false "may still be live"
// alarm, which is the report an operator must be able to trust.
func TestRollbackRidesOutATransientBusy(t *testing.T) {
	withDevDir(t, t.TempDir())

	fake := newFakeDeviceMapper()
	fake.targets["rollback-transient"] = "CRYPT-LUKS2-transient"
	calls := countingRemove(t, fake, 2)
	recordRetryWaits(t)

	if err := removeCreatedMapping("rollback-transient", "CRYPT-LUKS2-transient", fakeDefaultDevNo); err != nil {
		t.Fatalf("the rollback raised %v for a hold that cleared; a false ErrMappingStillLive is an alarm an operator will learn to ignore", err)
	}
	if *calls != 3 {
		t.Fatalf("remove was called %d times, want 3", *calls)
	}
}

// TestRemoveRetryDoesNotRetryWhatCannotClear guards the other direction: only
// EBUSY is transient. A device that is gone, or a refusal for any other
// reason, must be answered immediately rather than after the full budget --
// otherwise every unrelated failure becomes slow.
func TestRemoveRetryDoesNotRetryWhatCannotClear(t *testing.T) {
	for _, errno := range []unix.Errno{unix.ENXIO, unix.ENODEV, unix.EPERM, unix.EINVAL} {
		t.Run(errno.Error(), func(t *testing.T) {
			withDevDir(t, t.TempDir())

			fake := newFakeDeviceMapper()
			fake.targets["other-failure"] = "CRYPT-LUKS2-other"
			fake.install(t)

			calls := 0
			previous := dm.remove
			t.Cleanup(func() { dm.remove = previous })
			dm.remove = func(string) error {
				calls++
				return os.NewSyscallError("dm ioctl", errno)
			}
			waits := recordRetryWaits(t)

			if err := Lock("other-failure"); err == nil {
				t.Fatalf("Lock reported success on %v", errno)
			}
			if calls != 1 {
				t.Fatalf("remove was attempted %d times for %v; only EBUSY is retryable", calls, errno)
			}
			if len(waits.Waits()) != 0 {
				t.Fatalf("backoff was spent on %v, which cannot clear", errno)
			}
		})
	}
}

// TestRollbackWillNotRemoveAMappingThatChangedIdentityMidRetry is the
// regression test for a defect the retry INTRODUCED, caught in local review
// before it was pushed (#122).
//
// The rollback confirms the target is ours by UUID before removing it. With the
// removal retried by name for up to three seconds, that check guarded only the
// FIRST of up to eight attempts: during a backoff another actor can remove our
// target and create a different mapping under the same name, and the next
// attempt would remove theirs. The single-shot code had a one-ioctl window for
// this; retrying by name alone widened it to the whole budget.
//
// The fix is that the identity check lives inside the retried unit. This test
// makes the window real: the first attempt is refused with EBUSY, and the
// mapping changes identity before the second.
func TestRollbackWillNotRemoveAMappingThatChangedIdentityMidRetry(t *testing.T) {
	withDevDir(t, t.TempDir())

	const name = "recycled-name"
	fake := newFakeDeviceMapper()
	fake.targets[name] = "CRYPT-LUKS2-ours"
	fake.install(t)
	recordRetryWaits(t)

	removeCalls := 0
	previousRemove := dm.remove
	t.Cleanup(func() { dm.remove = previousRemove })
	dm.remove = func(n string) error {
		removeCalls++
		if removeCalls == 1 {
			// Held for an instant -- and while we wait, somebody else takes
			// the name.
			fake.targets[name] = "CRYPT-LUKS2-SOMEONE-ELSES"
			return os.NewSyscallError("dm ioctl", unix.EBUSY)
		}
		return previousRemove(n)
	}

	if err := removeCreatedMapping(name, "CRYPT-LUKS2-ours", fakeDefaultDevNo); err != nil {
		t.Fatalf("removeCreatedMapping = %v; a name that is no longer ours is not an error, it is nothing to do", err)
	}

	// The damage plane: somebody else's plaintext mapping is still there.
	if uuid, live := fake.targets[name]; !live || uuid != "CRYPT-LUKS2-SOMEONE-ELSES" {
		t.Fatalf("the rollback removed a mapping that was not ours: targets[%q] = %q, live=%v", name, uuid, live)
	}
	// And it stopped at the identity check rather than issuing a second remove.
	if removeCalls != 1 {
		t.Fatalf("remove was issued %d times; the second attempt must be refused by the identity re-check, not by luck", removeCalls)
	}
}

// TestRollbackStopsWhenTheTargetDisappearsMidRetry is the sibling state: the
// mapping is gone by the next attempt, which is success and not an alarm.
func TestRollbackStopsWhenTheTargetDisappearsMidRetry(t *testing.T) {
	withDevDir(t, t.TempDir())

	const name = "vanishes"
	fake := newFakeDeviceMapper()
	fake.targets[name] = "CRYPT-LUKS2-ours"
	fake.install(t)
	recordRetryWaits(t)

	removeCalls := 0
	previousRemove := dm.remove
	t.Cleanup(func() { dm.remove = previousRemove })
	dm.remove = func(n string) error {
		removeCalls++
		if removeCalls == 1 {
			delete(fake.targets, name) // somebody else finished the job
			return os.NewSyscallError("dm ioctl", unix.EBUSY)
		}
		return previousRemove(n)
	}

	if err := removeCreatedMapping(name, "CRYPT-LUKS2-ours", fakeDefaultDevNo); err != nil {
		t.Fatalf("removeCreatedMapping = %v; a target that is already gone is the success case", err)
	}
	if removeCalls != 1 {
		t.Fatalf("remove was issued %d times against a target that had vanished", removeCalls)
	}
}

// TestLockWillNotRemoveAMappingThatChangedIdentityMidRetry is the same defect as
// the rollback's, on the ordinary close path -- found by the same local review
// one round later, because fixing it in one place did not fix it in the other
// (#122).
//
// Lock captured the target's identity to clean up its device nodes, then
// retried the removal BY NAME. During a backoff another actor can take the
// name, and removing that mapping would destroy a plaintext device this caller
// never opened.
func TestLockWillNotRemoveAMappingThatChangedIdentityMidRetry(t *testing.T) {
	withDevDir(t, t.TempDir())

	const name = "recycled-on-close"
	fake := newFakeDeviceMapper()
	fake.targets[name] = "CRYPT-LUKS2-ours"
	fake.install(t)
	recordRetryWaits(t)

	removeCalls := 0
	previousRemove := dm.remove
	t.Cleanup(func() { dm.remove = previousRemove })
	dm.remove = func(n string) error {
		removeCalls++
		if removeCalls == 1 {
			fake.targets[name] = "CRYPT-LUKS2-SOMEONE-ELSES"
			return os.NewSyscallError("dm ioctl", unix.EBUSY)
		}
		return previousRemove(n)
	}

	if err := Lock(name); err != nil {
		t.Fatalf("Lock = %v; the mapping it was asked to close is gone, which is the goal", err)
	}
	if uuid, live := fake.targets[name]; !live || uuid != "CRYPT-LUKS2-SOMEONE-ELSES" {
		t.Fatalf("Lock removed a mapping that was not the one it inspected: targets[%q] = %q, live=%v", name, uuid, live)
	}
	if removeCalls != 1 {
		t.Fatalf("remove was issued %d times; the second attempt must be refused by the identity re-check", removeCalls)
	}
}

// The dm UUID is CRYPT-LUKS2-<header uuid>-<name>, so it is a function of the
// VOLUME and the NAME rather than of the activation. A mapping of the same
// volume recreated under the same name during a backoff therefore carries an
// IDENTICAL UUID, and a check on the UUID alone cannot tell it from ours
// (found on the fourth local review round of #122).
//
// These two pin the DevNo half of the comparison. They narrow the window; they
// do not close it, because dm minors are eventually reused -- the residue is
// the pre-existing inspect-then-remove race, not something the retry added.

// devNoAwareFake installs a fake whose infoByName reports a per-name device
// number the test can change, so a recreation can be modeled without
// pretending the UUID changes -- which is exactly what the real deterministic
// UUID would NOT do.
func devNoAwareFake(t *testing.T, name, uuid string, devNo *uint64) *fakeDeviceMapper {
	t.Helper()

	fake := newFakeDeviceMapper()
	fake.targets[name] = uuid
	fake.install(t)

	t.Cleanup(func() {})
	dm.infoByName = func(n string) (*devmapper.DeviceInfo, error) {
		u, live := fake.targets[n]
		if !live {
			return nil, os.NewSyscallError("dm ioctl", unix.ENXIO)
		}
		return &devmapper.DeviceInfo{Name: n, UUID: u, DevNo: *devNo}, nil
	}
	return fake
}

func TestLockWillNotRemoveARecreatedMappingWithTheSameUUID(t *testing.T) {
	withDevDir(t, t.TempDir())

	const name = "same-uuid-new-activation"
	const uuid = "CRYPT-LUKS2-deterministic-same-uuid-new-activation"
	devNo := uint64(0xfe00)
	fake := devNoAwareFake(t, name, uuid, &devNo)
	recordRetryWaits(t)

	removeCalls := 0
	previousRemove := dm.remove
	t.Cleanup(func() { dm.remove = previousRemove })
	dm.remove = func(n string) error {
		removeCalls++
		if removeCalls == 1 {
			// Another actor closes it and re-opens THE SAME VOLUME under THE
			// SAME NAME: identical UUID, new activation.
			devNo = 0xfe01
			return os.NewSyscallError("dm ioctl", unix.EBUSY)
		}
		return previousRemove(n)
	}

	if err := Lock(name); err != nil {
		t.Fatalf("Lock = %v; the activation it was closing is gone", err)
	}
	if _, live := fake.targets[name]; !live {
		t.Fatal("Lock removed a mapping that was a different activation with the same UUID")
	}
	if removeCalls != 1 {
		t.Fatalf("remove was issued %d times; the device number must stop the second attempt", removeCalls)
	}
}

func TestRollbackWillNotRemoveARecreatedMappingWithTheSameUUID(t *testing.T) {
	withDevDir(t, t.TempDir())

	const name = "rollback-same-uuid"
	const uuid = "CRYPT-LUKS2-deterministic-rollback-same-uuid"
	devNo := uint64(0xfe00)
	fake := devNoAwareFake(t, name, uuid, &devNo)
	recordRetryWaits(t)

	removeCalls := 0
	previousRemove := dm.remove
	t.Cleanup(func() { dm.remove = previousRemove })
	dm.remove = func(n string) error {
		removeCalls++
		if removeCalls == 1 {
			devNo = 0xfe01
			return os.NewSyscallError("dm ioctl", unix.EBUSY)
		}
		return previousRemove(n)
	}

	if err := removeCreatedMapping(name, uuid, fakeDefaultDevNo); err != nil {
		t.Fatalf("removeCreatedMapping = %v; the activation it created is gone", err)
	}
	if _, live := fake.targets[name]; !live {
		t.Fatal("the rollback removed a different activation carrying the same UUID")
	}
	if removeCalls != 1 {
		t.Fatalf("remove was issued %d times; the device number must stop the second attempt", removeCalls)
	}
}

// The two cells the coverage matrix was missing.
//
// Answering "how many parallel paths does this change touch, and does a test
// cover each?" from the DIFF rather than from memory found them: this change
// has two call sites and six behaviors, and two of the twelve cells had no
// test. Both are cases where a path was covered on one site and assumed on the
// other -- the same asymmetry that made round 3 of this branch's review
// necessary, one level down.

// TestLockStopsWhenTheTargetDisappearsMidRetry is Lock's half of the vanished
// case. The rollback had it; Lock did not.
func TestLockStopsWhenTheTargetDisappearsMidRetry(t *testing.T) {
	withDevDir(t, t.TempDir())

	const name = "vanishes-on-close"
	fake := newFakeDeviceMapper()
	fake.targets[name] = "CRYPT-LUKS2-ours"
	fake.install(t)
	recordRetryWaits(t)

	removeCalls := 0
	previousRemove := dm.remove
	t.Cleanup(func() { dm.remove = previousRemove })
	dm.remove = func(n string) error {
		removeCalls++
		if removeCalls == 1 {
			delete(fake.targets, name) // somebody else finished the job
			return os.NewSyscallError("dm ioctl", unix.EBUSY)
		}
		return previousRemove(n)
	}

	if err := Lock(name); err != nil {
		t.Fatalf("Lock = %v; a mapping that is already gone is the success case", err)
	}
	if removeCalls != 1 {
		t.Fatalf("remove was issued %d times against a target that had vanished", removeCalls)
	}
}

// TestRollbackDoesNotRetryWhatCannotClear is the rollback's half of the
// errno-selectivity case. The existing table drives Lock only, so the rollback's
// budget could have been spent on failures that can never clear without any
// test noticing.
func TestRollbackDoesNotRetryWhatCannotClear(t *testing.T) {
	for _, errno := range []unix.Errno{unix.EPERM, unix.EINVAL, unix.EIO} {
		t.Run(errno.Error(), func(t *testing.T) {
			withDevDir(t, t.TempDir())

			const name = "rollback-other-failure"
			const uuid = "CRYPT-LUKS2-rollback-other"
			fake := newFakeDeviceMapper()
			fake.targets[name] = uuid
			fake.install(t)

			calls := 0
			previous := dm.remove
			t.Cleanup(func() { dm.remove = previous })
			dm.remove = func(string) error {
				calls++
				return os.NewSyscallError("dm ioctl", errno)
			}
			waits := recordRetryWaits(t)

			err := removeCreatedMapping(name, uuid, fakeDefaultDevNo)
			if err == nil {
				t.Fatalf("the rollback reported success on %v", errno)
			}
			// Still fails closed, whatever the errno.
			if !errors.Is(err, ErrMappingStillLive) {
				t.Fatalf("removeCreatedMapping = %v, want ErrMappingStillLive", err)
			}
			if calls != 1 {
				t.Fatalf("remove was attempted %d times for %v; only EBUSY is retryable", calls, errno)
			}
			if len(waits.Waits()) != 0 {
				t.Fatalf("backoff was spent on %v, which cannot clear", errno)
			}
		})
	}
}

// TestRollbackClearsAStaleInspectionError is the regression for a transient
// EBUSY on one inspection surviving a LATER attempt that inspected and removed
// successfully. inspectErr was assigned and never reset, so the result switch
// reported ErrMappingStillLive for a target it had just confirmed gone -- and
// skipped node cleanup on the strength of it. The caller was told a plaintext
// mapping might still exist when it demonstrably did not.
//
// The assertion is on the RESULT, not on the call count: both orderings return
// through the same path, and only the verdict distinguishes them.
func TestRollbackClearsAStaleInspectionError(t *testing.T) {
	withDevDir(t, t.TempDir())

	const name = "stale-inspect-err"
	const uuid = "CRYPT-LUKS2-stale-inspect-err"

	fake := newFakeDeviceMapper()
	fake.targets[name] = uuid
	fake.install(t)

	inspects := 0
	dm.infoByName = func(n string) (*devmapper.DeviceInfo, error) {
		inspects++
		if inspects == 1 {
			// Transient: exactly the condition the retry exists for.
			return nil, os.NewSyscallError("dm ioctl", unix.EBUSY)
		}
		u, live := fake.targets[n]
		if !live {
			return nil, os.NewSyscallError("dm ioctl", unix.ENXIO)
		}
		return &devmapper.DeviceInfo{Name: n, UUID: u, DevNo: 0xfe00}, nil
	}
	recordRetryWaits(t)

	if err := removeCreatedMapping(name, uuid, fakeDefaultDevNo); err != nil {
		t.Fatalf("removeCreatedMapping = %v, want success: the second attempt "+
			"inspected and removed the target, so a stale inspection error from "+
			"the first attempt must not decide the result", err)
	}
	if inspects < 2 {
		t.Fatalf("the transient inspection error was not retried (%d inspections); "+
			"this test would pass vacuously", inspects)
	}
	if _, live := fake.targets[name]; live {
		t.Fatalf("the target %q is still live, so the removal did not happen "+
			"and this test is asserting the wrong thing", name)
	}
}

// TestLockRefusesToRemoveWhenIdentityCannotBeEstablished is the regression for
// Lock retrying BY NAME when its identity lookup failed. IsUnlocked can succeed
// through its device-node fallback, so a failed inspection is reachable in
// ordinary operation; the old code discarded that error, left info nil, and the
// retry then removed whatever held the name -- across the full budget. Remove
// must never be called.
func TestLockRefusesToRemoveWhenIdentityCannotBeEstablished(t *testing.T) {
	withDevDir(t, t.TempDir())

	const name = "identity-unknown"

	fake := newFakeDeviceMapper()
	fake.targets[name] = "CRYPT-LUKS2-identity-unknown"
	fake.install(t)

	// IsUnlocked inspects first and would short-circuit on a failure, so the
	// first call succeeds and the IDENTITY CAPTURE fails. That is the same code
	// path as the device-node fallback Codex describes -- IsUnlocked says the
	// mapping exists, the identity inspection then fails -- and it is reachable
	// without root. Creating the real fallback needs mknod, and a test that
	// cannot run unprivileged would be skipped, which this repository does not
	// permit.
	inspects := 0
	dm.infoByName = func(n string) (*devmapper.DeviceInfo, error) {
		inspects++
		if inspects == 1 {
			return &devmapper.DeviceInfo{Name: n, UUID: fake.targets[n], DevNo: 0xfe00}, nil
		}
		return nil, os.NewSyscallError("dm ioctl", unix.EPERM)
	}
	removes := 0
	previous := dm.remove
	t.Cleanup(func() { dm.remove = previous })
	dm.remove = func(string) error {
		removes++
		return nil
	}
	recordRetryWaits(t)

	err := Lock(name)
	if err == nil {
		t.Fatal("Lock reported success without ever establishing the mapping identity")
	}
	if removes != 0 {
		t.Fatalf("remove was called %d times with an unknown identity; "+
			"that is the race the identity check exists to prevent", removes)
	}
	if errors.Is(err, ErrVolumeNotUnlocked) {
		t.Fatalf("Lock = %v, want an inspection failure: EPERM is not "+
			"'nothing to close', and reporting it as such sends an operator to "+
			"the wrong place", err)
	}
	if inspects < 2 {
		t.Fatalf("the identity capture was never reached (%d inspections); "+
			"this test would pass for the wrong reason", inspects)
	}
}

// TestLockRidesOutATransientIdentityLookupFailure is the regression for a fix
// that traded one defect for another. Requiring a successful identity capture
// before the retry stopped the remove-by-name race -- and made Lock fail fast on
// a transient EBUSY from that very lookup, which is the flakiness this function
// exists to absorb. The lookup uses the same device-mapper control path as the
// close, so it is subject to the same transient hold.
//
// The mapping must end up CLOSED, not merely error-free: an assertion that Lock
// returned nil would also pass if the retry gave up quietly.
func TestLockRidesOutATransientIdentityLookupFailure(t *testing.T) {
	withDevDir(t, t.TempDir())

	const name = "transient-identity"
	const uuid = "CRYPT-LUKS2-transient-identity"

	fake := newFakeDeviceMapper()
	fake.targets[name] = uuid
	fake.install(t)

	inspects := 0
	dm.infoByName = func(n string) (*devmapper.DeviceInfo, error) {
		inspects++
		// 1: IsUnlocked. 2: the identity capture, transiently busy. 3+: fine.
		if inspects == 2 {
			return nil, os.NewSyscallError("dm ioctl", unix.EBUSY)
		}
		u, live := fake.targets[n]
		if !live {
			return nil, os.NewSyscallError("dm ioctl", unix.ENXIO)
		}
		return &devmapper.DeviceInfo{Name: n, UUID: u, DevNo: 0xfe00}, nil
	}
	recordRetryWaits(t)

	if err := Lock(name); err != nil {
		t.Fatalf("Lock = %v, want success: a transient EBUSY from the identity "+
			"lookup is the condition this path absorbs, not a reason to leave "+
			"the mapping live", err)
	}
	if inspects < 3 {
		t.Fatalf("the transient lookup failure was not retried (%d inspections); "+
			"this test would pass vacuously", inspects)
	}
	if _, live := fake.targets[name]; live {
		t.Fatalf("Lock returned success but %q is still live", name)
	}
}

// TestDeviceMapperWaitsEndAtTheirDeadlineOnALoadedHost: every device-mapper
// wait is bounded by a DEADLINE on the clock, not by a count of sleeps. On a
// loaded host a sleep overruns what it was asked for; the waits used to count
// polls (30 for udev's node, 50 for a verified node) or subtract the sleeps
// they REQUESTED from a budget, so each overrun stretched the wait further --
// thirty overrunning polls of a 3-second wait took thirty times the overrun
// longer. Here each sleep overruns by a full second, and every wait still
// ends within one overrun of its bound.
func TestDeviceMapperWaitsEndAtTheirDeadlineOnALoadedHost(t *testing.T) {
	const overrun = time.Second
	loaded := func(t *testing.T) *clock.Fake {
		clk := clock.NewFake(t)
		clk.OnWait(func(time.Time) { clk.Advance(overrun) })
		previous := dmClock
		t.Cleanup(func() { dmClock = previous })
		dmClock = clk
		return clk
	}

	t.Run("busy retry", func(t *testing.T) {
		clk := loaded(t)
		_, err := retryWhileBusy(func() error { return os.NewSyscallError("dm ioctl", unix.EBUSY) })
		if !errors.Is(err, unix.EBUSY) {
			t.Fatalf("retryWhileBusy = %v, want the last EBUSY", err)
		}
		if clk.Elapsed() > dmRemoveRetryBudget+overrun {
			t.Fatalf("a %v retry budget took %v", dmRemoveRetryBudget, clk.Elapsed())
		}
	})

	t.Run("node polls", func(t *testing.T) {
		clk := loaded(t)
		if pollUntil(deviceReadyTimeout, deviceReadyPollInterval, func() bool { return false }) {
			t.Fatal("pollUntil reported a condition that never held")
		}
		if clk.Elapsed() > deviceReadyTimeout+overrun {
			t.Fatalf("a %v node wait took %v over %d sleeps", deviceReadyTimeout, clk.Elapsed(), len(clk.Waits()))
		}
	})
}
