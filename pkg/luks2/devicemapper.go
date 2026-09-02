// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/anatol/devmapper.go"
	"golang.org/x/sys/unix"
)

// The seam between this package and the kernel's device mapper.
//
// Every dm operation goes through the deviceMapper value below rather than
// calling github.com/anatol/devmapper.go directly. That exists for one reason:
// the failure this package must handle correctly -- a dm-crypt target that is
// LIVE while Unlock reports failure -- cannot be produced any other way in a
// test. Real dm activation needs root, the unprivileged test account cannot
// create a target at all, and a failure that only ever runs in a
// root-and-real-kernel integration environment is a failure nothing checks.
//
// So the injection point is here, at the boundary, and the tests drive the
// exact sequence the kernel and udev produce: create succeeds, readiness does
// not.
type deviceMapper struct {
	createAndLoad func(name, uuid string, flags uint32, tables ...devmapper.Table) error
	infoByName    func(name string) (*devmapper.DeviceInfo, error)
	remove        func(name string) error
	ensureNode    func(name string) error
	waitReady     func(name string) error
}

// dm is the live device mapper. It is a package-level value rather than a
// parameter threaded through Unlock because every consumer of this library
// wants the real kernel and only the tests want anything else; a constructor
// argument would put that choice in every caller's signature to serve none of
// them.
var dm = liveDeviceMapper()

// liveDeviceMapper returns the real implementation.
func liveDeviceMapper() deviceMapper {
	return deviceMapper{
		createAndLoad: devmapper.CreateAndLoad,
		infoByName:    devmapper.InfoByName,
		remove:        devmapper.Remove,
		ensureNode:    ensureDeviceNode,
		waitReady:     waitForDeviceReady,
	}
}

// removeCreatedMapping tears down a dm target that THIS unlock created, and
// refuses to touch anything else.
//
// # Why the identity check is the whole point
//
// A rollback that removes by name alone is a denial of service waiting to
// happen. dm names are a flat, process-wide namespace: between this unlock
// creating "cryptroot" and its readiness check failing, another process can
// remove that target and create its own under the same name. Removing "the
// target called cryptroot" would then take down a mapping this call never
// created and has no business closing -- and it would do so on an ERROR path,
// where the operator is already reading a failure message and would have no
// reason to suspect a second volume just went away.
//
// So the target is identified by the dm UUID this unlock generated
// ("CRYPT-LUKS2-<header uuid>-<name>"), which devmapper.Create sets in the
// DM_DEV_CREATE ioctl itself, so a target either carries it or was not created
// by this call. A different UUID under our name means our target is already
// gone and someone else's is there: nothing to clean up, and nothing that may
// be touched.
//
// The CHECK is not atomic with the removal, and this comment does not claim it
// is. Between the inspection and DM_DEV_REMOVE another process can remove our
// target and create its own under the same name, and the remove would then take
// theirs. Closing it needs a remove that takes the expected UUID as a
// precondition, which the dm ioctl interface does not offer; devmapper exposes
// no such call either. The window is bounded by two consecutive ioctls and
// requires a name collision on top of a race, which is why it is documented
// rather than worked around -- but it is a real residual, not an absent one.
//
// # What each return means
//
//   - nil: nothing of ours is live. It was removed, or it was already gone, or
//     the name now belongs to a mapping this call did not create.
//   - non-nil, matching ErrMappingStillLive: a plaintext target created by this
//     unlock MAY STILL BE LIVE and the caller must treat the volume as
//     partially open. This is deliberately returned when the state cannot be
//     CONFIRMED, not only when removal is known to have failed -- silence about
//     an unverifiable plaintext mapping is the failure mode this whole function
//     exists to prevent.
func removeCreatedMapping(name, uuid string) error {
	var (
		// info is the inspection belonging to the attempt that actually
		// removed, so the node cleanup below uses the identity it removed.
		info *devmapper.DeviceInfo
		// inspectErr distinguishes "could not look" from "could not remove".
		// They send an operator to different places, so they keep different
		// messages.
		inspectErr error
		// nothingToDo covers the states where the right action is to stop and
		// report success: the target is already gone, it is no longer ours, or
		// it was recreated as a different activation. None is an error.
		nothingToDo bool
		// firstDevNo pins the activation seen on the first attempt, so a
		// recreated mapping is not mistaken for the original.
		firstDevNo uint64
		seenDevNo  bool
	)

	// The identity is re-confirmed before EVERY attempt, inside the retried
	// unit. During a backoff another actor can remove our target and create a
	// different mapping under the same name; removing THAT would be removing
	// someone else's plaintext device, which is the exact harm the UUID check
	// exists to prevent. Checking once outside the loop would leave the check
	// guarding only the first of up to eight attempts.
	//
	// Retried, but the verdict on exhaustion is UNCHANGED. A transient udev
	// hold no longer raises a false "may still be live" alarm -- an alarm an
	// operator learns to ignore is worse than no alarm -- while a target that
	// genuinely cannot be removed still fails closed, which is the contract
	// this function exists for (#122).
	attempts, err := retryWhileBusy(func() error {
		current, err := dm.infoByName(name)
		// Cleared on EVERY entry, so it only ever describes THIS attempt. It was
		// assigned and never reset, so a transient EBUSY on one inspection
		// survived a later attempt that inspected AND removed successfully: the
		// switch below then reported ErrMappingStillLive for a target confirmed
		// gone, skipped node cleanup, and told the caller a plaintext mapping
		// might still exist. Keeping the invariant local to the loop is what
		// makes it hold for every future attempt too.
		inspectErr = nil
		if err != nil {
			if isNoSuchDevice(err) {
				// Already gone. The common case when devmapper's own
				// CreateAndLoad cleaned up after a failed table load, and also
				// what a competing remover leaves behind mid-backoff.
				nothingToDo = true
				return nil
			}
			inspectErr = err
			return err
		}
		if current.UUID != uuid {
			// Not ours. Leaving it alone is the only safe action; see above.
			nothingToDo = true
			return nil
		}
		// Same volume, same name, DIFFERENT activation. The dm UUID is
		// CRYPT-LUKS2-<header uuid>-<name> and so is identical for a mapping
		// of the same volume recreated under the same name mid-backoff; DevNo
		// is the only instance-ish discriminator the API offers. It narrows
		// the window without closing it -- minors are eventually reused -- and
		// what remains is the pre-existing inspect-then-remove race rather
		// than anything the retry added.
		if seenDevNo && current.DevNo != firstDevNo {
			nothingToDo = true
			return nil
		}
		firstDevNo, seenDevNo = current.DevNo, true
		info = current
		return dm.remove(name)
	})

	switch {
	case nothingToDo:
		return nil
	case inspectErr != nil:
		return fmt.Errorf("%w: device-mapper target %q could not be inspected after a failed unlock (%v), so it cannot be confirmed removed; check for it with: dmsetup info %s",
			ErrMappingStillLive, name, inspectErr, name)
	case err != nil:
		return fmt.Errorf("%w: the plaintext device-mapper target %q created by this unlock could not be removed after %d attempt(s) over %v (%v) and is STILL LIVE; close it with: luks close %s",
			ErrMappingStillLive, name, attempts, dmRemoveRetryBudget, err, name)
	}

	removeMappingNodes(name, info)
	return nil
}

// Removing a device-mapper target intermittently fails with EBUSY because
// something holds it open for a moment after the activity that preceded the
// close. In practice that is a process started by a udev rule scanning the
// device it has just been told about (#122, traced from go-blockstore #45,
// where it cost roughly one failure per full integration run).
//
// # The remedy is device-mapper's own, not ours
//
// dmsetup(8) documents this exact condition and ships a flag for it:
//
//	remove [--retry] ... "If an attempt to remove a device fails, perhaps
//	because a process run from a udev rule is temporarily using the device,
//	the --retry option will cause the operation to be retried for a few
//	seconds before failing."
//
// So the diagnosis is not a guess and the budget below is anchored to "a few
// seconds" rather than to a number that felt right.
//
// # Only EBUSY
//
// Nothing else here is transient. A device that is gone (ENXIO/ENODEV) will
// still be gone; a refusal on permissions or a bad argument will be refused
// again. Retrying those would spend the whole budget turning a fast, correct
// failure into a slow one -- so they return immediately and the budget is
// reserved for the one condition that clears itself.
const (
	// dmRemoveRetryBudget is the total time spent waiting for a hold to clear.
	//
	// It is the bound that keeps a genuine holder -- a mounted filesystem, an
	// open fd, a stacked target -- from becoming a hang. A caller that waits
	// three seconds and is then told precisely what is wrong is better served
	// than one that waits indefinitely, and far better than one that fails
	// instantly on a hold that would have cleared in 20 milliseconds.
	dmRemoveRetryBudget = 3 * time.Second

	// dmRemoveRetryInitialDelay is the first backoff, doubling thereafter.
	//
	// Small, because the hold this exists for is short: the common case is one
	// sleep and one successful retry. Doubling keeps the attempt count low if
	// it turns out not to be short, so a genuinely held device costs a handful
	// of ioctls rather than hundreds.
	dmRemoveRetryInitialDelay = 20 * time.Millisecond
)

// retryWait is the backoff sleep, as a seam so tests assert the retry's BUDGET
// instead of spending it. Same idiom as dm, devDir and nodeRdev.
//
// A test that really slept would take a hundred times as long to assert the
// same property, and would be flaky on a loaded runner besides.
var retryWait = time.Sleep

// retryWhileBusy runs attempt until it stops reporting EBUSY or the budget is
// spent, and reports how many times it ran.
//
// # The ATTEMPT is the caller's whole unit of work, not just the removal
//
// That is the point of the signature, and it was a review finding rather than
// foresight. An earlier version retried dm.remove(name) directly, with the
// rollback's identity check left outside the loop -- so during a backoff another
// actor could remove our target and create a DIFFERENT mapping under the same
// name, and the next attempt would remove theirs. The single-shot code had only
// a one-ioctl window for that; retrying by name alone widened it to the whole
// budget. Whatever a caller must be sure of before removing has to be inside
// the thing being retried.
//
// It reports the LAST error and leaves the meaning to the caller, because the
// two callers face the same errno and owe the operator different answers: Lock
// is an ordinary close and says the device is held (ErrMappingBusy), while
// removeCreatedMapping is the rollback after a failed unlock and must still say
// the plaintext target MAY STILL BE LIVE (ErrMappingStillLive).
func retryWhileBusy(attempt func() error) (attempts int, err error) {
	remaining := dmRemoveRetryBudget
	delay := dmRemoveRetryInitialDelay

	for {
		attempts++
		err = attempt()
		if err == nil || !errors.Is(err, unix.EBUSY) {
			return attempts, err
		}
		if remaining <= 0 {
			return attempts, err
		}
		// The LAST wait is clipped to whatever is left, rather than the loop
		// giving up as soon as the next doubling would overshoot.
		//
		// Giving up early spends 20+40+...+1280 = 2.54s of a 3s budget and then
		// reports "over 3s" -- so a hold that would have cleared in the final
		// 460ms still fails, and the error states a duration that was never
		// spent. An error that overstates what was tried is the same defect as
		// a suppression whose justification was never true: it stops the next
		// reader checking. Caught in review of #122.
		if delay > remaining {
			delay = remaining
		}
		retryWait(delay)
		remaining -= delay
		delay *= 2
	}
}

// devDir is the directory holding device nodes. It is a variable so the node
// bookkeeping can be tested unprivileged: the real /dev cannot be written to as
// an ordinary user, and a test that needed root would not run on the way in.
var devDir = "/dev"

// dmNodePath is the /dev/dm-N path for a minor, and mapperNodePath the
// /dev/mapper/<name> entry. Every caller goes through these rather than
// formatting the path itself, so the four places that build them cannot drift.
func dmNodePath(minor uint32) string    { return fmt.Sprintf("%s/dm-%d", devDir, minor) }
func mapperNodePath(name string) string { return fmt.Sprintf("%s/mapper/%s", devDir, name) }
func mapperDir() string                 { return devDir + "/mapper" }

// decodeDevNo splits a device-mapper device number into its major and minor.
//
// It delegates to unix.Major/unix.Minor, which are the exact inverses of the
// unix.Mkdev this package uses to CREATE nodes. That pairing is the point: the
// arithmetic was previously hand-rolled at four sites in THREE different forms
// -- the full encoding twice, `DevNo & 0xFF` in the node removal, and
// `DevNo & 0xFFFFFFFF` in the mapped-path lookup -- so a node could be created
// under one name and looked for, or unlinked, under another.
//
// The truncating form is wrong for every minor above 255: a dm minor of 300
// came out as 44. dm minors above 255 are routine on any host running LVM or
// Docker.
func decodeDevNo(devNo uint64) (major, minor uint32) {
	return unix.Major(devNo), unix.Minor(devNo)
}

// nodeRdev reports the device number of the node at path. It is a variable for
// the same reason devDir is.
var nodeRdev = statRdev

// statRdev stats path and returns its raw device number. It FOLLOWS symlinks,
// because /dev/mapper/<name> is one and what matters is the device it names.
func statRdev(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Rdev), nil
}

// removeMappingNodes deletes the device nodes a mapping left behind, and ONLY
// those that are still that mapping's.
//
// It is shared with Lock so that a rolled-back unlock leaves the filesystem in
// the same state a deliberate close does. That symmetry matters because
// ensureDeviceNode CREATES nodes on the unlock path: a rollback that removed
// the dm target but not the nodes it had just made would leave a dangling
// /dev/mapper entry pointing at a device that no longer exists, which is
// exactly the stale symlink IsUnlocked has to work around.
//
// # Why each node is identified before it is unlinked
//
// A path is not an identity. Two things make the name insufficient: the minor
// is decoded from a device number, so a decoding bug aims the unlink at some
// other device's node; and dm minors are RECYCLED, so /dev/dm-7 may belong to a
// device created after ours went away. Both produce the same outcome -- a node
// belonging to something else is silently unlinked -- and it happens on
// Unlock's error path, where an operator is reading a failure message and has
// no reason to connect a vanished device to what they just ran.
//
// So each node is stat'd and its rdev compared with the DeviceInfo captured
// before the target was removed. Only a match is unlinked.
//
// The one deliberate exception is a DANGLING /dev/mapper/<name> symlink. It
// cannot be stat'd, so it cannot be identified that way, but it names our
// mapping and points at nothing: leaving it is leaving the stale entry this
// function exists to clear. A dangling symlink also cannot be mistaken for
// another live device, which is what makes the exception safe.
//
// Errors from the unlinks themselves stay ignored on purpose: a node may never
// have existed or may already have been reaped by udev, and neither changes the
// outcome the caller cares about, which is whether the dm target is gone.
func removeMappingNodes(name string, info *devmapper.DeviceInfo) {
	// The mapper entry goes FIRST, while its target still resolves. Removing
	// the dm node first would turn this symlink into a dangling one and force
	// it down the exception path for no reason.
	mapperPath := mapperNodePath(name)
	if isOurNode(mapperPath, info) || isDanglingSymlink(mapperPath) {
		_ = os.Remove(mapperPath)
	}

	if info == nil {
		return
	}
	_, minor := decodeDevNo(info.DevNo)
	dmPath := dmNodePath(minor)
	if isOurNode(dmPath, info) {
		_ = os.Remove(dmPath)
	}
}

// isOurNode reports whether the node at path is the device info describes.
//
// A path that cannot be stat'd is NOT ours as far as this is concerned: the
// answer is unknown, and unlinking on an unknown is the failure mode being
// avoided.
func isOurNode(path string, info *devmapper.DeviceInfo) bool {
	if info == nil {
		return false
	}
	rdev, err := nodeRdev(path)
	if err != nil {
		return false
	}
	major, minor := decodeDevNo(info.DevNo)
	return rdev == unix.Mkdev(major, minor)
}

// isDanglingSymlink reports whether path is a symlink whose target does not
// resolve. Lstat sees the link itself; Stat follows it and fails when the
// target is gone.
func isDanglingSymlink(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return false
	}
	_, err = os.Stat(path)
	return err != nil
}

// isNoSuchDevice reports whether err is the kernel saying the dm target does
// not exist, as opposed to any other reason an inspection can fail.
//
// The distinction decides whether removeCreatedMapping reports a possible live
// plaintext mapping, so it is drawn on the ERRNO rather than on the message: a
// permission failure, a missing /dev/mapper/control or an interrupted syscall
// all leave the target's existence unknown and must not be read as absence.
// devmapper wraps its errno in *os.SyscallError, which errors.Is unwraps.
//
// ENOENT is deliberately NOT in this set, even though it is the obvious
// "does not exist" errno. Here it comes from opening /dev/mapper/control, not
// from the kernel's answer about the target -- an absent control node means dm
// cannot be QUERIED, while any target it already holds stays live. Reading that
// as absence would report a plaintext mapping gone on precisely the evidence
// that nothing can be known about it. The kernel's answer for an unknown dm
// device is ENXIO.
func isNoSuchDevice(err error) bool {
	return errors.Is(err, unix.ENXIO) || errors.Is(err, unix.ENODEV)
}
