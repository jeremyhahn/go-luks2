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
	"github.com/jeremyhahn/go-luks2/internal/clock"
	dmpkg "github.com/jeremyhahn/go-luks2/internal/dm"
	"github.com/jeremyhahn/go-luks2/internal/errs"
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
//
// The mechanism behind each field's live default -- the ioctl, the busy
// retry, the node placement and readiness wait -- lives in internal/dm, which
// this package calls into with its own seams (dmClock, devDir, blockNodeRdev,
// makeBlockNode) passed explicitly: internal/dm has no package-level state of
// its own (#265, H7).
type deviceMapper struct {
	// create makes an EMPTY, suspended target under name and uuid and returns
	// the device number the kernel assigned it, taken from the create ioctl's
	// own reply. That number is this activation's identity from then on: every
	// later step, and the rollback, is pinned to it (#250, C4).
	create func(name, uuid string) (uint64, error)
	// load and resume are the second and third steps of an activation.
	load   func(name string, table devmapper.Table) error
	resume func(name string) error

	infoByName func(name string) (*devmapper.DeviceInfo, error)
	remove     func(name string) error

	// ensureNode and waitReady make /dev/dm-N and /dev/mapper/<name> name the
	// device info describes, replacing a stale node rather than trusting it.
	ensureNode func(name string, info *devmapper.DeviceInfo) error
	waitReady  func(name string, info *devmapper.DeviceInfo) error
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
		create:     createTarget,
		load:       func(name string, table devmapper.Table) error { return devmapper.Load(name, 0, table) },
		resume:     devmapper.Resume,
		infoByName: devmapper.InfoByName,
		remove:     devmapper.Remove,
		ensureNode: ensureDeviceNode,
		waitReady:  waitForDeviceReady,
	}
}

// createTarget issues DM_DEV_CREATE and returns the device number from the
// kernel's reply. The ioctl itself lives in internal/dm; this is the
// pkg/luks2-level translation of its one distinguished failure (a name or
// UUID that does not fit the ioctl) onto ErrInvalidMappingName, which is also
// what ValidateMappingName reports for the same condition.
func createTarget(name, uuid string) (uint64, error) {
	devNo, err := dmpkg.CreateTarget(name, uuid)
	if errors.Is(err, dmpkg.ErrNameTooLong) {
		return 0, &errs.Error{Kind: ErrInvalidMappingName,
			Detail: "the device-mapper name or UUID does not fit the create ioctl without being cut"}
	}
	return devNo, err
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
// ("CRYPT-LUKS2-<header uuid>-<name>") AND by the device number the create
// ioctl returned. The UUID alone is not enough: it is a function of the volume
// and the name, so a concurrent unlock of the same volume under the same name
// carries an identical one. That is exactly how a losing concurrent Unlock
// used to remove the WINNER's live mapping (#250, C4). The device number is
// the activation's own, captured from the kernel's reply to this call's
// create, so a target with another number was not created by this call.
//
// The rollback is only ever reached after this call's create SUCCEEDED. A
// create that failed -- the name is taken -- created nothing and has nothing to
// undo.
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
func removeCreatedMapping(name, uuid string, devNo uint64) error {
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
		// CRYPT-LUKS2-<header uuid>-<name> and so is identical for a concurrent
		// or recreated mapping of the same volume under the same name; the
		// device number this call's create returned is what tells them apart.
		// The removal itself is still by name, so a recreation that reuses
		// the same minor between this inspection and DM_DEV_REMOVE remains the
		// residual described above.
		if current.DevNo != devNo {
			nothingToDo = true
			return nil
		}
		info = current
		return dm.remove(name)
	})

	switch {
	case nothingToDo:
		return nil
	case inspectErr != nil:
		return &errs.Error{
			Kind: ErrMappingStillLive,
			Detail: fmt.Sprintf("device-mapper target %q could not be inspected after a failed unlock (%v), so it cannot be confirmed removed; check for it with: dmsetup info %s",
				name, inspectErr, name),
		}
	case err != nil:
		return &errs.Error{
			Kind: ErrMappingStillLive,
			Detail: fmt.Sprintf("the plaintext device-mapper target %q created by this unlock could not be removed after %d attempt(s) over %v (%v) and is STILL LIVE; close it with: luks2 close %s",
				name, attempts, dmRemoveRetryBudget, err, name),
		}
	}

	removeMappingNodes(name, info)
	return nil
}

// dmRemoveRetryBudget and dmRemoveRetryInitialDelay mirror internal/dm's
// RetryWhileBusy budget, so this package's own error messages (removeCreatedMapping,
// Lock) can quote the budget that was actually spent without a second
// definition to drift out of sync.
const (
	dmRemoveRetryBudget       = dmpkg.RemoveRetryBudget
	dmRemoveRetryInitialDelay = dmpkg.RemoveRetryInitialDelay
)

// dmClock is the clock every device-mapper wait runs on -- the busy retry and
// the two node waits -- so tests assert a wait's BUDGET on a clock they
// control instead of spending it. Same idiom as dm, devDir and nodeRdev, and
// the same clock seam the lock and loop-device waits use (#233).
//
// A test that really slept would take a hundred times as long to assert the
// same property, and would be flaky on a loaded runner besides.
var dmClock clock.Clock = clock.System{}

// retryWhileBusy runs attempt until it stops reporting EBUSY or the budget is
// spent on dmClock, and reports how many times it ran. The retry loop itself
// lives in internal/dm; see dmpkg.RetryWhileBusy.
func retryWhileBusy(attempt func() error) (attempts int, err error) {
	return dmpkg.RetryWhileBusy(dmClock, attempt)
}

// devDir is the directory holding device nodes. It is a variable so the node
// bookkeeping can be tested unprivileged: the real /dev cannot be written to as
// an ordinary user, and a test that needed root would not run on the way in.
var devDir = "/dev"

// dmNodePath is the /dev/dm-N path for a minor, and mapperNodePath the
// /dev/mapper/<name> entry. Every caller goes through these rather than
// formatting the path itself, so the four places that build them cannot drift.
func dmNodePath(minor uint32) string    { return dmpkg.NodePath(devDir, minor) }
func mapperNodePath(name string) string { return dmpkg.MapperPath(devDir, name) }
func mapperDir() string                 { return dmpkg.MapperDir(devDir) }

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
	return uint64(st.Rdev), nil //nolint:unconvert // Rdev is not uint64 on every GOARCH
}

// blockNodeRdev reports the device number of the BLOCK node at path, and is
// what isOurNode identifies device-mapper nodes with. A variable for the same
// reason nodeRdev is.
var blockNodeRdev = statBlockRdev

// statBlockRdev is statRdev for a node that must be a block device. Anything
// else is refused: a character device carries an rdev too and a regular file
// has rdev 0, and neither is a dm target whatever its number says.
func statBlockRdev(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFBLK {
		return 0, &DeviceError{Device: path, Op: "check the device node", Err: ErrNotBlockDevice}
	}
	return uint64(st.Rdev), nil //nolint:unconvert // Rdev is not uint64 on every GOARCH
}

// removeMappingNodes deletes the device nodes a mapping left behind, and ONLY
// those that are still that mapping's. The identity-checked removal mechanism
// lives in internal/dm; see dmpkg.RemoveMappingNodes.
//
// It is shared with Lock so that a rolled-back unlock leaves the filesystem in
// the same state a deliberate close does.
func removeMappingNodes(name string, info *devmapper.DeviceInfo) {
	dmpkg.RemoveMappingNodes(devDir, blockNodeRdev, name, info)
}

// isOurNode reports whether the node at path is the device info describes.
func isOurNode(path string, info *devmapper.DeviceInfo) bool {
	return dmpkg.IsOurNode(blockNodeRdev, path, info)
}

// Waiting for a device node.
//
// udev creates /dev/mapper/<name> asynchronously after the resume, and the
// kernel creates /dev/dm-N through devtmpfs. Neither is ordered against this
// process, so a node is polled for before this package makes one itself:
// polling re-checks the real condition each pass, until a deadline on dmClock.
const (
	// deviceReadyTimeout bounds the wait for udev's /dev/mapper/<name> after
	// an unlock: 3 seconds, as it always was.
	deviceReadyTimeout      = dmpkg.DeviceReadyTimeout
	deviceReadyPollInterval = dmpkg.DeviceReadyPollInterval

	// mappedNodeTimeout bounds mappedDevicePath's wait for a verified node:
	// 5 seconds, as it always was.
	mappedNodeTimeout = dmpkg.MappedNodeTimeout
)

// pollUntil checks done until it reports true or timeout has passed on
// dmClock, sleeping interval between checks (the last sleep clipped to the
// deadline), and reports whether done ever did. The polling loop itself lives
// in internal/dm; see dmpkg.PollUntil.
func pollUntil(timeout, interval time.Duration, done func() bool) bool {
	return dmpkg.PollUntil(dmClock, timeout, interval, done)
}

// makeBlockNode creates a block-device node. It is a seam because mknod needs
// CAP_MKNOD, which the unit-test account does not have.
var makeBlockNode = func(path string, devNo uint64) error {
	major, minor := decodeDevNo(devNo)
	dev, err := SafeUint64ToInt(unix.Mkdev(major, minor))
	if err != nil {
		return err
	}
	return unix.Mknod(path, unix.S_IFBLK|0o660, dev)
}

// placeNode puts a new directory entry at path, made by create, REPLACING
// whatever is there. The replace-by-rename mechanism lives in internal/dm;
// this is the pkg/luks2-level translation of its one distinguished refusal
// (an existing entry that is not a safe candidate to replace) onto
// ErrDeviceNodeUnverified, matching this package's own DeviceError shape.
func placeNode(path string, create func(tmp string) error) error {
	if err := dmpkg.PlaceNode(path, create); err != nil {
		if errors.Is(err, dmpkg.ErrNodeUnverified) {
			return &DeviceError{Device: path, Op: "replace the device node", Err: ErrDeviceNodeUnverified}
		}
		return err
	}
	return nil
}

// ensureDeviceNode makes /dev/dm-<minor> the block node of the device info
// describes. It is needed where udev and devtmpfs do not provide it, which is
// the case in a container with its own /dev.
//
// A node that is already there is used ONLY if it carries this device's
// number. It used to be enough that SOMETHING existed at /dev/dm-N or at
// /dev/mapper/<name>, so a stale node left by an earlier mapping -- dm minors
// are recycled -- was taken as this one.
func ensureDeviceNode(_ string, info *devmapper.DeviceInfo) error {
	_, minor := decodeDevNo(info.DevNo)
	dmPath := dmNodePath(minor)
	if isOurNode(dmPath, info) {
		return nil
	}
	if err := placeNode(dmPath, func(tmp string) error { return makeBlockNode(tmp, info.DevNo) }); err != nil {
		return &DeviceError{Device: dmPath, Op: "create the device node", Err: err}
	}
	return nil
}

// waitForDeviceReady waits for /dev/mapper/<name> to name the device info
// describes, and makes that entry itself when udev does not.
//
// "Ready" is decided by identity, not existence. It used to return as soon as
// ANY block device was reachable at /dev/mapper/<name>, so a stale entry from
// an earlier mapping -- or one planted there -- passed for the new mapping, and
// the caller went on to mount or mkfs whatever it pointed at (#250, C5).
func waitForDeviceReady(name string, info *devmapper.DeviceInfo) error {
	mapperPath := mapperNodePath(name)
	if pollUntil(deviceReadyTimeout, deviceReadyPollInterval, func() bool { return isOurNode(mapperPath, info) }) {
		return nil
	}

	// udev has not made it, or made it and it was replaced. Make it here,
	// pointing at a /dev/dm-N that has itself been verified.
	if err := ensureDeviceNode(name, info); err != nil {
		return err
	}
	_, minor := decodeDevNo(info.DevNo)
	dmPath := dmNodePath(minor)
	if err := os.MkdirAll(mapperDir(), 0o750); err != nil {
		return &DeviceError{Device: mapperDir(), Op: "create the directory", Err: err}
	}
	if err := placeNode(mapperPath, func(tmp string) error { return os.Symlink(dmPath, tmp) }); err != nil {
		return &DeviceError{Device: mapperPath, Op: "create the device-mapper symlink", Err: err}
	}
	if !isOurNode(mapperPath, info) {
		return &DeviceError{Device: mapperPath, Op: "verify the device-mapper symlink", Err: ErrDeviceNodeUnverified}
	}
	return nil
}

// mappedDevicePath resolves a mapping name to a device node that is verifiably
// that mapping, and returns the dm identity it was checked against.
//
// device-mapper is the authority. The name is validated, the target is looked
// up by name, and a node is accepted only when its rdev equals the target's
// DevNo. Path existence proves nothing: /dev/mapper/../sdb is /dev/sdb, a
// stale /dev/mapper/<name> can outlive its mapping, and a /dev/dm-N can belong
// to a later device that reused the minor (#250, C3 and C5).
func mappedDevicePath(name string) (string, *devmapper.DeviceInfo, error) {
	if err := ValidateMappingName(name); err != nil {
		return "", nil, err
	}
	info, err := dm.infoByName(name)
	if err != nil {
		if isNoSuchDevice(err) {
			return "", nil, &VolumeError{Volume: name, Op: "resolve", Err: ErrVolumeNotUnlocked}
		}
		return "", nil, &VolumeError{Volume: name, Op: "inspect the device-mapper target of", Err: err}
	}

	_, minor := decodeDevNo(info.DevNo)
	candidates := []string{mapperNodePath(name), dmNodePath(minor)}
	var found string
	if pollUntil(mappedNodeTimeout, deviceReadyPollInterval, func() bool {
		for _, candidate := range candidates {
			if isOurNode(candidate, info) {
				found = candidate
				return true
			}
		}
		return false
	}) {
		return found, info, nil
	}
	return "", info, &VolumeError{Volume: name, Op: "find a device node for", Err: &errs.Error{
		Kind:   ErrDeviceNodeUnverified,
		Detail: "neither " + candidates[0] + " nor " + candidates[1] + " is a block node carrying the device number device-mapper reports",
	}}
}

// isNoSuchDevice reports whether err is the kernel saying the dm target does
// not exist, as opposed to any other reason an inspection can fail.
func isNoSuchDevice(err error) bool {
	return dmpkg.IsNoSuchDevice(err)
}
