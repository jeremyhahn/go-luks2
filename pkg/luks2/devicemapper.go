// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"errors"
	"fmt"
	"os"

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
	info, err := dm.infoByName(name)
	if err != nil {
		if isNoSuchDevice(err) {
			// Already gone. The common case when devmapper's own CreateAndLoad
			// cleaned up after a failed table load.
			return nil
		}
		return fmt.Errorf("%w: device-mapper target %q could not be inspected after a failed unlock (%v), so it cannot be confirmed removed; check for it with: dmsetup info %s",
			ErrMappingStillLive, name, err, name)
	}

	if info.UUID != uuid {
		// Not ours. Leaving it alone is the only safe action; see above.
		return nil
	}

	if err := dm.remove(name); err != nil {
		return fmt.Errorf("%w: the plaintext device-mapper target %q created by this unlock could not be removed (%v) and is STILL LIVE; close it with: luks close %s",
			ErrMappingStillLive, name, err, name)
	}

	removeMappingNodes(name, info)
	return nil
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
