// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/anatol/devmapper.go"
	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/clock"
)

// SystemRemover is the real Remover: it talks to the kernel.
//
// It removes ONLY what it is asked for, by exact name or exact backing path.
// There is deliberately no sweep, no prefix match and no "remove everything
// that looks like ours" anywhere in this file. PR #85 removed
// `dmsetup remove_all` and `losetup -D` from this repository because they can
// destroy a developer's machine -- a host was measured carrying test litter and
// a live encrypted root in the same listing -- and nothing here may reintroduce
// them under a different spelling.
//
// That absence is ruled policy, not an omission: a device no ledger recorded is
// cleared by an operator, per device, on positive attribution with stock
// losetup, and never by code here (owner ruling 2026-09-22, issue #114). The
// reasoning is in docs/TESTING.md, "A device no ledger recorded is an
// operator's job, not this repository's".
type SystemRemover struct{}

// MappingIdentity returns the dm UUID of the live mapping called name.
func (SystemRemover) MappingIdentity(name string) (string, bool, error) {
	info, err := devmapper.InfoByName(name)
	if err != nil {
		// Absent is the ordinary case, not a failure: most ledger entries name
		// a mapping whose test removed it before the run died.
		if errors.Is(err, unix.ENXIO) || errors.Is(err, unix.ENODEV) || errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		// devmapper reports an unknown device without a typed error on some
		// kernels, so the message is the only signal left. Matching it is
		// unattractive; reporting a hard failure for every absent entry would
		// make the reaper useless, which is worse.
		if strings.Contains(strings.ToLower(err.Error()), "no such device") {
			return "", false, nil
		}
		if isPermissionDenied(err) {
			return "", false, fmt.Errorf("inspecting dm %q: %w%s", name, err, dmPrivilegeRemedy)
		}
		return "", false, fmt.Errorf("inspecting dm %q: %w", name, err)
	}
	if info == nil {
		return "", false, nil
	}
	return info.UUID, true, nil
}

// RemoveMapping removes the dm target called name.
func (SystemRemover) RemoveMapping(name string) error {
	if err := devmapper.Remove(name); err != nil {
		if isPermissionDenied(err) {
			return fmt.Errorf("removing dm %q: %w%s", name, err, dmPrivilegeRemedy)
		}
		return fmt.Errorf("removing dm %q: %w", name, err)
	}
	return nil
}

// dmPrivilegeRemedy is appended to a permission failure against device-mapper.
//
// The bare errno -- "open /dev/mapper/control: permission denied" -- is
// accurate and useless: it reads as a broken installation rather than as the
// suite being run without the privileges its tier requires. Someone WILL meet
// this on a developer box, because `go test -tags=integration ./...` is the
// obvious thing to type and it is not how this tier runs.
//
// It is a suffix rather than a wrapped type because the caller's context
// ("could not confirm the host is clean") is the sentence that matters; this
// only has to explain what to do about it.
const dmPrivilegeRemedy = "\n" +
	"    The integration tier needs device-mapper access, which means root (or CAP_SYS_ADMIN\n" +
	"    plus access to /dev/mapper/control). Without it the reaper cannot confirm whether\n" +
	"    the host is clean, and an unverifiable host is refused rather than assumed clean.\n" +
	"    Run it the way CI does -- `make integration-test`, which runs the container -- or\n" +
	"    `make host-integration-test`, which runs it under sudo."

// isPermissionDenied reports whether err is an EACCES/EPERM anywhere in its
// chain. Both appear here: EACCES from opening /dev/mapper/control, EPERM from
// the ioctl once it is open.
func isPermissionDenied(err error) bool {
	return errors.Is(err, os.ErrPermission) ||
		errors.Is(err, unix.EACCES) ||
		errors.Is(err, unix.EPERM)
}

// LoopDevicesFor returns the loop devices whose backing file is backingFile.
//
// The kernel is the source of truth, read from
// /sys/block/loop<N>/loop/backing_file. A container that has been torn down
// leaves its files gone, and the kernel then reports the path with a
// " (deleted)" suffix -- which is why the comparison strips it rather than
// requiring an exact string match against a path that no longer resolves.
func (SystemRemover) LoopDevicesFor(backingFile string) ([]LoopDevice, error) {
	return loopDevicesForIn("/sys/block", backingFile, captureLoopIdentity)
}

// identityCapturer reads a loop device's kernel identity. It is a parameter so
// the enumeration can be tested against a fake /sys tree, where /dev/loopN does
// not correspond to the entries under it.
type identityCapturer func(device string) (loopIdentity, bool, error)

func loopDevicesForIn(sysBlock, backingFile string, capture identityCapturer) ([]LoopDevice, error) {
	if backingFile == "" {
		return nil, errors.New("an empty backing file matches nothing and must not be looked up")
	}

	dirs, err := filepath.Glob(filepath.Join(sysBlock, "loop*"))
	if err != nil {
		return nil, err
	}

	var devices []LoopDevice
	for _, dir := range dirs {
		backing, present, err := readBackingFile(dir)
		if err != nil {
			return nil, err
		}
		if !present || backing != backingFile {
			continue
		}
		device, ok := identifyLoopDevice(dir, backing, capture)
		if !ok {
			continue
		}
		devices = append(devices, device)
	}

	sortLoopDevices(devices)
	return devices, nil
}

// identifyLoopDevice pairs a device matched in sysfs with the kernel identity
// of the binding it is carrying RIGHT NOW, which is what the detach re-checks.
//
// ok=false means the device is no longer bound and there is nothing to detach.
// A capture FAILURE is not that: it returns a device carrying the failure, so
// the detach refuses it by name and the run reports it, rather than the scan
// silently returning a shorter list -- which is the AlreadyGone fail-open that
// readBackingFile above exists to prevent, reached one function later.
func identifyLoopDevice(sysDir, backing string, capture identityCapturer) (LoopDevice, bool) {
	path := "/dev/" + filepath.Base(sysDir)

	// PRESENT / ABSENT / UNKNOWN, one branch each and no compound condition.
	//
	// The first draft of this was `if err == nil && !bound` with the identity
	// flagged as `IdentityKnown: err == nil`, and scripts/error-collapse-guard.sh
	// flagged it. That instance was the INVERSE of the defect the guard hunts --
	// the error fell through to the strict answer, not the benign one -- but the
	// guard was still pointing at something real: a three-way decision squeezed
	// into a two-way test, with `err == nil` evaluated in two places that a later
	// edit could easily disagree about. Written out, the three answers cannot be
	// collapsed by accident.
	id, bound, err := capture(path)
	switch {
	case err != nil:
		// UNKNOWN. The device stays in the list carrying the reason, so the
		// detach refuses it by name. Dropping it here would report the ledger
		// entry AlreadyGone and consume the record for a device still attached.
		return LoopDevice{Path: path, Backing: backing, IdentityErr: err}, true

	case !bound:
		// ABSENT. ENXIO: released between the sysfs scan and the ioctl. There is
		// nothing to detach and nothing went wrong.
		return LoopDevice{}, false

	default:
		// PRESENT.
		return LoopDevice{Path: path, Backing: backing, Identity: id, IdentityKnown: true}, true
	}
}

// readBackingFile returns the backing path a loop device reports, and whether
// it has one at all.
//
// ABSENT AND UNREADABLE ARE DIFFERENT ANSWERS, and collapsing them is the
// defect this function exists to prevent. ENOENT, ENODEV and ENXIO mean the
// device is unused -- or was detached while this loop was running -- and
// skipping it is correct (see loopReleased for which kernel says which).
// Anything else (EACCES, EIO, EISDIR, a sysfs quirk) means the backing file
// COULD NOT BE VERIFIED, and treating that as "no backing file" makes the
// caller report an empty device list, which makes the reaper report AlreadyGone
// and DELETE the ledger for a device that may still be attached.
//
// That is the fail-open path the whole ledger exists to close, and it had been
// reintroduced here by a bare `continue` on every error.
func readBackingFile(loopDir string) (backing string, present bool, err error) {
	path := filepath.Join(loopDir, "loop", "backing_file")
	raw, err := readSysfsAttr(path)
	if err != nil {
		if loopReleased(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("reading %s: %w", path, err)
	}
	return normalizeBackingFile(string(raw)), true, nil
}

// readSysfsAttr reads one sysfs attribute. It is a variable so the answers
// only some kernels give can be driven in a test; nothing else replaces it.
var readSysfsAttr = os.ReadFile

// loopReleased reports whether a failed read of a loop device's backing_file
// means the device is bound to nothing -- which is the answer, not an error.
//
// Kernels disagree on how they say it. Some remove the attribute (ENOENT);
// others keep it, and the read fails with ENODEV once the device is released
// -- measured on the CI runner, where it made a successful detach fail its own
// release confirmation (#141). ENXIO is the loop driver's own "not bound"
// answer, and is treated the same way. Any other failure is a real one: the
// reaper does not know what the device backs, so it must not guess "nothing".
func loopReleased(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENXIO)
}

// LoopDevicesUnder returns the loop devices whose backing file lives under dir.
//
// dir must be a directory THIS suite created; see KindLoopRoot for why a prefix
// is acceptable there and nowhere else. The check is on a cleaned path plus a
// separator, so "/tmp/go-luks2-run-1" does not match "/tmp/go-luks2-run-10".
//
// dir is bounded the way RemoveDir bounds it (#247): absolute, below the root,
// and named like a run root. Before, only "" and "/" were refused, so a damaged
// or forged loop-root line such as /var/lib/snapd would have detached every
// snap's loop device. The bound is not the ownership decision -- the record is
// -- it limits what a damaged record can reach.
func (SystemRemover) LoopDevicesUnder(dir string) ([]LoopDevice, error) {
	return loopDevicesUnderIn("/sys/block", dir, captureLoopIdentity)
}

func loopDevicesUnderIn(sysBlock, dir string, capture identityCapturer) ([]LoopDevice, error) {
	if err := checkRunRoot("match loop devices under", dir); err != nil {
		return nil, err
	}
	prefix := filepath.Clean(dir) + string(filepath.Separator)

	dirs, err := filepath.Glob(filepath.Join(sysBlock, "loop*"))
	if err != nil {
		return nil, err
	}

	var devices []LoopDevice
	for _, d := range dirs {
		backing, present, err := readBackingFile(d)
		if err != nil {
			return nil, err
		}
		if !present || !strings.HasPrefix(backing, prefix) {
			continue
		}
		device, ok := identifyLoopDevice(d, backing, capture)
		if !ok {
			continue
		}
		devices = append(devices, device)
	}

	sortLoopDevices(devices)
	return devices, nil
}

// normalizeBackingFile turns what sysfs reports into the path that was
// recorded: it drops the trailing newline and the " (deleted)" marker the
// kernel appends once the file itself is unlinked.
func normalizeBackingFile(raw string) string {
	return strings.TrimSuffix(strings.TrimSpace(raw), " (deleted)")
}

// sortLoopDevices orders by device path so output is stable between runs.
func sortLoopDevices(d []LoopDevice) {
	sort.Slice(d, func(i, j int) bool { return d[i].Path < d[j].Path })
}

// RemoveDir removes a directory this suite created.
//
// The path comes from a ledger, and a ledger is a file. The state directory is
// validated before anything in it is read (statedir.go), so a forged entry is
// not the expected case -- but os.RemoveAll is the one operation here whose
// blast radius is unbounded, and a corrupt line should not be able to aim it.
//
// So the value is bounded before it is used: absolute, more than one component,
// and named the way this suite names its roots. That last check is NOT the
// ownership decision -- ownership comes from the record, as everywhere else in
// this package -- it is a limit on what a damaged record can do.
func (SystemRemover) RemoveDir(path string) error {
	if err := safeToRemove(path); err != nil {
		return err
	}
	return os.RemoveAll(path)
}

// runRootPrefix is how this suite names the directories it creates; see
// BeginSuite.
const runRootPrefix = "go-luks2-run-"

func safeToRemove(path string) error {
	return checkRunRoot("remove", path)
}

// checkRunRoot bounds a recorded run root before action is taken on it:
// absolute, below the root, and named the way BeginSuite names run roots.
func checkRunRoot(action, path string) error {
	clean := filepath.Clean(path)
	if path == "" || clean == "/" || clean == "." || !filepath.IsAbs(clean) {
		return &RunRootError{Action: action, Path: path, Problem: "it is not an absolute path below the root"}
	}
	if !strings.HasPrefix(filepath.Base(clean), runRootPrefix) {
		return &RunRootError{Action: action, Path: path,
			Problem: "it is not named like a directory this suite creates (" + runRootPrefix + "*)"}
	}
	return nil
}

// DetachLoop releases a loop device with LOOP_CLR_FD, refusing unless the
// kernel still reports the device as carrying the binding that was enumerated.
//
// It is the single-device ioctl, never `losetup -D`, which detaches every loop
// device on the host including a developer's mounted image.
//
// # Why the expectation is re-checked here rather than by the caller
//
// /dev/loopN is a REUSABLE name. Between enumerating a device by its backing
// path and clearing it, the number can be released and reassigned to something
// else entirely -- and a privileged reaper would then detach a stranger's
// device while believing it was removing its own. The enumeration cannot close
// that window because it works through sysfs paths, which are resolved afresh
// on every access.
//
// So the check moves onto the FILE DESCRIPTOR: open the device once, ask the
// kernel through that fd what it is currently bound to, and clear it through
// the same fd. The lookup is no longer repeated between the check and the act.
//
// WHAT THIS DOES NOT CLAIM: the two ioctls are still two ioctls. There is no
// "clear if bound to X" operation in the loop interface, so a reassignment
// landing precisely between LOOP_GET_STATUS64 and LOOP_CLR_FD is not
// prevented. It is narrowed from a window spanning a sysfs scan to one spanning
// two syscalls on a held descriptor, which is the smallest the kernel offers.
// Reassigning a loop device requires privilege in the first place, so this is a
// correctness guard against a concurrent job, not a boundary against an
// unprivileged attacker.
//
// Nor does it claim the inode is unforgeable: the backing file is typically
// unlinked by now, and a freed inode number can be reallocated. A device that
// were re-bound, by another privileged job, to a brand-new file that happened
// to land on our freed inode, within the same window, would compare equal. That
// residue is a property of the kernel interface, not of this check.
func (SystemRemover) DetachLoop(dev LoopDevice) error {
	// An identity that could not be captured is not a license to proceed. See
	// LoopDevice.IdentityKnown: this is the one branch that must NOT fall
	// through to LOOP_CLR_FD, because it is precisely the case where nothing
	// here knows what it would be destroying.
	if !dev.IdentityKnown {
		if dev.IdentityErr != nil {
			return fmt.Errorf("refusing to detach %s: its identity could not be captured when it was enumerated: %w",
				dev.Path, dev.IdentityErr)
		}
		return fmt.Errorf("refusing to detach %s: it carries no enumeration identity to re-check against", dev.Path)
	}

	f, err := os.OpenFile(dev.Path, os.O_RDONLY, 0) // #nosec G304 -- device path comes from a sysfs listing
	if err != nil {
		return fmt.Errorf("opening %s: %w", dev.Path, err)
	}

	info, err := unix.IoctlLoopGetStatus64(int(f.Fd()))
	if err != nil {
		_ = f.Close()
		// ENXIO is the kernel saying the device is not bound to anything. That
		// is the goal state, not a failure: something released it between the
		// scan and here -- the test's own cleanup, or an autoclear on the last
		// close. There is nothing to detach and nothing went wrong.
		if errors.Is(err, unix.ENXIO) {
			return nil
		}
		return fmt.Errorf("reading the status of %s to confirm what it is bound to: %w", dev.Path, err)
	}

	if now := identityFromStatus(info); now != dev.Identity {
		_ = f.Close()
		return fmt.Errorf("refusing to detach %s: it is now bound to %s, not the %s it carried when it was "+
			"enumerated as backing %q -- the loop number was reused",
			dev.Path, now, dev.Identity, dev.Backing)
	}

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.LOOP_CLR_FD, 0); errno != 0 {
		_ = f.Close()
		return fmt.Errorf("LOOP_CLR_FD on %s: %w", dev.Path, errno)
	}

	// THE DESCRIPTOR IS A REFERENCE, AND IT IS CLOSED HERE RATHER THAN DEFERRED.
	//
	// LOOP_CLR_FD does not necessarily release the device. When any descriptor
	// is still open on it -- including THIS one -- the kernel sets autoclear and
	// defers the release until the last close. Returning at this point reported
	// success while the caller's own open fd was the thing preventing it, and
	// `defer f.Close()` ran only after the return, so the release could not even
	// begin until the caller was already acting on the "success".
	//
	// pkg/luks2/loopdev.go states this exactly, for its own detach path: "this
	// descriptor is a reference, and the release cannot complete while it is
	// held. A deferred close would make the wait wait for itself." The harness
	// did the thing that comment forbids.
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing %s after LOOP_CLR_FD, which must happen before the release can complete: %w", dev.Path, err)
	}

	// NO PATH RETURNS SUCCESS WITHOUT AN AUTHORITATIVE OBSERVATION -- the same
	// contract pkg/luks2 holds itself to. Without this the function reported a
	// PROMISE as a fact, and whether the promise had been kept by the caller's
	// next syscall was a race the caller could not see.
	return waitForLoopRelease("/sys/block", dev, loopReleaseTimeout, loopReleasePoll, captureLoopIdentity)
}

// Release wait bounds. The release being waited on is the kernel completing a
// deferred autoclear once the last reference goes away; it is normally already
// done by the first poll, and the bound exists so a device something else holds
// open fails with a diagnosis instead of hanging a suite.
const (
	loopReleaseTimeout = 2 * time.Second
	loopReleasePoll    = 500 * time.Microsecond
)

// waitForLoopRelease blocks until the enumerated device no longer backs the
// file, and says so authoritatively rather than assuming it.
//
// "Released" is not the same as "absent from the listing for some other
// reason", so the two cases the scan can legitimately produce are both
// accepted and neither is guessed at:
//
//   - the device is gone from the listing for this backing file -- released;
//   - it is present but now carries a DIFFERENT identity -- the loop number was
//     freed and reused by another job, which also means ours is released.
//
// Anything else is still held, and the bound turns that into an error naming
// the device rather than a suite that hangs or, worse, one that proceeds.
// The sysfs root and the identity capturer are PARAMETERS, in the same idiom
// and for the same reason as loopDevicesForIn: the waiting logic can then be
// exercised against a fake /sys tree, with no loop device, no root, and without
// waiting out a real timeout. A wait that could only be tested by attaching a
// real device would not be tested.
func waitForLoopRelease(sysBlock string, dev LoopDevice, timeout, poll time.Duration, capture identityCapturer) error {
	deadline := waitClock.Now().Add(timeout)
	for {
		devices, err := loopDevicesForIn(sysBlock, dev.Backing, capture)
		if err != nil {
			return fmt.Errorf("confirming %s was released from %q: %w", dev.Path, dev.Backing, err)
		}

		stillOurs := false
		for _, d := range devices {
			if d.Path == dev.Path && d.IdentityKnown && d.Identity == dev.Identity {
				stillOurs = true
				break
			}
		}
		if !stillOurs {
			return nil
		}

		if waitClock.Now().After(deadline) {
			return fmt.Errorf("%s still backs %q %s after LOOP_CLR_FD reported success: the release is deferred "+
				"and something still holds the device open", dev.Path, dev.Backing, timeout)
		}
		<-waitClock.NewTimer(poll).C()
	}
}

// waitClock is the clock every wait in this package uses: the reaper's wait
// for another reaper, its wait for a detach to settle, and DetachLoop's wait
// for a release. Tests substitute a clock.Fake so that a bound is asserted on
// the code rather than on how busy the machine running it is (#233). The
// package has no parallel tests, which is what makes a package-level clock
// safe to substitute.
var waitClock clock.Clock = clock.System{}

// loopIdentity is the kernel's own identity for a loop device's CURRENT
// binding: the device number and inode of the file behind it.
//
// # Why not lo_file_name
//
// The backing NAME is the obvious candidate and an earlier revision of this
// file used it. It is unfit, and every reason below was measured on a running
// system
// (Linux 6.8.0-58-generic, 2026-09-02) rather than reasoned about, after three
// successive fixes had each reasoned wrongly about what an empty name means:
//
//   - It is a BIND-TIME SNAPSHOT WRITTEN BY USERSPACE, not a live view of the
//     binding. losetup sets it through LOOP_SET_STATUS64. pkg/luks2/loopdev.go
//     binds with LOOP_SET_FD alone and never sets it, so EVERY loop device this
//     library creates reports an empty name -- the "unverifiable" case was not
//     an exotic corner, it was the normal path for our own devices.
//   - Unlinking the backing file does not change it. sysfs starts reporting
//     "... (deleted)" while lo_file_name reports exactly what it did before, so
//     "empty means the file was unlinked" -- the previous comment here -- is
//     false.
//   - A path longer than the 64-byte field is TRUNCATED to 63 bytes, not
//     emptied, so length does not explain an empty name either.
//
// lo_device and lo_inode have none of those problems: the kernel maintains
// them, they are populated for a LOOP_SET_FD-only binding, they are unaffected
// by unlinking, and they are cleared on detach (measured: re-binding a device
// to a different file reports the NEW inode, never the old name). They identify
// the backing INODE, which is what "still the same device" has to mean once the
// name is gone.
type loopIdentity struct {
	dev   uint64
	inode uint64
}

func (id loopIdentity) String() string {
	return fmt.Sprintf("dev %d inode %d", id.dev, id.inode)
}

func identityFromStatus(info *unix.LoopInfo64) loopIdentity {
	return loopIdentity{dev: info.Device, inode: info.Inode}
}

// captureLoopIdentity reads the kernel's identity for a bound loop device.
//
// bound=false with a nil error means the device is not bound at all: the ioctl
// returned ENXIO because it was released between the sysfs scan and this call.
// That is the goal state, and the caller drops the device rather than reporting
// it. Every other failure is returned, because "I could not find out" must
// never reach the detach as "go ahead".
func captureLoopIdentity(device string) (id loopIdentity, bound bool, err error) {
	f, err := os.OpenFile(device, os.O_RDONLY, 0) // #nosec G304 -- device path is built from a sysfs listing
	if err != nil {
		return loopIdentity{}, false, fmt.Errorf("opening %s to capture its identity: %w", device, err)
	}
	defer func() { _ = f.Close() }()

	info, err := unix.IoctlLoopGetStatus64(int(f.Fd()))
	if err != nil {
		if errors.Is(err, unix.ENXIO) {
			return loopIdentity{}, false, nil
		}
		return loopIdentity{}, false, fmt.Errorf("reading the status of %s to capture its identity: %w", device, err)
	}
	return identityFromStatus(info), true, nil
}
