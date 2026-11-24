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
// that looks like ours" anywhere in this file. `dmsetup remove_all` and
// `losetup -D` are absent because they can destroy a developer's machine -- a host was measured carrying test litter and
// a live encrypted root in the same listing -- and nothing here may reintroduce
// them under a different spelling.
//
// That absence is policy, not an omission: a device no ledger recorded is
// cleared by an operator, per device, on positive attribution with stock
// losetup, and never by code here. The
// reasoning is in docs/volumes/engineering.md, "A device no ledger recorded is an
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

// dmPrivilegeRemedy is appended to a device-mapper permission failure to explain the privileges the tier needs.
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

// identifyLoopDevice pairs a sysfs-matched device with its current binding's identity; ok=false means unbound, and a capture failure travels with the device.
func identifyLoopDevice(sysDir, backing string, capture identityCapturer) (LoopDevice, bool) {
	path := "/dev/" + filepath.Base(sysDir)

	// Present, absent or unknown: one branch each.
	id, bound, err := capture(path)
	switch {
	case err != nil:
		// Unknown: the device stays in the list with the reason, so the detach refuses it.
		return LoopDevice{Path: path, Backing: backing, IdentityErr: err}, true

	case !bound:
		// Absent: ENXIO, released between the scan and the ioctl.
		return LoopDevice{}, false

	default:
		// PRESENT.
		return LoopDevice{Path: path, Backing: backing, Identity: id, IdentityKnown: true}, true
	}
}

// readBackingFile returns a loop device's backing path and whether it has one; unused (see loopReleased) differs from unreadable, which is an error.
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

// loopReleased reports whether a failed backing_file read (ENOENT, ENODEV or ENXIO) means the device is bound to nothing.
func loopReleased(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENXIO)
}

// LoopDevicesUnder returns the loop devices whose backing file lives under dir.
//
// dir must be a directory THIS suite created; see KindLoopRoot for why a prefix
// is acceptable there and nowhere else. The check is on a cleaned path plus a
// separator, so "/tmp/go-luks2-run-1" does not match "/tmp/go-luks2-run-10".
//
// dir is bounded the way RemoveDir bounds it: absolute, below the root,
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
		// ENXIO: already unbound, the goal state.
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

	// Close the descriptor here, not deferred: it would hold the release.
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing %s after LOOP_CLR_FD, which must happen before the release can complete: %w", dev.Path, err)
	}

	// Success requires an authoritative observation of the release.
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

// waitForLoopRelease blocks until the device no longer backs the file (gone, or reused with another identity), up to a bound; the sysfs root and capturer are parameters for tests.
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

// waitClock is the clock every wait in this package uses; tests substitute a clock.Fake.
var waitClock clock.Clock = clock.System{}

// loopIdentity is the device number and inode of a loop device's current backing file, which unlike lo_file_name the kernel maintains.
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

// captureLoopIdentity reads a bound loop device's identity; bound=false with nil error means ENXIO, any other failure is returned.
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
