// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// The state directory is part of the TRUST BOUNDARY, and this file is what
// makes that explicit.
//
// # Why a directory needs validating at all
//
// The entrypoint runs the reaper as root, before the #85 guard, and the reaper
// does exactly what a ledger tells it: remove a device-mapper target, or detach
// every loop device backed under a recorded path. That is a host-wide device
// removal primitive, and its only input is a file in a directory.
//
// /var/tmp is world-writable with the sticky bit, so on a shared runner an
// unprivileged local user can create the state directory FIRST, with whatever
// mode they like, and drop *.ledger files into it. A forged KindLoopRoot of
// "/home" would then have a privileged container detach every loop device under
// /home; a forged KindMapping with a known UUID would remove that mapping.
//
// The dm half has some protection -- removal requires the live mapping to still
// carry the recorded UUID -- but the loop half has none and cannot: for loop
// devices the recorded path IS the identity, so a ledger that can be forged is
// a detach that can be aimed.
//
// This is the same class of hazard PR #85 removed from this repository, moved
// behind the ledger parser rather than eliminated. So the directory is checked
// before anything in it is read or written, by both the writer and the reaper,
// and an untrusted one fails the run rather than being repaired -- silently
// widening someone else's directory is not this code's business.

// trustedDir is the state directory, opened ONCE and validated through that
// handle. Every ledger read, lock, create and delete goes through the handle
// too, never through the path again (#247).
//
// Validating a path and then re-resolving it for each later operation is a
// check on one directory followed by use of whatever the name points at by
// then. With LUKS2_TEST_STATE_DIR under a parent another user can write to,
// that user could swap a forged directory in after the check, and the
// privileged reaper would act on its ledgers. A handle cannot be swapped: what
// was validated is what is read.
type trustedDir struct {
	path string
	root *os.Root
}

// Close releases the handle.
func (d *trustedDir) Close() error { return d.root.Close() }

// openTrustedStateDir creates the state directory if it is absent, opens it,
// and refuses it unless the OPENED directory is trustworthy.
//
// It is called from BOTH the writer (OpenLedger) and the reaper (lockReaper),
// deliberately: a check on one path only is a check an attacker routes around
// by racing the other.
func openTrustedStateDir(dir string) (*trustedDir, error) {
	if dir == "" {
		return nil, &StateDirError{Problem: "no state directory was configured"}
	}

	// 0o700, not 0o750: nothing else has any business in here, and a group the
	// directory happens to inherit is a group that can aim the reaper.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, &StateDirError{Dir: dir, Problem: "creating it", Err: err}
	}

	// Lstat, not Stat: a symlink must be REJECTED rather than followed. Stat
	// would resolve it and validate the target, which is precisely the check an
	// attacker wants -- point the name at a directory that passes and swap it
	// afterwards.
	named, err := os.Lstat(dir)
	if err != nil {
		return nil, &StateDirError{Dir: dir, Problem: "inspecting it", Err: err}
	}
	if named.Mode()&os.ModeSymlink != 0 {
		return nil, validateStateDir(dir, named.Mode(), 0, os.Geteuid())
	}

	stateDirHook(stateDirNamed, dir)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, &StateDirError{Dir: dir, Problem: "opening it", Err: err}
	}
	d := &trustedDir{path: dir, root: root}

	// The decision is made on the OPENED directory (fstat of the handle), and
	// it must be the same directory the name showed a moment ago: a swap
	// between the two is refused rather than raced.
	opened, err := root.Stat(".")
	if err != nil {
		_ = d.Close()
		return nil, &StateDirError{Dir: dir, Problem: "inspecting the opened directory", Err: err}
	}
	if !os.SameFile(named, opened) {
		_ = d.Close()
		return nil, &StateDirError{Dir: dir, Problem: "it was replaced while it was being opened"}
	}

	owner, ok := fileOwner(opened)
	if !ok {
		_ = d.Close()
		return nil, &StateDirError{Dir: dir, Problem: "cannot determine its owner, so it cannot be trusted"}
	}
	if err := validateStateDir(dir, opened.Mode(), owner, os.Geteuid()); err != nil {
		_ = d.Close()
		return nil, err
	}
	if err := refuseEphemeralStateDir(d); err != nil {
		_ = d.Close()
		return nil, err
	}
	stateDirHook(stateDirValidated, dir)
	return d, nil
}

// The points in openTrustedStateDir where the directory's name could be
// swapped under it. stateDirHook runs at each; it does nothing outside tests,
// which use it to perform the swap at exactly that point.
const (
	stateDirNamed     = "named"     // after the name was inspected, before it is opened
	stateDirValidated = "validated" // after the opened directory passed every check
)

var stateDirHook = func(stage, dir string) {}

// EphemeralMarker names a file whose PRESENCE declares that the state
// directory does not outlive the process using it.
//
// The container image creates one at its own /var/lib/go-luks2-test-state. A
// bind mount SHADOWS the image's directory, so the marker is visible exactly
// when the mount is absent -- which is precisely when the ledger is worthless:
// the records die with the container that wrote them, while the host devices
// they describe do not.
//
// This is a positive declaration rather than an inference. "Is this path a
// mount point" would be the obvious test and it is the wrong one: a plain
// directory on a developer's host is not a mount point and IS persistent, so
// that check would refuse the `make host-integration-test` path while passing
// anything that happened to be mounted. The image knows what it created, so
// the image says so.
const EphemeralMarker = ".ephemeral-not-a-persistent-mount"

// refuseEphemeralStateDir fails when the state directory is known not to
// outlive its writer.
//
// Running without persistence is worse than not running: every mapping and
// loop device the suite creates is recorded into a file that vanishes with the
// container, so the host accumulates devices nothing can attribute and the #85
// guard blocks the next run with no record to reap. That is the exact defect
// #96 exists to close, reached by omitting a flag.
func refuseEphemeralStateDir(d *trustedDir) error {
	dir := d.path
	marker := filepath.Join(dir, EphemeralMarker)
	if _, err := d.root.Lstat(EphemeralMarker); err == nil {
		return fmt.Errorf("%w: %s is the image's own directory, not a persistent mount "+
			"(%s is present) -- the ledger would die with this container while the host devices it "+
			"records would not. Mount a host path over it: "+
			"docker run -v <host-dir>:%s",
			ErrLedgerUnavailable, dir, marker, dir)
	} else if !os.IsNotExist(err) {
		// Cannot tell. Absent and unreadable are different answers, and only
		// absent may proceed.
		return fmt.Errorf("%w: cannot determine whether %s is persistent: %v",
			ErrLedgerUnavailable, dir, err)
	}
	return nil
}

// validateStateDir is the decision, separated from the syscalls so every branch
// is reachable in a test without root and without chown.
//
// NOTE ON THE FIXTURES: the tests drive this with constructed modes and uids
// rather than by chmod'ing a real directory, which also sidesteps the
// root-bypasses-permission-bits trap -- this code READS mode bits and decides,
// it does not rely on the kernel to deny access, so a test must exercise the
// decision rather than the enforcement.
func validateStateDir(dir string, mode os.FileMode, owner uint32, euid int) error {
	if mode&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink; the state directory must be a real directory, "+
			"because a link can be repointed after it is checked", ErrLedgerUnavailable, dir)
	}
	if !mode.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrLedgerUnavailable, dir)
	}

	// Write access is the whole risk. Anyone who can write here can hand the
	// privileged reaper a list of devices to remove.
	if perm := mode.Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%w: %s is writable by group or other (mode %04o); "+
			"anyone who can write here can make the privileged reaper detach loop devices "+
			"or remove device-mapper targets of their choosing",
			ErrLedgerUnavailable, dir, perm)
	}

	// Owned by root or by whoever is running. Anything else means the records
	// this process is about to trust are maintained by somebody else.
	if owner != 0 && owner != uint32(euid) { // #nosec G115 -- a uid fits a uint32 by definition
		return fmt.Errorf("%w: %s is owned by uid %d, but this process runs as uid %d; "+
			"the reaper acts on what this directory says, so it must not be another user's",
			ErrLedgerUnavailable, dir, owner, euid)
	}

	return nil
}

// fileOwner extracts the owning uid, reporting ok=false where the platform does
// not supply one. An owner that cannot be determined is not treated as safe.
func fileOwner(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
