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

// The state directory is a trust boundary: the root reaper acts on its ledgers, so it is validated before any read or write and an untrusted one fails the run.

// trustedDir is the state directory, opened once and validated and used through that handle, never the path.
type trustedDir struct {
	path string
	root *os.Root
}

// Close releases the handle.
func (d *trustedDir) Close() error { return d.root.Close() }

// openTrustedStateDir creates the state directory if absent, opens it and refuses it unless the opened directory is trustworthy; used by writer and reaper.
func openTrustedStateDir(dir string) (*trustedDir, error) {
	if dir == "" {
		return nil, &StateDirError{Problem: "no state directory was configured"}
	}

	// 0o700, not 0o750: nothing else has any business in here, and a group the
	// directory happens to inherit is a group that can aim the reaper.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, &StateDirError{Dir: dir, Problem: "creating it", Err: err}
	}

	// Lstat, so a symlink is rejected rather than followed.
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

	// Decide on the opened directory (fstat), refusing if it differs from the one Lstat saw.
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

// refuseEphemeralStateDir fails when the state directory is known not to outlive its writer.
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

// validateStateDir is the decision, separated from the syscalls so tests reach every branch without root.
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
