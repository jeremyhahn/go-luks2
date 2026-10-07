// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !integration

package loop

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// sysfsFixture builds a sysfs tree for one attached loop device.
func sysfsFixture(t *testing.T, name, backing, autoclear string) string {
	t.Helper()

	root := t.TempDir()
	dir := filepath.Join(root, name, "loop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("failed to build the fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "backing_file"), []byte(backing), 0o644); err != nil {
		t.Fatalf("failed to build the fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "autoclear"), []byte(autoclear), 0o644); err != nil {
		t.Fatalf("failed to build the fixture: %v", err)
	}
	return root
}

// TestReadLoopStateInReportsAnAttachedDevice is the positive control for the
// reader: without it the negative tests below would also pass against a
// reader that reported an error for everything.
func TestReadLoopStateInReportsAnAttachedDevice(t *testing.T) {
	root := sysfsFixture(t, "loop0", "/tmp/volume.img\n", "0\n")

	st, err := readLoopStateIn(root, "/dev/loop0")
	if err != nil {
		t.Fatalf("readLoopStateIn returned error: %v", err)
	}
	if st.backing != "/tmp/volume.img" {
		t.Errorf("backing = %q, want %q", st.backing, "/tmp/volume.img")
	}
	if st.autoclear {
		t.Error("autoclear = true for a device whose flag reads 0")
	}
}

// TestReadLoopStateInReportsAutoclear pins the flag the deferred-release
// case depends on.
func TestReadLoopStateInReportsAutoclear(t *testing.T) {
	root := sysfsFixture(t, "loop0", "/tmp/volume.img\n", "1\n")

	st, err := readLoopStateIn(root, "/dev/loop0")
	if err != nil {
		t.Fatalf("readLoopStateIn returned error: %v", err)
	}
	if !st.autoclear {
		t.Error("autoclear = false for a device whose flag reads 1")
	}
}

// TestReadLoopStateInTreatsMissingLoopAttributesAsDetached is the
// authoritative negative: the loop attributes exist only while a device is
// attached, so their absence -- with the block device still present -- is a
// positive answer and must NOT come back as an error.
func TestReadLoopStateInTreatsMissingLoopAttributesAsDetached(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "loop0"), 0o755); err != nil {
		t.Fatalf("failed to build the fixture: %v", err)
	}

	st, err := readLoopStateIn(root, "/dev/loop0")
	if err != nil {
		t.Fatalf("a detached device reported an error rather than 'not attached': %v", err)
	}
	if st.backing != "" {
		t.Errorf("backing = %q, want %q", st.backing, "")
	}
}

// TestReadLoopStateInDoesNotTreatAnAbsentBlockDeviceAsDetached is the
// fail-open this reader got wrong twice, in two different disguises.
//
// A name that is not a top-level /sys/block entry -- a udev symlink,
// /dev/block/7:0, or a PARTITION like /dev/loop0p1, which lives at
// /sys/block/loop0/loop0p1 -- makes the whole path absent. Reading that as
// "not attached" would let the wait conclude a release it never observed,
// for a device it was never able to look at. Absence of the BLOCK DEVICE and
// absence of its LOOP ATTRIBUTES are different facts.
func TestReadLoopStateInDoesNotTreatAnAbsentBlockDeviceAsDetached(t *testing.T) {
	root := t.TempDir()

	for _, device := range []string{"/dev/loop0p1", "/dev/block/7:0", "/dev/disk/by-id/some-symlink"} {
		t.Run(device, func(t *testing.T) {
			st, err := readLoopStateIn(root, device)
			if err == nil {
				t.Fatal("a device that could not be observed was reported as 'not attached'")
			}
			if st.backing != "" {
				t.Errorf("backing = %q, want %q alongside the error", st.backing, "")
			}
		})
	}
}

// TestReadLoopStateInPropagatesAnUnreadableEntry covers the branch the real
// sysfs path cannot provide: under /sys/block every path either exists or
// does not, so the error that must NOT be mistaken for "detached" is
// unreachable from a real device name. A directory where the attribute
// belongs produces exactly that class.
func TestReadLoopStateInPropagatesAnUnreadableEntry(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "loop0", "loop", "backing_file"), 0o755); err != nil {
		t.Fatalf("failed to build the fixture: %v", err)
	}

	st, err := readLoopStateIn(root, "/dev/loop0")
	if err == nil {
		t.Fatal("an unreadable sysfs entry was reported as 'not attached'")
	}
	if st.backing != "" {
		t.Errorf("backing = %q, want %q alongside the error", st.backing, "")
	}
}

// TestLoopAttributeSaysUnboundOnEveryKernelsAnswer: the answers that mean a
// loop device is attached to nothing -- the attribute gone (ENOENT), or the
// read refused with ENODEV as the CI runner's kernel does for a released
// device (go-luks2 #141) -- against the ones that mean the state could not
// be read, which readLoopStateIn must keep as errors.
func TestLoopAttributeSaysUnboundOnEveryKernelsAnswer(t *testing.T) {
	for _, tc := range []struct {
		errno   error
		unbound bool
	}{
		{unix.ENOENT, true},
		{unix.ENODEV, true},
		{unix.ENXIO, true},
		{unix.EIO, false},
		{unix.EACCES, false},
		{unix.EISDIR, false},
	} {
		err := &os.PathError{Op: "read", Path: "/sys/block/loop0/loop/backing_file", Err: tc.errno}
		if got := loopAttributeSaysUnbound(err); got != tc.unbound {
			t.Errorf("loopAttributeSaysUnbound(%v) = %v, want %v", tc.errno, got, tc.unbound)
		}
	}
}
