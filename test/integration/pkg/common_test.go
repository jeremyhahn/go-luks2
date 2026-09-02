// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package pkg_test

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// releaseVolume closes volumeName and FAILS THE TEST if a device-mapper
// mapping is left behind on the host (#100).
//
// The same helper, and the same reasoning, as pkg/luks2's own -- these are
// separate packages, so the code cannot be shared, but the defect was not
// confined to one of them. Every teardown here was a bare close with the error
// discarded, so a run that failed to release its mapping reported success and
// the NEXT integration job on that runner refused to start.
//
// It asserts the END STATE rather than the call: luks2.Lock returns
// ErrVolumeNotUnlocked when there is nothing to close, which is the desired
// outcome and not a failure, while a Lock that returns nil with the mapping
// still present must still fail. The bounded retry absorbs the transient EBUSY
// that mkfs and its udev/blkid activity produce; exhausting it is a reported
// failure, because a retry that gives up quietly is the same defect wearing a
// delay.
func releaseVolume(t *testing.T, volumeName string) {
	t.Helper()

	const timeout = 10 * time.Second
	var last error
	deadline := time.Now().Add(timeout)
	for {
		if err := luks2.Lock(volumeName); err != nil && !errors.Is(err, luks2.ErrVolumeNotUnlocked) {
			last = err
		}
		if mappingConfirmedGone(volumeName) {
			return
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Errorf("device-mapper mapping %q is STILL PRESENT after %s, so this run "+
		"is leaving it on the host for the next job, which will refuse to "+
		"start. Last error from Lock: %v", volumeName, timeout, last)
}

// mappingConfirmedGone reports whether the mapping is CONFIRMED absent, asking
// dmsetup directly rather than trusting luks2.IsUnlocked.
//
// IsUnlocked treats every device-mapper query error as absence unless a device
// node happens to stat, so a transient dm-control failure would make this
// teardown report success on the evidence that nothing could be known. Inside
// the package that is fixed by reusing its unexported isNoSuchDevice, which
// counts only ENXIO/ENODEV as absence. This package is EXTERNAL and cannot
// reach that, so it gets its answer from the same place the container's own
// host guard does: `dmsetup info`.
//
// Three outcomes, kept distinct, which is the entire point:
//
//	exit 0                        present
//	"Device does not exist."      absent
//	anything else, or no dmsetup  unknown -> treated as PRESENT
//
// Treating unknown as present keeps the retry running and, if it never clears,
// produces a reported failure rather than a quiet success. Absence that cannot
// be established is not absence.
//
// THE ABSENT STRING IS MEASURED, NOT GUESSED, and that mattered. The first
// version of this function looked for "not found" and "no such" -- both
// plausible, both wrong. Real output, dmsetup 2.03 as root:
//
//	$ dmsetup info definitely-not-a-real-mapping
//	Device does not exist.
//	Command failed.
//
// Neither guessed substring appears. The classifier would have read every
// absent mapping as UNKNOWN, treated it as present, and failed every teardown
// after the timeout -- fail-closed, and wrong. Consuming what the command
// actually prints is the only way to know.
//
// Unprivileged output was checked too, because that is the other real case:
// "/dev/mapper/control: open failed: Permission denied" classifies as unknown,
// which is correct -- a query that could not be made says nothing about the
// mapping.
func mappingConfirmedGone(volumeName string) bool {
	out, err := exec.Command("dmsetup", "info", volumeName).CombinedOutput()
	if err == nil {
		return false // dmsetup found it
	}
	if strings.Contains(strings.ToLower(string(out)), "device does not exist") {
		return true
	}
	// Unclassifiable: dmsetup missing, permission denied, control node absent.
	// None of those is evidence the mapping is gone.
	return false
}

// testCleanup performs common test cleanup
func testCleanup(volumeName string, loopDev string, tmpfile string) {
	// Try to lock volume
	_ = luks2.Lock(volumeName)

	// Wait for device mapper to settle
	for i := 0; i < 30; i++ {
		if !luks2.IsUnlocked(volumeName) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Detach loop device
	if loopDev != "" {
		_ = luks2.DetachLoopDevice(loopDev)
	}

	// Remove temp file
	if tmpfile != "" {
		_ = os.Remove(tmpfile)
	}
}

// createTestFile creates a test file with the given size
func createTestFile(path string, sizeMB int) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return f.Truncate(int64(sizeMB * 1024 * 1024))
}

// waitForUnlock waits for a volume to be unlocked
func waitForUnlock(volumeName string, timeoutMs int) bool {
	for i := 0; i < timeoutMs/100; i++ {
		if luks2.IsUnlocked(volumeName) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// waitForLock waits for a volume to be locked
func waitForLock(volumeName string, timeoutMs int) bool {
	for i := 0; i < timeoutMs/100; i++ {
		if !luks2.IsUnlocked(volumeName) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
