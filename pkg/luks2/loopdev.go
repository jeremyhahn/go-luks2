// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package luks2

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// SetupLoopDevice creates a loop device for a file
func SetupLoopDevice(file string) (string, error) {
	// Open the backing file read-write
	backingFile, err := os.OpenFile(file, os.O_RDWR, 0) // #nosec G304 -- user-provided file path for disk image
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = backingFile.Close() }()

	// Open loop control to get free device
	loopControl, err := os.OpenFile("/dev/loop-control", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("failed to open loop-control: %w", err)
	}
	defer func() { _ = loopControl.Close() }()

	// Get free loop device number
	devNum, _, errno := unix.Syscall(unix.SYS_IOCTL, loopControl.Fd(), unix.LOOP_CTL_GET_FREE, 0)
	if errno != 0 {
		return "", fmt.Errorf("LOOP_CTL_GET_FREE failed: %v", errno)
	}

	loopDevice := fmt.Sprintf("/dev/loop%d", devNum)

	// Open loop device
	loopFile, err := os.OpenFile(loopDevice, os.O_RDWR, 0) // #nosec G304 -- loop device path constructed from kernel
	if err != nil {
		return "", fmt.Errorf("failed to open %s: %w", loopDevice, err)
	}
	defer func() { _ = loopFile.Close() }()

	// Attach backing file to loop device
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, loopFile.Fd(), unix.LOOP_SET_FD, backingFile.Fd())
	if errno != 0 {
		return "", fmt.Errorf("LOOP_SET_FD failed: %v", errno)
	}

	return loopDevice, nil
}

// DetachLoopDevice detaches a loop device
func DetachLoopDevice(device string) error {
	loopFile, err := os.OpenFile(device, os.O_RDWR, 0) // #nosec G304 -- loop device path from SetupLoopDevice
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", device, err)
	}
	defer func() { _ = loopFile.Close() }()

	// Detach loop device
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, loopFile.Fd(), unix.LOOP_CLR_FD, 0)
	if errno != 0 {
		return fmt.Errorf("LOOP_CLR_FD failed: %v", errno)
	}

	return nil
}

// FindLoopDevice finds the loop device for a given file by reading /sys
func FindLoopDevice(file string) (string, error) {
	absFile, err := filepath.Abs(file)
	if err != nil {
		return "", err
	}

	// Read /sys/block to find loop devices
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return "", err
	}

	for _, entry := range entries {
		name := entry.Name()
		if len(name) < 4 || name[:4] != "loop" {
			continue
		}

		// Read backing_file
		backingFilePath := fmt.Sprintf("/sys/block/%s/loop/backing_file", name)
		data, err := os.ReadFile(backingFilePath) // #nosec G304 -- sysfs path constructed from known prefix
		if err != nil {
			continue
		}

		// Trim newline
		backingFile := string(data)
		if len(backingFile) > 0 && backingFile[len(backingFile)-1] == '\n' {
			backingFile = backingFile[:len(backingFile)-1]
		}

		absBackingFile, err := filepath.Abs(backingFile)
		if err != nil {
			continue
		}

		if absFile == absBackingFile {
			return "/dev/" + name, nil
		}
	}

	return "", fmt.Errorf("no loop device found for %s", file)
}
