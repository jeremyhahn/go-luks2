// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// MountOptions contains options for mounting
type MountOptions struct {
	Device     string  // Device mapper name (e.g., "my-volume")
	MountPoint string  // Where to mount (e.g., "/mnt/encrypted")
	FSType     string  // Filesystem type (e.g., "ext4", "xfs")
	Flags      uintptr // Mount flags (unix.MS_RDONLY, etc.)
	Data       string  // Mount data/options
}

// Mount mounts an unlocked LUKS volume using syscall
func Mount(opts MountOptions) error {
	// Get the device path (handles both udev and non-udev environments)
	devicePath, err := GetMappedDevicePath(opts.Device)
	if err != nil {
		return fmt.Errorf("device %s not found: is it unlocked?", opts.Device)
	}

	// Check if device exists
	if _, err := os.Stat(devicePath); err != nil {
		return fmt.Errorf("device %s not found: is it unlocked?", devicePath)
	}

	// Check if mount point exists
	if _, err := os.Stat(opts.MountPoint); os.IsNotExist(err) {
		return fmt.Errorf("mount point %s does not exist", opts.MountPoint)
	}

	// Use syscall to mount
	err = unix.Mount(devicePath, opts.MountPoint, opts.FSType, opts.Flags, opts.Data)
	if err != nil {
		return fmt.Errorf("mount syscall failed: %w", err)
	}

	return nil
}

// Unmount unmounts a LUKS volume using syscall
func Unmount(mountPoint string, flags int) error {
	err := unix.Unmount(mountPoint, flags)
	if err != nil {
		return fmt.Errorf("unmount syscall failed: %w", err)
	}
	return nil
}

// IsMounted checks if a path is mounted by reading /proc/mounts
func IsMounted(mountPoint string) (bool, error) {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return false, fmt.Errorf("failed to open /proc/mounts: %w", err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[1] == mountPoint {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("error reading /proc/mounts: %w", err)
	}

	return false, nil
}
