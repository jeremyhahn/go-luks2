// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package filesystem

import (
	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/command"
)

// sysT holds this package's seams: the tool resolver, the mount(2)/umount(2)
// syscalls, and the two mount tables Mount, Unmount, IsMounted and
// DeviceMounted read. It is a single unexported package value, not a family
// of package-level func vars; the unit tests substitute its
// fields for the duration of a test and restore them with t.Cleanup.
type sysT struct {
	// tools resolves and runs mkfs.*, e2fsck, xfs_repair, fsck.fat, zpool,
	// zfs and blkid.
	tools command.Tools

	// mount and unmount are the syscalls Mount and Unmount go through.
	mount   func(source, target, fstype string, flags uintptr, data string) error
	unmount func(target string, flags int) error

	// mountInfoPath and procMountsPath are /proc/self/mountinfo and
	// /proc/mounts, read by DeviceMounted and IsMounted respectively.
	mountInfoPath  string
	procMountsPath string
}

func defaultSys() sysT {
	return sysT{
		tools:          command.System(),
		mount:          unix.Mount,
		unmount:        unix.Unmount,
		mountInfoPath:  "/proc/self/mountinfo",
		procMountsPath: "/proc/mounts",
	}
}

var sys = defaultSys()
