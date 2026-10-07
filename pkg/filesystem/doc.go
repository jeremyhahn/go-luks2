// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package filesystem makes, checks, repairs, detects and inspects
// filesystems on a block device, and mounts and unmounts them.
//
// Make, Check and Repair run an external tool (mkfs.*, e2fsck, xfs_repair,
// fsck.fat, zpool, zfs) through internal/command, which resolves it from a
// fixed set of system directories with a minimal environment rather than the
// caller's PATH; Detect and Inspect do the same with blkid. Mount, Unmount,
// IsMounted and DeviceMounted call the mount(2)/umount(2) syscalls and read
// the kernel's mount tables directly.
//
// Every function takes a device PATH, never a device-mapper mapping name:
// resolving a mapping name to a path, and verifying the path actually names
// the mapping, is the caller's job. pkg/luks2 does that with device-mapper
// before calling here.
package filesystem
