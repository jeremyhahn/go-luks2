// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package filesystem

// Type names a filesystem, as cryptsetup, blkid and the mkfs/fsck tools
// spell it (vfat, not fat32).
type Type string

const (
	// Ext4 is the ext4 filesystem.
	Ext4 Type = "ext4"

	// XFS is the XFS filesystem.
	XFS Type = "xfs"

	// ZFS is the ZFS filesystem (requires zfs-utils).
	ZFS Type = "zfs"

	// FAT32 is the FAT32 filesystem (for EFI partitions).
	FAT32 Type = "vfat"
)

// supported is the single source of truth for the supported set (#195).
// Supported reads it, and Make and Check/Repair refuse anything not in it.
// Every entry must have a dispatch entry with both a make and a check
// implementation; TestSupportedFilesystemsCanBeCreatedAndChecked enforces
// that in both directions.
var supported = []Type{Ext4, XFS, ZFS, FAT32}

// Supported returns the filesystem types this package can create and check.
// The returned slice is a copy; changing it does not change the supported
// set.
func Supported() []Type {
	out := make([]Type, len(supported))
	copy(out, supported)
	return out
}

// isSupported reports whether t is in Supported().
func isSupported(t Type) bool {
	for _, s := range supported {
		if s == t {
			return true
		}
	}
	return false
}
