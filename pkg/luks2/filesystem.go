// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package luks2

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// FilesystemType represents supported filesystem types
type FilesystemType string

const (
	// FilesystemExt2 is the ext2 filesystem
	FilesystemExt2 FilesystemType = "ext2"

	// FilesystemExt3 is the ext3 filesystem
	FilesystemExt3 FilesystemType = "ext3"

	// FilesystemExt4 is the ext4 filesystem
	FilesystemExt4 FilesystemType = "ext4"

	// FilesystemXFS is the XFS filesystem
	FilesystemXFS FilesystemType = "xfs"

	// FilesystemZFS is the ZFS filesystem (requires zfs-utils)
	FilesystemZFS FilesystemType = "zfs"

	// FilesystemFAT32 is the FAT32 filesystem (for EFI partitions)
	FilesystemFAT32 FilesystemType = "vfat"
)

// FilesystemOptions contains filesystem-specific options
type FilesystemOptions struct {
	// Label for the filesystem
	Label string

	// BlockSize for ext4/xfs (0 = default)
	BlockSize int

	// Force formatting even if existing filesystem detected
	Force bool

	// Ext4Options contains ext4-specific options
	Ext4Options *Ext4Options

	// XFSOptions contains xfs-specific options
	XFSOptions *XFSOptions

	// ZFSOptions contains zfs-specific options
	ZFSOptions *ZFSOptions
}

// Ext4Options contains ext4-specific formatting options
type Ext4Options struct {
	// JournalSize in MB (0 = auto)
	JournalSize int

	// InodeSize (128, 256, 512) - default 256
	InodeSize int

	// InodesPerGroup (0 = auto)
	InodesPerGroup int

	// ReservedBlocks percentage (default 5%)
	ReservedBlocksPercent float64

	// StrideSize for RAID arrays (0 = none)
	StrideSize int

	// StripeWidth for RAID arrays (0 = none)
	StripeWidth int

	// DisableMetadataChecksums disables metadata checksums
	DisableMetadataChecksums bool

	// EnableLargeDir enables large directory support (dir_index)
	EnableLargeDir bool

	// Enable64bit enables 64-bit block numbers
	Enable64bit bool
}

// XFSOptions contains xfs-specific formatting options
type XFSOptions struct {
	// AgCount is the number of allocation groups (0 = auto)
	AgCount int

	// BlockSize (512, 1024, 2048, 4096) - default 4096
	BlockSize int

	// InodeSize (256, 512, 1024, 2048) - default 512
	InodeSize int

	// SectorSize (512, 4096) - default 512
	SectorSize int

	// LogSize in MB (0 = auto)
	LogSize int

	// RealTime enables real-time subvolume
	RealTime bool

	// RefLink enables reflink support (CoW)
	RefLink bool

	// BigTime enables timestamps beyond 2038
	BigTime bool

	// NoAlign disables stripe unit alignment
	NoAlign bool
}

// ZFSOptions contains zfs-specific options
type ZFSOptions struct {
	// PoolName is the name of the ZFS pool to create
	PoolName string

	// DatasetName is the name of the dataset (default: root)
	DatasetName string

	// Compression algorithm (lz4, zstd, gzip, off)
	Compression string

	// Ashift value for alignment (9=512, 12=4K, 13=8K)
	Ashift int

	// RecordSize (128K default)
	RecordSize string

	// EnableDedup enables deduplication
	EnableDedup bool

	// MountPoint for the pool
	MountPoint string

	// Features to enable
	Features []string

	// Properties to set
	Properties map[string]string
}

// SupportedFilesystems returns the list of supported filesystem types
func SupportedFilesystems() []FilesystemType {
	return []FilesystemType{
		FilesystemExt4,
		FilesystemXFS,
		FilesystemZFS,
		FilesystemFAT32,
	}
}

// IsFilesystemSupported checks if a filesystem type is supported
func IsFilesystemSupported(fstype FilesystemType) bool {
	for _, fs := range SupportedFilesystems() {
		if fs == fstype {
			return true
		}
	}
	return false
}

// MakeFilesystem creates a filesystem on an unlocked LUKS volume
func MakeFilesystem(device, fstype, label string) error {
	return MakeFilesystemWithOptions(device, FilesystemType(fstype), &FilesystemOptions{Label: label})
}

// MakeFilesystemWithOptions creates a filesystem with detailed options
func MakeFilesystemWithOptions(device string, fstype FilesystemType, opts *FilesystemOptions) error {
	if opts == nil {
		opts = &FilesystemOptions{}
	}

	// Wait for device to appear (device-mapper creates it asynchronously)
	var deviceExists bool
	for i := 0; i < 50; i++ {
		if IsUnlocked(device) {
			deviceExists = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !deviceExists {
		return fmt.Errorf("device not found: %s (is volume unlocked?)", device)
	}

	// Get the actual device path
	devicePath, err := GetMappedDevicePath(device)
	if err != nil {
		return fmt.Errorf("failed to get device path: %w", err)
	}

	switch fstype {
	case FilesystemExt2:
		return makeExtFS(devicePath, "mkfs.ext2", opts)
	case FilesystemExt3:
		return makeExtFS(devicePath, "mkfs.ext3", opts)
	case FilesystemExt4:
		return makeExt4(devicePath, opts)
	case FilesystemXFS:
		return makeXFS(devicePath, opts)
	case FilesystemZFS:
		return makeZFS(devicePath, opts)
	case FilesystemFAT32:
		return makeFAT32(devicePath, opts)
	default:
		return fmt.Errorf("unsupported filesystem type: %s", fstype)
	}
}

// makeExt4 creates an ext4 filesystem
func makeExt4(devicePath string, opts *FilesystemOptions) error {
	args := []string{}

	// Label
	if opts.Label != "" {
		args = append(args, "-L", opts.Label)
	}

	// Block size
	if opts.BlockSize > 0 {
		args = append(args, "-b", fmt.Sprintf("%d", opts.BlockSize))
	}

	// Force
	if opts.Force {
		args = append(args, "-F")
	}

	// Ext4-specific options
	if opts.Ext4Options != nil {
		ext4 := opts.Ext4Options

		// Journal size
		if ext4.JournalSize > 0 {
			args = append(args, "-J", fmt.Sprintf("size=%d", ext4.JournalSize))
		}

		// Inode size
		if ext4.InodeSize > 0 {
			args = append(args, "-I", fmt.Sprintf("%d", ext4.InodeSize))
		}

		// Reserved blocks percentage
		if ext4.ReservedBlocksPercent > 0 {
			args = append(args, "-m", fmt.Sprintf("%.1f", ext4.ReservedBlocksPercent))
		}

		// Extended options
		var extOpts []string
		if ext4.StrideSize > 0 {
			extOpts = append(extOpts, fmt.Sprintf("stride=%d", ext4.StrideSize))
		}
		if ext4.StripeWidth > 0 {
			extOpts = append(extOpts, fmt.Sprintf("stripe_width=%d", ext4.StripeWidth))
		}
		if len(extOpts) > 0 {
			args = append(args, "-E", strings.Join(extOpts, ","))
		}

		// Features
		var features []string
		if ext4.Enable64bit {
			features = append(features, "64bit")
		}
		if ext4.EnableLargeDir {
			features = append(features, "dir_index", "large_dir")
		}
		if ext4.DisableMetadataChecksums {
			features = append(features, "^metadata_csum")
		}
		if len(features) > 0 {
			args = append(args, "-O", strings.Join(features, ","))
		}
	}

	args = append(args, devicePath)

	cmd := exec.Command("mkfs.ext4", args...) // #nosec G204 -- args constructed from validated options
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mkfs.ext4 failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}

// makeExtFS creates an ext2 or ext3 filesystem using the specified mkfs command
func makeExtFS(devicePath string, mkfsCmd string, opts *FilesystemOptions) error {
	args := []string{}

	// Label
	if opts.Label != "" {
		args = append(args, "-L", opts.Label)
	}

	// Block size
	if opts.BlockSize > 0 {
		args = append(args, "-b", fmt.Sprintf("%d", opts.BlockSize))
	}

	// Force
	if opts.Force {
		args = append(args, "-F")
	}

	args = append(args, devicePath)

	cmd := exec.Command(mkfsCmd, args...) // #nosec G204 -- mkfsCmd is from trusted internal constant
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s failed: %w\nOutput: %s", mkfsCmd, err, string(output))
	}

	return nil
}

// makeXFS creates an XFS filesystem
func makeXFS(devicePath string, opts *FilesystemOptions) error {
	args := []string{}

	// Label
	if opts.Label != "" {
		args = append(args, "-L", opts.Label)
	}

	// Force
	if opts.Force {
		args = append(args, "-f")
	}

	// XFS-specific options
	if opts.XFSOptions != nil {
		xfs := opts.XFSOptions

		// Block size
		if xfs.BlockSize > 0 {
			args = append(args, "-b", fmt.Sprintf("size=%d", xfs.BlockSize))
		}

		// Sector size
		if xfs.SectorSize > 0 {
			args = append(args, "-s", fmt.Sprintf("size=%d", xfs.SectorSize))
		}

		// Inode options
		if xfs.InodeSize > 0 {
			args = append(args, "-i", fmt.Sprintf("size=%d", xfs.InodeSize))
		}

		// Allocation groups
		if xfs.AgCount > 0 {
			args = append(args, "-d", fmt.Sprintf("agcount=%d", xfs.AgCount))
		}

		// Log size
		if xfs.LogSize > 0 {
			args = append(args, "-l", fmt.Sprintf("size=%dm", xfs.LogSize))
		}

		// Metadata options
		var metaOpts []string
		if xfs.RefLink {
			metaOpts = append(metaOpts, "reflink=1")
		}
		if xfs.BigTime {
			metaOpts = append(metaOpts, "bigtime=1")
		}
		if len(metaOpts) > 0 {
			args = append(args, "-m", strings.Join(metaOpts, ","))
		}

		// Alignment
		if xfs.NoAlign {
			args = append(args, "-d", "noalign")
		}
	}

	args = append(args, devicePath)

	cmd := exec.Command("mkfs.xfs", args...) // #nosec G204 -- args constructed from validated options
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mkfs.xfs failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}

// makeZFS creates a ZFS pool and dataset
func makeZFS(devicePath string, opts *FilesystemOptions) error {
	if opts.ZFSOptions == nil {
		return fmt.Errorf("ZFS requires ZFSOptions to be specified")
	}

	zfs := opts.ZFSOptions
	if zfs.PoolName == "" {
		return fmt.Errorf("ZFS pool name is required")
	}

	// Build zpool create command
	args := []string{"create"}

	// Force
	if opts.Force {
		args = append(args, "-f")
	}

	// Mount point
	if zfs.MountPoint != "" {
		args = append(args, "-m", zfs.MountPoint)
	}

	// Ashift
	if zfs.Ashift > 0 {
		args = append(args, "-o", fmt.Sprintf("ashift=%d", zfs.Ashift))
	}

	// Pool properties
	for key, val := range zfs.Properties {
		args = append(args, "-o", fmt.Sprintf("%s=%s", key, val))
	}

	// Dataset properties
	var datasetProps []string
	if zfs.Compression != "" {
		datasetProps = append(datasetProps, fmt.Sprintf("compression=%s", zfs.Compression))
	}
	if zfs.RecordSize != "" {
		datasetProps = append(datasetProps, fmt.Sprintf("recordsize=%s", zfs.RecordSize))
	}
	if zfs.EnableDedup {
		datasetProps = append(datasetProps, "dedup=on")
	}
	for _, prop := range datasetProps {
		args = append(args, "-O", prop)
	}

	// Features
	for _, feature := range zfs.Features {
		args = append(args, "-o", fmt.Sprintf("feature@%s=enabled", feature))
	}

	// Pool name and device
	args = append(args, zfs.PoolName, devicePath)

	cmd := exec.Command("zpool", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("zpool create failed: %w\nOutput: %s", err, string(output))
	}

	// Create dataset if specified
	if zfs.DatasetName != "" && zfs.DatasetName != "root" {
		dsArgs := []string{"create"}
		for _, prop := range datasetProps {
			dsArgs = append(dsArgs, "-o", prop)
		}
		dsArgs = append(dsArgs, fmt.Sprintf("%s/%s", zfs.PoolName, zfs.DatasetName))

		cmd = exec.Command("zfs", dsArgs...)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("zfs create failed: %w\nOutput: %s", err, string(output))
		}
	}

	return nil
}

// makeFAT32 creates a FAT32 filesystem
func makeFAT32(devicePath string, opts *FilesystemOptions) error {
	args := []string{"-F", "32"}

	// Label
	if opts.Label != "" {
		args = append(args, "-n", opts.Label)
	}

	args = append(args, devicePath)

	cmd := exec.Command("mkfs.fat", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mkfs.fat failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}

// CheckFilesystem checks the filesystem on a device
func CheckFilesystem(devicePath string, fstype FilesystemType, repair bool) error {
	var cmd *exec.Cmd

	switch fstype {
	case FilesystemExt4:
		args := []string{"-n"} // Read-only check by default
		if repair {
			args = []string{"-p"} // Auto-repair
		}
		args = append(args, devicePath)
		cmd = exec.Command("e2fsck", args...)

	case FilesystemXFS:
		args := []string{"-n"} // Read-only check by default
		if repair {
			args = []string{} // XFS repairs automatically
		}
		args = append(args, devicePath)
		cmd = exec.Command("xfs_repair", args...)

	case FilesystemZFS:
		// ZFS scrub is the equivalent
		args := []string{"scrub", devicePath}
		cmd = exec.Command("zpool", args...) // #nosec G204 -- args constructed from validated options

	default:
		return fmt.Errorf("filesystem check not supported for: %s", fstype)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("filesystem check failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}

// GetFilesystemInfo returns information about a filesystem
type FilesystemInfo struct {
	Type       FilesystemType
	Label      string
	UUID       string
	BlockSize  int
	TotalSize  uint64
	UsedSize   uint64
	FreeSize   uint64
	MountPoint string
}

// GetFilesystemInfo retrieves filesystem information from a device
func GetFilesystemInfo(devicePath string) (*FilesystemInfo, error) {
	// Use blkid to get filesystem information
	cmd := exec.Command("blkid", "-o", "export", devicePath)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("blkid failed: %w", err)
	}

	info := &FilesystemInfo{}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], parts[1]
		switch key {
		case "TYPE":
			info.Type = FilesystemType(value)
		case "LABEL":
			info.Label = value
		case "UUID":
			info.UUID = value
		case "BLOCK_SIZE":
			_, _ = fmt.Sscanf(value, "%d", &info.BlockSize)
		}
	}

	return info, nil
}
