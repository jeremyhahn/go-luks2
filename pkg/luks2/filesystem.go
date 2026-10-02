// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package luks2

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// FilesystemType represents supported filesystem types
type FilesystemType string

const (
	// FilesystemExt2 names the ext2 filesystem. It is deliberately NOT
	// supported: ext2 has no journal, and the owner ruled ext2 and ext3 out
	// of this library's supported set (#195). The constant remains so the
	// name can be refused explicitly; MakeFilesystemWithOptions and
	// CheckFilesystem return ErrUnsupportedFilesystem for it.
	FilesystemExt2 FilesystemType = "ext2"

	// FilesystemExt3 names the ext3 filesystem. It is NOT supported: this
	// library does not offer ext3 on an encrypted volume (owner ruling, #195)
	// -- ext4 is the ext-family filesystem it supports. The constant remains
	// so the name can be refused explicitly; MakeFilesystemWithOptions and
	// CheckFilesystem return ErrUnsupportedFilesystem for it.
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

// supportedFilesystems is the single source of truth for the supported set
// (#195). SupportedFilesystems and IsFilesystemSupported read it, and
// MakeFilesystemWithOptions and CheckFilesystem refuse anything not in it.
// Every entry must have a filesystemDispatch entry with both a make and a
// check implementation; TestSupportedFilesystemsCanBeCreatedAndChecked
// enforces that in both directions.
var supportedFilesystems = []FilesystemType{
	FilesystemExt4,
	FilesystemXFS,
	FilesystemZFS,
	FilesystemFAT32,
}

// filesystemOps is how one supported filesystem is created and checked.
type filesystemOps struct {
	// make creates the filesystem on devicePath.
	make func(devicePath string, opts *FilesystemOptions) error

	// check checks the filesystem on devicePath, running its tools through
	// run, and interprets their exit status. See CheckFilesystem for what
	// repair means for each type.
	check func(run commandRunner, devicePath string, repair bool) error
}

// commandRunner runs an external program and returns its combined stdout and
// stderr. A program that ran and exited nonzero is reported as an error with
// an ExitCode() int method, as *exec.ExitError is.
type commandRunner func(name string, args ...string) ([]byte, error)

// execCommand is the commandRunner CheckFilesystem uses.
func execCommand(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput() // #nosec G204 -- name is a fixed checker from filesystemDispatch; args are fixed flags plus the caller's device path
}

// runCheck runs one checker command and reports any failure as a
// *FilesystemCommandError. The device is the last argument.
func runCheck(run commandRunner, name string, args ...string) error {
	output, err := run(name, args...)
	if err != nil {
		return &FilesystemCommandError{Command: name, Device: args[len(args)-1], Output: string(output), Err: err}
	}
	return nil
}

// exitStatus returns the exit status carried by err, or -1 when err is nil or
// is not a program's nonzero exit (for example, the program was not found).
func exitStatus(err error) int {
	var ec interface{ ExitCode() int }
	if err == nil || !errors.As(err, &ec) {
		return -1
	}
	return ec.ExitCode()
}

// filesystemDispatch holds the create and check implementation for every
// entry in supportedFilesystems, and for nothing else.
var filesystemDispatch = map[FilesystemType]filesystemOps{
	FilesystemExt4:  {make: makeExt4, check: checkExt4},
	FilesystemXFS:   {make: makeXFS, check: checkXFS},
	FilesystemZFS:   {make: makeZFS, check: checkZFS},
	FilesystemFAT32: {make: makeFAT32, check: checkFAT32},
}

// SupportedFilesystems returns the filesystem types this package can create
// and check. The returned slice is a copy; changing it does not change the
// supported set.
func SupportedFilesystems() []FilesystemType {
	out := make([]FilesystemType, len(supportedFilesystems))
	copy(out, supportedFilesystems)
	return out
}

// IsFilesystemSupported reports whether fstype is in SupportedFilesystems().
// It agrees with MakeFilesystemWithOptions and CheckFilesystem: both refuse
// exactly the types this returns false for.
func IsFilesystemSupported(fstype FilesystemType) bool {
	for _, fs := range supportedFilesystems {
		if fs == fstype {
			return true
		}
	}
	return false
}

// dispatchFor returns the implementation for fstype, or an error wrapping
// ErrUnsupportedFilesystem when fstype is not in SupportedFilesystems().
func dispatchFor(fstype FilesystemType) (filesystemOps, error) {
	ops, ok := filesystemDispatch[fstype]
	if !IsFilesystemSupported(fstype) || !ok {
		return filesystemOps{}, &UnsupportedFilesystemError{Filesystem: fstype}
	}
	return ops, nil
}

// MakeFilesystem creates a filesystem on an unlocked LUKS volume
func MakeFilesystem(device, fstype, label string) error {
	return MakeFilesystemWithOptions(device, FilesystemType(fstype), &FilesystemOptions{Label: label})
}

// MakeFilesystemWithOptions creates a filesystem with detailed options
func MakeFilesystemWithOptions(device string, fstype FilesystemType, opts *FilesystemOptions) error {
	ops, err := dispatchFor(fstype)
	if err != nil {
		return err
	}

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
		return &DeviceError{Device: device, Op: "make filesystem", Err: ErrVolumeNotUnlocked}
	}

	// Get the actual device path
	devicePath, err := GetMappedDevicePath(device)
	if err != nil {
		return &DeviceError{Device: device, Op: "get mapped device path", Err: err}
	}

	return ops.make(devicePath, opts)
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

// CheckFilesystem checks the filesystem on a device. Every type in
// SupportedFilesystems() can be checked; any other type is refused with
// ErrUnsupportedFilesystem before a command is run.
//
// For ext4, xfs and vfat the check is read-only unless repair is set, and it
// returns nil only when the filesystem is clean or, with repair, has been
// repaired. With repair, vfat repairs that fsck.fat reports by exiting 1 are
// confirmed by a read-only recheck and then count as success.
//
// ZFS is the exception, and repair does not change it:
//   - devicePath is the name of a ZFS pool, not a device path.
//   - It starts `zpool scrub` and returns once the scrub has started. It does
//     not wait for the scrub or report what it finds; read `zpool status`
//     for that.
//   - A scrub is not read-only. On a pool with redundancy (mirror, raidz) it
//     repairs damaged data as it goes, even when repair is false.
func CheckFilesystem(devicePath string, fstype FilesystemType, repair bool) error {
	ops, err := dispatchFor(fstype)
	if err != nil {
		return err
	}
	return ops.check(execCommand, devicePath, repair)
}

// checkExt4 checks an ext4 filesystem with e2fsck.
func checkExt4(run commandRunner, devicePath string, repair bool) error {
	if repair {
		return runCheck(run, "e2fsck", "-p", devicePath) // Auto-repair
	}
	return runCheck(run, "e2fsck", "-n", devicePath) // Read-only
}

// checkXFS checks an XFS filesystem with xfs_repair.
func checkXFS(run commandRunner, devicePath string, repair bool) error {
	if repair {
		return runCheck(run, "xfs_repair", devicePath) // XFS repairs automatically
	}
	return runCheck(run, "xfs_repair", "-n", devicePath) // Read-only
}

// checkZFS starts a scrub of the ZFS pool named devicePath, the ZFS
// equivalent of fsck. It ignores repair: see CheckFilesystem.
func checkZFS(run commandRunner, devicePath string, _ bool) error {
	return runCheck(run, "zpool", "scrub", devicePath)
}

// fatRepairedOrInconsistent is the fsck.fat exit status that means either
// "changes were written" or "stopped on an internal inconsistency". dosfstools
// exits 1 in both cases, so with -a it does not by itself say whether the
// repair worked.
const fatRepairedOrInconsistent = 1

// checkFAT32 checks a FAT filesystem with fsck.fat, from the same dosfstools
// package as the mkfs.fat that makeFAT32 runs.
//
// Read-only (-n), any nonzero exit is a failure: exit 1 means problems were
// found. Repairing (-a), exit 1 is ambiguous (see fatRepairedOrInconsistent),
// so it is followed by a read-only recheck: a clean recheck means the repair
// worked, and anything else returns the repair run's error, whose output says
// what fsck.fat found.
func checkFAT32(run commandRunner, devicePath string, repair bool) error {
	if !repair {
		return runCheck(run, "fsck.fat", "-n", devicePath) // Read-only
	}

	err := runCheck(run, "fsck.fat", "-a", devicePath) // Auto-repair
	if exitStatus(err) != fatRepairedOrInconsistent {
		return err
	}
	if runCheck(run, "fsck.fat", "-n", devicePath) != nil {
		return err
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
	cmd := exec.Command("blkid", "-o", "export", devicePath) // #nosec G204 -- fixed argv, no shell; devicePath is a block-device path chosen by the caller
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
