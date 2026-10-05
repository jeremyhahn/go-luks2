// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package luks2

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
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
	// run, and interprets their exit status. See CheckFilesystemDetailed for
	// what repair means for each type and what the result reports.
	check func(run commandRunner, devicePath string, repair bool) (FilesystemCheckResult, error)
}

// FilesystemCheckResult describes a check that CheckFilesystemDetailed
// reports as successful. A failed check returns an error instead. A zero
// result means the checker reported no repair and no reboot request: for
// ext4 and vfat that is a clean filesystem with nothing written, but
// xfs_repair and zpool scrub never report either, so for xfs and zfs a zero
// result says nothing about whether data was repaired (see CheckFilesystem).
type FilesystemCheckResult struct {
	// Repaired is true when the checker wrote corrections to the filesystem
	// and the filesystem is now consistent. It is only ever set when repair
	// was requested.
	Repaired bool

	// RebootRequired is true when the checker corrected errors and asks for
	// the system to be rebooted before the filesystem is used (e2fsck exit
	// status bit 2). It matters when the filesystem was mounted, for example
	// as the root filesystem, while it was repaired.
	RebootRequired bool
}

// commandRunner runs an external program and returns its combined stdout and
// stderr. A program that ran and exited nonzero is reported as an error with
// an ExitCode() int method, as *exec.ExitError is.
type commandRunner func(name string, args ...string) ([]byte, error)

// execCommand is the commandRunner CheckFilesystem uses. It runs the checker
// from a fixed system directory with a minimal environment; see runSystemTool.
func execCommand(name string, args ...string) ([]byte, error) {
	return runSystemTool(name, args...)
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

	// device is a MAPPING NAME, and it is resolved to a node only through
	// device-mapper: the name is validated, the target is looked up, and the
	// node handed to mkfs must carry the target's device number. This used to
	// accept any name whose /dev/mapper/<name> stat'd as a block device, and
	// /dev/mapper/../sdb is /dev/sdb -- so MakeFilesystem("../sdb", ...) ran
	// mkfs on the raw disk (#250, C3). A stale /dev/mapper entry is refused the
	// same way (C5). See mappedDevicePath.
	if err := ValidateMappingName(device); err != nil {
		return &DeviceError{Device: device, Op: "make filesystem", Err: err}
	}
	devicePath, _, err := mappedDevicePath(device)
	if err != nil {
		if errors.Is(err, ErrVolumeNotUnlocked) {
			return &DeviceError{Device: device, Op: "make filesystem", Err: ErrVolumeNotUnlocked}
		}
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

	// "--" ends the options, so the device is never read as one.
	args = append(args, "--", devicePath)

	output, err := runSystemTool("mkfs.ext4", args...)
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

	args = append(args, "--", devicePath)

	output, err := runSystemTool("mkfs.xfs", args...)
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
	if err := validateZFSOptions(zfs); err != nil {
		return err
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

	// Pool properties, in key order so the command is the same every run.
	for _, key := range slices.Sorted(maps.Keys(zfs.Properties)) {
		args = append(args, "-o", key+"="+zfs.Properties[key])
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

	// Pool name and device, after "--" so neither is read as an option.
	args = append(args, "--", zfs.PoolName, devicePath)

	output, err := runSystemTool("zpool", args...)
	if err != nil {
		return fmt.Errorf("zpool create failed: %w\nOutput: %s", err, string(output))
	}

	// Create dataset if specified
	if zfs.DatasetName != "" && zfs.DatasetName != "root" {
		dsArgs := []string{"create"}
		for _, prop := range datasetProps {
			dsArgs = append(dsArgs, "-o", prop)
		}
		dsArgs = append(dsArgs, "--", zfs.PoolName+"/"+zfs.DatasetName)

		output, err = runSystemTool("zfs", dsArgs...)
		if err != nil {
			return fmt.Errorf("zfs create failed: %w\nOutput: %s", err, string(output))
		}
	}

	return nil
}

// ZFS names and option values reach zpool and zfs as separate arguments, so
// there is no shell to inject into -- but an argument that starts with "-" is
// an OPTION to those programs, and a pool name like "-f" or a dataset like
// "tank/-o" changes what the command does rather than what it names (#250,
// C7). Each value is therefore held to the naming rules zpool(8) and zfs(8)
// document, which no option can satisfy.

// zfsReservedPoolPrefixes are the vdev keywords zpool(8) reserves: a pool may
// not be named, or begin with, any of them.
var zfsReservedPoolPrefixes = []string{"mirror", "raidz", "draid", "spare"}

// zfsReservedPoolNames are the further vdev class keywords a pool may not be
// named.
var zfsReservedPoolNames = []string{"log", "cache", "special", "dedup"}

// isZFSNameByte reports whether c may appear in a ZFS pool or dataset
// component: letters, digits, underscore, hyphen, colon and period.
func isZFSNameByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		c == '_' || c == '-' || c == ':' || c == '.'
}

// zfsMaxNameLength is ZFS_MAX_DATASET_NAME_LEN less its terminating NUL.
const zfsMaxNameLength = 255

func invalidZFSOption(what, value, why string) error {
	return &detailError{Kind: ErrInvalidFilesystemOption, Detail: fmt.Sprintf("ZFS %s %q %s", what, value, why)}
}

// validateZFSPoolName enforces zpool(8)'s pool naming rules: a letter first,
// then letters, digits, "_", "-", ":" and ".", and none of the reserved vdev
// keywords. A space is permitted by zpool and refused here.
func validateZFSPoolName(name string) error {
	if name == "" || len(name) > zfsMaxNameLength {
		return invalidZFSOption("pool name", name, "must be 1 to 255 bytes long")
	}
	if c := name[0]; (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
		return invalidZFSOption("pool name", name, "must begin with a letter")
	}
	for i := 0; i < len(name); i++ {
		if !isZFSNameByte(name[i]) {
			return invalidZFSOption("pool name", name, "may contain only letters, digits, _ - : and .")
		}
	}
	lower := strings.ToLower(name)
	for _, prefix := range zfsReservedPoolPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return invalidZFSOption("pool name", name, "begins with the reserved word "+prefix)
		}
	}
	if slices.Contains(zfsReservedPoolNames, lower) {
		return invalidZFSOption("pool name", name, "is a reserved word")
	}
	if len(lower) > 1 && lower[0] == 'c' && lower[1] >= '0' && lower[1] <= '9' {
		return invalidZFSOption("pool name", name, "begins with c and a digit, which zpool reserves for device names")
	}
	return nil
}

// validateZFSDatasetName enforces zfs(8)'s component rules on a dataset path
// below the pool: "/"-separated components of letters, digits, "_", "-", ":"
// and ".", none empty, none "." or "..", and none starting with "-".
func validateZFSDatasetName(name string) error {
	if len(name) > zfsMaxNameLength {
		return invalidZFSOption("dataset name", name, "is longer than 255 bytes")
	}
	for _, component := range strings.Split(name, "/") {
		if component == "" || component == "." || component == ".." || component[0] == '-' {
			return invalidZFSOption("dataset name", name, "has an empty, \".\", \"..\" or option-like component")
		}
		for i := 0; i < len(component); i++ {
			if !isZFSNameByte(component[i]) {
				return invalidZFSOption("dataset name", name, "may contain only letters, digits, _ - : . and /")
			}
		}
	}
	return nil
}

// validateZFSToken checks a value that becomes part of a key=value argument --
// a property name, a feature, a compression or record size: it must be
// non-empty and drawn from letters, digits, "_", "-", ":", "." and "@", and
// must not start with "-".
func validateZFSToken(what, value string) error {
	if value == "" || value[0] == '-' {
		return invalidZFSOption(what, value, "must be non-empty and must not start with -")
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; !isZFSNameByte(c) && c != '@' {
			return invalidZFSOption(what, value, "may contain only letters, digits, _ - : . and @")
		}
	}
	return nil
}

// validateZFSOptions checks every ZFSOptions field that reaches a command line.
func validateZFSOptions(zfs *ZFSOptions) error {
	if err := validateZFSPoolName(zfs.PoolName); err != nil {
		return err
	}
	if zfs.DatasetName != "" && zfs.DatasetName != "root" {
		if err := validateZFSDatasetName(zfs.DatasetName); err != nil {
			return err
		}
	}
	if zfs.Ashift != 0 && (zfs.Ashift < 9 || zfs.Ashift > 16) {
		return invalidZFSOption("ashift", fmt.Sprint(zfs.Ashift), "must be between 9 and 16")
	}
	if mp := zfs.MountPoint; mp != "" && mp != "none" && mp != "legacy" && (!strings.HasPrefix(mp, "/") || strings.ContainsAny(mp, "\x00\n")) {
		return invalidZFSOption("mount point", mp, "must be an absolute path, \"none\" or \"legacy\"")
	}
	for _, check := range []struct{ what, value string }{
		{"compression", zfs.Compression},
		{"record size", zfs.RecordSize},
	} {
		if check.value != "" {
			if err := validateZFSToken(check.what, check.value); err != nil {
				return err
			}
		}
	}
	for _, feature := range zfs.Features {
		if err := validateZFSToken("feature", feature); err != nil {
			return err
		}
	}
	for key, value := range zfs.Properties {
		if err := validateZFSToken("property name", key); err != nil {
			return err
		}
		if strings.ContainsAny(value, "\x00\n") {
			return invalidZFSOption("property value for", key, "contains a NUL or newline")
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

	args = append(args, "--", devicePath)

	output, err := runSystemTool("mkfs.fat", args...)
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
// repaired. With repair, e2fsck exiting 1 (errors corrected) or 2 (corrected,
// reboot requested) is success, and vfat repairs that fsck.fat reports by
// exiting 1 are confirmed by a read-only recheck and then count as success.
//
// ZFS is the exception, and repair does not change it:
//   - devicePath is the name of a ZFS pool, not a device path.
//   - It starts `zpool scrub` and returns once the scrub has started. It does
//     not wait for the scrub or report what it finds; read `zpool status`
//     for that.
//   - A scrub is not read-only. On a pool with redundancy (mirror, raidz) it
//     repairs damaged data as it goes, even when repair is false.
//
// CheckFilesystem reports only success or failure. CheckFilesystemDetailed
// runs the same check and also reports whether a repair was written and
// whether the checker asked for a reboot.
func CheckFilesystem(devicePath string, fstype FilesystemType, repair bool) error {
	_, err := CheckFilesystemDetailed(devicePath, fstype, repair)
	return err
}

// CheckFilesystemDetailed is CheckFilesystem, and on success it also reports
// what the check did. Everything CheckFilesystem documents applies here.
//
// Result.Repaired is set when, with repair, the checker wrote corrections and
// the filesystem is now consistent: e2fsck exiting 1 or 2, or fsck.fat
// exiting 1 followed by a clean read-only recheck. Result.RebootRequired is
// set when e2fsck exits with bit 2 set ("errors corrected, system should be
// rebooted"). xfs_repair and zpool scrub report neither, so their results are
// always zero.
//
// A failed check is returned as an error: a *FilesystemCommandError carrying
// the checker's output for a checker that ran or could not be started, and
// ErrUnsupportedFilesystem for a type outside SupportedFilesystems().
func CheckFilesystemDetailed(devicePath string, fstype FilesystemType, repair bool) (FilesystemCheckResult, error) {
	ops, err := dispatchFor(fstype)
	if err != nil {
		return FilesystemCheckResult{}, err
	}
	return ops.check(execCommand, devicePath, repair)
}

// e2fsck exit status bits, from e2fsck(8). The status is a bitmask: several
// bits can be set at once, and any bit from e2fsckUncorrected upward is a
// failure (uncorrected errors, an operational error, a usage error, a
// canceled check or a shared-library error).
const (
	// e2fsckCorrected: filesystem errors were corrected.
	e2fsckCorrected = 1

	// e2fsckRebootRequired: errors were corrected and the system should be
	// rebooted.
	e2fsckRebootRequired = 2

	// e2fsckUncorrected: errors were left uncorrected. Every higher bit is a
	// failure as well.
	e2fsckUncorrected = 4
)

// checkExt4 checks an ext4 filesystem with e2fsck.
//
// Read-only (-n), any nonzero exit is a failure: e2fsck could not certify the
// filesystem clean, and -n wrote nothing. Repairing (-p), the exit status is
// read as e2fsck's bitmask: 0 is clean, 1 and 2 (and 3) are success with the
// repair -- and for bit 2 the reboot request -- reported in the result, and
// any status with bit 4 or higher set is a failure.
func checkExt4(run commandRunner, devicePath string, repair bool) (FilesystemCheckResult, error) {
	if !repair {
		return FilesystemCheckResult{}, runCheck(run, "e2fsck", "-n", "--", devicePath) // Read-only
	}

	err := runCheck(run, "e2fsck", "-p", "--", devicePath) // Auto-repair
	if err == nil {
		return FilesystemCheckResult{}, nil
	}
	status := exitStatus(err)
	if status <= 0 || status >= e2fsckUncorrected {
		// Not started, killed by a signal, or a failure bit is set.
		return FilesystemCheckResult{}, err
	}
	return FilesystemCheckResult{
		Repaired:       status&(e2fsckCorrected|e2fsckRebootRequired) != 0,
		RebootRequired: status&e2fsckRebootRequired != 0,
	}, nil
}

// checkXFS checks an XFS filesystem with xfs_repair.
func checkXFS(run commandRunner, devicePath string, repair bool) (FilesystemCheckResult, error) {
	if repair {
		return FilesystemCheckResult{}, runCheck(run, "xfs_repair", "--", devicePath) // XFS repairs automatically
	}
	return FilesystemCheckResult{}, runCheck(run, "xfs_repair", "-n", "--", devicePath) // Read-only
}

// checkZFS starts a scrub of the ZFS pool named devicePath, the ZFS
// equivalent of fsck. It ignores repair: see CheckFilesystem.
func checkZFS(run commandRunner, devicePath string, _ bool) (FilesystemCheckResult, error) {
	if err := validateZFSPoolName(devicePath); err != nil {
		return FilesystemCheckResult{}, err
	}
	return FilesystemCheckResult{}, runCheck(run, "zpool", "scrub", "--", devicePath)
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
func checkFAT32(run commandRunner, devicePath string, repair bool) (FilesystemCheckResult, error) {
	if !repair {
		return FilesystemCheckResult{}, runCheck(run, "fsck.fat", "-n", "--", devicePath) // Read-only
	}

	err := runCheck(run, "fsck.fat", "-a", "--", devicePath) // Auto-repair
	if exitStatus(err) != fatRepairedOrInconsistent {
		return FilesystemCheckResult{}, err
	}
	if runCheck(run, "fsck.fat", "-n", "--", devicePath) != nil {
		return FilesystemCheckResult{}, err
	}
	return FilesystemCheckResult{Repaired: true}, nil
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
	cmd, err := toolCommand("blkid", "-o", "export", "--", devicePath)
	if err != nil {
		return nil, &detailError{Detail: "blkid failed", Err: err}
	}
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
