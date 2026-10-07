// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package filesystem

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// MakeParams contains filesystem-specific options for Make.
type MakeParams struct {
	// Label for the filesystem.
	Label string

	// BlockSize for ext4/xfs (0 = default).
	BlockSize int

	// Force formatting even if an existing filesystem is detected.
	Force bool

	// Ext4 contains ext4-specific options.
	Ext4 *Ext4Params

	// XFS contains xfs-specific options.
	XFS *XFSParams

	// ZFS contains zfs-specific options.
	ZFS *ZFSParams
}

// Ext4Params contains ext4-specific formatting options.
type Ext4Params struct {
	// JournalSize in MB (0 = auto).
	JournalSize int

	// InodeSize (128, 256, 512) - default 256.
	InodeSize int

	// InodesPerGroup (0 = auto).
	InodesPerGroup int

	// ReservedBlocksPercent (default 5%).
	ReservedBlocksPercent float64

	// StrideSize for RAID arrays (0 = none).
	StrideSize int

	// StripeWidth for RAID arrays (0 = none).
	StripeWidth int

	// DisableMetadataChecksums disables metadata checksums.
	DisableMetadataChecksums bool

	// EnableLargeDir enables large directory support (dir_index).
	EnableLargeDir bool

	// Enable64bit enables 64-bit block numbers.
	Enable64bit bool
}

// XFSParams contains xfs-specific formatting options.
type XFSParams struct {
	// AgCount is the number of allocation groups (0 = auto).
	AgCount int

	// BlockSize (512, 1024, 2048, 4096) - default 4096.
	BlockSize int

	// InodeSize (256, 512, 1024, 2048) - default 512.
	InodeSize int

	// SectorSize (512, 4096) - default 512.
	SectorSize int

	// LogSize in MB (0 = auto).
	LogSize int

	// RealTime enables the real-time subvolume.
	RealTime bool

	// RefLink enables reflink support (CoW).
	RefLink bool

	// BigTime enables timestamps beyond 2038.
	BigTime bool

	// NoAlign disables stripe unit alignment.
	NoAlign bool
}

// ZFSParams contains zfs-specific options.
type ZFSParams struct {
	// PoolName is the name of the ZFS pool to create.
	PoolName string

	// DatasetName is the name of the dataset (default: root).
	DatasetName string

	// Compression algorithm (lz4, zstd, gzip, off).
	Compression string

	// Ashift value for alignment (9=512, 12=4K, 13=8K).
	Ashift int

	// RecordSize (128K default).
	RecordSize string

	// EnableDedup enables deduplication.
	EnableDedup bool

	// MountPoint for the pool.
	MountPoint string

	// Features to enable.
	Features []string

	// Properties to set.
	Properties map[string]string
}

// typeOps is how one supported filesystem is created and checked.
type typeOps struct {
	// make creates the filesystem on devicePath.
	make func(ctx context.Context, devicePath string, p MakeParams) error

	// check checks the filesystem on devicePath, running its tools through
	// run, and interprets their exit status. See Repair for what repair
	// means for each type and what the result reports.
	check func(ctx context.Context, run commandRunner, devicePath string, repair bool) (CheckResult, error)
}

// dispatch holds the create and check implementation for every entry in
// supported, and for nothing else.
var dispatch = map[Type]typeOps{
	Ext4:  {make: makeExt4, check: checkExt4},
	XFS:   {make: makeXFS, check: checkXFS},
	ZFS:   {make: makeZFS, check: checkZFS},
	FAT32: {make: makeFAT32, check: checkFAT32},
}

// dispatchFor returns the implementation for t, or an error wrapping
// ErrUnsupported when t is not in Supported().
func dispatchFor(t Type) (typeOps, error) {
	to, ok := dispatch[t]
	if !isSupported(t) || !ok {
		return typeOps{}, &Error{Kind: ErrUnsupported, Detail: fmt.Sprintf("%q", string(t))}
	}
	return to, nil
}

// Make creates a filesystem of type t on device, a device path (not a
// device-mapper mapping name).
func Make(ctx context.Context, device string, t Type, p MakeParams) (err error) {
	defer func() { err = errs.At("filesystem", "Make", device, err) }()
	if err := ctx.Err(); err != nil {
		return &Error{Kind: err}
	}
	to, err := dispatchFor(t)
	if err != nil {
		return err
	}
	return to.make(ctx, device, p)
}

// makeExt4 creates an ext4 filesystem.
func makeExt4(ctx context.Context, devicePath string, p MakeParams) error {
	args := []string{}

	if p.Label != "" {
		args = append(args, "-L", p.Label)
	}
	if p.BlockSize > 0 {
		args = append(args, "-b", fmt.Sprintf("%d", p.BlockSize))
	}
	if p.Force {
		args = append(args, "-F")
	}

	if p.Ext4 != nil {
		ext4 := p.Ext4

		if ext4.JournalSize > 0 {
			args = append(args, "-J", fmt.Sprintf("size=%d", ext4.JournalSize))
		}
		if ext4.InodeSize > 0 {
			args = append(args, "-I", fmt.Sprintf("%d", ext4.InodeSize))
		}
		if ext4.ReservedBlocksPercent > 0 {
			args = append(args, "-m", fmt.Sprintf("%.1f", ext4.ReservedBlocksPercent))
		}

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

	output, err := sys.tools.Run(ctx, "mkfs.ext4", args...)
	if err != nil {
		return &CommandError{Command: "mkfs.ext4", ExitCode: exitStatus(err), Output: string(output), Err: err}
	}
	return nil
}

// makeXFS creates an XFS filesystem.
func makeXFS(ctx context.Context, devicePath string, p MakeParams) error {
	args := []string{}

	if p.Label != "" {
		args = append(args, "-L", p.Label)
	}
	if p.Force {
		args = append(args, "-f")
	}

	if p.XFS != nil {
		xfs := p.XFS

		if xfs.BlockSize > 0 {
			args = append(args, "-b", fmt.Sprintf("size=%d", xfs.BlockSize))
		}
		if xfs.SectorSize > 0 {
			args = append(args, "-s", fmt.Sprintf("size=%d", xfs.SectorSize))
		}
		if xfs.InodeSize > 0 {
			args = append(args, "-i", fmt.Sprintf("size=%d", xfs.InodeSize))
		}
		if xfs.AgCount > 0 {
			args = append(args, "-d", fmt.Sprintf("agcount=%d", xfs.AgCount))
		}
		if xfs.LogSize > 0 {
			args = append(args, "-l", fmt.Sprintf("size=%dm", xfs.LogSize))
		}

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

		if xfs.NoAlign {
			args = append(args, "-d", "noalign")
		}
	}

	args = append(args, "--", devicePath)

	output, err := sys.tools.Run(ctx, "mkfs.xfs", args...)
	if err != nil {
		return &CommandError{Command: "mkfs.xfs", ExitCode: exitStatus(err), Output: string(output), Err: err}
	}
	return nil
}

// makeZFS creates a ZFS pool and dataset.
func makeZFS(ctx context.Context, devicePath string, p MakeParams) error {
	if p.ZFS == nil {
		return &Error{Kind: ErrInvalidArgument, Detail: "ZFS requires ZFS params to be specified"}
	}

	zfs := p.ZFS
	if zfs.PoolName == "" {
		return &Error{Kind: ErrInvalidArgument, Detail: "ZFS pool name is required"}
	}
	if err := validateZFSOptions(zfs); err != nil {
		return err
	}

	// Build zpool create command.
	args := []string{"create"}

	if p.Force {
		args = append(args, "-f")
	}
	if zfs.MountPoint != "" {
		args = append(args, "-m", zfs.MountPoint)
	}
	if zfs.Ashift > 0 {
		args = append(args, "-o", fmt.Sprintf("ashift=%d", zfs.Ashift))
	}

	// Pool properties, in key order so the command is the same every run.
	for _, key := range slices.Sorted(maps.Keys(zfs.Properties)) {
		args = append(args, "-o", key+"="+zfs.Properties[key])
	}

	// Dataset properties.
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

	for _, feature := range zfs.Features {
		args = append(args, "-o", fmt.Sprintf("feature@%s=enabled", feature))
	}

	// Pool name and device, after "--" so neither is read as an option.
	args = append(args, "--", zfs.PoolName, devicePath)

	output, err := sys.tools.Run(ctx, "zpool", args...)
	if err != nil {
		return &CommandError{Command: "zpool create", ExitCode: exitStatus(err), Output: string(output), Err: err}
	}

	// Create the dataset if one is named.
	if zfs.DatasetName != "" && zfs.DatasetName != "root" {
		dsArgs := []string{"create"}
		for _, prop := range datasetProps {
			dsArgs = append(dsArgs, "-o", prop)
		}
		dsArgs = append(dsArgs, "--", zfs.PoolName+"/"+zfs.DatasetName)

		output, err = sys.tools.Run(ctx, "zfs", dsArgs...)
		if err != nil {
			return &CommandError{Command: "zfs create", ExitCode: exitStatus(err), Output: string(output), Err: err}
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
	return &Error{Kind: ErrInvalidArgument, Detail: fmt.Sprintf("ZFS %s %q %s", what, value, why)}
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

// validateZFSOptions checks every ZFSParams field that reaches a command line.
func validateZFSOptions(zfs *ZFSParams) error {
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

// makeFAT32 creates a FAT32 filesystem.
func makeFAT32(ctx context.Context, devicePath string, p MakeParams) error {
	args := []string{"-F", "32"}

	if p.Label != "" {
		args = append(args, "-n", p.Label)
	}

	args = append(args, "--", devicePath)

	output, err := sys.tools.Run(ctx, "mkfs.fat", args...)
	if err != nil {
		return &CommandError{Command: "mkfs.fat", ExitCode: exitStatus(err), Output: string(output), Err: err}
	}
	return nil
}
