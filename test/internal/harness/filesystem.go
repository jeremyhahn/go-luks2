// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"github.com/jeremyhahn/go-luks2/pkg/filesystem"
)

// FilesystemType is the pre-redesign library's filesystem type name, now
// pkg/filesystem.Type.
type FilesystemType = filesystem.Type

const (
	FilesystemExt4  FilesystemType = filesystem.Ext4
	FilesystemXFS   FilesystemType = filesystem.XFS
	FilesystemFAT32 FilesystemType = filesystem.FAT32
)

// FilesystemCheckResult is the pre-redesign library's check-result shape,
// now pkg/filesystem.CheckResult.
type FilesystemCheckResult = filesystem.CheckResult

// FilesystemCommandError reports that an external filesystem tool exited
// unsuccessfully, the way the pre-redesign library's luks2.FilesystemCommandError
// did: pkg/filesystem.CommandError carries the same fields except Device,
// whose caller already has it (DESIGN.md), so this wraps it back in for
// integration tests that still assert on it.
type FilesystemCommandError struct {
	Command string
	Device  string
	Output  string
	Err     error
}

func (e *FilesystemCommandError) Error() string {
	return e.Command + " " + e.Device + " failed: " + e.Err.Error() + "\nOutput: " + e.Output
}

func (e *FilesystemCommandError) Unwrap() error { return e.Err }

// commandErr translates a *filesystem.CommandError into *FilesystemCommandError.
func commandErr(device string, err error) error {
	var ce *filesystem.CommandError
	if errors.As(err, &ce) {
		return &FilesystemCommandError{Command: ce.Command, Device: device, Output: ce.Output, Err: ce.Err}
	}
	return err
}

// MakeFilesystem creates a filesystem on an unlocked LUKS volume named by
// its device-mapper mapping, the way the pre-redesign library's
// luks2.MakeFilesystem did before B.6 moved filesystem creation to
// pkg/filesystem, which takes a device path rather than a mapping name --
// dmcrypt.Lookup is the new way to go from one to the other.
func MakeFilesystem(mappingName, fstype, label string) error {
	ctx := context.Background()
	m, err := dmcrypt.Lookup(ctx, mappingName)
	if err != nil {
		return err
	}
	err = filesystem.Make(ctx, m.Path(), FilesystemType(fstype), filesystem.MakeParams{Label: label})
	return commandErr(m.Path(), err)
}

// CheckFilesystem checks the filesystem at devicePath, the way the
// pre-redesign library's luks2.CheckFilesystem did.
func CheckFilesystem(devicePath string, fstype FilesystemType, repair bool) error {
	_, err := CheckFilesystemDetailed(devicePath, fstype, repair)
	return err
}

// CheckFilesystemDetailed is CheckFilesystem, also reporting what the check
// did, the way the pre-redesign library's luks2.CheckFilesystemDetailed did.
func CheckFilesystemDetailed(devicePath string, fstype FilesystemType, repair bool) (FilesystemCheckResult, error) {
	var res filesystem.CheckResult
	var err error
	if repair {
		res, err = filesystem.Repair(context.Background(), devicePath, fstype)
	} else {
		res, err = filesystem.Check(context.Background(), devicePath, fstype)
	}
	if err != nil {
		return FilesystemCheckResult{}, commandErr(devicePath, err)
	}
	return res, nil
}

// DetectFilesystem detects the filesystem on the unlocked device-mapper
// mapping named by mappingName, the way the pre-redesign library's
// luks2.DetectFilesystem did: mappingName is resolved to the mapping's device
// node first (dmcrypt.Lookup, the same resolution MakeFilesystem and Mount
// already do), since pkg/filesystem.Detect takes a device path, not a mapping
// name.
func DetectFilesystem(mappingName string) (FilesystemType, error) {
	ctx := context.Background()
	m, err := dmcrypt.Lookup(ctx, mappingName)
	if err != nil {
		return "", err
	}
	t, err := filesystem.Detect(ctx, m.Path())
	if err != nil {
		return "", commandErr(m.Path(), err)
	}
	return t, nil
}
