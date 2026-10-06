// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package luks2

import (
	"strings"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// blkidNothingFound and blkidAmbivalent are the exit statuses blkid(8) gives
// a low-level probe (-p) that identified nothing, and one that found more than
// one signature it cannot choose between.
const (
	blkidNothingFound = 2
	blkidAmbivalent   = 8
)

// probeOutput runs a probe program and returns its STANDARD OUTPUT only. A
// variable so the unit tests can stand in for blkid; nothing else changes it.
//
// Not the combined output the checkers use: the probe's stdout is parsed as
// KEY=VALUE lines, and a warning on stderr is not part of that grammar.
var probeOutput commandRunner = func(name string, args ...string) ([]byte, error) {
	cmd, err := tools.Command(name, args...)
	if err != nil {
		return nil, err
	}
	return cmd.Output()
}

// DetectFilesystem reports the filesystem on the unlocked device-mapper
// mapping name, as blkid's low-level probe identifies it.
//
// The mapping is resolved the way Mount resolves it -- through device-mapper,
// to a node that verifiably is the mapping -- and the probe reads the device
// itself (blkid -p), never blkid's cache, which can describe a device as it
// was before the last mkfs.
//
// It refuses rather than guesses. Nothing identified, more than one signature,
// or a signature that is not a filesystem (another LUKS container, swap, a
// RAID or LVM member) is an error matching ErrFilesystemNotDetected, naming
// what was found.
func DetectFilesystem(name string) (FilesystemType, error) {
	devicePath, _, err := mappedDevicePath(name)
	if err != nil {
		return "", err
	}
	return probeFilesystem(probeOutput, devicePath)
}

// probeFilesystem runs blkid's low-level probe on devicePath through run and
// interprets the result. See DetectFilesystem.
func probeFilesystem(run commandRunner, devicePath string) (FilesystemType, error) {
	output, err := run("blkid", "-p", "-o", "export", "--", devicePath)
	if err != nil {
		switch exitStatus(err) {
		case blkidNothingFound:
			return "", &errs.Error{Kind: ErrFilesystemNotDetected, Detail: devicePath + " carries no signature blkid recognizes; make a filesystem on it first, or name the type explicitly"}
		case blkidAmbivalent:
			return "", &errs.Error{Kind: ErrFilesystemNotDetected, Detail: devicePath + " carries more than one filesystem signature, and blkid cannot tell which is current; name the type explicitly"}
		default:
			return "", &FilesystemCommandError{Command: "blkid", Device: devicePath, Output: string(output), Err: err}
		}
	}

	var fsType, usage string
	for line := range strings.SplitSeq(string(output), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "TYPE":
			fsType = value
		case "USAGE":
			usage = value
		}
	}

	if fsType == "" {
		return "", &errs.Error{Kind: ErrFilesystemNotDetected, Detail: "blkid reported no TYPE for " + devicePath}
	}
	if usage != "filesystem" {
		return "", &errs.Error{Kind: ErrFilesystemNotDetected,
			Detail: devicePath + " holds " + fsType + " (usage " + usageOrUnknown(usage) + "), which is not a mountable filesystem"}
	}
	return FilesystemType(fsType), nil
}

// usageOrUnknown spells an absent USAGE field for an error message.
func usageOrUnknown(usage string) string {
	if usage == "" {
		return "not reported"
	}
	return usage
}
