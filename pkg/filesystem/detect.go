// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package filesystem

import (
	"context"
	"strings"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// blkidNothingFound and blkidAmbivalent are the exit statuses blkid(8) gives
// a low-level probe (-p) that identified nothing, and one that found more
// than one signature it cannot choose between.
const (
	blkidNothingFound = 2
	blkidAmbivalent   = 8
)

// probeOutputRunner runs a probe program and returns its STANDARD OUTPUT
// only.
//
// Not the combined output the checkers use: the probe's stdout is parsed as
// KEY=VALUE lines, and a warning on stderr is not part of that grammar.
func probeOutputRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return sys.tools.Output(ctx, name, args...)
}

// Detect reports the filesystem on device, a device path (not a
// device-mapper mapping name), as blkid's low-level probe identifies it.
//
// It reads the device itself (blkid -p), never blkid's cache, which can
// describe a device as it was before the last Make.
//
// It refuses rather than guesses. Nothing identified, more than one
// signature, or a signature that is not a filesystem (another LUKS
// container, swap, a RAID or LVM member) is an error matching
// ErrNotDetected, naming what was found.
func Detect(ctx context.Context, device string) (Type, error) {
	if err := ctx.Err(); err != nil {
		return "", errs.At("filesystem", "Detect", device, &Error{Kind: err})
	}
	t, err := probeFilesystem(ctx, probeOutputRunner, device)
	return t, errs.At("filesystem", "Detect", device, err)
}

// probeFilesystem runs blkid's low-level probe on devicePath through run and
// interprets the result. See Detect.
func probeFilesystem(ctx context.Context, run commandRunner, devicePath string) (Type, error) {
	output, err := run(ctx, "blkid", "-p", "-o", "export", "--", devicePath)
	if err != nil {
		switch exitStatus(err) {
		case blkidNothingFound:
			return "", &Error{Kind: ErrNotDetected, Detail: devicePath + " carries no signature blkid recognizes; make a filesystem on it first, or name the type explicitly"}
		case blkidAmbivalent:
			return "", &Error{Kind: ErrNotDetected, Detail: devicePath + " carries more than one filesystem signature, and blkid cannot tell which is current; name the type explicitly"}
		default:
			return "", &CommandError{Command: "blkid", ExitCode: exitStatus(err), Output: string(output), Err: err}
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
		return "", &Error{Kind: ErrNotDetected, Detail: "blkid reported no TYPE for " + devicePath}
	}
	if usage != "filesystem" {
		return "", &Error{Kind: ErrNotDetected,
			Detail: devicePath + " holds " + fsType + " (usage " + usageOrUnknown(usage) + "), which is not a mountable filesystem"}
	}
	return Type(fsType), nil
}

// usageOrUnknown spells an absent USAGE field for an error message.
func usageOrUnknown(usage string) string {
	if usage == "" {
		return "not reported"
	}
	return usage
}
