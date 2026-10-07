// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package filesystem

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// CheckResult describes a check that Check or Repair reports as successful.
// A failed check returns an error instead. A zero result means the checker
// reported no repair and no reboot request: for ext4 and vfat that is a
// clean filesystem with nothing written, but xfs_repair and zpool scrub
// never report either, so for xfs and zfs a zero result says nothing about
// whether data was repaired (see Check).
type CheckResult struct {
	// Repaired is true when the checker wrote corrections to the
	// filesystem and the filesystem is now consistent. It is only ever set
	// by Repair.
	Repaired bool

	// RebootRequired is true when the checker corrected errors and asks
	// for the system to be rebooted before the filesystem is used (e2fsck
	// exit status bit 2). It matters when the filesystem was mounted, for
	// example as the root filesystem, while it was repaired.
	RebootRequired bool
}

// commandRunner runs an external program and returns its combined stdout and
// stderr. A program that ran and exited nonzero is reported as an error with
// an ExitCode() int method, as *exec.ExitError is.
type commandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// defaultRunner is the commandRunner Check and Repair use. It runs the
// checker from a fixed system directory with a minimal environment; see
// internal/command.
func defaultRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return sys.tools.Run(ctx, name, args...)
}

// runCheck runs one checker command and reports any failure as a
// *CommandError. The device is the last argument.
func runCheck(ctx context.Context, run commandRunner, name string, args ...string) error {
	output, err := run(ctx, name, args...)
	if err != nil {
		return &CommandError{Command: name, ExitCode: exitStatus(err), Output: string(output), Err: err}
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

// Check checks the filesystem of type t on device. Every type in Supported()
// can be checked; any other type is refused with ErrUnsupported before a
// command is run.
//
// For ext4, xfs and vfat the check is read-only, and it returns nil only
// when the filesystem is clean.
//
// ZFS is the exception:
//   - device is the name of a ZFS pool, not a device path.
//   - It starts `zpool scrub` and returns once the scrub has started. It
//     does not wait for the scrub or report what it finds; read
//     `zpool status` for that.
//   - A scrub is not read-only. On a pool with redundancy (mirror, raidz) it
//     repairs damaged data as it goes.
//
// Check reports only success or failure; Repair also reports whether a
// repair was written and whether the checker asked for a reboot.
func Check(ctx context.Context, device string, t Type) (CheckResult, error) {
	res, err := checkDetailed(ctx, device, t, false)
	return res, errs.At("filesystem", "Check", device, err)
}

// Repair is Check, except that ext4, xfs and vfat are checked with repair
// enabled: e2fsck exiting 1 (errors corrected) or 2 (corrected, reboot
// requested) is success, and vfat repairs that fsck.fat reports by exiting 1
// are confirmed by a read-only recheck and then count as success.
// Result.Repaired is set when the checker wrote corrections and the
// filesystem is now consistent; Result.RebootRequired is set when e2fsck
// exits with bit 2 set ("errors corrected, system should be rebooted").
// xfs_repair and zpool scrub report neither, so their results are always
// zero. ZFS ignores repair; see Check.
//
// A failed check is returned as an error: a *CommandError carrying the
// checker's output for a checker that ran or could not be started, and
// ErrUnsupported for a type outside Supported().
func Repair(ctx context.Context, device string, t Type) (CheckResult, error) {
	res, err := checkDetailed(ctx, device, t, true)
	return res, errs.At("filesystem", "Repair", device, err)
}

func checkDetailed(ctx context.Context, device string, t Type, repair bool) (CheckResult, error) {
	if err := ctx.Err(); err != nil {
		return CheckResult{}, &Error{Kind: err}
	}
	to, err := dispatchFor(t)
	if err != nil {
		return CheckResult{}, err
	}
	return to.check(ctx, defaultRunner, device, repair)
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
func checkExt4(ctx context.Context, run commandRunner, devicePath string, repair bool) (CheckResult, error) {
	if !repair {
		return CheckResult{}, runCheck(ctx, run, "e2fsck", "-n", "--", devicePath) // Read-only
	}

	err := runCheck(ctx, run, "e2fsck", "-p", "--", devicePath) // Auto-repair
	if err == nil {
		return CheckResult{}, nil
	}
	status := exitStatus(err)
	if status <= 0 || status >= e2fsckUncorrected {
		// Not started, killed by a signal, or a failure bit is set.
		return CheckResult{}, err
	}
	return CheckResult{
		Repaired:       status&(e2fsckCorrected|e2fsckRebootRequired) != 0,
		RebootRequired: status&e2fsckRebootRequired != 0,
	}, nil
}

// checkXFS checks an XFS filesystem with xfs_repair.
func checkXFS(ctx context.Context, run commandRunner, devicePath string, repair bool) (CheckResult, error) {
	if repair {
		return CheckResult{}, runCheck(ctx, run, "xfs_repair", "--", devicePath) // XFS repairs automatically
	}
	return CheckResult{}, runCheck(ctx, run, "xfs_repair", "-n", "--", devicePath) // Read-only
}

// checkZFS starts a scrub of the ZFS pool named devicePath, the ZFS
// equivalent of fsck. It ignores repair: see Check.
func checkZFS(ctx context.Context, run commandRunner, devicePath string, _ bool) (CheckResult, error) {
	if err := validateZFSPoolName(devicePath); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{}, runCheck(ctx, run, "zpool", "scrub", "--", devicePath)
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
func checkFAT32(ctx context.Context, run commandRunner, devicePath string, repair bool) (CheckResult, error) {
	if !repair {
		return CheckResult{}, runCheck(ctx, run, "fsck.fat", "-n", "--", devicePath) // Read-only
	}

	err := runCheck(ctx, run, "fsck.fat", "-a", "--", devicePath) // Auto-repair
	if exitStatus(err) != fatRepairedOrInconsistent {
		return CheckResult{}, err
	}
	if runCheck(ctx, run, "fsck.fat", "-n", "--", devicePath) != nil {
		return CheckResult{}, err
	}
	return CheckResult{Repaired: true}, nil
}
