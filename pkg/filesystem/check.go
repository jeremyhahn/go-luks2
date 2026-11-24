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

// CheckResult describes a successful Check or Repair; for xfs and zfs a zero result says nothing about repairs.
type CheckResult struct {
	// Repaired is true when the checker wrote corrections to the
	// filesystem and the filesystem is now consistent. It is only ever set
	// by Repair.
	Repaired bool

	// RebootRequired is true when e2fsck corrected errors and asks for a reboot (exit bit 2).
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

// Check checks the filesystem of type t on device, read-only for ext4, xfs and vfat; for ZFS device is a pool name and a zpool scrub is started, not awaited.
func Check(ctx context.Context, device string, t Type) (CheckResult, error) {
	res, err := checkDetailed(ctx, device, t, false)
	return res, errs.At("filesystem", "Check", device, err)
}

// Repair is Check with repair enabled; Result reports Repaired and RebootRequired where the checker says so. Failures are *CommandError or ErrUnsupported.
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

// e2fsck exit status bits (e2fsck(8)); any bit from e2fsckUncorrected up is a failure.
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

// checkExt4 runs e2fsck: with -n any nonzero exit fails; with -p exits 0-3 succeed and bit 4 or higher fails.
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

// fatRepairedOrInconsistent is fsck.fat's ambiguous exit 1: changes written, or stopped on an inconsistency.
const fatRepairedOrInconsistent = 1

// checkFAT32 runs fsck.fat; with -n any nonzero exit fails, and with -a exit 1 is confirmed by a read-only recheck.
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
