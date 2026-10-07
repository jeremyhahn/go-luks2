// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package filesystem

import (
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-luks2/internal/command"
	"github.com/jeremyhahn/go-luks2/internal/errs"
)

var (
	// ErrInvalidArgument indicates a filesystem option -- a ZFS pool,
	// dataset, feature or property name, for example -- that could be read
	// as a command-line option, or does not follow the tool's naming rules.
	ErrInvalidArgument = errors.New("invalid filesystem option")

	// ErrUnsupported indicates a filesystem type that is not in Supported().
	// Make and Check/Repair raise it before touching a device. ext2 and
	// ext3 are deliberately in this category (#195); Detect can still
	// report them, as the raw strings "ext2" and "ext3", since that is what
	// blkid found on the device.
	ErrUnsupported = errors.New("unsupported filesystem type")

	// ErrNotDetected indicates that the filesystem on a device could not be
	// determined: blkid found no signature, more than one, or one that is
	// not a mountable filesystem. Detect returns it, and so does Mount when
	// it is asked to detect the type rather than guessing one.
	ErrNotDetected = errors.New("the filesystem on the device could not be determined")

	// ErrTool indicates a filesystem program could not be found in the
	// fixed system directories this package runs tools from, or was found
	// but is writable by someone other than root or the current user.
	ErrTool = command.ErrTool

	// ErrNotMounted indicates Unmount asked the kernel about a path and the
	// kernel said it is not a mount point.
	ErrNotMounted = errors.New("not mounted")
)

// Error is this package's one error shape: a classifying sentinel (Kind),
// the detail in words, and the underlying cause, if any.
type Error = errs.Error

// CommandError reports that an external filesystem tool -- a creator or a
// checker -- exited unsuccessfully, or could not be started. It carries the
// tool's combined output so the cause can be read without re-running it, and
// keeps the run error reachable through Unwrap.
type CommandError struct {
	// Command is the program that was run.
	Command string

	// ExitCode is the program's exit status, or -1 when it was not started
	// or did not exit normally (killed by a signal, for example).
	ExitCode int

	// Output is the program's combined stdout and stderr.
	Output string

	// Err is the error from running the program, typically an *exec.ExitError.
	Err error
}

func (e *CommandError) Error() string {
	if e.ExitCode < 0 {
		return fmt.Sprintf("%s failed: %v\nOutput: %s", e.Command, e.Err, e.Output)
	}
	return fmt.Sprintf("%s failed (exit %d): %v\nOutput: %s", e.Command, e.ExitCode, e.Err, e.Output)
}

func (e *CommandError) Unwrap() error { return e.Err }
