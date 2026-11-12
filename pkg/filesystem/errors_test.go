// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !integration

package filesystem

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"golang.org/x/sys/unix"
)

// TestCommandErrorNamesTheProgramItsStatusAndItsOutput pins the text of a
// *CommandError: the program, the exit status when it exited, the run error
// and the program's output; and that Unwrap reaches the run error.
func TestCommandErrorNamesTheProgramItsStatusAndItsOutput(t *testing.T) {
	cause := errors.New("exit status 4")
	exited := &CommandError{Command: "e2fsck", ExitCode: 4, Output: "bad superblock", Err: cause}
	if got, want := exited.Error(), "e2fsck failed (exit 4): exit status 4\nOutput: bad superblock"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(exited, cause) {
		t.Errorf("errors.Is(%v, the run error) = false, want Unwrap to reach it", exited)
	}

	notStarted := &CommandError{Command: "mkfs.xfs", ExitCode: -1, Output: "", Err: ErrTool}
	got := notStarted.Error()
	if strings.Contains(got, "exit") {
		t.Errorf("Error() = %q, want no exit status for a program that did not exit", got)
	}
	if !strings.HasPrefix(got, "mkfs.xfs failed: ") {
		t.Errorf("Error() = %q, want it to name mkfs.xfs", got)
	}
	if !errors.Is(notStarted, ErrTool) {
		t.Errorf("errors.Is(%v, ErrTool) = false", notStarted)
	}
}

// TestAnAbsentToolIsACommandErrorThatMatchesErrTool: Make, Check, Repair and
// Detect report a program missing from the tool directories as a
// *CommandError with ExitCode -1 that matches ErrTool; Inspect as an Error,
// detail "blkid failed", that matches ErrTool. Nothing falls back.
func TestAnAbsentToolIsACommandErrorThatMatchesErrTool(t *testing.T) {
	fakeTools(t, map[string]fakeTool{}) // an empty, trusted tool directory
	const dev = "/dev/mapper/vol"
	entries := map[string]func(ctx context.Context) error{
		"Make": func(ctx context.Context) error { return Make(ctx, dev, Ext4, MakeParams{}) },
		"Check": func(ctx context.Context) error {
			_, err := Check(ctx, dev, XFS)
			return err
		},
		"Repair": func(ctx context.Context) error {
			_, err := Repair(ctx, dev, FAT32)
			return err
		},
		"Detect": func(ctx context.Context) error {
			_, err := Detect(ctx, dev)
			return err
		},
	}
	for name, entry := range entries {
		t.Run(name, func(t *testing.T) {
			err := entry(t.Context())
			var ce *CommandError
			if !errors.As(err, &ce) {
				t.Fatalf("%s = %v (%T), want a *CommandError", name, err, err)
			}
			if ce.ExitCode != -1 {
				t.Errorf("CommandError.ExitCode = %d, want -1 for a program that did not start", ce.ExitCode)
			}
			if !errors.Is(err, ErrTool) {
				t.Errorf("errors.Is(%v, ErrTool) = false", err)
			}
		})
	}

	t.Run("Inspect", func(t *testing.T) {
		_, err := Inspect(t.Context(), dev)
		var e *Error
		if !errors.As(err, &e) {
			t.Fatalf("Inspect = %v (%T), want an *Error", err, err)
		}
		if e.Detail != "blkid failed" {
			t.Errorf("Error.Detail = %q, want %q", e.Detail, "blkid failed")
		}
		if !errors.Is(err, ErrTool) {
			t.Errorf("errors.Is(%v, ErrTool) = false", err)
		}
	})
}

// TestMountWithANamedTypeNeedsNoTool: Mount with an explicit type calls
// mount(2) without running blkid; with no type it needs blkid and reports its
// absence as ErrTool, without calling mount(2).
func TestMountWithANamedTypeNeedsNoTool(t *testing.T) {
	fakeTools(t, map[string]fakeTool{})
	calls := 0
	withSys(t, func(s *sysT) {
		s.mount = func(source, target, fstype string, flags uintptr, data string) error {
			calls++
			return nil
		}
	})
	dir := t.TempDir()
	if err := Mount(t.Context(), MountParams{Source: "/dev/mapper/vol", Target: dir, Type: Ext4}); err != nil {
		t.Fatalf("Mount with a named type = %v, want nil with no tools present", err)
	}
	if calls != 1 {
		t.Fatalf("mount(2) called %d times, want 1", calls)
	}
	if err := Mount(t.Context(), MountParams{Source: "/dev/mapper/vol", Target: dir}); !errors.Is(err, ErrTool) {
		t.Fatalf("Mount with no type and no blkid = %v, want ErrTool", err)
	}
	if calls != 1 {
		t.Errorf("mount(2) was called after detection failed")
	}
}

// TestMountReportsASyscallFailureAsIO: a failed mount(2) is an Error of the
// I/O kind carrying the errno.
func TestMountReportsASyscallFailureAsIO(t *testing.T) {
	withSys(t, func(s *sysT) {
		s.mount = func(source, target, fstype string, flags uintptr, data string) error { return unix.EPERM }
	})
	err := Mount(t.Context(), MountParams{Source: "/dev/mapper/vol", Target: t.TempDir(), Type: XFS})
	if !errors.Is(err, errs.ErrIO) {
		t.Errorf("Mount = %v, want the I/O kind", err)
	}
	if !errors.Is(err, unix.EPERM) {
		t.Errorf("Mount = %v, want the errno reachable", err)
	}
}
