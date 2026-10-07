// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !integration

package filesystem

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strconv"
	"testing"
)

// exitCode is a fake nonzero program exit, standing in for *exec.ExitError.
type exitCode int

func (e exitCode) Error() string { return "exit status " + strconv.Itoa(int(e)) }
func (e exitCode) ExitCode() int { return int(e) }

// scriptedRunner is a commandRunner that records every argv it is asked to
// run and answers with the next scripted error (nil once the script runs
// out).
type scriptedRunner struct {
	results []error
	calls   [][]string
}

func (r *scriptedRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if len(r.results) == 0 {
		return []byte("output"), nil
	}
	err := r.results[0]
	r.results = r.results[1:]
	return []byte("output"), err
}

// TestCheckFailureIsTyped checks that a checker that fails -- the program
// exits nonzero, or cannot be started at all -- comes back as a
// *CommandError naming the command, with the runner's error reachable, and
// is not mistaken for a refusal.
func TestCheckFailureIsTyped(t *testing.T) {
	const dev = "/dev/mapper/vol"
	for _, cause := range []error{exitCode(8), exec.ErrNotFound} {
		t.Run(cause.Error(), func(t *testing.T) {
			r := &scriptedRunner{results: []error{cause}}
			_, err := dispatch[Ext4].check(context.Background(), r.run, dev, false)

			var ce *CommandError
			if !errors.As(err, &ce) {
				t.Fatalf("check = %v (%T), want *CommandError", err, err)
			}
			if ce.Command != "e2fsck" {
				t.Errorf("CommandError{Command: %q}, want e2fsck", ce.Command)
			}
			if ce.Output != "output" {
				t.Errorf("CommandError.Output = %q, want the runner's output", ce.Output)
			}
			if !errors.Is(err, cause) {
				t.Errorf("errors.Is(%v, %v) = false, want the runner's error reachable", err, cause)
			}
			if errors.Is(err, ErrUnsupported) {
				t.Errorf("a failed check of a supported type matched ErrUnsupported: %v", err)
			}
		})
	}
}

// TestCheckCommands pins the argv each checker runs on a clean filesystem,
// read-only and repairing, including the vfat arm #195 added.
func TestCheckCommands(t *testing.T) {
	// "--" ends the options on every command (#250, C7), so the operand can
	// never be read as one. For ZFS the operand is a pool NAME, not a device.
	const dev = "/dev/mapper/vol"
	const pool = "tank"
	tests := []struct {
		fs      Type
		repair  bool
		operand string
		want    []string
	}{
		{Ext4, false, dev, []string{"e2fsck", "-n", "--", dev}},
		{Ext4, true, dev, []string{"e2fsck", "-p", "--", dev}},
		{XFS, false, dev, []string{"xfs_repair", "-n", "--", dev}},
		{XFS, true, dev, []string{"xfs_repair", "--", dev}},
		{ZFS, false, pool, []string{"zpool", "scrub", "--", pool}},
		{ZFS, true, pool, []string{"zpool", "scrub", "--", pool}},
		{FAT32, false, dev, []string{"fsck.fat", "-n", "--", dev}},
		{FAT32, true, dev, []string{"fsck.fat", "-a", "--", dev}},
	}

	for _, tt := range tests {
		to := dispatch[tt.fs]
		if to.check == nil {
			t.Errorf("%q has no checker", tt.fs)
			continue
		}
		r := &scriptedRunner{}
		res, err := to.check(context.Background(), r.run, tt.operand, tt.repair)
		if err != nil {
			t.Errorf("check(%q, repair=%v) on a clean filesystem = %v, want nil", tt.fs, tt.repair, err)
		}
		if res != (CheckResult{}) {
			t.Errorf("check(%q, repair=%v) on a clean filesystem reported %+v, want a zero result", tt.fs, tt.repair, res)
		}
		if want := [][]string{tt.want}; !reflect.DeepEqual(r.calls, want) {
			t.Errorf("check(%q, repair=%v) ran %v, want %v", tt.fs, tt.repair, r.calls, want)
		}
	}
}

// TestCheckFAT32Outcomes checks how fsck.fat's exit status is read. fsck.fat
// exits 1 both when -a wrote repairs and when it stopped on an internal
// inconsistency, so a repair that exits 1 is confirmed by a read-only
// recheck: a successful repair is not reported as a failure, and an
// unsuccessful one is.
func TestCheckFAT32Outcomes(t *testing.T) {
	const dev = "/dev/mapper/vol"
	repairArgv := []string{"fsck.fat", "-a", "--", dev}
	readOnlyArgv := []string{"fsck.fat", "-n", "--", dev}
	notFound := errors.New("executable file not found")

	tests := []struct {
		name      string
		repair    bool
		results   []error
		wantCalls [][]string
		wantErr   error // nil means success; otherwise the error the command failed with
		wantRes   CheckResult
	}{
		{"read-only clean", false, nil, [][]string{readOnlyArgv}, nil, CheckResult{}},
		{"read-only finds problems", false, []error{exitCode(1)}, [][]string{readOnlyArgv}, exitCode(1), CheckResult{}},
		{"repair clean", true, nil, [][]string{repairArgv}, nil, CheckResult{}},
		{"repair wrote fixes, recheck clean", true, []error{exitCode(1), nil}, [][]string{repairArgv, readOnlyArgv}, nil, CheckResult{Repaired: true}},
		{"repair exit 1, recheck still finds problems", true, []error{exitCode(1), exitCode(1)}, [][]string{repairArgv, readOnlyArgv}, exitCode(1), CheckResult{}},
		{"repair usage or fatal error", true, []error{exitCode(2)}, [][]string{repairArgv}, exitCode(2), CheckResult{}},
		{"checker not found", true, []error{notFound}, [][]string{repairArgv}, notFound, CheckResult{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &scriptedRunner{results: tt.results}
			res, err := checkFAT32(context.Background(), r.run, dev, tt.repair)

			if !reflect.DeepEqual(r.calls, tt.wantCalls) {
				t.Errorf("ran %v, want %v", r.calls, tt.wantCalls)
			}
			if res != tt.wantRes {
				t.Errorf("checkFAT32 result = %+v, want %+v", res, tt.wantRes)
			}
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("checkFAT32 = %v, want nil", err)
				}
				return
			}

			var ce *CommandError
			if !errors.As(err, &ce) {
				t.Fatalf("checkFAT32 = %v (%T), want *CommandError", err, err)
			}
			if ce.Command != "fsck.fat" {
				t.Errorf("CommandError{Command: %q}, want fsck.fat", ce.Command)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("checkFAT32 = %v, want it to wrap %v", err, tt.wantErr)
			}
		})
	}
}

// TestCheckExt4Outcomes pins how e2fsck's exit status is read (#228). The
// status is a bitmask (e2fsck(8)): 1 = errors corrected, 2 = corrected and a
// reboot is requested, 4 = errors left uncorrected, 8 = operational error,
// 16 = usage error, 32 = canceled, 128 = shared-library error. Repairing,
// 0-3 is success with the repair and reboot request reported, and any
// status with a bit of 4 or above is a failure. Read-only, every nonzero
// status is a failure: -n writes nothing, so nothing was corrected.
func TestCheckExt4Outcomes(t *testing.T) {
	const dev = "/dev/mapper/vol"
	repairArgv := [][]string{{"e2fsck", "-p", "--", dev}}
	readOnlyArgv := [][]string{{"e2fsck", "-n", "--", dev}}
	signaled := exitCode(-1) // *exec.ExitError reports -1 for a signal
	notFound := exec.ErrNotFound

	tests := []struct {
		name      string
		repair    bool
		result    error
		wantCalls [][]string
		wantErr   error // nil means success; otherwise the error the command failed with
		wantRes   CheckResult
	}{
		{"repair clean", true, nil, repairArgv, nil, CheckResult{}},
		{"repair corrected", true, exitCode(1), repairArgv, nil, CheckResult{Repaired: true}},
		{"repair corrected, reboot", true, exitCode(2), repairArgv, nil, CheckResult{Repaired: true, RebootRequired: true}},
		{"repair corrected both bits", true, exitCode(3), repairArgv, nil, CheckResult{Repaired: true, RebootRequired: true}},
		{"repair uncorrected", true, exitCode(4), repairArgv, exitCode(4), CheckResult{}},
		{"repair corrected some, others uncorrected", true, exitCode(5), repairArgv, exitCode(5), CheckResult{}},
		{"repair operational error", true, exitCode(8), repairArgv, exitCode(8), CheckResult{}},
		{"repair usage error", true, exitCode(16), repairArgv, exitCode(16), CheckResult{}},
		{"repair canceled after corrections", true, exitCode(33), repairArgv, exitCode(33), CheckResult{}},
		{"repair shared-library error", true, exitCode(128), repairArgv, exitCode(128), CheckResult{}},
		{"repair killed by a signal", true, signaled, repairArgv, signaled, CheckResult{}},
		{"repair checker not found", true, notFound, repairArgv, notFound, CheckResult{}},
		{"read-only clean", false, nil, readOnlyArgv, nil, CheckResult{}},
		{"read-only status 1", false, exitCode(1), readOnlyArgv, exitCode(1), CheckResult{}},
		{"read-only status 2", false, exitCode(2), readOnlyArgv, exitCode(2), CheckResult{}},
		{"read-only errors present", false, exitCode(4), readOnlyArgv, exitCode(4), CheckResult{}},
		{"read-only operational error", false, exitCode(8), readOnlyArgv, exitCode(8), CheckResult{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &scriptedRunner{results: []error{tt.result}}
			res, err := checkExt4(context.Background(), r.run, dev, tt.repair)

			if !reflect.DeepEqual(r.calls, tt.wantCalls) {
				t.Errorf("ran %v, want %v", r.calls, tt.wantCalls)
			}
			if res != tt.wantRes {
				t.Errorf("checkExt4 result = %+v, want %+v", res, tt.wantRes)
			}
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("checkExt4 = %v, want nil", err)
				}
				return
			}

			var ce *CommandError
			if !errors.As(err, &ce) {
				t.Fatalf("checkExt4 = %v (%T), want *CommandError", err, err)
			}
			if ce.Command != "e2fsck" || ce.Output != "output" {
				t.Errorf("CommandError{Command: %q, Output: %q}, want e2fsck with the checker's output", ce.Command, ce.Output)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("checkExt4 = %v, want it to wrap %v", err, tt.wantErr)
			}
		})
	}
}

// TestRepairRefusesUnsupported checks that Repair refuses exactly what Check
// refuses, with a zero result, before running anything.
func TestRepairRefusesUnsupported(t *testing.T) {
	for _, fs := range []Type{"ext2", "ext3", "btrfs", ""} {
		res, err := Repair(t.Context(), "/dev/luks2-test-no-such-device", fs)
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("Repair(%q) = %v, want ErrUnsupported", fs, err)
		}
		if res != (CheckResult{}) {
			t.Errorf("Repair(%q) result = %+v, want zero on refusal", fs, res)
		}
	}
}

// TestCheckRefusesACanceledContext checks the ctx boundary check.
func TestCheckRefusesACanceledContext(t *testing.T) {
	record := fakeTools(t, map[string]fakeTool{"e2fsck": {}})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Check(ctx, "/dev/mapper/vol", Ext4); !errors.Is(err, context.Canceled) {
		t.Fatalf("Check with a canceled context = %v, want context.Canceled", err)
	}
	if got := record("e2fsck"); got != nil {
		t.Fatalf("e2fsck ran with %q, want it not run at all", got)
	}
}
