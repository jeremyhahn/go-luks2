// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !integration

package luks2

import (
	"errors"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"testing"
)

// TestSupportedFilesystemsCanBeCreatedAndChecked is the #195 invariant:
// everything SupportedFilesystems() advertises can be created AND checked,
// and nothing can be created or checked that it does not advertise.
//
// Before #195 the supported set was spelled three times -- the list, the
// MakeFilesystemWithOptions switch and the CheckFilesystem switch -- and the
// three disagreed: ext2/ext3 were creatable but not advertised, and vfat was
// advertised and creatable but not checkable. Adding an entry to
// SupportedFilesystems() without a make and a check implementation fails
// this test.
func TestSupportedFilesystemsCanBeCreatedAndChecked(t *testing.T) {
	advertised := SupportedFilesystems()
	if len(advertised) == 0 {
		t.Fatal("SupportedFilesystems() is empty")
	}

	seen := make(map[FilesystemType]bool, len(advertised))
	for _, fs := range advertised {
		if seen[fs] {
			t.Errorf("SupportedFilesystems() lists %q twice", fs)
		}
		seen[fs] = true

		ops, ok := filesystemDispatch[fs]
		if !ok {
			t.Errorf("%q is advertised but has no dispatch entry", fs)
			continue
		}
		if ops.make == nil {
			t.Errorf("%q is advertised but cannot be created", fs)
		}
		if ops.check == nil {
			t.Errorf("%q is advertised but cannot be checked", fs)
		}
		if !IsFilesystemSupported(fs) {
			t.Errorf("IsFilesystemSupported(%q) = false for an advertised type", fs)
		}
	}

	for fs := range filesystemDispatch {
		if !seen[fs] {
			t.Errorf("%q can be created/checked but SupportedFilesystems() does not advertise it", fs)
		}
	}
}

// TestSupportedFilesystemsExactSet pins the owner's ruling on #195: ext4,
// xfs, zfs and vfat, and not ext2 or ext3.
func TestSupportedFilesystemsExactSet(t *testing.T) {
	var got []string
	for _, fs := range SupportedFilesystems() {
		got = append(got, string(fs))
	}
	sort.Strings(got)

	want := []string{"ext4", "vfat", "xfs", "zfs"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SupportedFilesystems() = %v, want %v", got, want)
	}
}

// TestSupportedFilesystemsReturnsACopy guards the single source of truth
// against a caller mutating the slice it was handed.
func TestSupportedFilesystemsReturnsACopy(t *testing.T) {
	first := SupportedFilesystems()
	first[0] = FilesystemType("mutated")
	if IsFilesystemSupported(FilesystemType("mutated")) {
		t.Fatal("mutating the returned slice changed the supported set")
	}
}

// TestUnsupportedFilesystemsAreRefused checks that every type outside the
// supported set -- ext2 and ext3 included -- is refused by all three entry
// points with ErrUnsupportedFilesystem, before any device is touched.
func TestUnsupportedFilesystemsAreRefused(t *testing.T) {
	for _, fs := range []FilesystemType{FilesystemExt2, FilesystemExt3, "btrfs", ""} {
		t.Run(string(fs), func(t *testing.T) {
			if IsFilesystemSupported(fs) {
				t.Errorf("IsFilesystemSupported(%q) = true", fs)
			}

			err := MakeFilesystemWithOptions("luks2-test-no-such-volume", fs, nil)
			if !errors.Is(err, ErrUnsupportedFilesystem) {
				t.Errorf("MakeFilesystemWithOptions(%q) = %v, want ErrUnsupportedFilesystem", fs, err)
			}

			var ufe *UnsupportedFilesystemError
			if !errors.As(err, &ufe) || ufe.Filesystem != fs {
				t.Errorf("MakeFilesystemWithOptions(%q) = %v, want *UnsupportedFilesystemError naming %q", fs, err, fs)
			}

			err = CheckFilesystem("/dev/luks2-test-no-such-device", fs, false)
			if !errors.Is(err, ErrUnsupportedFilesystem) {
				t.Errorf("CheckFilesystem(%q) = %v, want ErrUnsupportedFilesystem", fs, err)
			}
			ufe = nil
			if !errors.As(err, &ufe) || ufe.Filesystem != fs {
				t.Errorf("CheckFilesystem(%q) = %v, want *UnsupportedFilesystemError naming %q", fs, err, fs)
			}
		})
	}
}

// TestCheckFilesystemFailureIsTyped checks that a checker that fails -- the
// program exits nonzero, or cannot be started at all -- comes back as a
// *FilesystemCommandError naming the command and device, with the runner's
// error reachable, and is not mistaken for a refusal. It runs in-process
// through an injected commandRunner; the real e2fsck is exercised by
// TestCheckFilesystemFailureIsTypedOnHost in the integration suite.
func TestCheckFilesystemFailureIsTyped(t *testing.T) {
	const dev = "/dev/mapper/vol"
	for _, cause := range []error{exitCode(8), exec.ErrNotFound} {
		t.Run(cause.Error(), func(t *testing.T) {
			r := &scriptedRunner{results: []error{cause}}
			_, err := filesystemDispatch[FilesystemExt4].check(r.run, dev, false)

			var fce *FilesystemCommandError
			if !errors.As(err, &fce) {
				t.Fatalf("check = %v (%T), want *FilesystemCommandError", err, err)
			}
			if fce.Command != "e2fsck" || fce.Device != dev {
				t.Errorf("FilesystemCommandError{Command: %q, Device: %q}, want e2fsck on %q", fce.Command, fce.Device, dev)
			}
			if fce.Output != "output" {
				t.Errorf("FilesystemCommandError.Output = %q, want the runner's output", fce.Output)
			}
			if !errors.Is(err, cause) {
				t.Errorf("errors.Is(%v, %v) = false, want the runner's error reachable", err, cause)
			}
			if errors.Is(err, ErrUnsupportedFilesystem) {
				t.Errorf("a failed check of a supported type matched ErrUnsupportedFilesystem: %v", err)
			}
		})
	}
}

// exitCode is a fake nonzero program exit, standing in for *exec.ExitError.
type exitCode int

func (e exitCode) Error() string { return "exit status " + strconv.Itoa(int(e)) }
func (e exitCode) ExitCode() int { return int(e) }

// scriptedRunner is a commandRunner that records every argv it is asked to
// run and answers with the next scripted error (nil once the script runs out).
type scriptedRunner struct {
	results []error
	calls   [][]string
}

func (r *scriptedRunner) run(name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if len(r.results) == 0 {
		return []byte("output"), nil
	}
	err := r.results[0]
	r.results = r.results[1:]
	return []byte("output"), err
}

// TestFilesystemCheckCommands pins the argv each checker runs on a clean
// filesystem, read-only and repairing, including the vfat arm #195 added.
func TestFilesystemCheckCommands(t *testing.T) {
	const dev = "/dev/mapper/vol"
	tests := []struct {
		fs     FilesystemType
		repair bool
		want   []string
	}{
		{FilesystemExt4, false, []string{"e2fsck", "-n", dev}},
		{FilesystemExt4, true, []string{"e2fsck", "-p", dev}},
		{FilesystemXFS, false, []string{"xfs_repair", "-n", dev}},
		{FilesystemXFS, true, []string{"xfs_repair", dev}},
		{FilesystemZFS, false, []string{"zpool", "scrub", dev}},
		{FilesystemZFS, true, []string{"zpool", "scrub", dev}},
		{FilesystemFAT32, false, []string{"fsck.fat", "-n", dev}},
		{FilesystemFAT32, true, []string{"fsck.fat", "-a", dev}},
	}

	for _, tt := range tests {
		ops := filesystemDispatch[tt.fs]
		if ops.check == nil {
			t.Errorf("%q has no checker", tt.fs)
			continue
		}
		r := &scriptedRunner{}
		res, err := ops.check(r.run, dev, tt.repair)
		if err != nil {
			t.Errorf("check(%q, repair=%v) on a clean filesystem = %v, want nil", tt.fs, tt.repair, err)
		}
		if res != (FilesystemCheckResult{}) {
			t.Errorf("check(%q, repair=%v) on a clean filesystem reported %+v, want a zero result", tt.fs, tt.repair, res)
		}
		if want := [][]string{tt.want}; !reflect.DeepEqual(r.calls, want) {
			t.Errorf("check(%q, repair=%v) ran %v, want %v", tt.fs, tt.repair, r.calls, want)
		}
	}
}

// TestCheckFAT32Outcomes checks how fsck.fat's exit status is read. fsck.fat
// exits 1 both when -a wrote repairs and when it stopped on an internal
// inconsistency, so a repair that exits 1 is confirmed by a read-only recheck:
// a successful repair is not reported as a failure, and an unsuccessful one is.
func TestCheckFAT32Outcomes(t *testing.T) {
	const dev = "/dev/mapper/vol"
	repairArgv := []string{"fsck.fat", "-a", dev}
	readOnlyArgv := []string{"fsck.fat", "-n", dev}
	notFound := errors.New("executable file not found")

	tests := []struct {
		name      string
		repair    bool
		results   []error
		wantCalls [][]string
		wantErr   error // nil means success; otherwise the error the command failed with
		wantRes   FilesystemCheckResult
	}{
		{"read-only clean", false, nil, [][]string{readOnlyArgv}, nil, FilesystemCheckResult{}},
		{"read-only finds problems", false, []error{exitCode(1)}, [][]string{readOnlyArgv}, exitCode(1), FilesystemCheckResult{}},
		{"repair clean", true, nil, [][]string{repairArgv}, nil, FilesystemCheckResult{}},
		{"repair wrote fixes, recheck clean", true, []error{exitCode(1), nil}, [][]string{repairArgv, readOnlyArgv}, nil, FilesystemCheckResult{Repaired: true}},
		{"repair exit 1, recheck still finds problems", true, []error{exitCode(1), exitCode(1)}, [][]string{repairArgv, readOnlyArgv}, exitCode(1), FilesystemCheckResult{}},
		{"repair usage or fatal error", true, []error{exitCode(2)}, [][]string{repairArgv}, exitCode(2), FilesystemCheckResult{}},
		{"checker not found", true, []error{notFound}, [][]string{repairArgv}, notFound, FilesystemCheckResult{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &scriptedRunner{results: tt.results}
			res, err := checkFAT32(r.run, dev, tt.repair)

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

			var fce *FilesystemCommandError
			if !errors.As(err, &fce) {
				t.Fatalf("checkFAT32 = %v (%T), want *FilesystemCommandError", err, err)
			}
			if fce.Command != "fsck.fat" || fce.Device != dev {
				t.Errorf("FilesystemCommandError{Command: %q, Device: %q}, want fsck.fat on %q", fce.Command, fce.Device, dev)
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
// 0-3 is success with the repair and reboot request reported, and any status
// with a bit of 4 or above is a failure. Read-only, every nonzero status is a
// failure: -n writes nothing, so nothing was corrected.
func TestCheckExt4Outcomes(t *testing.T) {
	const dev = "/dev/mapper/vol"
	repairArgv := [][]string{{"e2fsck", "-p", dev}}
	readOnlyArgv := [][]string{{"e2fsck", "-n", dev}}
	signaled := exitCode(-1) // *exec.ExitError reports -1 for a signal
	notFound := exec.ErrNotFound

	tests := []struct {
		name      string
		repair    bool
		result    error
		wantCalls [][]string
		wantErr   error // nil means success; otherwise the error the command failed with
		wantRes   FilesystemCheckResult
	}{
		{"repair clean", true, nil, repairArgv, nil, FilesystemCheckResult{}},
		{"repair corrected", true, exitCode(1), repairArgv, nil, FilesystemCheckResult{Repaired: true}},
		{"repair corrected, reboot", true, exitCode(2), repairArgv, nil, FilesystemCheckResult{Repaired: true, RebootRequired: true}},
		{"repair corrected both bits", true, exitCode(3), repairArgv, nil, FilesystemCheckResult{Repaired: true, RebootRequired: true}},
		{"repair uncorrected", true, exitCode(4), repairArgv, exitCode(4), FilesystemCheckResult{}},
		{"repair corrected some, others uncorrected", true, exitCode(5), repairArgv, exitCode(5), FilesystemCheckResult{}},
		{"repair operational error", true, exitCode(8), repairArgv, exitCode(8), FilesystemCheckResult{}},
		{"repair usage error", true, exitCode(16), repairArgv, exitCode(16), FilesystemCheckResult{}},
		{"repair canceled after corrections", true, exitCode(33), repairArgv, exitCode(33), FilesystemCheckResult{}},
		{"repair shared-library error", true, exitCode(128), repairArgv, exitCode(128), FilesystemCheckResult{}},
		{"repair killed by a signal", true, signaled, repairArgv, signaled, FilesystemCheckResult{}},
		{"repair checker not found", true, notFound, repairArgv, notFound, FilesystemCheckResult{}},
		{"read-only clean", false, nil, readOnlyArgv, nil, FilesystemCheckResult{}},
		{"read-only status 1", false, exitCode(1), readOnlyArgv, exitCode(1), FilesystemCheckResult{}},
		{"read-only status 2", false, exitCode(2), readOnlyArgv, exitCode(2), FilesystemCheckResult{}},
		{"read-only errors present", false, exitCode(4), readOnlyArgv, exitCode(4), FilesystemCheckResult{}},
		{"read-only operational error", false, exitCode(8), readOnlyArgv, exitCode(8), FilesystemCheckResult{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &scriptedRunner{results: []error{tt.result}}
			res, err := checkExt4(r.run, dev, tt.repair)

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

			var fce *FilesystemCommandError
			if !errors.As(err, &fce) {
				t.Fatalf("checkExt4 = %v (%T), want *FilesystemCommandError", err, err)
			}
			if fce.Command != "e2fsck" || fce.Device != dev || fce.Output != "output" {
				t.Errorf("FilesystemCommandError{Command: %q, Device: %q, Output: %q}, want e2fsck on %q with the checker's output",
					fce.Command, fce.Device, fce.Output, dev)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("checkExt4 = %v, want it to wrap %v", err, tt.wantErr)
			}
		})
	}
}

// TestCheckFilesystemDetailedRefusesUnsupported checks that the detailed
// entry point refuses exactly what CheckFilesystem refuses, with a zero
// result, before running anything.
func TestCheckFilesystemDetailedRefusesUnsupported(t *testing.T) {
	for _, fs := range []FilesystemType{FilesystemExt2, FilesystemExt3, "btrfs", ""} {
		res, err := CheckFilesystemDetailed("/dev/luks2-test-no-such-device", fs, true)
		var ufe *UnsupportedFilesystemError
		if !errors.As(err, &ufe) || ufe.Filesystem != fs || !errors.Is(err, ErrUnsupportedFilesystem) {
			t.Errorf("CheckFilesystemDetailed(%q) = %v, want *UnsupportedFilesystemError naming it", fs, err)
		}
		if res != (FilesystemCheckResult{}) {
			t.Errorf("CheckFilesystemDetailed(%q) result = %+v, want zero on refusal", fs, res)
		}
	}
}
