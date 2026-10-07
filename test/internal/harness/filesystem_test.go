// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/filesystem"
)

func TestCommandErrTranslatesACommandErrorAndPassesThroughAnythingElse(t *testing.T) {
	ce := &filesystem.CommandError{Command: "mkfs.ext4", ExitCode: 1, Output: "mke2fs 1.47.0\nfake failure", Err: errors.New("exit status 1")}
	err := commandErr("/dev/mapper/fake", ce)

	var fce *FilesystemCommandError
	if !errors.As(err, &fce) {
		t.Fatalf("commandErr(%v) = %v (%T), want a *FilesystemCommandError", ce, err, err)
	}
	if fce.Command != ce.Command || fce.Device != "/dev/mapper/fake" || fce.Output != ce.Output {
		t.Errorf("commandErr translated = %+v, want Command/Device/Output carried over from %+v", fce, ce)
	}
	if !errors.Is(err, ce.Err) {
		t.Errorf("Unwrap() chain does not reach the original *exec error %v", ce.Err)
	}
	if got := err.Error(); got == "" {
		t.Error("FilesystemCommandError.Error() is empty")
	}

	plain := errors.New("not a command error at all")
	if got := commandErr("/dev/mapper/fake", plain); got != plain {
		t.Errorf("commandErr(%v) = %v, want the original error passed through unchanged", plain, got)
	}
}

func TestMakeFilesystemOnAnUnmappedDeviceFails(t *testing.T) {
	if err := MakeFilesystem(nonexistentMapping, "ext4", "label"); err == nil {
		t.Fatal("MakeFilesystem against an unmapped device = nil, want dmcrypt.Lookup's ErrNotActive")
	}
}

func TestDetectFilesystemOnAnUnmappedDeviceFails(t *testing.T) {
	if _, err := DetectFilesystem(nonexistentMapping); err == nil {
		t.Fatal("DetectFilesystem against an unmapped device = nil, want dmcrypt.Lookup's ErrNotActive")
	}
}

// TestCheckFilesystemRefusesAnUnsupportedType and its Detailed sibling drive
// CheckFilesystem/CheckFilesystemDetailed through pkg/filesystem's own type
// dispatch, which refuses an unrecognized FilesystemType before running any
// external tool -- so both the repair and the read-only path are reachable
// without e2fsprogs or root, unlike the happy path the integration tier
// covers against a real filesystem.
func TestCheckFilesystemRefusesAnUnsupportedType(t *testing.T) {
	device := filepath.Join(t.TempDir(), "whatever.img")
	const bogus FilesystemType = "not-a-real-filesystem"

	if err := CheckFilesystem(device, bogus, false); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Errorf("CheckFilesystem(repair=false, bogus type) = %v, want filesystem.ErrUnsupported", err)
	}
}

func TestCheckFilesystemDetailedRefusesAnUnsupportedTypeForBothRepairModes(t *testing.T) {
	device := filepath.Join(t.TempDir(), "whatever.img")
	const bogus FilesystemType = "not-a-real-filesystem"

	for _, repair := range []bool{false, true} {
		res, err := CheckFilesystemDetailed(device, bogus, repair)
		if !errors.Is(err, filesystem.ErrUnsupported) {
			t.Errorf("CheckFilesystemDetailed(repair=%v, bogus type) = %v, %v, want filesystem.ErrUnsupported", repair, res, err)
		}
		if res != (FilesystemCheckResult{}) {
			t.Errorf("CheckFilesystemDetailed(repair=%v, bogus type) result = %+v, want the zero value on failure", repair, res)
		}
		// ErrUnsupported is not a *filesystem.CommandError, so commandErr's
		// pass-through branch is what reaches the caller here, not the
		// *FilesystemCommandError translation.
		var fce *FilesystemCommandError
		if errors.As(err, &fce) {
			t.Errorf("CheckFilesystemDetailed(repair=%v, bogus type) = %v, want the unsupported error untranslated", repair, err)
		}
	}
}
