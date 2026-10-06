// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Format used to write first and find out later (#248, B4): a cipher mode
// dm-crypt cannot parse, aes-cbc with a key it cannot take, a label with no
// room for its NUL, and a device too small for the layout all produced a
// header on the device -- and an in-use block device was formatted anyway.

// sizedImage creates a file of size bytes whose first 4 KiB carry a pattern, so
// a test can tell a refused Format from one that wrote.
func sizedImage(t *testing.T, size int64) (string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "format.img")
	pattern := bytes.Repeat([]byte{0xA5}, 4096)
	if err := os.WriteFile(path, pattern, 0o600); err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	if err := os.Truncate(path, size); err != nil {
		t.Fatalf("size %s: %v", path, err)
	}
	return path, pattern
}

// assertUntouched fails unless path still has size bytes beginning pattern.
func assertUntouched(t *testing.T, path string, size int64, pattern []byte) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Size() != size || !bytes.Equal(readAreaBytes(t, path, 0, int64(len(pattern))), pattern) {
		t.Fatalf("a refused Format changed the device (size %d, want %d)", info.Size(), size)
	}
}

func TestFormatRefusesBeforeWritingAnything(t *testing.T) {
	defer parallel(t)()

	for _, tc := range []struct {
		name   string
		size   int64
		mutate func(*FormatOptions)
		want   error
	}{
		{"a mode dm-crypt cannot parse", 64 << 20, func(o *FormatOptions) { o.CipherMode = "xts-plain64 x" }, ErrUnsupportedCipher},
		{"aes-cbc with a 512-bit key", 64 << 20, func(o *FormatOptions) { o.CipherMode, o.KeySize = "cbc-essiv:sha256", 512 }, ErrUnsupportedCipher},
		{"a cipher outside the allow-list", 64 << 20, func(o *FormatOptions) { o.Cipher = "serpent" }, ErrUnsupportedCipher},
		{"a 48-byte label", 64 << 20, func(o *FormatOptions) { o.Label = strings.Repeat("L", 48) }, ErrInvalidLabel},
		{"a label with a NUL", 64 << 20, func(o *FormatOptions) { o.Label = "ab\x00cd" }, ErrInvalidLabel},
		{"a 48-byte subsystem", 64 << 20, func(o *FormatOptions) { o.Subsystem = strings.Repeat("S", 48) }, ErrInvalidLabel},
		{"no room for data", 16 << 20, func(*FormatOptions) {}, ErrDeviceTooSmall},
		{"no room for one 4 KiB sector", 16<<20 + 2048, func(o *FormatOptions) { o.SectorSize = 4096 }, ErrDeviceTooSmall},
		{"data not a whole number of 4 KiB sectors", 17<<20 + 512, func(o *FormatOptions) { o.SectorSize = 4096 }, ErrInvalidSize},
		{"no room for a larger key's keyslot", 16 << 20, func(o *FormatOptions) { o.MetadataSize = 4 << 20 }, ErrDeviceTooSmall},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, pattern := sizedImage(t, tc.size)
			opts := standardFormatOptions(path)
			tc.mutate(&opts)
			if err := Format(opts); !errors.Is(err, tc.want) {
				t.Fatalf("Format: got %v, want %v", err, tc.want)
			}
			assertUntouched(t, path, tc.size, pattern)
		})
	}
}

// TestFormatOpensTheDeviceExclusively: Format asks for O_EXCL, and the EBUSY a
// block device answers while mounted or mapped is reported as ErrDeviceInUse
// with nothing written. The kernel's side is proved in the integration suite;
// this proves the request and the classification on every platform.
func TestFormatOpensTheDeviceExclusively(t *testing.T) {
	// Not parallel: it substitutes the package's open seam.
	path, pattern := sizedImage(t, 64<<20)

	previous := openFileFunc
	t.Cleanup(func() { openFileFunc = previous })
	openFileFunc = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		// The exclusive open is the claim: it reopens the locked descriptor's
		// own /proc/self/fd entry (Locked.Claim), not path again, so that is
		// what this intercepts.
		if strings.HasPrefix(name, "/proc/self/fd/") && flag&os.O_EXCL != 0 {
			return nil, &fs.PathError{Op: "open", Path: name, Err: syscall.EBUSY}
		}
		return previous(name, flag, perm)
	}

	if err := Format(standardFormatOptions(path)); !errors.Is(err, ErrDeviceInUse) || !errors.Is(err, syscall.EBUSY) {
		t.Fatalf("Format of a device the kernel reports busy: got %v, want ErrDeviceInUse", err)
	}
	assertUntouched(t, path, 64<<20, pattern)
}

// TestFormatWritesTheLongestLabelAndASmallerKey is the accepting side: a
// 47-byte label and a subsystem fit with their NUL, and a 256-bit key is a
// combination the allow-list admits.
func TestFormatWritesTheLongestLabelAndASmallerKey(t *testing.T) {
	defer parallel(t)()

	path := keySize256Volume(t)
	info, err := GetVolumeInfo(path)
	if err != nil {
		t.Fatalf("GetVolumeInfo: %v", err)
	}
	if info.Label != strings.Repeat("L", maxLabelLength) {
		t.Fatalf("Label = %q, want the 47-byte label", info.Label)
	}
	hdr, _, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if hdr.Label[maxLabelLength] != 0 || hdr.SubsystemLabel[maxLabelLength] != 0 {
		t.Fatal("the label fields have no NUL terminator")
	}
}

// keySize256Volume is a container formatted with a 256-bit key and the longest
// labels the header holds, shared by the tests that need one.
func keySize256Volume(t *testing.T) string {
	t.Helper()
	return formattedImage(t, "keySize256Volume", "volume.img", 17<<20, func() FormatOptions {
		opts := standardFormatOptions("")
		opts.KeySize = 256
		opts.Label = strings.Repeat("L", maxLabelLength)
		opts.Subsystem = strings.Repeat("S", maxLabelLength)
		return opts
	})
}

func TestClassifyDeviceOpenReportsABusyDeviceAsInUse(t *testing.T) {
	cause := &fs.PathError{Op: "open", Path: "/dev/sdb1", Err: syscall.EBUSY}
	err := classifyDeviceOpen("format the device", cause)
	if !errors.Is(err, ErrDeviceInUse) || !errors.Is(err, syscall.EBUSY) || !strings.Contains(err.Error(), "format the device") {
		t.Fatalf("classifyDeviceOpen(EBUSY) = %v, want ErrDeviceInUse naming the operation and keeping the errno", err)
	}
}

// TestFormatClaimsTheLockedDescriptorRegardlessOfASymlinkRetarget: the locks
// are taken on one open of the path and the format writes through a second,
// exclusive one -- the claim -- which reopens the FIRST descriptor's own
// /proc/self/fd entry rather than resolving the path again (Locked.Claim).
// So a symlink retargeted between the lock and the claim cannot move the
// write to a different file: the format still lands on the file that was
// locked, and the file the symlink now names is untouched. This replaces an
// older test of requireSameDevice, which this design deletes -- the
// retargeting it guarded against is now impossible by construction rather
// than caught after the fact.
func TestFormatClaimsTheLockedDescriptorRegardlessOfASymlinkRetarget(t *testing.T) {
	// Not parallel: it substitutes the package's lock-held hook.
	dir := t.TempDir()
	pattern := bytes.Repeat([]byte{0xA5}, 4096)
	makeTarget := func(name string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pattern, 0o600); err != nil {
			t.Fatalf("create %s: %v", path, err)
		}
		if err := os.Truncate(path, 64<<20); err != nil {
			t.Fatalf("size %s: %v", path, err)
		}
		return path
	}
	locked := makeTarget("locked.img")
	retargeted := makeTarget("retargeted.img")

	link := filepath.Join(dir, "device.img")
	if err := os.Symlink(locked, link); err != nil {
		t.Fatal(err)
	}

	previous := fileLockHeld
	t.Cleanup(func() { fileLockHeld = previous })
	fileLockHeld = func(string) {
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(retargeted, link); err != nil {
			t.Fatal(err)
		}
	}

	if err := Format(standardFormatOptions(link)); err != nil {
		t.Fatalf("Format through a symlink retargeted after the lock: %v", err)
	}
	assertUntouched(t, retargeted, 64<<20, pattern)
	if bytes.Equal(readAreaBytes(t, locked, 0, int64(len(pattern))), pattern) {
		t.Fatal("Format did not write to the file it locked")
	}
}
