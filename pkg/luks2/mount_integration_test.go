// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMountUnmount tests mounting and unmounting LUKS volumes
func TestMountUnmount(t *testing.T) {
	requireRoot(t)

	tmpfile, err := os.CreateTemp("", "luks-mount-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	if err := tmpfile.Truncate(100 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	passphrase := []byte("test-mount-pass")
	volumeName := runVolume(t, "test-mount")

	// Format
	opts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Setup loop device
	loopDev, err := SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}
	defer DetachLoopDevice(loopDev)

	// Unlock
	// Registered BEFORE the mapping can exist, so a partial or rolled-back
	// unlock cannot leave one behind either (#100). Idempotent.
	defer releaseVolume(t, volumeName)
	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer releaseVolume(t, volumeName)

	// Create filesystem
	if err := MakeFilesystem(volumeName, "ext4", "test-label"); err != nil {
		t.Fatalf("Failed to create filesystem: %v", err)
	}

	// Mount
	mountPoint := filepath.Join(os.TempDir(), "luks-mount-test")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("Failed to create mount point: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	mountOpts := MountOptions{
		Device:     volumeName,
		MountPoint: mountPoint,
		FSType:     "ext4",
	}

	if err := Mount(mountOpts); err != nil {
		t.Fatalf("Mount failed: %v", err)
	}

	// Verify mounted
	mounted, err := IsMounted(mountPoint)
	if err != nil {
		t.Fatalf("IsMounted check failed: %v", err)
	}
	if !mounted {
		t.Fatal("Volume should be mounted")
	}

	// Unmount
	if err := Unmount(mountPoint, 0); err != nil {
		t.Fatalf("Unmount failed: %v", err)
	}

	// Verify unmounted
	mounted, err = IsMounted(mountPoint)
	if err != nil {
		t.Fatalf("IsMounted check failed: %v", err)
	}
	if mounted {
		t.Fatal("Volume should be unmounted")
	}
}

// TestMountErrors tests mount error conditions
func TestMountErrors(t *testing.T) {
	requireRoot(t)

	tests := []struct {
		name string
		opts MountOptions
	}{
		{
			name: "nonexistent-device",
			opts: MountOptions{
				Device:     "nonexistent",
				MountPoint: "/tmp/test",
				FSType:     "ext4",
			},
		},
		{
			name: "invalid-mountpoint",
			opts: MountOptions{
				Device:     "test",
				MountPoint: "/nonexistent/path/that/does/not/exist",
				FSType:     "ext4",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Mount(tt.opts)
			if err == nil {
				Unmount(tt.opts.MountPoint, 0)
				t.Fatal("Expected error, got nil")
			}
		})
	}
}

// TestMountDetectsTheFilesystemOnTheDevice: with no FSType, Mount mounts what
// blkid finds on the mapping -- here xfs, which the CLI's old hard-coded ext4
// could not mount -- and an empty mapping is refused rather than guessed at.
func TestMountDetectsTheFilesystemOnTheDevice(t *testing.T) {
	requireRoot(t)

	volumePath := filepath.Join(t.TempDir(), "detect.img")
	if err := os.WriteFile(volumePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(volumePath, 400<<20); err != nil { // xfs wants 300 MiB
		t.Fatal(err)
	}
	passphrase := []byte("detect-the-filesystem")
	if err := Format(FormatOptions{Device: volumePath, Passphrase: passphrase, KDFType: "pbkdf2", PBKDFIterTime: 100}); err != nil {
		t.Fatalf("Format: %v", err)
	}
	loopDev, err := SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("SetupLoopDevice: %v", err)
	}
	defer DetachLoopDevice(loopDev)

	volumeName := runVolume(t, "mount-detect")
	defer releaseVolume(t, volumeName)
	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	mountPoint := t.TempDir()

	// Nothing on it yet: refused, and nothing mounted.
	if _, err := DetectFilesystem(volumeName); !errors.Is(err, ErrFilesystemNotDetected) {
		t.Fatalf("DetectFilesystem on an empty mapping = %v, want ErrFilesystemNotDetected", err)
	}
	if err := Mount(MountOptions{Device: volumeName, MountPoint: mountPoint}); !errors.Is(err, ErrFilesystemNotDetected) {
		_ = Unmount(mountPoint, 0)
		t.Fatalf("Mount with no type on an empty mapping = %v, want ErrFilesystemNotDetected", err)
	}

	if err := MakeFilesystem(volumeName, string(FilesystemXFS), "detected"); err != nil {
		t.Fatalf("MakeFilesystem xfs: %v", err)
	}
	if got, err := DetectFilesystem(volumeName); err != nil || got != FilesystemXFS {
		t.Fatalf("DetectFilesystem = %q, %v; want xfs", got, err)
	}

	if err := Mount(MountOptions{Device: volumeName, MountPoint: mountPoint}); err != nil {
		t.Fatalf("Mount with no type: %v", err)
	}
	defer func() {
		if err := Unmount(mountPoint, 0); err != nil {
			t.Errorf("Unmount: %v", err)
		}
	}()

	if fsType := mountedType(t, mountPoint); fsType != "xfs" {
		t.Fatalf("%s is mounted as %q, want xfs", mountPoint, fsType)
	}
}

// mountedType is the filesystem type /proc/self/mountinfo records for the
// mount at mountPoint, or "" when nothing is mounted there.
func mountedType(t *testing.T, mountPoint string) string {
	t.Helper()
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		pre, post, ok := strings.Cut(line, " - ")
		fields, after := strings.Fields(pre), strings.Fields(post)
		if ok && len(fields) >= 5 && len(after) >= 1 && unescapeMountField(fields[4]) == mountPoint {
			return after[0]
		}
	}
	return ""
}
