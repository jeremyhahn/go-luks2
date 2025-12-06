// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMountUnmount tests mounting and unmounting LUKS volumes
func TestMountUnmount(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

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
	volumeName := "test-mount"

	// Cleanup any leftover device mapper from previous runs
	_ = Lock(volumeName)

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
	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer Lock(volumeName)

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
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

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
