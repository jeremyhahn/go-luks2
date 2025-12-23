// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"os"
	"testing"
)

func TestIsMounted_EmptyFile(t *testing.T) {
	// Test with a non-mounted path
	tmpDir, err := os.MkdirTemp("", "luks-mount-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	mounted, err := IsMounted(tmpDir)
	if err != nil {
		t.Fatalf("IsMounted() error = %v", err)
	}
	if mounted {
		t.Error("IsMounted() = true for non-mounted directory")
	}
}

func TestIsMounted_InvalidPath(t *testing.T) {
	mounted, err := IsMounted("/nonexistent/path/12345")
	if err != nil {
		t.Fatalf("IsMounted() error = %v", err)
	}
	if mounted {
		t.Error("IsMounted() = true for nonexistent path")
	}
}

func TestMountOptions_Defaults(t *testing.T) {
	opts := MountOptions{
		Device:     "test-device",
		MountPoint: "/mnt/test",
		FSType:     "ext4",
	}

	if opts.Device != "test-device" {
		t.Errorf("Device = %q, want %q", opts.Device, "test-device")
	}
	if opts.MountPoint != "/mnt/test" {
		t.Errorf("MountPoint = %q, want %q", opts.MountPoint, "/mnt/test")
	}
	if opts.FSType != "ext4" {
		t.Errorf("FSType = %q, want %q", opts.FSType, "ext4")
	}
	if opts.Flags != 0 {
		t.Errorf("Flags = %d, want 0", opts.Flags)
	}
	if opts.Data != "" {
		t.Errorf("Data = %q, want empty string", opts.Data)
	}
}
