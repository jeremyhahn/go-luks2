// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package filesystem_test

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/dm"
	"github.com/jeremyhahn/go-luks2/pkg/filesystem"
	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

// Mount and MakeFilesystem resolve a MAPPING NAME to a device through
// device-mapper (dmcrypt.Lookup), not a raw path -- the C3/C5 fixes --
// before forwarding to pkg/filesystem: that resolution is what these tests
// exercise, so they go through test/internal/harness's old-shaped wrappers
// rather than pkg/filesystem's own device-path entry points.

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

	if err := formatForTest(volumePath, passphrase); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	loopDev, err := harness.SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}
	defer harness.DetachLoopDevice(loopDev)

	defer releaseVolume(t, volumeName)
	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer releaseVolume(t, volumeName)

	if err := harness.MakeFilesystem(volumeName, "ext4", "test-label"); err != nil {
		t.Fatalf("Failed to create filesystem: %v", err)
	}

	mountPoint := filepath.Join(os.TempDir(), "luks-mount-test")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("Failed to create mount point: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	if err := harness.Mount(harness.MountOptions{Device: volumeName, MountPoint: mountPoint, FSType: "ext4"}); err != nil {
		t.Fatalf("Mount failed: %v", err)
	}

	mounted, err := harness.IsMounted(mountPoint)
	if err != nil {
		t.Fatalf("IsMounted check failed: %v", err)
	}
	if !mounted {
		t.Fatal("Volume should be mounted")
	}

	if err := harness.Unmount(mountPoint, 0); err != nil {
		t.Fatalf("Unmount failed: %v", err)
	}

	mounted, err = harness.IsMounted(mountPoint)
	if err != nil {
		t.Fatalf("IsMounted check failed: %v", err)
	}
	if mounted {
		t.Fatal("Volume should be unmounted")
	}
}

func TestMountErrors(t *testing.T) {
	requireRoot(t)

	tests := []struct {
		name string
		opts harness.MountOptions
	}{
		{"nonexistent-device", harness.MountOptions{Device: "nonexistent", MountPoint: "/tmp/test", FSType: "ext4"}},
		{"invalid-mountpoint", harness.MountOptions{Device: "test", MountPoint: "/nonexistent/path/that/does/not/exist", FSType: "ext4"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := harness.Mount(tt.opts)
			if err == nil {
				harness.Unmount(tt.opts.MountPoint, 0)
				t.Fatal("Expected error, got nil")
			}
		})
	}
}

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
	if err := formatForTest(volumePath, passphrase); err != nil {
		t.Fatalf("Format: %v", err)
	}
	loopDev, err := harness.SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("SetupLoopDevice: %v", err)
	}
	defer harness.DetachLoopDevice(loopDev)

	volumeName := runVolume(t, "mount-detect")
	defer releaseVolume(t, volumeName)
	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	mountPoint := t.TempDir()

	if _, err := harness.DetectFilesystem(volumeName); !errors.Is(err, filesystem.ErrNotDetected) {
		t.Fatalf("DetectFilesystem on an empty mapping = %v, want ErrFilesystemNotDetected", err)
	}
	if err := harness.Mount(harness.MountOptions{Device: volumeName, MountPoint: mountPoint}); !errors.Is(err, filesystem.ErrNotDetected) {
		_ = harness.Unmount(mountPoint, 0)
		t.Fatalf("Mount with no type on an empty mapping = %v, want ErrFilesystemNotDetected", err)
	}

	if err := harness.MakeFilesystem(volumeName, string(harness.FilesystemXFS), "detected"); err != nil {
		t.Fatalf("MakeFilesystem xfs: %v", err)
	}
	if got, err := harness.DetectFilesystem(volumeName); err != nil || got != harness.FilesystemXFS {
		t.Fatalf("DetectFilesystem = %q, %v; want xfs", got, err)
	}

	if err := harness.Mount(harness.MountOptions{Device: volumeName, MountPoint: mountPoint}); err != nil {
		t.Fatalf("Mount with no type: %v", err)
	}
	defer func() {
		if err := harness.Unmount(mountPoint, 0); err != nil {
			t.Errorf("Unmount: %v", err)
		}
	}()

	if fsType := mountedType(t, mountPoint); fsType != "xfs" {
		t.Fatalf("%s is mounted as %q, want xfs", mountPoint, fsType)
	}
}

func unescapeMountField(field string) string {
	if !strings.Contains(field, "\\") {
		return field
	}
	var out strings.Builder
	out.Grow(len(field))
	for i := 0; i < len(field); {
		if field[i] == '\\' && i+3 < len(field) {
			if value, err := strconv.ParseUint(field[i+1:i+4], 8, 8); err == nil {
				out.WriteByte(byte(value))
				i += 4
				continue
			}
		}
		out.WriteByte(field[i])
		i++
	}
	return out.String()
}

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

// TestIsMappingMountedSeesAMountedMapping is the C3/C5 fix's own real-kernel
// assertion, moved from pkg/luks2/activation_integration_test.go (#274):
// IsMappingMounted must resolve the MAPPING, not whatever happens to be at
// the same device-mapper minor another mapping once held.
func TestIsMappingMountedSeesAMountedMapping(t *testing.T) {
	requireRoot(t)

	tmpfile, err := os.CreateTemp("", "luks-mapping-mounted-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)
	if err := tmpfile.Truncate(100 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	passphrase := []byte("test-mapping-mounted-pass")
	if err := formatForTest(volumePath, passphrase); err != nil {
		t.Fatalf("Format failed: %v", err)
	}
	loopDev, err := harness.SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	defer harness.DetachLoopDevice(loopDev)

	name := runVolume(t, "mapping-mounted")
	defer releaseVolume(t, name)
	if err := Unlock(loopDev, passphrase, name); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	if err := harness.MakeFilesystem(name, "ext4", ""); err != nil {
		t.Fatalf("MakeFilesystem failed: %v", err)
	}
	mountPoint := t.TempDir()
	if err := harness.Mount(harness.MountOptions{Device: name, MountPoint: mountPoint, FSType: "ext4"}); err != nil {
		t.Fatalf("Mount failed: %v", err)
	}
	t.Cleanup(func() { _ = harness.Unmount(mountPoint, 0) })

	if mounted, err := harness.IsMappingMounted(name); err != nil || !mounted {
		t.Fatalf("IsMappingMounted = %v, %v; want true while mounted at %s", mounted, err, mountPoint)
	}
	if mounted, err := harness.IsMounted(dm.MapperPath("/dev", name)); err != nil || mounted {
		t.Fatalf("IsMounted(%s) = %v, %v; the fixture no longer shows the old defect", dm.MapperPath("/dev", name), mounted, err)
	}

	if err := harness.Unmount(mountPoint, 0); err != nil {
		t.Fatalf("Unmount failed: %v", err)
	}
	if mounted, err := harness.IsMappingMounted(name); err != nil || mounted {
		t.Fatalf("IsMappingMounted = %v, %v after the unmount; want false", mounted, err)
	}
}
