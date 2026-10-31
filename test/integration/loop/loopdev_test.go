// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package loop_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/pkg/loop"
)

func TestSetupLoopDevice(t *testing.T) {
	tmpfile := filepath.Join(t.TempDir(), "test-loop.img")

	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(10 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate file: %v", err)
	}
	f.Close()

	dev, err := loop.Attach(context.Background(), tmpfile)
	if err != nil {
		t.Fatalf("Attach failed: %v", err)
	}
	defer dev.Detach(context.Background())

	if _, err := os.Stat(dev.Path()); err != nil {
		t.Fatalf("Loop device %s does not exist: %v", dev.Path(), err)
	}
	if !strings.HasPrefix(dev.Path(), "/dev/loop") {
		t.Fatalf("Expected loop device path to start with /dev/loop, got: %s", dev.Path())
	}
}

func TestSetupLoopDeviceErrors(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T) string
	}{
		{"nonexistent-file", func(t *testing.T) string { return "/nonexistent/path/to/file.img" }},
		{"directory-instead-of-file", func(t *testing.T) string { return t.TempDir() }},
		{"empty-file-path", func(t *testing.T) string { return "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup(t)
			dev, err := loop.Attach(context.Background(), path)
			if err == nil {
				if dev != nil {
					dev.Detach(context.Background())
				}
				t.Fatal("Expected error, got nil")
			}
		})
	}
}

func TestDetachLoopDeviceErrors(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T) string
	}{
		{"invalid-device-path", func(t *testing.T) string { return "/dev/nonexistent_loop999" }},
		{"empty-device-path", func(t *testing.T) string { return "" }},
		{
			"already-detached-device",
			func(t *testing.T) string {
				tmpfile := filepath.Join(t.TempDir(), "test-double-detach.img")
				f, err := os.Create(tmpfile)
				if err != nil {
					t.Fatalf("Failed to create file: %v", err)
				}
				if err := f.Truncate(10 * 1024 * 1024); err != nil {
					f.Close()
					t.Fatalf("Failed to truncate file: %v", err)
				}
				f.Close()

				dev, err := loop.Attach(context.Background(), tmpfile)
				if err != nil {
					t.Fatalf("Attach failed: %v", err)
				}
				if _, err := dev.Detach(context.Background()); err != nil {
					t.Fatalf("First detach failed: %v", err)
				}
				return dev.Path()
			},
		},
		{"not-a-loop-device", func(t *testing.T) string { return "/dev/null" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup(t)

			dev, err := loop.Lookup(context.Background(), path)
			if err == nil {
				_, err = dev.Detach(context.Background())
			}
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
		})
	}
}

func TestFindLoopDeviceNotFound(t *testing.T) {
	tmpfile := filepath.Join(t.TempDir(), "test-not-attached.img")

	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(10 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate file: %v", err)
	}
	f.Close()

	found, err := loop.Find(context.Background(), tmpfile)
	if err == nil {
		t.Fatalf("Expected error for unattached file, but found device: %s", found.Path())
	}
	if !errors.Is(err, loop.ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got: %v", err)
	}
}

// TestFindLoopDeviceFindsAFileNamedThroughASymlink moved from
// pkg/luks2/activation_integration_test.go (#274): Find resolves the
// backing file by its real path, so a symlink to the attached image must
// still find the loop device.
func TestFindLoopDeviceFindsAFileNamedThroughASymlink(t *testing.T) {
	tmpfile := filepath.Join(t.TempDir(), "symlinked.img")
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(4 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	dev, err := loop.Attach(context.Background(), tmpfile)
	if err != nil {
		t.Fatalf("Attach failed: %v", err)
	}
	defer dev.Detach(context.Background())

	link := filepath.Join(t.TempDir(), "alias.img")
	if err := os.Symlink(tmpfile, link); err != nil {
		t.Fatalf("symlink failed: %v", err)
	}

	found, err := loop.Find(context.Background(), link)
	if err != nil || found.Path() != dev.Path() {
		t.Fatalf("Find(%s) = %v, %v; want %s", link, found, err, dev.Path())
	}
}

func TestLoopDeviceMultiple(t *testing.T) {
	const numDevices = 5
	tmpDir := t.TempDir()

	devices := make([]*loop.Device, numDevices)
	files := make([]string, numDevices)

	defer func() {
		for _, dev := range devices {
			if dev != nil {
				dev.Detach(context.Background())
			}
		}
	}()

	for i := 0; i < numDevices; i++ {
		tmpfile := filepath.Join(tmpDir, "test-multi-"+string(rune('a'+i))+".img")
		files[i] = tmpfile

		f, err := os.Create(tmpfile)
		if err != nil {
			t.Fatalf("Failed to create file %d: %v", i, err)
		}
		if err := f.Truncate(10 * 1024 * 1024); err != nil {
			f.Close()
			t.Fatalf("Failed to truncate file %d: %v", i, err)
		}
		f.Close()

		dev, err := loop.Attach(context.Background(), tmpfile)
		if err != nil {
			t.Fatalf("Attach failed for file %d: %v", i, err)
		}
		devices[i] = dev
	}

	seen := make(map[string]bool)
	for i, dev := range devices {
		if seen[dev.Path()] {
			t.Fatalf("Duplicate loop device detected: %s", dev.Path())
		}
		seen[dev.Path()] = true

		if _, err := os.Stat(dev.Path()); err != nil {
			t.Fatalf("Loop device %d (%s) does not exist: %v", i, dev.Path(), err)
		}
	}

	for i, file := range files {
		found, err := loop.Find(context.Background(), file)
		if err != nil {
			t.Fatalf("Failed to find loop device for file %d: %v", i, err)
		}
		if found.Path() != devices[i].Path() {
			t.Fatalf("Found device %s for file %d does not match created device %s",
				found.Path(), i, devices[i].Path())
		}
	}
}

func TestLoopDeviceCleanup(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("detach-after-failed-operation", func(t *testing.T) {
		tmpfile := filepath.Join(tmpDir, "test-cleanup1.img")

		f, err := os.Create(tmpfile)
		if err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
		if err := f.Truncate(10 * 1024 * 1024); err != nil {
			f.Close()
			t.Fatalf("Failed to truncate file: %v", err)
		}
		f.Close()

		dev, err := loop.Attach(context.Background(), tmpfile)
		if err != nil {
			t.Fatalf("Attach failed: %v", err)
		}

		// Released HERE, immediately after the acquisition, so a t.Fatalf
		// below cannot leak this device: see loopdev_integration_test.go
		// (now moved) for why this matters on a busy host (#116).
		firstReleased := false
		t.Cleanup(func() {
			if firstReleased {
				return
			}
			if _, err := dev.Detach(context.Background()); err != nil {
				t.Errorf("Failed to release %s on the way out: %v", dev.Path(), err)
			}
		})

		// Attach the SAME FILE a second time: the kernel permits several
		// loop devices to share one backing file.
		second, err := loop.Attach(context.Background(), tmpfile)
		if err != nil {
			t.Fatalf("attaching %s to a second loop device should succeed: %v", tmpfile, err)
		}
		t.Cleanup(func() {
			if _, err := second.Detach(context.Background()); err != nil {
				t.Errorf("Failed to detach the second loop device %s: %v", second.Path(), err)
			}
		})

		if _, err := dev.Detach(context.Background()); err != nil {
			t.Fatalf("Failed to detach after failed operation: %v", err)
		}
		firstReleased = true
	})

	t.Run("detach-after-failed-operation-leaves-no-device", func(t *testing.T) {
		tmpfile := filepath.Join(tmpDir, "test-cleanup1.img")
		if _, err := os.Stat(tmpfile); err != nil {
			t.Fatalf("the previous subtest did not run, so this asserts nothing: %v", err)
		}
		if dev, err := loop.Find(context.Background(), tmpfile); err == nil {
			t.Fatalf("%s is still attached to %s after its subtest finished", dev.Path(), tmpfile)
		}
	})

	t.Run("resources-freed-after-detach", func(t *testing.T) {
		tmpfile := filepath.Join(tmpDir, "test-cleanup2.img")

		f, err := os.Create(tmpfile)
		if err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
		if err := f.Truncate(10 * 1024 * 1024); err != nil {
			f.Close()
			t.Fatalf("Failed to truncate file: %v", err)
		}
		f.Close()

		for i := 0; i < 3; i++ {
			dev, err := loop.Attach(context.Background(), tmpfile)
			if err != nil {
				t.Fatalf("Attach failed on iteration %d: %v", i, err)
			}
			if _, err := dev.Detach(context.Background()); err != nil {
				t.Fatalf("Detach failed on iteration %d: %v", i, err)
			}
		}
	})

	t.Run("defer-cleanup", func(t *testing.T) {
		tmpfile := filepath.Join(tmpDir, "test-cleanup3.img")

		f, err := os.Create(tmpfile)
		if err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
		if err := f.Truncate(10 * 1024 * 1024); err != nil {
			f.Close()
			t.Fatalf("Failed to truncate file: %v", err)
		}
		f.Close()

		var path string
		func() {
			dev, err := loop.Attach(context.Background(), tmpfile)
			if err != nil {
				t.Fatalf("Attach failed: %v", err)
			}
			path = dev.Path()
			defer func() {
				if _, err := dev.Detach(context.Background()); err != nil {
					t.Errorf("Defer detach failed: %v", err)
				}
			}()

			found, err := loop.Find(context.Background(), tmpfile)
			if err != nil {
				t.Fatalf("Failed to find loop device: %v", err)
			}
			if found.Path() != path {
				t.Fatalf("Found device %s does not match created device %s", found.Path(), path)
			}
		}()

		if _, err := loop.Find(context.Background(), tmpfile); err == nil {
			t.Fatal("Expected loop device to be detached after defer, but it still exists")
		}
	})
}

// TestDetachLoopDeviceStateReportsADeferredRelease is the kernel-facing test
// for the deferred-release contract. See loopdev_integration_test.go (now
// moved) for why the unit test alone cannot establish it.
func TestDetachLoopDeviceStateReportsADeferredRelease(t *testing.T) {
	tmpfile := filepath.Join(t.TempDir(), "test-deferred.img")

	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(10 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate file: %v", err)
	}
	f.Close()

	dev, err := loop.Attach(context.Background(), tmpfile)
	if err != nil {
		t.Fatalf("Attach failed: %v", err)
	}

	holder, err := os.OpenFile(dev.Path(), os.O_RDONLY, 0)
	if err != nil {
		_, _ = dev.Detach(context.Background())
		t.Fatalf("Failed to hold the loop device open: %v", err)
	}
	holderClosed := false
	defer func() {
		if !holderClosed {
			_ = holder.Close()
		}
	}()

	state, err := dev.Detach(context.Background())
	if err != nil {
		_ = holder.Close()
		holderClosed = true
		_, _ = dev.Detach(context.Background())
		t.Fatalf("Detach reported a failure for a device the kernel should have deferred: %v", err)
	}
	if state != loop.Deferred {
		_ = holder.Close()
		holderClosed = true
		_, _ = dev.Detach(context.Background())
		t.Fatalf("state = %v, want Deferred while another descriptor holds the device", state)
	}

	if err := holder.Close(); err != nil {
		t.Fatalf("Failed to release the holder: %v", err)
	}
	holderClosed = true

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := loop.Find(context.Background(), tmpfile); err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("The association survived after the last holder was released")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestDetachLoopDeviceStateReportsAnImmediateRelease is the control.
func TestDetachLoopDeviceStateReportsAnImmediateRelease(t *testing.T) {
	tmpfile := filepath.Join(t.TempDir(), "test-immediate.img")

	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(10 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate file: %v", err)
	}
	f.Close()

	dev, err := loop.Attach(context.Background(), tmpfile)
	if err != nil {
		t.Fatalf("Attach failed: %v", err)
	}

	state, err := dev.Detach(context.Background())
	if err != nil {
		t.Fatalf("Detach returned error: %v", err)
	}
	if state != loop.Released {
		t.Errorf("state = %v, want Released for a device nothing else holds", state)
	}

	if found, err := loop.Find(context.Background(), tmpfile); err == nil {
		t.Errorf("device %s is still attached after Detach returned released", found.Path())
	}
}
