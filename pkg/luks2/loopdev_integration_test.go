// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSetupLoopDevice tests setting up a loop device from a file
func TestSetupLoopDevice(t *testing.T) {
	// Create temporary file
	tmpfile := filepath.Join(t.TempDir(), "test-loop.img")

	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	// Create a 10MB file
	if err := f.Truncate(10 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate file: %v", err)
	}
	f.Close()

	t.Logf("Created temporary file: %s", tmpfile)

	// Setup loop device
	loopDev, err := SetupLoopDevice(tmpfile)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	defer DetachLoopDevice(loopDev)

	t.Logf("Loop device created: %s", loopDev)

	// Verify loop device exists
	if _, err := os.Stat(loopDev); err != nil {
		t.Fatalf("Loop device %s does not exist: %v", loopDev, err)
	}

	// Verify device name format
	if !strings.HasPrefix(loopDev, "/dev/loop") {
		t.Fatalf("Expected loop device path to start with /dev/loop, got: %s", loopDev)
	}

	t.Logf("Loop device verified successfully")
}

// TestSetupLoopDeviceErrors tests error conditions when setting up loop devices
func TestSetupLoopDeviceErrors(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr bool
	}{
		{
			name: "nonexistent-file",
			setup: func(t *testing.T) string {
				return "/nonexistent/path/to/file.img"
			},
			wantErr: true,
		},
		{
			name: "directory-instead-of-file",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				return dir
			},
			wantErr: true,
		},
		{
			name: "empty-file-path",
			setup: func(t *testing.T) string {
				return ""
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup(t)
			t.Logf("Testing with path: %s", path)

			loopDev, err := SetupLoopDevice(path)
			if tt.wantErr {
				if err == nil {
					// Clean up if we unexpectedly succeeded
					if loopDev != "" {
						DetachLoopDevice(loopDev)
					}
					t.Fatal("Expected error, got nil")
				}
				t.Logf("Got expected error: %v", err)
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				if loopDev != "" {
					defer DetachLoopDevice(loopDev)
				}
			}
		})
	}
}

// TestDetachLoopDevice tests detaching a loop device
func TestDetachLoopDevice(t *testing.T) {
	// Create temporary file
	tmpfile := filepath.Join(t.TempDir(), "test-detach.img")

	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	if err := f.Truncate(10 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate file: %v", err)
	}
	f.Close()

	t.Logf("Created temporary file: %s", tmpfile)

	// Setup loop device
	loopDev, err := SetupLoopDevice(tmpfile)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}

	t.Logf("Loop device created: %s", loopDev)

	// Verify it exists
	if _, err := os.Stat(loopDev); err != nil {
		t.Fatalf("Loop device does not exist before detach: %v", err)
	}

	// Detach the loop device
	if err := DetachLoopDevice(loopDev); err != nil {
		t.Fatalf("DetachLoopDevice failed: %v", err)
	}

	t.Logf("Loop device detached successfully")

	// Verify we cannot find it anymore
	foundDev, err := FindLoopDevice(tmpfile)
	if err == nil {
		t.Fatalf("Expected error finding detached loop device, but found: %s", foundDev)
	}

	t.Logf("Verified loop device is no longer associated with file")
}

// TestDetachLoopDeviceErrors tests error conditions when detaching loop devices
func TestDetachLoopDeviceErrors(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr bool
	}{
		{
			name: "invalid-device-path",
			setup: func(t *testing.T) string {
				return "/dev/nonexistent_loop999"
			},
			wantErr: true,
		},
		{
			name: "empty-device-path",
			setup: func(t *testing.T) string {
				return ""
			},
			wantErr: true,
		},
		{
			name: "already-detached-device",
			setup: func(t *testing.T) string {
				// Create and immediately detach
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

				loopDev, err := SetupLoopDevice(tmpfile)
				if err != nil {
					t.Fatalf("SetupLoopDevice failed: %v", err)
				}

				// Detach it once
				if err := DetachLoopDevice(loopDev); err != nil {
					t.Fatalf("First detach failed: %v", err)
				}

				return loopDev
			},
			wantErr: true,
		},
		{
			name: "not-a-loop-device",
			setup: func(t *testing.T) string {
				return "/dev/null"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device := tt.setup(t)
			t.Logf("Testing detach on device: %s", device)

			err := DetachLoopDevice(device)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				t.Logf("Got expected error: %v", err)
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestFindLoopDevice tests finding a loop device for a file
func TestFindLoopDevice(t *testing.T) {
	// Create temporary file
	tmpfile := filepath.Join(t.TempDir(), "test-find.img")

	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	if err := f.Truncate(10 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate file: %v", err)
	}
	f.Close()

	t.Logf("Created temporary file: %s", tmpfile)

	// Setup loop device
	loopDev, err := SetupLoopDevice(tmpfile)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	defer DetachLoopDevice(loopDev)

	t.Logf("Loop device created: %s", loopDev)

	// Find the loop device
	foundDev, err := FindLoopDevice(tmpfile)
	if err != nil {
		t.Fatalf("FindLoopDevice failed: %v", err)
	}

	t.Logf("Found loop device: %s", foundDev)

	// Verify it matches what we created
	if foundDev != loopDev {
		t.Fatalf("Found device %s does not match created device %s", foundDev, loopDev)
	}

	t.Logf("Loop device found and verified successfully")
}

// TestFindLoopDeviceNotFound tests finding a loop device for an unattached file
func TestFindLoopDeviceNotFound(t *testing.T) {
	// Create temporary file that is not attached
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

	t.Logf("Created temporary file: %s", tmpfile)

	// Try to find loop device for unattached file
	foundDev, err := FindLoopDevice(tmpfile)
	if err == nil {
		t.Fatalf("Expected error for unattached file, but found device: %s", foundDev)
	}

	t.Logf("Got expected error: %v", err)

	// Verify error message is appropriate
	if !strings.Contains(err.Error(), "no loop device found") {
		t.Fatalf("Expected 'no loop device found' in error, got: %v", err)
	}
}

// TestLoopDeviceMultiple tests setting up multiple loop devices simultaneously
func TestLoopDeviceMultiple(t *testing.T) {
	const numDevices = 5
	tmpDir := t.TempDir()

	devices := make([]string, numDevices)
	files := make([]string, numDevices)

	// Cleanup function
	defer func() {
		for _, dev := range devices {
			if dev != "" {
				DetachLoopDevice(dev)
			}
		}
	}()

	// Create multiple loop devices
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

		t.Logf("Created temporary file %d: %s", i, tmpfile)

		// Setup loop device
		loopDev, err := SetupLoopDevice(tmpfile)
		if err != nil {
			t.Fatalf("SetupLoopDevice failed for file %d: %v", i, err)
		}
		devices[i] = loopDev

		t.Logf("Loop device %d created: %s", i, loopDev)
	}

	// Verify all devices are unique
	seen := make(map[string]bool)
	for i, dev := range devices {
		if seen[dev] {
			t.Fatalf("Duplicate loop device detected: %s", dev)
		}
		seen[dev] = true

		// Verify device exists
		if _, err := os.Stat(dev); err != nil {
			t.Fatalf("Loop device %d (%s) does not exist: %v", i, dev, err)
		}
	}

	t.Logf("All %d loop devices are unique and exist", numDevices)

	// Verify each device can be found by its file
	for i, file := range files {
		foundDev, err := FindLoopDevice(file)
		if err != nil {
			t.Fatalf("Failed to find loop device for file %d: %v", i, err)
		}

		if foundDev != devices[i] {
			t.Fatalf("Found device %s for file %d does not match created device %s",
				foundDev, i, devices[i])
		}

		t.Logf("Verified loop device %d: %s -> %s", i, file, foundDev)
	}
}

// TestLoopDeviceCleanup tests proper cleanup on errors
func TestLoopDeviceCleanup(t *testing.T) {
	tmpDir := t.TempDir()

	// Test case 1: Ensure detach works after failed operations
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

		t.Logf("Created temporary file: %s", tmpfile)

		// Setup loop device
		loopDev, err := SetupLoopDevice(tmpfile)
		if err != nil {
			t.Fatalf("SetupLoopDevice failed: %v", err)
		}

		t.Logf("Loop device created: %s", loopDev)

		// Release the first device even if this subtest dies before reaching
		// the explicit detach below.
		//
		// Registered HERE, immediately after the acquisition, rather than at
		// the detach: every t.Fatalf between the two is a path out of this
		// function, and the one directly below fires precisely when the runner
		// has no spare loop minors -- so without this the fix would leak a
		// device exactly on the busy hosts it exists to protect.
		//
		// The flag keeps the explicit detach a real assertion rather than a
		// formality: it is what this subtest is about, its failure must still
		// fail the test, and this cleanup must not quietly do the job for it.
		firstReleased := false
		t.Cleanup(func() {
			if firstReleased {
				return
			}
			if err := DetachLoopDevice(loopDev); err != nil {
				t.Errorf("Failed to release %s on the way out: %v", loopDev, err)
			}
		})

		// Attach the SAME FILE a second time.
		//
		// This used to say "should fail", and treat success as a surprise worth
		// logging. The kernel has no such rule: one file can back several loop
		// devices, and `losetup` does it without complaint. So the "unexpected"
		// branch was the ONLY branch -- it printed on every run since the test
		// was written, read as a curiosity, and hid the fact that the device it
		// had just created was being dropped on the floor. The result was one
		// permanently leaked loop device per run, per host (#116).
		//
		// Loop minors are a global host resource and a container can only ever
		// use the ones that existed when it started, so a leak here is not
		// untidiness: six leaked devices on one runner made TestLoopDeviceMultiple
		// below fail outright, and the suite exhausted the host and then failed
		// itself.
		second, err := SetupLoopDevice(tmpfile)
		if err != nil {
			t.Fatalf("attaching %s to a second loop device should succeed -- the kernel permits "+
				"several loop devices to share one backing file: %v", tmpfile, err)
		}
		t.Logf("Second loop device created: %s", second)
		t.Cleanup(func() {
			if err := DetachLoopDevice(second); err != nil {
				t.Errorf("Failed to detach the second loop device %s: %v", second, err)
			}
		})

		// The first device must still be independently detachable -- which is
		// what this subtest is actually about, and what the second attachment is
		// there to complicate.
		if err := DetachLoopDevice(loopDev); err != nil {
			t.Fatalf("Failed to detach after failed operation: %v", err)
		}
		firstReleased = true

		t.Logf("Successfully detached after failed operation")
	})

	// Test case 1b: the subtest above must leave NOTHING attached to its file.
	//
	// This is the assertion the leak survived the absence of. Nothing checked
	// the end state, so a device created and never released looked exactly like
	// a device that was never created.
	t.Run("detach-after-failed-operation-leaves-no-device", func(t *testing.T) {
		tmpfile := filepath.Join(tmpDir, "test-cleanup1.img")
		if _, err := os.Stat(tmpfile); err != nil {
			t.Fatalf("the previous subtest did not run, so this asserts nothing: %v", err)
		}
		if dev, err := FindLoopDevice(tmpfile); err == nil {
			t.Fatalf("%s is still attached to %s after its subtest finished -- a leaked loop minor is "+
				"permanent, and the host's supply is fixed and shared", dev, tmpfile)
		}
	})

	// Test case 2: Ensure resources are freed after detach
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

		t.Logf("Created temporary file: %s", tmpfile)

		// Setup and detach multiple times
		for i := 0; i < 3; i++ {
			loopDev, err := SetupLoopDevice(tmpfile)
			if err != nil {
				t.Fatalf("SetupLoopDevice failed on iteration %d: %v", i, err)
			}

			t.Logf("Iteration %d: Loop device created: %s", i, loopDev)

			if err := DetachLoopDevice(loopDev); err != nil {
				t.Fatalf("DetachLoopDevice failed on iteration %d: %v", i, err)
			}

			t.Logf("Iteration %d: Loop device detached", i)
		}

		t.Logf("Successfully created and detached loop device 3 times")
	})

	// Test case 3: Verify cleanup in defer works correctly
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

		t.Logf("Created temporary file: %s", tmpfile)

		var loopDev string

		// Use anonymous function to test defer
		func() {
			var err error
			loopDev, err = SetupLoopDevice(tmpfile)
			if err != nil {
				t.Fatalf("SetupLoopDevice failed: %v", err)
			}
			defer func() {
				if err := DetachLoopDevice(loopDev); err != nil {
					t.Errorf("Defer detach failed: %v", err)
				}
			}()

			t.Logf("Loop device created: %s", loopDev)

			// Verify it's attached
			foundDev, err := FindLoopDevice(tmpfile)
			if err != nil {
				t.Fatalf("Failed to find loop device: %v", err)
			}
			if foundDev != loopDev {
				t.Fatalf("Found device %s does not match created device %s", foundDev, loopDev)
			}
		}()

		// After function exits, device should be detached
		_, err = FindLoopDevice(tmpfile)
		if err == nil {
			t.Fatal("Expected loop device to be detached after defer, but it still exists")
		}

		t.Logf("Defer cleanup verified successfully")
	})
}

// TestDetachLoopDeviceStateReportsADeferredRelease is the kernel-facing test
// for the deferred-release contract, and it exists because the unit test alone
// could not establish it.
//
// The unit test supplies the autoclear state through a fake reader, so it
// verifies the WAIT's behavior given that state — and nothing about whether
// the kernel produces it. Three assumptions were load-bearing for the API
// decision and were checked only against a double built to match them:
//
//   - LOOP_CLR_FD returns SUCCESS on a device another descriptor still holds
//     open, rather than EBUSY;
//   - sysfs exposes autoclear=1 at that point, not later;
//   - the release completes once the last holder goes away.
//
// A fake that supplies its own answer cannot fail an assertion about the thing
// it is standing in for. This drives the real kernel.
//
// The holder is a second open descriptor on the device, which is the minimal
// form of the condition — a mounted filesystem or a dm-crypt mapping is the
// same situation with more moving parts.
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

	loopDev, err := SetupLoopDevice(tmpfile)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	t.Logf("Loop device created: %s", loopDev)

	// A second opener. While this is held, the kernel cannot complete a
	// release, so it should accept the request and defer it.
	holder, err := os.OpenFile(loopDev, os.O_RDONLY, 0)
	if err != nil {
		_ = DetachLoopDevice(loopDev)
		t.Fatalf("Failed to hold the loop device open: %v", err)
	}
	holderClosed := false
	defer func() {
		if !holderClosed {
			_ = holder.Close()
		}
	}()

	state, err := DetachLoopDeviceState(loopDev)
	if err != nil {
		_ = holder.Close()
		holderClosed = true
		_ = DetachLoopDevice(loopDev)
		t.Fatalf("DetachLoopDeviceState reported a failure for a device the kernel should have deferred: %v", err)
	}
	if state != DetachDeferred {
		_ = holder.Close()
		holderClosed = true
		_ = DetachLoopDevice(loopDev)
		t.Fatalf("state = %v, want DetachDeferred while another descriptor holds the device", state)
	}
	t.Logf("Detach accepted and deferred while the device was held")

	// Releasing the last holder is what lets the kernel finish.
	if err := holder.Close(); err != nil {
		t.Fatalf("Failed to release the holder: %v", err)
	}
	holderClosed = true

	// The release is asynchronous by definition here, so this waits rather
	// than asserting immediately — the same reason DetachLoopDevice waits.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := FindLoopDevice(tmpfile); err != nil {
			t.Logf("Association released after the holder went away")
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("The association survived after the last holder was released")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestDetachLoopDeviceStateReportsAnImmediateRelease is the control. Without
// it the test above would also pass against an implementation that reported
// DetachDeferred for everything.
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

	loopDev, err := SetupLoopDevice(tmpfile)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}

	state, err := DetachLoopDeviceState(loopDev)
	if err != nil {
		t.Fatalf("DetachLoopDeviceState returned error: %v", err)
	}
	if state != DetachReleased {
		t.Errorf("state = %v, want DetachReleased for a device nothing else holds", state)
	}

	// And the release really is observable on return, which is the guarantee
	// this whole change exists to provide.
	if dev, err := FindLoopDevice(tmpfile); err == nil {
		t.Errorf("device %s is still attached after DetachLoopDeviceState returned released", dev)
	}
}
