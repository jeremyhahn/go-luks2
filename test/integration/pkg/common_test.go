// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package pkg_test

import (
	"os"
	"time"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// testCleanup performs common test cleanup
func testCleanup(volumeName string, loopDev string, tmpfile string) {
	// Try to lock volume
	_ = luks2.Lock(volumeName)

	// Wait for device mapper to settle
	for i := 0; i < 30; i++ {
		if !luks2.IsUnlocked(volumeName) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Detach loop device
	if loopDev != "" {
		_ = luks2.DetachLoopDevice(loopDev)
	}

	// Remove temp file
	if tmpfile != "" {
		_ = os.Remove(tmpfile)
	}
}

// createTestFile creates a test file with the given size
func createTestFile(path string, sizeMB int) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return f.Truncate(int64(sizeMB * 1024 * 1024))
}

// waitForUnlock waits for a volume to be unlocked
func waitForUnlock(volumeName string, timeoutMs int) bool {
	for i := 0; i < timeoutMs/100; i++ {
		if luks2.IsUnlocked(volumeName) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// waitForLock waits for a volume to be locked
func waitForLock(volumeName string, timeoutMs int) bool {
	for i := 0; i < timeoutMs/100; i++ {
		if !luks2.IsUnlocked(volumeName) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
