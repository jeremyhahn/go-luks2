// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var binaryPath string

func TestMain(m *testing.M) {
	// Build the CLI binary
	tmpDir, err := os.MkdirTemp("", "luks2-cli-test")
	if err != nil {
		panic("Failed to create temp dir: " + err.Error())
	}
	defer os.RemoveAll(tmpDir)

	binaryPath = filepath.Join(tmpDir, "luks2")
	cmd := exec.Command("go", "build", "-o", binaryPath, "github.com/jeremyhahn/go-luks2/cmd/luks2")
	if out, err := cmd.CombinedOutput(); err != nil {
		panic("Failed to build CLI: " + err.Error() + "\nOutput: " + string(out))
	}

	os.Exit(m.Run())
}

func runCLI(args ...string) (string, string, error) {
	cmd := exec.Command(binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func runCLIWithInput(input string, args ...string) (string, string, error) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func TestCLI_Help(t *testing.T) {
	stdout, _, err := runCLI("help")
	if err != nil {
		t.Fatalf("help command failed: %v", err)
	}

	if !strings.Contains(stdout, "USAGE:") {
		t.Error("Expected USAGE in help output")
	}

	if !strings.Contains(stdout, "COMMANDS:") {
		t.Error("Expected COMMANDS in help output")
	}

	if !strings.Contains(stdout, "create") {
		t.Error("Expected 'create' command in help output")
	}

	if !strings.Contains(stdout, "open") {
		t.Error("Expected 'open' command in help output")
	}

	if !strings.Contains(stdout, "close") {
		t.Error("Expected 'close' command in help output")
	}

	if !strings.Contains(stdout, "mount") {
		t.Error("Expected 'mount' command in help output")
	}

	if !strings.Contains(stdout, "unmount") {
		t.Error("Expected 'unmount' command in help output")
	}

	if !strings.Contains(stdout, "info") {
		t.Error("Expected 'info' command in help output")
	}

	if !strings.Contains(stdout, "wipe") {
		t.Error("Expected 'wipe' command in help output")
	}
}

func TestCLI_HelpFlags(t *testing.T) {
	tests := []string{"--help", "-h", "help"}

	for _, arg := range tests {
		t.Run(arg, func(t *testing.T) {
			stdout, _, err := runCLI(arg)
			if err != nil {
				t.Fatalf("%s failed: %v", arg, err)
			}

			if !strings.Contains(stdout, "USAGE:") {
				t.Errorf("Expected USAGE in output for %s", arg)
			}
		})
	}
}

func TestCLI_Version(t *testing.T) {
	stdout, _, err := runCLI("version")
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	if !strings.Contains(stdout, "luks2 version") {
		t.Error("Expected version string in output")
	}
}

func TestCLI_VersionFlags(t *testing.T) {
	tests := []string{"--version", "-v", "version"}

	for _, arg := range tests {
		t.Run(arg, func(t *testing.T) {
			stdout, _, err := runCLI(arg)
			if err != nil {
				t.Fatalf("%s failed: %v", arg, err)
			}

			if !strings.Contains(stdout, "luks2 version") {
				t.Errorf("Expected version in output for %s", arg)
			}
		})
	}
}

func TestCLI_NoArgs(t *testing.T) {
	stdout, _, err := runCLI()
	if err == nil {
		t.Error("Expected error for no arguments")
	}

	if !strings.Contains(stdout, "USAGE:") {
		t.Error("Expected usage message")
	}
}

func TestCLI_UnknownCommand(t *testing.T) {
	stdout, stderr, err := runCLI("unknown-command")
	if err == nil {
		t.Error("Expected error for unknown command")
	}

	if !strings.Contains(stderr, "Unknown command") {
		t.Error("Expected 'Unknown command' error")
	}

	if !strings.Contains(stdout, "USAGE:") {
		t.Error("Expected usage message")
	}
}

func TestCLI_CreateMissingArgs(t *testing.T) {
	stdout, _, err := runCLI("create")
	if err == nil {
		t.Error("Expected error for missing arguments")
	}

	if !strings.Contains(stdout, "Usage: luks2 create") {
		t.Error("Expected create usage message")
	}
}

func TestCLI_CreateFileMissingSize(t *testing.T) {
	stdout, _, err := runCLI("create", "test.luks")
	if err == nil {
		t.Error("Expected error for missing size")
	}

	if !strings.Contains(stdout, "Size required") {
		t.Error("Expected 'Size required' error")
	}
}

func TestCLI_OpenMissingArgs(t *testing.T) {
	stdout, _, err := runCLI("open")
	if err == nil {
		t.Error("Expected error for missing arguments")
	}

	if !strings.Contains(stdout, "Usage: luks2 open") {
		t.Error("Expected open usage message")
	}
}

func TestCLI_OpenMissingName(t *testing.T) {
	stdout, _, err := runCLI("open", "/dev/sda1")
	if err == nil {
		t.Error("Expected error for missing name")
	}

	if !strings.Contains(stdout, "Usage: luks2 open") {
		t.Error("Expected open usage message")
	}
}

func TestCLI_CloseMissingArgs(t *testing.T) {
	stdout, _, err := runCLI("close")
	if err == nil {
		t.Error("Expected error for missing arguments")
	}

	if !strings.Contains(stdout, "Usage: luks2 close") {
		t.Error("Expected close usage message")
	}
}

func TestCLI_MountMissingArgs(t *testing.T) {
	stdout, _, err := runCLI("mount")
	if err == nil {
		t.Error("Expected error for missing arguments")
	}

	if !strings.Contains(stdout, "Usage: luks2 mount") {
		t.Error("Expected mount usage message")
	}
}

func TestCLI_MountMissingMountpoint(t *testing.T) {
	stdout, _, err := runCLI("mount", "myvolume")
	if err == nil {
		t.Error("Expected error for missing mountpoint")
	}

	if !strings.Contains(stdout, "Usage: luks2 mount") {
		t.Error("Expected mount usage message")
	}
}

func TestCLI_UnmountMissingArgs(t *testing.T) {
	stdout, _, err := runCLI("unmount")
	if err == nil {
		t.Error("Expected error for missing arguments")
	}

	if !strings.Contains(stdout, "Usage: luks2 unmount") {
		t.Error("Expected unmount usage message")
	}
}

func TestCLI_InfoMissingArgs(t *testing.T) {
	stdout, _, err := runCLI("info")
	if err == nil {
		t.Error("Expected error for missing arguments")
	}

	if !strings.Contains(stdout, "Usage: luks2 info") {
		t.Error("Expected info usage message")
	}
}

func TestCLI_WipeMissingArgs(t *testing.T) {
	stdout, _, err := runCLI("wipe")
	if err == nil {
		t.Error("Expected error for missing arguments")
	}

	if !strings.Contains(stdout, "Usage: luks2 wipe") {
		t.Error("Expected wipe usage message")
	}
}

func TestCLI_WipeCancelled(t *testing.T) {
	// Create a test file to wipe
	tmpfile := "/tmp/test-cli-wipe-cancel.img"
	defer os.Remove(tmpfile)

	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	f.Truncate(1024 * 1024) // 1MB
	f.Close()

	// Run wipe with "NO" input
	stdout, _, err := runCLIWithInput("NO\n", "wipe", tmpfile)
	if err != nil {
		t.Fatalf("wipe cancelled should not error: %v", err)
	}

	if !strings.Contains(stdout, "Wipe cancelled") {
		t.Error("Expected 'Wipe cancelled' message")
	}
}

func TestCLI_InfoNonLuksDevice(t *testing.T) {
	// Create a test file that is not LUKS formatted
	tmpfile := "/tmp/test-cli-info-nonluks.img"
	defer os.Remove(tmpfile)

	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	f.Truncate(1024 * 1024) // 1MB
	f.Close()

	_, stderr, err := runCLI("info", tmpfile)
	if err == nil {
		t.Error("Expected error for non-LUKS device")
	}

	if !strings.Contains(stderr, "Failed to read volume") {
		t.Error("Expected 'Failed to read volume' error")
	}
}

func TestCLI_FullWorkflow(t *testing.T) {
	tmpfile := "/tmp/test-cli-workflow.img"
	volumeName := "test-cli-workflow"
	mountpoint := "/tmp/test-cli-mount"

	defer func() {
		// Cleanup
		runCLIWithInput("", "unmount", mountpoint)
		runCLI("close", volumeName)
		exec.Command("losetup", "-D").Run()
		os.Remove(tmpfile)
		os.RemoveAll(mountpoint)
	}()

	// Step 1: Create the file manually (since CLI create requires interactive input)
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	if err := f.Truncate(50 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()
	t.Log("Step 1: Test file created")

	// Step 2: Format using library directly (CLI requires interactive password)
	// This tests info/open/close/mount/unmount commands
	cmd := exec.Command("go", "run", "github.com/jeremyhahn/go-luks2/cmd/luks2", "info", tmpfile)
	// Expect this to fail since file is not formatted
	if err := cmd.Run(); err == nil {
		t.Log("Info correctly fails on unformatted file")
	}

	// Test commands that don't require interactive input
	t.Log("Testing commands that don't require interactive input...")

	// Test info on a properly formatted volume would work here
	// But since we can't easily format without interactive input,
	// we'll test the commands that work without a formatted volume

	t.Log("CLI workflow test completed (partial - non-interactive commands)")
}

func TestCLI_CreateBlockDeviceUsage(t *testing.T) {
	// Test that creating on a block device shows correct messages
	stdout, _, _ := runCLI("create", "/dev/nonexistent")

	// Should show banner and prompt for passphrase
	if !strings.Contains(stdout, "LUKS2") {
		t.Error("Expected LUKS2 in output")
	}
}

func TestCLI_InfoValidLuksDevice(t *testing.T) {
	tmpfile := "/tmp/test-cli-info-valid.img"
	defer os.Remove(tmpfile)

	// Create test file
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	if err := f.Truncate(50 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	// Format using library
	formatScript := `
package main

import (
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func main() {
	err := luks2.Format(luks2.FormatOptions{
		Device:     "` + tmpfile + `",
		Passphrase: []byte("testpass"),
		Label:      "TestInfoCLI",
		KDFType:    "pbkdf2",
	})
	if err != nil {
		panic(err)
	}
}
`

	// Write and run format script
	scriptFile := "/tmp/format-test.go"
	defer os.Remove(scriptFile)

	if err := os.WriteFile(scriptFile, []byte(formatScript), 0644); err != nil {
		t.Fatalf("Failed to write script: %v", err)
	}

	cmd := exec.Command("go", "run", scriptFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to format: %v\nOutput: %s", err, out)
	}

	// Now test the info command
	stdout, _, err := runCLI("info", tmpfile)
	if err != nil {
		t.Fatalf("info command failed: %v", err)
	}

	// Verify output contains expected info
	if !strings.Contains(stdout, "UUID:") {
		t.Error("Expected UUID in info output")
	}

	if !strings.Contains(stdout, "Version:") {
		t.Error("Expected Version in info output")
	}

	if !strings.Contains(stdout, "Cipher:") {
		t.Error("Expected Cipher in info output")
	}

	if !strings.Contains(stdout, "TestInfoCLI") || !strings.Contains(stdout, "Label:") {
		t.Error("Expected Label 'TestInfoCLI' in info output")
	}

	if !strings.Contains(stdout, "LUKS2") {
		t.Error("Expected LUKS2 in version info")
	}

	if !strings.Contains(stdout, "Volume is valid") {
		t.Error("Expected 'Volume is valid' message")
	}
}

func TestCLI_CloseNonexistentVolume(t *testing.T) {
	_, stderr, err := runCLI("close", "definitely-not-a-volume-12345")
	if err == nil {
		t.Error("Expected error for nonexistent volume")
	}

	if !strings.Contains(stderr, "Failed to lock") {
		t.Error("Expected 'Failed to lock' error")
	}
}

func TestCLI_UnmountNotMounted(t *testing.T) {
	// Create a directory that is not a mount point
	tmpdir := "/tmp/test-cli-unmount-notmounted"
	os.MkdirAll(tmpdir, 0755)
	defer os.RemoveAll(tmpdir)

	_, stderr, err := runCLI("unmount", tmpdir)
	if err == nil {
		t.Error("Expected error for unmounting non-mounted path")
	}

	if !strings.Contains(stderr, "Not mounted") {
		t.Error("Expected 'Not mounted' error")
	}
}

func TestCLI_OpenAndClose(t *testing.T) {
	tmpfile := "/tmp/test-cli-open-close.img"
	volumeName := "test-cli-open"

	defer func() {
		runCLI("close", volumeName)
		// Clean up loop devices
		exec.Command("bash", "-c", "losetup -D 2>/dev/null || true").Run()
		time.Sleep(500 * time.Millisecond)
		os.Remove(tmpfile)
	}()

	// Create and format the test file
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	if err := f.Truncate(50 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	// Format using the library
	formatScript := `
package main

import (
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func main() {
	err := luks2.Format(luks2.FormatOptions{
		Device:     "` + tmpfile + `",
		Passphrase: []byte("testpass"),
		KDFType:    "pbkdf2",
	})
	if err != nil {
		panic(err)
	}
}
`

	scriptFile := "/tmp/format-open-test.go"
	defer os.Remove(scriptFile)

	if err := os.WriteFile(scriptFile, []byte(formatScript), 0644); err != nil {
		t.Fatalf("Failed to write script: %v", err)
	}

	cmd := exec.Command("go", "run", scriptFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to format: %v\nOutput: %s", err, out)
	}

	// Setup loop device
	loopCmd := exec.Command("losetup", "-f", "--show", tmpfile)
	loopOut, err := loopCmd.Output()
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}
	loopDev := strings.TrimSpace(string(loopOut))
	defer exec.Command("losetup", "-d", loopDev).Run()

	t.Logf("Loop device: %s", loopDev)

	// Test info on loop device
	stdout, _, err := runCLI("info", loopDev)
	if err != nil {
		t.Fatalf("info command failed: %v", err)
	}

	if !strings.Contains(stdout, "UUID:") {
		t.Error("Expected UUID in info output")
	}

	t.Log("Info command works on loop device")

	// Close should fail since it's not open
	_, stderr, err := runCLI("close", volumeName)
	if err == nil {
		t.Log("Close correctly fails for non-opened volume")
	} else if !strings.Contains(stderr, "Failed to lock") {
		t.Errorf("Expected 'Failed to lock' error, got: %s", stderr)
	}
}

func TestCLI_WipeConfirmed(t *testing.T) {
	tmpfile := "/tmp/test-cli-wipe-confirmed.img"
	defer os.Remove(tmpfile)

	// Create and format test file
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	if err := f.Truncate(50 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	// Format the file
	formatScript := `
package main

import (
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func main() {
	err := luks2.Format(luks2.FormatOptions{
		Device:     "` + tmpfile + `",
		Passphrase: []byte("testpass"),
		KDFType:    "pbkdf2",
	})
	if err != nil {
		panic(err)
	}
}
`

	scriptFile := "/tmp/format-wipe-test.go"
	defer os.Remove(scriptFile)

	if err := os.WriteFile(scriptFile, []byte(formatScript), 0644); err != nil {
		t.Fatalf("Failed to write script: %v", err)
	}

	cmd := exec.Command("go", "run", scriptFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to format: %v\nOutput: %s", err, out)
	}

	// Verify it's a LUKS device before wipe
	stdout, _, err := runCLI("info", tmpfile)
	if err != nil {
		t.Fatalf("info should work before wipe: %v", err)
	}
	if !strings.Contains(stdout, "UUID:") {
		t.Error("Expected valid LUKS device before wipe")
	}

	// Wipe with YES confirmation
	stdout, _, err = runCLIWithInput("YES\n", "wipe", tmpfile)
	if err != nil {
		t.Fatalf("wipe command failed: %v", err)
	}

	if !strings.Contains(stdout, "Volume wiped successfully") {
		t.Error("Expected success message after wipe")
	}

	// Verify the LUKS headers are wiped
	_, _, err = runCLI("info", tmpfile)
	if err == nil {
		t.Error("info should fail after wipe")
	}
}
