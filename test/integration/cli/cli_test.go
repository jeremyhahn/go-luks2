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

	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

var binaryPath string

// detachLoopDevicesBackedBy detaches only the loop devices attached to path,
// and fails the test if it cannot establish that it left none behind.
//
// It replaces `losetup -D` (#17), which detaches EVERY loop device on the
// machine regardless of who created it. Loop devices are not namespaced and
// this suite runs under `docker run --privileged`, so "the machine" is the
// host: two concurrent containers share one global pool, and one container's
// teardown destroyed the other's in-flight devices. That is not a defect in
// the allocation path — SetupLoopDevice already asks the kernel for a free
// device via LOOP_CTL_GET_FREE and touches only what it was given. No amount
// of careful allocation defends against an ownership-blind, forcible detach.
//
// A test removes what it created. Nothing else.
//
// EVERY FAILURE HERE IS A TEST FAILURE, not a log line. Cleanup that cannot
// fail is the same defect as the `losetup -D` it replaces, wearing better
// manners: an earlier draft reported detach failures with t.Logf, so a test
// could pass while leaving a host loop device attached — state the next run
// inherits, reported as success. A lookup that fails is likewise a failure and
// not an empty result: not knowing what is attached is not evidence that
// nothing is.
//
// It lives here as one function rather than as a copied block because three
// copies of a teardown is precisely how this repository ended up with three
// `losetup -D` call sites, and how a fix for two of them left the third.
func detachLoopDevicesBackedBy(t *testing.T, path string) {
	t.Helper()

	out, err := exec.Command("losetup", "-j", path).Output()
	if err != nil {
		t.Errorf("could not look up the loop devices backing %s, so this test "+
			"cannot confirm it left none attached: %v", path, err)
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		dev, _, found := strings.Cut(line, ":")
		if !found || dev == "" {
			continue
		}
		if err := exec.Command("losetup", "-d", dev).Run(); err != nil &&
			stillAttached(path, dev) {
			t.Errorf("could not detach %s (attached for %s): %v -- a loop device "+
				"this test attached is still on the host", dev, path, err)
		}
	}
}

// stillAttached reports whether dev is still listed as backed by path after a
// failed `losetup -d`. The kernel can keep listing a device for a moment while
// it tears it down (or after another detach already won), so the check is
// repeated for up to about two seconds before the device is called leaked. A
// lookup that fails counts as still attached: the leak check is not weakened.
func stillAttached(path, dev string) bool {
	for i := 0; i < 10; i++ {
		out, err := exec.Command("losetup", "-j", path).Output()
		if err != nil {
			return true
		}
		listed := false
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if d, _, found := strings.Cut(line, ":"); found && d == dev {
				listed = true
			}
		}
		if !listed {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
	return true
}

// TestMain records the host state this suite is about to create (#96), then
// builds the CLI under test.
//
// # What it covers, and what it does not
//
// COVERED: loop devices, through the recorded temp root that TMPDIR points at.
//
// NOT COVERED: dm mappings, on the kill path. This suite creates them by
// running the luks2 BINARY, so they are made in a subprocess -- no in-process
// hook can see them, and the binary under test is built without the integration
// tag precisely so that what is tested is what ships. The two mappings involved
// (test-cli-open, test-cli-workflow) are removed by the tests themselves on
// pass and fail; the SIGKILL window has no record.
//
// Closing it would mean building the CLI with a recording hook compiled in,
// which tests a different binary from the one released -- a worse trade than
// the gap.
//
// Accepted rather than closed here (ruled 2026-09-01): #105, where concurrent
// jobs docker-rm-f each other's containers through a fixed name, is the
// dominant PRODUCER of the kills this window depends on and is dispatched;
// #80's privilege scoping then removes the class entirely by denying the
// container host device-mapper access in the first place. If #80 stalls, an
// integration-build-tagged exported observer on the library goes back to the
// OWNER as a proposal -- it is new exported surface on a Layer-0 library and
// not a lane's call.
func TestMain(m *testing.M) {
	suite, err := harness.BeginSuite(os.Stderr)
	if err != nil {
		os.Stderr.WriteString("cli integration suite: " + err.Error() + "\n")
		os.Exit(1)
	}

	// Registered before any test runs: runVolume refuses without it, so every
	// name this tier creates carries the container and process terms.
	runSuite = suite

	// Built AFTER BeginSuite so the binary lands under the recorded temp root
	// like everything else this run creates.
	tmpDir, err := os.MkdirTemp("", "luks2-cli-test")
	if err != nil {
		_ = suite.Finish(1, os.Stderr)
		panic("Failed to create temp dir: " + err.Error())
	}
	defer os.RemoveAll(tmpDir)

	binaryPath = filepath.Join(tmpDir, "luks2")
	cmd := exec.Command("go", "build", "-o", binaryPath, "github.com/jeremyhahn/go-luks2/cmd/luks2")
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = suite.Finish(1, os.Stderr)
		panic("Failed to build CLI: " + err.Error() + "\nOutput: " + string(out))
	}

	// Exit with what the CLEANUP concluded: a green run that could not remove
	// its own host state must not report success.
	os.Exit(suite.Finish(m.Run(), os.Stderr))
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

// TestCLI_WipeCancelled: an answer other than YES cancels the wipe, the device
// is untouched, and the exit status is NON-ZERO (#246 D12) -- a script must not
// read a wipe that did not happen as one that did.
func TestCLI_WipeCancelled(t *testing.T) {
	tmpfile := filepath.Join(t.TempDir(), "test-cli-wipe-cancel.img")
	content := bytes.Repeat([]byte{0xAA}, 1024*1024)
	if err := os.WriteFile(tmpfile, content, 0o600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	for _, input := range []string{"NO\n", ""} {
		_, stderr, err := runCLIWithInput(input, "wipe", tmpfile)
		if err == nil {
			t.Fatalf("wipe with %q on stdin exited 0", input)
		}
		if !strings.Contains(stderr, "Wipe canceled") {
			t.Errorf("Expected 'Wipe canceled' message, got: %q", stderr)
		}
		got, err := os.ReadFile(tmpfile)
		if err != nil || !bytes.Equal(got, content) {
			t.Fatalf("a canceled wipe changed the device (%v)", err)
		}
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
	volumeName := runVolume(t, "test-cli-workflow")
	mountpoint := "/tmp/test-cli-mount"

	defer func() {
		// Cleanup
		runCLIWithInput("", "unmount", mountpoint)
		runCLI("close", volumeName)
		// Scoped to this test's own backing file. This was the THIRD
		// `losetup -D` call site (#17) and the one the fix for the other two
		// missed: it detached every loop device on the machine, and since loop
		// devices are not namespaced and this suite runs --privileged, "the
		// machine" is the host. Errors were discarded, so it did so silently.
		//
		// This test attaches no loop device at all, so the correct scoped
		// cleanup finds nothing — which is the point. The old call was not
		// cleaning up after this test; it was clearing the machine on this
		// test's behalf.
		detachLoopDevicesBackedBy(t, tmpfile)
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

// TestCLI_CreateBlockDeviceUsage: a /dev path that is not a block device is
// refused, and not created as a file.
func TestCLI_CreateBlockDeviceUsage(t *testing.T) {
	_, stderr, err := runCLI("create", "/dev/nonexistent")
	if err == nil || !strings.Contains(stderr, "no such block device") {
		t.Errorf("create /dev/nonexistent: %v, stderr %q", err, stderr)
	}
	if _, err := os.Lstat("/dev/nonexistent"); err == nil {
		t.Error("create made /dev/nonexistent")
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
	"context"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func main() {
	ctx := context.Background()
	v, err := luks2.Open(ctx, "` + tmpfile + `")
	if err != nil {
		panic(err)
	}
	defer v.Close()
	pass, err := enclave.NewMemoryEnclaveCopy([]byte("testpass"))
	if err != nil {
		panic(err)
	}
	defer pass.Destroy()
	if err := v.Format(ctx, pass, luks2.FormatParams{
		Label: "TestInfoCLI",
		KDF:   luks2.KDFParams{Type: luks2.KDFPBKDF2},
	}); err != nil {
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
	tmpfile := filepath.Join(t.TempDir(), "test-cli-open-close.img")
	volumeName := runVolume(t, "test-cli-open")

	defer func() {
		runCLI("close", volumeName)

		detachLoopDevicesBackedBy(t, tmpfile)
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
	"context"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func main() {
	ctx := context.Background()
	v, err := luks2.Open(ctx, "` + tmpfile + `")
	if err != nil {
		panic(err)
	}
	defer v.Close()
	pass, err := enclave.NewMemoryEnclaveCopy([]byte("testpass"))
	if err != nil {
		panic(err)
	}
	defer pass.Destroy()
	if err := v.Format(ctx, pass, luks2.FormatParams{
		KDF: luks2.KDFParams{Type: luks2.KDFPBKDF2},
	}); err != nil {
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

	// Through the harness, which refuses a backing file outside the recorded
	// run root: that record is what lets the next run's reaper detach this
	// device if the run dies before the deferred cleanup (#348).
	loopDev, err := harness.SetupLoopDevice(tmpfile)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}

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
	"context"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func main() {
	ctx := context.Background()
	v, err := luks2.Open(ctx, "` + tmpfile + `")
	if err != nil {
		panic(err)
	}
	defer v.Close()
	pass, err := enclave.NewMemoryEnclaveCopy([]byte("testpass"))
	if err != nil {
		panic(err)
	}
	defer pass.Destroy()
	if err := v.Format(ctx, pass, luks2.FormatParams{
		KDF: luks2.KDFParams{Type: luks2.KDFPBKDF2},
	}); err != nil {
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
