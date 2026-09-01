// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// MockLuksOperations implements LuksOperations for testing
type MockLuksOperations struct {
	FormatFunc           func(opts luks2.FormatOptions) error
	UnlockFunc           func(device string, passphrase []byte, name string) error
	LockFunc             func(name string) error
	MountFunc            func(opts luks2.MountOptions) error
	UnmountFunc          func(mountPoint string, flags int) error
	GetVolumeInfoFunc    func(device string) (*luks2.VolumeInfo, error)
	WipeFunc             func(opts luks2.WipeOptions) error
	SetupLoopDeviceFunc  func(filename string) (string, error)
	DetachLoopDeviceFunc func(loopDev string) error
	MakeFilesystemFunc   func(volumeName, fstype, label string) error
	IsMountedFunc        func(mountPoint string) (bool, error)
	IsUnlockedFunc       func(name string) bool
}

func (m *MockLuksOperations) Format(opts luks2.FormatOptions) error {
	if m.FormatFunc != nil {
		return m.FormatFunc(opts)
	}
	return nil
}

func (m *MockLuksOperations) Unlock(device string, passphrase []byte, name string) error {
	if m.UnlockFunc != nil {
		return m.UnlockFunc(device, passphrase, name)
	}
	return nil
}

func (m *MockLuksOperations) Lock(name string) error {
	if m.LockFunc != nil {
		return m.LockFunc(name)
	}
	return nil
}

func (m *MockLuksOperations) Mount(opts luks2.MountOptions) error {
	if m.MountFunc != nil {
		return m.MountFunc(opts)
	}
	return nil
}

func (m *MockLuksOperations) Unmount(mountPoint string, flags int) error {
	if m.UnmountFunc != nil {
		return m.UnmountFunc(mountPoint, flags)
	}
	return nil
}

func (m *MockLuksOperations) GetVolumeInfo(device string) (*luks2.VolumeInfo, error) {
	if m.GetVolumeInfoFunc != nil {
		return m.GetVolumeInfoFunc(device)
	}
	return &luks2.VolumeInfo{
		UUID:           "test-uuid",
		Label:          "TestVolume",
		Version:        2,
		Cipher:         "aes-xts-plain64",
		SectorSize:     512,
		ActiveKeyslots: []int{0},
		Metadata: &luks2.LUKS2Metadata{
			Keyslots: map[string]*luks2.Keyslot{
				"0": {
					Type:    "luks2",
					KeySize: 64,
					KDF:     &luks2.KDF{Type: "argon2id"},
				},
			},
		},
	}, nil
}

func (m *MockLuksOperations) Wipe(opts luks2.WipeOptions) error {
	if m.WipeFunc != nil {
		return m.WipeFunc(opts)
	}
	return nil
}

func (m *MockLuksOperations) SetupLoopDevice(filename string) (string, error) {
	if m.SetupLoopDeviceFunc != nil {
		return m.SetupLoopDeviceFunc(filename)
	}
	return "/dev/loop0", nil
}

func (m *MockLuksOperations) DetachLoopDevice(loopDev string) error {
	if m.DetachLoopDeviceFunc != nil {
		return m.DetachLoopDeviceFunc(loopDev)
	}
	return nil
}

func (m *MockLuksOperations) MakeFilesystem(volumeName, fstype, label string) error {
	if m.MakeFilesystemFunc != nil {
		return m.MakeFilesystemFunc(volumeName, fstype, label)
	}
	return nil
}

func (m *MockLuksOperations) IsMounted(mountPoint string) (bool, error) {
	if m.IsMountedFunc != nil {
		return m.IsMountedFunc(mountPoint)
	}
	return false, nil
}

func (m *MockLuksOperations) IsUnlocked(name string) bool {
	if m.IsUnlockedFunc != nil {
		return m.IsUnlockedFunc(name)
	}
	return false
}

// MockTerminal implements Terminal for testing
type MockTerminal struct {
	Password []byte
	Err      error

	// Reads counts ReadPassword calls, so a test can tell a confirmation
	// prompt from a single one.
	Reads int

	// Handed retains every slice ReadPassword returned, so a test can assert
	// on what the caller did with buffers it no longer has a name for.
	Handed [][]byte
}

// ReadPassword returns a fresh COPY of the configured password on every call.
//
// Returning m.Password itself made two reads alias one slice, which no real
// terminal does -- golang.org/x/term allocates per call -- and which hides
// exactly the class of bug this mock is used to look for: a caller that wipes
// one buffer would appear to wipe the other too.
func (m *MockTerminal) ReadPassword(fd int) ([]byte, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	m.Reads++
	out := append([]byte(nil), m.Password...)
	m.Handed = append(m.Handed, out)
	return out, nil
}

// MockFileSystem implements FileSystem for testing
type MockFileSystem struct {
	Files       map[string]bool
	CreateErr   error
	StatErr     error
	RemoveErr   error
	MkdirAllErr error
	CreatedFile *MockFile
}

type MockFile struct {
	*os.File
	truncateErr error
	closed      bool
}

func (m *MockFile) Truncate(size int64) error {
	return m.truncateErr
}

func (m *MockFile) Close() error {
	m.closed = true
	return nil
}

func (m *MockFileSystem) Create(name string) (*os.File, error) {
	if m.CreateErr != nil {
		return nil, m.CreateErr
	}
	// Create a real temp file for testing
	f, err := os.CreateTemp("", "luks-test-*")
	if err != nil {
		return nil, err
	}
	m.Files[name] = true
	return f, nil
}

func (m *MockFileSystem) Stat(name string) (os.FileInfo, error) {
	if m.StatErr != nil {
		return nil, m.StatErr
	}
	if m.Files != nil && m.Files[name] {
		return nil, nil
	}
	return nil, os.ErrNotExist
}

func (m *MockFileSystem) Remove(name string) error {
	if m.RemoveErr != nil {
		return m.RemoveErr
	}
	delete(m.Files, name)
	return nil
}

func (m *MockFileSystem) MkdirAll(path string, perm os.FileMode) error {
	if m.MkdirAllErr != nil {
		return m.MkdirAllErr
	}
	m.Files[path] = true
	return nil
}

// newTestCLI creates a CLI with mock dependencies
func newTestCLI(args []string) (*CLI, *bytes.Buffer, *bytes.Buffer) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	stdin := strings.NewReader("")

	cli := &CLI{
		Args:       args,
		Stdin:      stdin,
		Stdout:     stdout,
		Stderr:     stderr,
		Luks:       &MockLuksOperations{},
		Terminal:   &MockTerminal{Password: []byte("testpassword")},
		FS:         &MockFileSystem{Files: make(map[string]bool)},
		ExitFunc:   func(code int) {},
		getStdinFd: func() int { return 0 },
	}

	return cli, stdout, stderr
}

func TestCLI_NoArgs(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2"})

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stdout.String(), "USAGE:") {
		t.Error("Expected usage message in output")
	}
}

func TestCLI_Help(t *testing.T) {
	tests := []string{"help", "--help", "-h"}

	for _, arg := range tests {
		t.Run(arg, func(t *testing.T) {
			cli, stdout, _ := newTestCLI([]string{"luks2", arg})

			code := cli.Run()

			if code != 0 {
				t.Errorf("Expected exit code 0, got %d", code)
			}

			if !strings.Contains(stdout.String(), "USAGE:") {
				t.Error("Expected usage message in output")
			}
		})
	}
}

func TestCLI_Version(t *testing.T) {
	tests := []string{"version", "--version", "-v"}

	for _, arg := range tests {
		t.Run(arg, func(t *testing.T) {
			cli, stdout, _ := newTestCLI([]string{"luks2", arg})

			code := cli.Run()

			if code != 0 {
				t.Errorf("Expected exit code 0, got %d", code)
			}

			if !strings.Contains(stdout.String(), "luks2 version") {
				t.Error("Expected version in output")
			}
		})
	}
}

func TestCLI_UnknownCommand(t *testing.T) {
	cli, stdout, stderr := newTestCLI([]string{"luks2", "unknown"})

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stderr.String(), "Unknown command") {
		t.Error("Expected unknown command error")
	}

	if !strings.Contains(stdout.String(), "USAGE:") {
		t.Error("Expected usage message in output")
	}
}

func TestCLI_Create_NoArgs(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "create"})

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stdout.String(), "Usage: luks2 create") {
		t.Error("Expected create usage message")
	}
}

func TestCLI_Create_FileNoSize(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "create", "test.luks"})

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stdout.String(), "Size required") {
		t.Error("Expected size required message")
	}
}

func TestCLI_Create_FileAlreadyExists(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "create", "test.luks", "100M"})
	cli.FS = &MockFileSystem{Files: map[string]bool{"test.luks": true}}

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stderr.String(), "File already exists") {
		t.Error("Expected file exists error")
	}
}

func TestCLI_Open_NoArgs(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "open"})

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stdout.String(), "Usage: luks2 open") {
		t.Error("Expected open usage message")
	}
}

func TestCLI_Open_MissingName(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "open", "/dev/sda1"})

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stdout.String(), "Usage: luks2 open") {
		t.Error("Expected open usage message")
	}
}

func TestCLI_Open_Success(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "open", "/dev/sda1", "myvolume"})

	code := cli.Run()

	if code != 0 {
		t.Errorf("Expected exit code 0, got %d", code)
	}

	if !strings.Contains(stdout.String(), "Volume unlocked successfully") {
		t.Error("Expected success message")
	}
}

func TestCLI_Open_Failure(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "open", "/dev/sda1", "myvolume"})
	cli.Luks = &MockLuksOperations{
		UnlockFunc: func(device string, passphrase []byte, name string) error {
			return errors.New("unlock failed")
		},
	}

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stderr.String(), "Failed to unlock") {
		t.Error("Expected failure message")
	}
}

func TestCLI_Close_NoArgs(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "close"})

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stdout.String(), "Usage: luks2 close") {
		t.Error("Expected close usage message")
	}
}

func TestCLI_Close_Success(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "close", "myvolume"})

	code := cli.Run()

	if code != 0 {
		t.Errorf("Expected exit code 0, got %d", code)
	}

	if !strings.Contains(stdout.String(), "Volume locked successfully") {
		t.Error("Expected success message")
	}
}

func TestCLI_Close_StillMounted(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "close", "myvolume"})
	cli.Luks = &MockLuksOperations{
		IsMountedFunc: func(mountPoint string) (bool, error) {
			return true, nil
		},
	}

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stderr.String(), "still mounted") {
		t.Error("Expected still mounted error")
	}
}

func TestCLI_Close_Failure(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "close", "myvolume"})
	cli.Luks = &MockLuksOperations{
		LockFunc: func(name string) error {
			return errors.New("lock failed")
		},
	}

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stderr.String(), "Failed to lock") {
		t.Error("Expected failure message")
	}
}

func TestCLI_Mount_NoArgs(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "mount"})

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stdout.String(), "Usage: luks2 mount") {
		t.Error("Expected mount usage message")
	}
}

func TestCLI_Mount_MissingMountpoint(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "mount", "myvolume"})

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stdout.String(), "Usage: luks2 mount") {
		t.Error("Expected mount usage message")
	}
}

func TestCLI_Mount_AlreadyMounted(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "mount", "myvolume", "/mnt/test"})
	cli.Luks = &MockLuksOperations{
		IsMountedFunc: func(mountPoint string) (bool, error) {
			return true, nil
		},
	}

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stderr.String(), "already in use") {
		t.Error("Expected already mounted error")
	}
}

func TestCLI_Mount_Success(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "mount", "myvolume", "/mnt/test"})
	cli.FS = &MockFileSystem{Files: map[string]bool{"/mnt/test": true}}

	code := cli.Run()

	if code != 0 {
		t.Errorf("Expected exit code 0, got %d", code)
	}

	if !strings.Contains(stdout.String(), "Volume mounted successfully") {
		t.Error("Expected success message")
	}
}

func TestCLI_Unmount_NoArgs(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "unmount"})

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stdout.String(), "Usage: luks2 unmount") {
		t.Error("Expected unmount usage message")
	}
}

func TestCLI_Unmount_NotMounted(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "unmount", "/mnt/test"})

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stderr.String(), "Not mounted") {
		t.Error("Expected not mounted error")
	}
}

func TestCLI_Unmount_Success(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "unmount", "/mnt/test"})
	cli.Luks = &MockLuksOperations{
		IsMountedFunc: func(mountPoint string) (bool, error) {
			return true, nil
		},
	}

	code := cli.Run()

	if code != 0 {
		t.Errorf("Expected exit code 0, got %d", code)
	}

	if !strings.Contains(stdout.String(), "Volume unmounted successfully") {
		t.Error("Expected success message")
	}
}

func TestCLI_Info_NoArgs(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "info"})

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stdout.String(), "Usage: luks2 info") {
		t.Error("Expected info usage message")
	}
}

func TestCLI_Info_Success(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "info", "/dev/sda1"})

	code := cli.Run()

	if code != 0 {
		t.Errorf("Expected exit code 0, got %d", code)
	}

	output := stdout.String()
	if !strings.Contains(output, "UUID:") {
		t.Error("Expected UUID in output")
	}
	if !strings.Contains(output, "test-uuid") {
		t.Error("Expected test-uuid in output")
	}
}

func TestCLI_Info_Failure(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "info", "/dev/sda1"})
	cli.Luks = &MockLuksOperations{
		GetVolumeInfoFunc: func(device string) (*luks2.VolumeInfo, error) {
			return nil, errors.New("read failed")
		},
	}

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stderr.String(), "Failed to read volume") {
		t.Error("Expected failure message")
	}
}

func TestCLI_Wipe_NoArgs(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "wipe"})

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stdout.String(), "Usage: luks2 wipe") {
		t.Error("Expected wipe usage message")
	}
}

func TestCLI_Wipe_Canceled(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "wipe", "/dev/sda1"})
	cli.Stdin = strings.NewReader("NO\n")

	code := cli.Run()

	if code != 0 {
		t.Errorf("Expected exit code 0, got %d", code)
	}

	if !strings.Contains(stdout.String(), "Wipe canceled") {
		t.Error("Expected canceled message")
	}
}

func TestCLI_Wipe_Success(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "wipe", "/dev/sda1"})
	cli.Stdin = strings.NewReader("YES\n")

	code := cli.Run()

	if code != 0 {
		t.Errorf("Expected exit code 0, got %d", code)
	}

	if !strings.Contains(stdout.String(), "Volume wiped successfully") {
		t.Error("Expected success message")
	}
}

func TestCLI_Wipe_Failure(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "wipe", "/dev/sda1"})
	cli.Stdin = strings.NewReader("YES\n")
	cli.Luks = &MockLuksOperations{
		WipeFunc: func(opts luks2.WipeOptions) error {
			return errors.New("wipe failed")
		},
	}

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stderr.String(), "Failed to wipe") {
		t.Error("Expected failure message")
	}
}

func TestCLI_Wipe_FullDevice(t *testing.T) {
	var capturedOpts luks2.WipeOptions
	cli, stdout, _ := newTestCLI([]string{"luks2", "wipe", "--full", "/dev/sda1"})
	cli.Stdin = strings.NewReader("YES\n")
	cli.Luks = &MockLuksOperations{
		WipeFunc: func(opts luks2.WipeOptions) error {
			capturedOpts = opts
			return nil
		},
	}

	code := cli.Run()

	if code != 0 {
		t.Errorf("Expected exit code 0, got %d", code)
	}

	if capturedOpts.HeaderOnly {
		t.Error("Expected HeaderOnly to be false for --full")
	}

	if !strings.Contains(stdout.String(), "Full device wipe") {
		t.Error("Expected 'Full device wipe' in output")
	}
}

func TestCLI_Wipe_WithPasses(t *testing.T) {
	var capturedOpts luks2.WipeOptions
	cli, stdout, _ := newTestCLI([]string{"luks2", "wipe", "--full", "--passes", "3", "/dev/sda1"})
	cli.Stdin = strings.NewReader("YES\n")
	cli.Luks = &MockLuksOperations{
		WipeFunc: func(opts luks2.WipeOptions) error {
			capturedOpts = opts
			return nil
		},
	}

	code := cli.Run()

	if code != 0 {
		t.Errorf("Expected exit code 0, got %d", code)
	}

	if capturedOpts.Passes != 3 {
		t.Errorf("Expected 3 passes, got %d", capturedOpts.Passes)
	}

	if !strings.Contains(stdout.String(), "3 passes") {
		t.Error("Expected '3 passes' in output")
	}
}

func TestCLI_Wipe_WithRandom(t *testing.T) {
	var capturedOpts luks2.WipeOptions
	cli, stdout, _ := newTestCLI([]string{"luks2", "wipe", "--full", "--random", "/dev/sda1"})
	cli.Stdin = strings.NewReader("YES\n")
	cli.Luks = &MockLuksOperations{
		WipeFunc: func(opts luks2.WipeOptions) error {
			capturedOpts = opts
			return nil
		},
	}

	code := cli.Run()

	if code != 0 {
		t.Errorf("Expected exit code 0, got %d", code)
	}

	if !capturedOpts.Random {
		t.Error("Expected Random to be true")
	}

	if !strings.Contains(stdout.String(), "Data: Random") {
		t.Error("Expected 'Data: Random' in output")
	}
}

func TestCLI_Wipe_WithTrim(t *testing.T) {
	var capturedOpts luks2.WipeOptions
	cli, stdout, _ := newTestCLI([]string{"luks2", "wipe", "--full", "--trim", "/dev/sda1"})
	cli.Stdin = strings.NewReader("YES\n")
	cli.Luks = &MockLuksOperations{
		WipeFunc: func(opts luks2.WipeOptions) error {
			capturedOpts = opts
			return nil
		},
	}

	code := cli.Run()

	if code != 0 {
		t.Errorf("Expected exit code 0, got %d", code)
	}

	if !capturedOpts.Trim {
		t.Error("Expected Trim to be true")
	}

	if !strings.Contains(stdout.String(), "TRIM: Enabled") {
		t.Error("Expected 'TRIM: Enabled' in output")
	}
}

func TestCLI_Wipe_AllOptions(t *testing.T) {
	var capturedOpts luks2.WipeOptions
	cli, _, _ := newTestCLI([]string{"luks2", "wipe", "--full", "--passes", "5", "--random", "--trim", "/dev/sda1"})
	cli.Stdin = strings.NewReader("YES\n")
	cli.Luks = &MockLuksOperations{
		WipeFunc: func(opts luks2.WipeOptions) error {
			capturedOpts = opts
			return nil
		},
	}

	code := cli.Run()

	if code != 0 {
		t.Errorf("Expected exit code 0, got %d", code)
	}

	if capturedOpts.HeaderOnly {
		t.Error("Expected HeaderOnly to be false")
	}
	if capturedOpts.Passes != 5 {
		t.Errorf("Expected 5 passes, got %d", capturedOpts.Passes)
	}
	if !capturedOpts.Random {
		t.Error("Expected Random to be true")
	}
	if !capturedOpts.Trim {
		t.Error("Expected Trim to be true")
	}
	if capturedOpts.Device != "/dev/sda1" {
		t.Errorf("Expected device /dev/sda1, got %s", capturedOpts.Device)
	}
}

func TestCLI_Wipe_InvalidPasses(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "wipe", "--passes", "invalid", "/dev/sda1"})

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stderr.String(), "Invalid passes value") {
		t.Error("Expected 'Invalid passes value' error")
	}
}

func TestCLI_Wipe_MissingPassesValue(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "wipe", "--passes"})

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stderr.String(), "--passes requires a value") {
		t.Error("Expected '--passes requires a value' error")
	}
}

func TestCLI_Wipe_UnknownOption(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "wipe", "--unknown", "/dev/sda1"})

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stderr.String(), "Unknown option") {
		t.Error("Expected 'Unknown option' error")
	}
}

func TestCLI_Wipe_MissingDevice(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "wipe", "--full"})

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stderr.String(), "device path required") {
		t.Error("Expected 'device path required' error")
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
		hasError bool
	}{
		{"100", 100, false},
		{"100K", 100 * 1024, false},
		{"100k", 100 * 1024, false},
		{"100M", 100 * 1024 * 1024, false},
		{"100m", 100 * 1024 * 1024, false},
		{"1G", 1024 * 1024 * 1024, false},
		{"1g", 1024 * 1024 * 1024, false},
		{"1T", 1024 * 1024 * 1024 * 1024, false},
		{"1t", 1024 * 1024 * 1024 * 1024, false},
		{"", 0, true},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseSize(tt.input)
			if tt.hasError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("Expected %d, got %d", tt.expected, result)
				}
			}
		})
	}
}

func TestClearBytes(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	ClearBytes(data)

	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d is not zero: %d", i, b)
		}
	}
}

func TestCLI_PasswordReadError(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "open", "/dev/sda1", "myvolume"})
	cli.Terminal = &MockTerminal{Err: errors.New("read error")}

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stderr.String(), "failed to read passphrase") {
		t.Error("Expected password read error")
	}
}

func TestCLI_CreateBlockDevice_Success(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "create", "/dev/sda1"})
	cli.Stdin = strings.NewReader("\n") // empty label

	code := cli.Run()

	if code != 0 {
		t.Errorf("Expected exit code 0, got %d", code)
	}

	if !strings.Contains(stdout.String(), "LUKS2 volume created successfully") {
		t.Error("Expected success message")
	}
}

func TestCLI_CreateBlockDevice_Failure(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "create", "/dev/sda1"})
	cli.Stdin = strings.NewReader("\n")
	cli.Luks = &MockLuksOperations{
		FormatFunc: func(opts luks2.FormatOptions) error {
			return errors.New("format failed")
		},
	}

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stderr.String(), "Failed to create volume") {
		t.Error("Expected failure message")
	}
}

func TestCLI_Mount_CreateMountpoint(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "mount", "myvolume", "/mnt/newdir"})
	// Mountpoint doesn't exist, should be created

	code := cli.Run()

	if code != 0 {
		t.Errorf("Expected exit code 0, got %d", code)
	}

	if !strings.Contains(stdout.String(), "Creating mountpoint") {
		t.Error("Expected creating mountpoint message")
	}
}

func TestCLI_Mount_Failure(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "mount", "myvolume", "/mnt/test"})
	cli.FS = &MockFileSystem{Files: map[string]bool{"/mnt/test": true}}
	cli.Luks = &MockLuksOperations{
		MountFunc: func(opts luks2.MountOptions) error {
			return errors.New("mount failed")
		},
	}

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stderr.String(), "Failed to mount") {
		t.Error("Expected failure message")
	}
}

func TestCLI_Unmount_Failure(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "unmount", "/mnt/test"})
	cli.Luks = &MockLuksOperations{
		IsMountedFunc: func(mountPoint string) (bool, error) {
			return true, nil
		},
		UnmountFunc: func(mountPoint string, flags int) error {
			return errors.New("unmount failed")
		},
	}

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stderr.String(), "Failed to unmount") {
		t.Error("Expected failure message")
	}
}

// TestPromptPassphraseClearsTheConfirmationBuffer is a custody test on the CLI's
// only secret-reading path.
//
// A confirmation prompt reads the passphrase TWICE, so it produces a second
// full copy of the credential. That copy used to be left on the heap for the
// collector while the first was carefully wiped, which made the wiping of the
// first close to pointless: both buffers hold the same secret.
func TestPromptPassphraseClearsTheConfirmationBuffer(t *testing.T) {
	term := &MockTerminal{Password: []byte("a-passphrase-worth-protecting")}
	cli := &CLI{
		Stdout:   &bytes.Buffer{},
		Stderr:   &bytes.Buffer{},
		Terminal: term,
	}

	passphrase, err := cli.promptPassphrase("Enter passphrase: ", true)
	if err != nil {
		t.Fatalf("promptPassphrase failed: %v", err)
	}
	defer ClearBytes(passphrase)

	if term.Reads != 2 {
		t.Fatalf("a confirming prompt read the terminal %d times, want 2", term.Reads)
	}
	if len(term.Handed) != 2 {
		t.Fatalf("the terminal handed out %d buffers, want 2", len(term.Handed))
	}

	// The first buffer is the returned passphrase and is the caller's to clear.
	if !bytes.Equal(passphrase, []byte("a-passphrase-worth-protecting")) {
		t.Fatal("promptPassphrase did not return the passphrase that was typed")
	}

	// The second is the confirmation, which the caller never sees and therefore
	// cannot clear itself.
	confirmation := term.Handed[1]
	if !bytes.Equal(confirmation, make([]byte, len(confirmation))) {
		t.Fatalf("the confirmation buffer was left readable: %q", confirmation)
	}
}

// TestPromptPassphraseClearsTheConfirmationWhenItDoesNotMatch covers the error
// path, where it is just as easy to leave the copy behind and where nothing
// downstream will ever clear it.
func TestPromptPassphraseClearsTheConfirmationWhenItDoesNotMatch(t *testing.T) {
	term := &mismatchingTerminal{first: []byte("one passphrase"), second: []byte("a different one")}
	cli := &CLI{
		Stdout:   &bytes.Buffer{},
		Stderr:   &bytes.Buffer{},
		Terminal: term,
	}

	if _, err := cli.promptPassphrase("Enter passphrase: ", true); err == nil {
		t.Fatal("promptPassphrase accepted two different passphrases")
	}

	if len(term.handed) != 2 {
		t.Fatalf("the terminal handed out %d buffers, want 2", len(term.handed))
	}
	confirmation := term.handed[1]
	if !bytes.Equal(confirmation, make([]byte, len(confirmation))) {
		t.Fatalf("the confirmation buffer was left readable after a mismatch: %q", confirmation)
	}
}

// mismatchingTerminal hands back a different value on the second read, which is
// what a user who mistypes the confirmation produces.
type mismatchingTerminal struct {
	first  []byte
	second []byte
	calls  int
	handed [][]byte
}

func (m *mismatchingTerminal) ReadPassword(fd int) ([]byte, error) {
	src := m.first
	if m.calls > 0 {
		src = m.second
	}
	m.calls++

	out := append([]byte(nil), src...)
	m.handed = append(m.handed, out)
	return out, nil
}

// TestCLI_Info_WarnsAboutDroppedNullEntries is the application half of #27.
//
// The library reports the entries it removed rather than logging them, because
// a Layer-0 primitive taking a logging dependency imposes a logging decision on
// every embedding application. That is only a capability if something exercises
// it; an offer nobody takes up is indistinguishable from the silence it
// replaced. `luks2 info` is that something.
func TestCLI_Info_WarnsAboutDroppedNullEntries(t *testing.T) {
	cli, stdout, stderr := newTestCLI([]string{"luks2", "info", "/dev/sda1"})
	cli.Luks = &MockLuksOperations{
		GetVolumeInfoFunc: func(device string) (*luks2.VolumeInfo, error) {
			return &luks2.VolumeInfo{
				UUID:           "test-uuid",
				Version:        2,
				ActiveKeyslots: []int{1},
				Metadata: &luks2.LUKS2Metadata{
					Keyslots: map[string]*luks2.Keyslot{},
					DroppedNullEntries: []luks2.DroppedEntry{
						{Kind: luks2.DroppedKindKeyslot, ID: "0"},
						{Kind: luks2.DroppedKindToken, ID: "3"},
					},
				},
			}, nil
		},
	}

	if code := cli.Run(); code != 0 {
		t.Fatalf("Expected exit code 0, got %d", code)
	}

	warning := stderr.String()
	// Both ids AND both kinds: a warning that names "0" and "3" without saying
	// which id space each came from tells an operator nothing actionable.
	for _, want := range []string{`keyslot "0"`, `token "3"`, "2 entries", "luksHeaderBackup"} {
		if !strings.Contains(warning, want) {
			t.Errorf("stderr = %q, want it to contain %q", warning, want)
		}
	}

	// The volume report is what people pipe; a damage warning does not belong
	// in the middle of it.
	if strings.Contains(stdout.String(), "WARNING") {
		t.Errorf("the warning went to stdout, which is the report stream: %q", stdout.String())
	}
}

// TestCLI_Info_DoesNotWarnForAnIntactHeader is the control. A warning that
// fires on healthy containers is one an operator learns to ignore.
func TestCLI_Info_DoesNotWarnForAnIntactHeader(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "info", "/dev/sda1"})
	cli.Luks = &MockLuksOperations{
		GetVolumeInfoFunc: func(device string) (*luks2.VolumeInfo, error) {
			return &luks2.VolumeInfo{
				UUID:     "test-uuid",
				Version:  2,
				Metadata: &luks2.LUKS2Metadata{Keyslots: map[string]*luks2.Keyslot{}},
			}, nil
		},
	}

	if code := cli.Run(); code != 0 {
		t.Fatalf("Expected exit code 0, got %d", code)
	}
	if stderr.String() != "" {
		t.Errorf("stderr = %q for an intact header, want nothing", stderr.String())
	}
}
