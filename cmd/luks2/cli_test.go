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
}

func (m *MockTerminal) ReadPassword(fd int) ([]byte, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	return m.Password, nil
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

func TestCLI_Wipe_Cancelled(t *testing.T) {
	cli, stdout, _ := newTestCLI([]string{"luks2", "wipe", "/dev/sda1"})
	cli.Stdin = strings.NewReader("NO\n")

	code := cli.Run()

	if code != 0 {
		t.Errorf("Expected exit code 0, got %d", code)
	}

	if !strings.Contains(stdout.String(), "Wipe cancelled") {
		t.Error("Expected cancelled message")
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
