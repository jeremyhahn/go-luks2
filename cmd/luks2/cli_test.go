// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// MockTerminal implements Terminal for testing
type MockTerminal struct {
	Password []byte
	Err      error

	// NotATerminal makes IsTerminal report false, which is how a test says
	// "this is a script, not a person".
	//
	// The default is the other way round -- a MockTerminal IS a terminal -- so
	// that every test written before non-interactive input existed keeps
	// exercising the prompt path it was written for. Defaulting to "not a
	// terminal" would have silently rerouted all of them through the pipe
	// reader, which reads from a Stdin those tests leave empty, and they would
	// have gone on passing while testing nothing they name.
	NotATerminal bool

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

// IsTerminal reports whether the configured stdin is a terminal.
func (m *MockTerminal) IsTerminal(fd int) bool {
	return !m.NotATerminal
}

// MockFileSystem implements FileSystem for testing
type MockFileSystem struct {
	Files       map[string]bool
	CreateErr   error
	StatErr     error
	RemoveErr   error
	MkdirAllErr error
	CreatedFile *MockFile
	OpenErr     error
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

// CreateExclusive refuses a name the mock already holds, as O_EXCL would, and
// otherwise hands back a real temp file.
func (m *MockFileSystem) CreateExclusive(name string) (*os.File, error) {
	if m.Files[name] {
		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrExist}
	}
	return m.Create(name)
}

// RemoveCreated removes name from the mock.
func (m *MockFileSystem) RemoveCreated(name string, _ *os.File) error {
	return m.Remove(name)
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

// Open opens a REAL file, so the key-file tests read the bytes an operator
// would have written rather than a fixture this mock invented. Their paths are
// under t.TempDir(); nothing here reaches the host.
func (m *MockFileSystem) Open(name string) (*os.File, error) {
	if m.OpenErr != nil {
		return nil, m.OpenErr
	}
	return os.Open(name) // #nosec G304 -- test paths are under t.TempDir()
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

// MockDeviceProber answers create's questions about a path without a device:
// a /dev path is a block device, anything else is absent unless Kinds says
// otherwise, and no block device holds a signature unless Found says so.
type MockDeviceProber struct {
	Kinds    map[string]pathKind
	KindErr  error
	Found    string
	FoundErr error
	Probed   []string
	Held     bool
	Released int
}

func (m *MockDeviceProber) Kind(path string) (pathKind, error) {
	if m.KindErr != nil {
		return pathOther, m.KindErr
	}
	if k, ok := m.Kinds[path]; ok {
		return k, nil
	}
	if strings.HasPrefix(path, "/dev/") {
		return pathBlockDevice, nil
	}
	return pathAbsent, nil
}

func (m *MockDeviceProber) Claim(path string) (string, func(), error) {
	m.Probed = append(m.Probed, path)
	if m.FoundErr != nil {
		return "", nil, m.FoundErr
	}
	m.Held = true
	return m.Found, func() { m.Held = false; m.Released++ }, nil
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
		Devices:    &MockDeviceProber{},
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

// TestCLI_Create_FilesystemTypesHelp checks that both create usage messages
// list exactly the filesystems create can build: not ext2 or ext3, which the
// library refuses (#195), and not zfs, which needs a pool name create does not
// take.
func TestCLI_Create_FilesystemTypesHelp(t *testing.T) {
	want := "Filesystem types: ext4, xfs, vfat (default: ext4)"

	for _, args := range [][]string{
		{"luks2", "create"},
		{"luks2", "create", "test.luks"},
	} {
		cli, stdout, _ := newTestCLI(args)
		if code := cli.Run(); code != 1 {
			t.Errorf("%v: expected exit code 1, got %d", args, code)
		}
		out := stdout.String()
		if !strings.Contains(out, want) {
			t.Errorf("%v: usage does not contain %q:\n%s", args, want, out)
		}
		if strings.Contains(out, "ext2") || strings.Contains(out, "ext3") {
			t.Errorf("%v: usage offers an unsupported ext2/ext3:\n%s", args, out)
		}
		if strings.Contains(out, "zfs") {
			t.Errorf("%v: usage offers zfs, which create cannot build:\n%s", args, out)
		}
	}
}

// TestCLI_Create_RejectsUnsupportedFilesystem checks that create refuses a
// filesystem it cannot build -- ext2/ext3, which the library refuses (#195),
// zfs, which needs a pool name, and an unknown type -- with a nonzero exit and
// before the file is created, formatted, attached or unlocked. Refusing only
// at the MakeFilesystem step would leave an unlocked, unformatted volume.
func TestCLI_Create_RejectsUnsupportedFilesystem(t *testing.T) {
	for _, fstype := range []string{"ext2", "ext3", "zfs", "btrfs"} {
		t.Run(fstype, func(t *testing.T) {
			cli, _, stderr := newTestCLI([]string{"luks2", "create", "test.luks", "10M", fstype})
			fs := &MockFileSystem{Files: make(map[string]bool)}
			cli.FS = fs
			touched := false
			cli.Luks = &MockLuksOperations{
				FormatFunc:          func(luks2.FormatOptions) error { touched = true; return nil },
				SetupLoopDeviceFunc: func(string) (string, error) { touched = true; return "/dev/loop0", nil },
				UnlockFunc:          func(string, []byte, string) error { touched = true; return nil },
				MakeFilesystemFunc:  func(string, string, string) error { touched = true; return nil },
			}

			if code := cli.Run(); code != 1 {
				t.Fatalf("create ... %s exited %d, want 1", fstype, code)
			}
			if fs.Files["test.luks"] {
				t.Errorf("create ... %s created the file before refusing", fstype)
			}
			if touched {
				t.Errorf("create ... %s formatted, attached, unlocked or formatted a filesystem before refusing", fstype)
			}
			if !strings.Contains(stderr.String(), "Unsupported filesystem: "+fstype) {
				t.Errorf("stderr = %q, want it to name the unsupported filesystem", stderr.String())
			}
		})
	}
}

// TestCLI_CliFilesystems_SubsetOfLibrary checks that every type create offers
// is one the library supports, and that every exclusion names a supported
// type (a stale exclusion would hide nothing and mislead the reader).
func TestCLI_CliFilesystems_SubsetOfLibrary(t *testing.T) {
	for _, fs := range cliFilesystems() {
		if !luks2.IsFilesystemSupported(fs) {
			t.Errorf("create offers %q, which the library does not support", fs)
		}
	}
	for fs := range cliExcludedFilesystems {
		if !luks2.IsFilesystemSupported(fs) {
			t.Errorf("exclusion %q is not a library-supported filesystem", fs)
		}
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
	abs, err := filepath.Abs("test.luks")
	if err != nil {
		t.Fatal(err)
	}
	cli.FS = &MockFileSystem{Files: map[string]bool{abs: true}}

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
		IsMappingMountedFunc: func(name string) (bool, error) {
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

// TestCLI_Close_AsksWhetherTheMappingIsMounted is the regression for #250
// (C10). close used to ask IsMounted whether "/dev/mapper/<name>" was a mount
// POINT, which it never is, so a mounted volume was closed out from under its
// filesystem. The mock reports exactly that state: no path named after the
// mapping is a mount point, and the mapping itself is mounted.
func TestCLI_Close_AsksWhetherTheMappingIsMounted(t *testing.T) {
	defer parallel(t)()
	cli, _, stderr := newTestCLI([]string{"luks2", "close", "myvolume"})
	locked := false
	var asked string
	cli.Luks = &MockLuksOperations{
		IsMountedFunc: func(string) (bool, error) { return false, nil },
		IsMappingMountedFunc: func(name string) (bool, error) {
			asked = name
			return true, nil
		},
		LockFunc: func(string) error { locked = true; return nil },
	}

	if code := cli.Run(); code != 1 {
		t.Errorf("exit code = %d, want 1 for a mounted mapping", code)
	}
	if locked {
		t.Fatal("close LOCKED a mapping whose filesystem is mounted")
	}
	if asked != "myvolume" {
		t.Errorf("the mount check was asked about %q, want the mapping name %q", asked, "myvolume")
	}
	if !strings.Contains(stderr.String(), "still mounted") {
		t.Errorf("stderr = %q, want the still-mounted refusal", stderr.String())
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

// TestCLI_Wipe_Canceled: a wipe that was not confirmed exits NON-ZERO (#246
// D12), so a script checking the status does not read it as done.
func TestCLI_Wipe_Canceled(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "wipe", "/dev/sda1"})
	cli.Stdin = strings.NewReader("NO\n")

	code := cli.Run()

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	if !strings.Contains(stderr.String(), "Wipe canceled") {
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

	if !strings.Contains(stderr.String(), "unknown option --unknown") {
		t.Error("Expected 'unknown option' error")
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
	cli.Stdin = strings.NewReader("YES\n\n") // the confirmation, then an empty label

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
	cli.Stdin = strings.NewReader("YES\n\n")
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

func (m *mismatchingTerminal) IsTerminal(fd int) bool { return true }

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

// The mount-state check must not treat "I could not find out" as "it is fine"
// (#185). IsMounted fails only when /proc/mounts cannot be read -- an absent
// mapper node is simply not listed and returns false with no error -- so an
// error means the state is UNKNOWN. Acting on the permissive guess is how a
// filesystem gets torn out from under its writers, or mounted over.
//
// Each asserts the ACTION WAS NOT TAKEN, not merely the exit code: a command
// that returns 1 after already locking the volume has still done the damage.

func TestCLI_Close_RefusesWhenMountStateIsUnknown(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "close", "myvolume"})
	locked := false
	cli.Luks = &MockLuksOperations{
		IsMappingMountedFunc: func(name string) (bool, error) {
			return false, errors.New("open /proc/mounts: permission denied")
		},
		LockFunc: func(name string) error {
			locked = true
			return nil
		},
	}

	code := cli.Run()

	if code != 1 {
		t.Errorf("exit code = %d, want 1: an unknown mount state must not be closed through", code)
	}
	if locked {
		t.Error("the volume was LOCKED while its mount state was unknown; this is the defect (#185)")
	}
	if !strings.Contains(stderr.String(), "Cannot determine whether") {
		t.Errorf("stderr = %q, want it to say the mount state could not be determined", stderr.String())
	}
	if !strings.Contains(stderr.String(), "permission denied") {
		t.Errorf("stderr = %q, want it to carry the underlying cause", stderr.String())
	}
}

func TestCLI_Mount_RefusesWhenMountStateIsUnknown(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "mount", "myvolume", "/mnt/x"})
	mounted := false
	cli.Luks = &MockLuksOperations{
		IsMountedFunc: func(mountPoint string) (bool, error) {
			return false, errors.New("open /proc/mounts: permission denied")
		},
		MountFunc: func(opts luks2.MountOptions) error {
			mounted = true
			return nil
		},
	}

	code := cli.Run()

	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if mounted {
		t.Error("MOUNTED over a mountpoint whose state was unknown; that hides whatever was already there")
	}
	if !strings.Contains(stderr.String(), "Cannot determine whether") {
		t.Errorf("stderr = %q, want the unknown-state diagnosis", stderr.String())
	}
}

// Unmount refuses either way, so this is about the DIAGNOSIS: "Not mounted"
// sent an operator looking in the wrong place for a /proc/mounts failure.
func TestCLI_Unmount_ReportsTheRealCauseNotNotMounted(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "unmount", "/mnt/x"})
	cli.Luks = &MockLuksOperations{
		IsMountedFunc: func(mountPoint string) (bool, error) {
			return false, errors.New("open /proc/mounts: permission denied")
		},
	}

	code := cli.Run()

	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if strings.Contains(stderr.String(), "Not mounted") {
		t.Errorf("stderr = %q, want the real cause rather than a false \"Not mounted\"", stderr.String())
	}
	if !strings.Contains(stderr.String(), "permission denied") {
		t.Errorf("stderr = %q, want it to carry the underlying cause", stderr.String())
	}
}

// The controls: a mount state that IS known must still behave as before.
func TestCLI_MountStateKnownStillBehaves(t *testing.T) {
	t.Run("close refuses a mounted volume", func(t *testing.T) {
		cli, _, stderr := newTestCLI([]string{"luks2", "close", "myvolume"})
		locked := false
		cli.Luks = &MockLuksOperations{
			IsMappingMountedFunc: func(string) (bool, error) { return true, nil },
			LockFunc:             func(string) error { locked = true; return nil },
		}
		if code := cli.Run(); code != 1 {
			t.Errorf("exit code = %d, want 1", code)
		}
		if locked {
			t.Error("locked a volume reported as mounted")
		}
		if !strings.Contains(stderr.String(), "still mounted") {
			t.Errorf("stderr = %q, want the still-mounted refusal", stderr.String())
		}
	})

	t.Run("close proceeds when not mounted", func(t *testing.T) {
		cli, stdout, _ := newTestCLI([]string{"luks2", "close", "myvolume"})
		locked := false
		cli.Luks = &MockLuksOperations{
			IsMappingMountedFunc: func(string) (bool, error) { return false, nil },
			LockFunc:             func(string) error { locked = true; return nil },
		}
		if code := cli.Run(); code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
		if !locked {
			t.Error("did not lock a volume that was not mounted; the refusal is too broad")
		}
		_ = stdout
	})
}

// TestCLI_Mount_MountsTheDetectedFilesystem: with no --type, the volume is
// mounted as the filesystem found on it. It used to be mounted as ext4 always,
// so the xfs volume `create ... xfs` made could not be mounted at all.
func TestCLI_Mount_MountsTheDetectedFilesystem(t *testing.T) {
	cli, stdout, stderr := newTestCLI([]string{"luks2", "mount", "myvolume", "/mnt/test"})
	cli.FS = &MockFileSystem{Files: map[string]bool{"/mnt/test": true}}
	var mountedAs string
	cli.Luks = &MockLuksOperations{
		DetectFilesystemFunc: func(name string) (luks2.FilesystemType, error) {
			if name != "myvolume" {
				t.Errorf("detected the filesystem of %q, want myvolume", name)
			}
			return luks2.FilesystemXFS, nil
		},
		MountFunc: func(opts luks2.MountOptions) error {
			mountedAs = opts.FSType
			return nil
		},
	}

	if code := cli.Run(); code != 0 {
		t.Fatalf("exit code = %d, stderr %q", code, stderr.String())
	}
	if mountedAs != "xfs" {
		t.Fatalf("mounted as %q, want the detected xfs", mountedAs)
	}
	if !strings.Contains(stdout.String(), "Detected filesystem: xfs") {
		t.Errorf("stdout = %q, want it to say what was detected", stdout.String())
	}
}

// TestCLI_Mount_RefusesToGuess: when nothing can be detected, nothing is
// mounted and the operator is told to make a filesystem or name the type.
func TestCLI_Mount_RefusesToGuess(t *testing.T) {
	cli, _, stderr := newTestCLI([]string{"luks2", "mount", "myvolume", "/mnt/test"})
	cli.FS = &MockFileSystem{Files: map[string]bool{"/mnt/test": true}}
	mounted := false
	cli.Luks = &MockLuksOperations{
		DetectFilesystemFunc: func(string) (luks2.FilesystemType, error) {
			return "", luks2.ErrFilesystemNotDetected
		},
		MountFunc: func(luks2.MountOptions) error {
			mounted = true
			return nil
		},
	}

	if code := cli.Run(); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if mounted {
		t.Fatal("mounted a volume whose filesystem could not be determined")
	}
	if !strings.Contains(stderr.String(), "--type") || !strings.Contains(stderr.String(), luks2.ErrFilesystemNotDetected.Error()) {
		t.Errorf("stderr = %q, want the cause and a pointer to --type", stderr.String())
	}
}

// TestCLI_Mount_TypeOptionIsUsedAsGiven: --type and -t name the type, in any
// position, and nothing is detected.
func TestCLI_Mount_TypeOptionIsUsedAsGiven(t *testing.T) {
	for _, args := range [][]string{
		{"--type", "vfat", "myvolume", "/mnt/test"},
		{"myvolume", "/mnt/test", "-t", "vfat"},
		{"--type=vfat", "-t", "vfat", "myvolume", "/mnt/test"},
	} {
		cli, _, stderr := newTestCLI(append([]string{"luks2", "mount"}, args...))
		cli.FS = &MockFileSystem{Files: map[string]bool{"/mnt/test": true}}
		var mountedAs string
		cli.Luks = &MockLuksOperations{
			DetectFilesystemFunc: func(string) (luks2.FilesystemType, error) {
				t.Errorf("%q: detected a type the operator named", args)
				return luks2.FilesystemExt4, nil
			},
			MountFunc: func(opts luks2.MountOptions) error {
				mountedAs = opts.FSType
				return nil
			},
		}
		if code := cli.Run(); code != 0 || mountedAs != "vfat" {
			t.Errorf("%q: exit %d, mounted as %q, stderr %q; want vfat", args, code, mountedAs, stderr.String())
		}
	}
}

// TestCLI_Mount_RefusesAContradictoryOrEmptyType: two different types, or an
// empty one, are usage errors -- an empty --type must not quietly mean
// "detect".
func TestCLI_Mount_RefusesAContradictoryOrEmptyType(t *testing.T) {
	for _, args := range [][]string{
		{"--type", "xfs", "-t", "ext4", "myvolume", "/mnt/test"},
		{"--type=", "myvolume", "/mnt/test"},
		{"-t", "", "myvolume", "/mnt/test"},
	} {
		cli, _, stderr := newTestCLI(append([]string{"luks2", "mount"}, args...))
		cli.FS = &MockFileSystem{Files: map[string]bool{"/mnt/test": true}}
		cli.Luks = &MockLuksOperations{
			MountFunc: func(luks2.MountOptions) error {
				t.Errorf("%q: mounted", args)
				return nil
			},
		}
		if code := cli.Run(); code != 1 || !strings.Contains(stderr.String(), "mount") {
			t.Errorf("%q: exit %d, stderr %q; want a usage error", args, code, stderr.String())
		}
	}
}
