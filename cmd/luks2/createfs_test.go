// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// createRecorder is a MockLuksOperations for the create command that records
// the order of the device-level calls, so the tests can assert that the
// mapping is closed before the loop device it holds is detached.
type createRecorder struct {
	calls []string
}

func (r *createRecorder) ops(mkfsErr, lockErr, detachErr error) *MockLuksOperations {
	return &MockLuksOperations{
		FormatFunc: func(luks2.FormatOptions) error { return nil },
		SetupLoopDeviceFunc: func(string) (string, error) {
			r.calls = append(r.calls, "attach")
			return "/dev/loop7", nil
		},
		UnlockFunc: func(device string, _ []byte, name string) error {
			r.calls = append(r.calls, "unlock "+device+" "+name)
			return nil
		},
		MakeFilesystemFunc: func(volumeName, fstype, _ string) error {
			r.calls = append(r.calls, "mkfs "+fstype+" "+volumeName)
			return mkfsErr
		},
		LockFunc: func(name string) error {
			r.calls = append(r.calls, "lock "+name)
			return lockErr
		},
		DetachLoopDeviceFunc: func(loopDev string) error {
			r.calls = append(r.calls, "detach "+loopDev)
			return detachErr
		},
	}
}

// newCreateCLI is `luks2 create --key-file <k> <dir>/vol.luks 32M ext4`,
// unattended, so no prompt reads stdin.
func newCreateCLI(t *testing.T) (cli *CLI, stdout, stderr interface{ String() string }, volume string) {
	t.Helper()
	dir := t.TempDir()
	keyFile := writeFile(t, dir, "key", "create-passphrase")
	volume = filepath.Join(dir, "vol.luks")
	c, out, errOut := newTestCLI([]string{"luks2", "create", "--key-file", keyFile, volume, "32M", "ext4"})
	c.Terminal = &MockTerminal{Err: errors.New("there is no terminal"), NotATerminal: true}
	c.FS = &MockFileSystem{Files: make(map[string]bool)}
	return c, out, errOut, volume
}

// TestCreateSucceedsWhenTheFilesystemIsCreated is the success path #229 must
// keep: exit 0, "Volume ready to use!", and the mapping left open for use.
func TestCreateSucceedsWhenTheFilesystemIsCreated(t *testing.T) {
	cli, stdout, stderr, _ := newCreateCLI(t)
	rec := &createRecorder{}
	cli.Luks = rec.ops(nil, nil, nil)

	if code := cli.Run(); code != 0 {
		t.Fatalf("create exited %d, want 0: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Volume ready to use!") {
		t.Errorf("stdout lacks the ready banner:\n%s", stdout.String())
	}
	want := []string{"attach", "unlock /dev/loop7 luks-auto", "mkfs ext4 luks-auto"}
	if !reflect.DeepEqual(rec.calls, want) {
		t.Errorf("calls = %v, want %v: a successful create must leave the volume open", rec.calls, want)
	}
}

// TestCreateFailsWhenFilesystemCreationFails is #229: a MakeFilesystem
// failure fails the command, prints the cause, closes the mapping and then
// detaches the loop device, says the container was kept, and does not claim
// the volume is ready.
func TestCreateFailsWhenFilesystemCreationFails(t *testing.T) {
	cause := errors.New("mkfs.ext4 failed: exit status 1")

	tests := []struct {
		name       string
		lockErr    error
		detachErr  error
		wantCalls  []string
		wantStderr []string
	}{
		{
			name: "mapping closed and loop device detached",
			wantCalls: []string{"attach", "unlock /dev/loop7 luks-auto", "mkfs ext4 luks-auto",
				"lock luks-auto", "detach /dev/loop7"},
			wantStderr: []string{
				"Error: Filesystem creation failed: " + cause.Error(),
				"Closed /dev/mapper/luks-auto",
				"Detached loop device /dev/loop7",
				"is valid and was kept",
			},
		},
		{
			name:    "mapping cannot be closed",
			lockErr: errors.New("device busy"),
			// No detach: the open mapping still holds the loop device.
			wantCalls: []string{"attach", "unlock /dev/loop7 luks-auto", "mkfs ext4 luks-auto",
				"lock luks-auto"},
			wantStderr: []string{
				"Error: Filesystem creation failed: " + cause.Error(),
				"Failed to close /dev/mapper/luks-auto: device busy",
				"still UNLOCKED",
				"sudo luks2 close luks-auto",
				"sudo losetup -d /dev/loop7",
			},
		},
		{
			name:      "loop device cannot be detached",
			detachErr: errors.New("resource busy"),
			wantCalls: []string{"attach", "unlock /dev/loop7 luks-auto", "mkfs ext4 luks-auto",
				"lock luks-auto", "detach /dev/loop7"},
			wantStderr: []string{
				"Error: Filesystem creation failed: " + cause.Error(),
				"Closed /dev/mapper/luks-auto",
				"Failed to detach loop device /dev/loop7: resource busy",
				"sudo losetup -d /dev/loop7",
				"is valid and was kept",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli, stdout, stderr, volume := newCreateCLI(t)
			rec := &createRecorder{}
			cli.Luks = rec.ops(cause, tt.lockErr, tt.detachErr)

			if code := cli.Run(); code != 1 {
				t.Fatalf("create exited %d, want 1", code)
			}
			if !reflect.DeepEqual(rec.calls, tt.wantCalls) {
				t.Errorf("calls = %v, want %v", rec.calls, tt.wantCalls)
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr lacks %q:\n%s", want, stderr.String())
				}
			}
			if tt.lockErr == nil && !strings.Contains(stderr.String(), volume) {
				t.Errorf("stderr does not name the kept container %s:\n%s", volume, stderr.String())
			}
			for _, out := range []string{stdout.String(), stderr.String()} {
				if strings.Contains(out, "Volume is ready") || strings.Contains(out, "Volume ready to use") {
					t.Errorf("create claimed the volume is ready after the filesystem failed:\n%s", out)
				}
			}
		})
	}
}

// TestCreateFailsWhenTheVolumeCannotBeOpened: create exits non-zero, with the
// cause on stderr, when the loop device cannot be attached or the volume
// cannot be unlocked. Both used to print a warning and exit 0, so a script
// went on to mount a volume that was never opened and has no filesystem. A
// loop device create attached is detached again, and the container is kept.
func TestCreateFailsWhenTheVolumeCannotBeOpened(t *testing.T) {
	tests := []struct {
		name       string
		attachErr  error
		unlockErr  error
		detachErr  error
		wantCalls  []string
		wantStderr []string
	}{
		{
			name:       "no loop device",
			attachErr:  errors.New("no free loop devices"),
			wantCalls:  []string{"attach"},
			wantStderr: []string{"Error: Failed to set up a loop device", "no free loop devices", "is valid and was kept", "mkfs.ext4"},
		},
		{
			name:      "unlock fails",
			unlockErr: errors.New("keyring unavailable"),
			wantCalls: []string{"attach", "unlock /dev/loop7 luks-auto", "detach /dev/loop7"},
			wantStderr: []string{"Error: Failed to unlock /dev/loop7", "keyring unavailable",
				"Detached loop device /dev/loop7", "is valid and was kept"},
		},
		{
			name:      "unlock fails and the loop device cannot be detached",
			unlockErr: errors.New("keyring unavailable"),
			detachErr: errors.New("resource busy"),
			wantCalls: []string{"attach", "unlock /dev/loop7 luks-auto", "detach /dev/loop7"},
			wantStderr: []string{"Error: Failed to unlock /dev/loop7", "Failed to detach loop device /dev/loop7: resource busy",
				"sudo losetup -d /dev/loop7", "is valid and was kept"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli, stdout, stderr, volume := newCreateCLI(t)
			rec := &createRecorder{}
			ops := rec.ops(nil, nil, tt.detachErr)
			attach, unlock := ops.SetupLoopDeviceFunc, ops.UnlockFunc
			ops.SetupLoopDeviceFunc = func(f string) (string, error) {
				dev, _ := attach(f)
				if tt.attachErr != nil {
					return "", tt.attachErr
				}
				return dev, nil
			}
			ops.UnlockFunc = func(device string, p []byte, name string) error {
				_ = unlock(device, p, name)
				return tt.unlockErr
			}
			cli.Luks = ops

			if code := cli.Run(); code != 1 {
				t.Fatalf("create exited %d, want 1; stderr %q", code, stderr.String())
			}
			if !reflect.DeepEqual(rec.calls, tt.wantCalls) {
				t.Errorf("calls = %v, want %v", rec.calls, tt.wantCalls)
			}
			for _, want := range append(tt.wantStderr, volume) {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr lacks %q:\n%s", want, stderr.String())
				}
			}
			if strings.Contains(stdout.String(), "Volume ready to use") {
				t.Errorf("create claimed the volume is ready:\n%s", stdout.String())
			}
		})
	}
}
