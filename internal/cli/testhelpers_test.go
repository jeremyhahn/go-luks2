// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/secret"
	"github.com/jeremyhahn/go-luks2/pkg/filesystem"
	"github.com/jeremyhahn/go-luks2/pkg/loop"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// testPassphrase is the passphrase every formatted test volume uses.
const testPassphrase = "correct horse battery staple"

const testVolumeImageSize = 64 << 20

// testVolume is a LUKS2 volume with testPassphrase in keyslot 0.
var testVolume = &volumeTemplate{build: formatTestVolume}

// newTestVolumeImage returns a temp-file copy of testVolume. Each copy is
// independent: a test may rewrite its own without affecting any other.
func newTestVolumeImage(t *testing.T, name string) string {
	t.Helper()
	return testVolume.copyTo(t, name)
}

// formatTestVolume formats testVolume through (*luks2.Volume).Format in a
// new image under dir. The 1ms PBKDF2 budget is held to the production
// iteration floor, so the derivation is still a full-cost one.
func formatTestVolume(dir string) (string, error) {
	path := filepath.Join(dir, "volume.img")
	f, err := os.Create(path) // #nosec G304 -- path is under the fixture's temp dir
	if err != nil {
		return "", fmt.Errorf("create image: %w", err)
	}
	if err := f.Truncate(testVolumeImageSize); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("size image: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close image: %w", err)
	}

	ctx := context.Background()
	v, err := luks2.Open(ctx, path)
	if err != nil {
		return "", fmt.Errorf("Open: %w", err)
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy([]byte(testPassphrase))
	if err != nil {
		return "", fmt.Errorf("NewMemoryEnclaveCopy: %w", err)
	}
	defer func() { _ = pass.Destroy() }()

	if err := v.Format(ctx, pass, luks2.FormatParams{
		KeySize: 512,
		KDF:     luks2.KDFParams{Type: luks2.KDFPBKDF2, IterTime: time.Millisecond},
	}); err != nil {
		return "", fmt.Errorf("Format: %w", err)
	}
	return path, nil
}

// testSecondPassphrase is the passphrase twoSlotVolume holds in keyslot 1.
const testSecondPassphrase = "second-pass"

// twoSlotVolume is testVolume with testSecondPassphrase added in keyslot 1,
// for the tests that remove or kill a second keyslot rather than add one.
var twoSlotVolume = &volumeTemplate{build: addSecondPassphrase}

// newTwoSlotVolumeImage returns a temp-file copy of twoSlotVolume.
func newTwoSlotVolumeImage(t *testing.T, name string) string {
	t.Helper()
	return twoSlotVolume.copyTo(t, name)
}

// addSecondPassphrase copies testVolume under dir and adds
// testSecondPassphrase to it through (*luks2.Volume).AddKeyslot, at the same
// production-floor PBKDF2 cost as keyslot 0.
func addSecondPassphrase(dir string) (string, error) {
	path := filepath.Join(dir, "volume.img")
	if err := testVolume.writeImage(path); err != nil {
		return "", err
	}

	ctx := context.Background()
	v, err := luks2.Open(ctx, path)
	if err != nil {
		return "", fmt.Errorf("Open: %w", err)
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy([]byte(testPassphrase))
	if err != nil {
		return "", fmt.Errorf("NewMemoryEnclaveCopy: %w", err)
	}
	defer func() { _ = pass.Destroy() }()

	key, err := v.Unlock(ctx, pass)
	if err != nil {
		return "", fmt.Errorf("Unlock: %w", err)
	}
	defer key.Destroy()

	added, err := enclave.NewMemoryEnclaveCopy([]byte(testSecondPassphrase))
	if err != nil {
		return "", fmt.Errorf("NewMemoryEnclaveCopy: %w", err)
	}
	defer func() { _ = added.Destroy() }()

	slot := 1
	if _, err := v.AddKeyslot(ctx, key, added, luks2.KeyslotParams{
		Slot:     &slot,
		Priority: luks2.PriorityNormal,
		KDF:      luks2.KDFParams{Type: luks2.KDFPBKDF2, Hash: crypto.SHA512, IterTime: time.Millisecond},
	}); err != nil {
		return "", fmt.Errorf("AddKeyslot: %w", err)
	}
	return path, nil
}

// newPlainImage creates an empty (all-zero) temp file of the given name,
// large enough that LUKS2's header read fails on "not LUKS2" rather than
// "too small to hold a header".
func newPlainImage(t *testing.T, name string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	f, err := os.Create(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("create image: %v", err)
	}
	if err := f.Truncate(1 << 20); err != nil {
		_ = f.Close()
		t.Fatalf("size image: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close image: %v", err)
	}
	return path
}

func newTestPassphraseEnclave(t *testing.T) *enclave.MemoryEnclave {
	t.Helper()
	e, err := enclave.NewMemoryEnclaveCopy([]byte(testPassphrase))
	if err != nil {
		t.Fatalf("build passphrase enclave: %v", err)
	}
	return e
}

// fakeTerminal answers ReadPassword with a fixed queue of canned answers,
// in order, and reports isTerm for IsTerminal.
type fakeTerminal struct {
	answers [][]byte
	calls   int
	isTerm  bool
	failAt  int // 1-based call number to fail on, 0 disables
}

func (f *fakeTerminal) ReadPassword(int) ([]byte, error) {
	f.calls++
	if f.failAt != 0 && f.calls == f.failAt {
		return nil, errors.New("fake terminal read failure")
	}
	if f.calls > len(f.answers) {
		return nil, errors.New("fake terminal: no more answers")
	}
	// Copy out: the real term.ReadPassword hands over a buffer nothing
	// else references, and Custody.Adopt takes ownership of (wipes) what
	// it is given -- a second call must not see an already-wiped slice.
	a := f.answers[f.calls-1]
	out := make([]byte, len(a))
	copy(out, a)
	return out, nil
}

func (f *fakeTerminal) IsTerminal(int) bool { return f.isTerm }

// fakeActivator is a scripted activator for tests: open/close/mount never
// touch a real dm-crypt mapping.
type fakeActivator struct {
	activateErr   error
	deactivateErr error
	lookupErr     error
	mapping       mapping

	// onActivate runs inside activate, so a test can cancel the caller's ctx
	// at that point. deactivateCtxErr is the ctx's error when deactivate ran.
	onActivate       func()
	deactivateCtxErr error

	activated   []string
	deactivated []string
	looked      []string
}

func (f *fakeActivator) activate(_ context.Context, _ *luks2.Volume, _ *luks2.Key, name string) (mapping, error) {
	f.activated = append(f.activated, name)
	if f.onActivate != nil {
		f.onActivate()
	}
	if f.activateErr != nil {
		return mapping{}, f.activateErr
	}
	m := f.mapping
	if m.name == "" {
		m.name = name
	}
	return m, nil
}

func (f *fakeActivator) deactivate(ctx context.Context, name string) error {
	f.deactivateCtxErr = ctx.Err()
	f.deactivated = append(f.deactivated, name)
	return f.deactivateErr
}

func (f *fakeActivator) lookup(_ context.Context, name string) (mapping, error) {
	f.looked = append(f.looked, name)
	if f.lookupErr != nil {
		return mapping{}, f.lookupErr
	}
	m := f.mapping
	if m.name == "" {
		m.name = name
	}
	return m, nil
}

// fakeMounter is a scripted mounter for tests: mount/unmount never touch
// the real mount table.
type fakeMounter struct {
	mountErr         error
	unmountErr       error
	mountedErr       error
	mounted          bool
	deviceMountedErr error
	deviceMounted_   bool
	detectErr        error
	detected         filesystem.Type

	makeErr   error
	makeCalls []filesystem.MakeParams
	onMake    func() // runs inside make, e.g. to cancel the caller's ctx

	mountCalls   []filesystem.MountParams
	unmountCalls []string
}

func (f *fakeMounter) mount(_ context.Context, p filesystem.MountParams) error {
	f.mountCalls = append(f.mountCalls, p)
	return f.mountErr
}

func (f *fakeMounter) unmount(_ context.Context, target string, _ filesystem.UnmountFlags) error {
	f.unmountCalls = append(f.unmountCalls, target)
	return f.unmountErr
}

func (f *fakeMounter) isMounted(context.Context, string) (bool, error) {
	return f.mounted, f.mountedErr
}

func (f *fakeMounter) deviceMounted(context.Context, uint32, uint32) (bool, error) {
	return f.deviceMounted_, f.deviceMountedErr
}

func (f *fakeMounter) detect(context.Context, string) (filesystem.Type, error) {
	return f.detected, f.detectErr
}

func (f *fakeMounter) make(_ context.Context, _ string, _ filesystem.Type, p filesystem.MakeParams) error {
	f.makeCalls = append(f.makeCalls, p)
	if f.onMake != nil {
		f.onMake()
	}
	return f.makeErr
}

// fakeLooper is a scripted looper for tests: attach/detach never touch a
// real loop device.
type fakeLooper struct {
	attachErr error
	device    loopDevice
	detachErr error
	detached  []loopDevice

	// detachCtxErr is the ctx's error when detach last ran.
	detachCtxErr error
}

func (f *fakeLooper) attach(_ context.Context, file string) (loopDevice, error) {
	if f.attachErr != nil {
		return loopDevice{}, f.attachErr
	}
	d := f.device
	if d.devPath == "" {
		// Stands in for the real loop device: dm-crypt activation is
		// faked too (fakeActivator), so the only thing that needs a real
		// path open and Unlock work on is the file create itself just
		// formatted.
		d.devPath = file
	}
	return d, nil
}

func (f *fakeLooper) detach(ctx context.Context, d loopDevice) (loop.DetachState, error) {
	f.detachCtxErr = ctx.Err()
	f.detached = append(f.detached, d)
	return loop.Released, f.detachErr
}

// newTestEnv returns an env wired to fakes, with stdin as given.
func newTestEnv(stdin *bytes.Buffer) (*env, *fakeActivator, *fakeMounter, *bytes.Buffer, *bytes.Buffer) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	act := &fakeActivator{}
	mnt := &fakeMounter{}
	e := &env{
		stdin:      stdin,
		stdout:     stdout,
		stderr:     stderr,
		term:       &fakeTerminal{isTerm: false},
		host:       host{activator: act, looper: &fakeLooper{}, mounter: mnt},
		custody:    secret.System(),
		getStdinFd: func() int { return -1 },
	}
	return e, act, mnt, stdout, stderr
}
