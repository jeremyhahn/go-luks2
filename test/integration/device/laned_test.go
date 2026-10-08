// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/clock"
	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-luks2/pkg/wipe"
	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

// fileLockForTest wraps internal/device's Pinned/Locked pair in the shape
// the pre-redesign library's luks2.FileLock gave acquireFileLockForTest's
// caller, before B.6 unexported AcquireFileLock/AcquireFileLockTimeout/
// FileLock in favor of internal/device's own (*Pinned).Lock -- which this
// test can reach directly, since it is already in the module.
type fileLockForTest struct {
	pinned *device.Pinned
	locked *device.Locked
}

// Release gives up the lock and closes the descriptor, as luks2.FileLock's
// own Release did.
func (l *fileLockForTest) Release() error {
	_ = l.locked.Unlock()
	return l.pinned.Close()
}

// acquireFileLockForTest opens and locks path exclusively.
func acquireFileLockForTest(ctx context.Context, path string, wait time.Duration) (*fileLockForTest, error) {
	pinned, err := device.OpenPinned(ctx, "open the device", path, os.O_RDWR, os.OpenFile)
	if err != nil {
		return nil, err
	}
	locked, err := pinned.Lock(ctx, device.LockExclusive, wait, clock.System{}, "/run/cryptsetup", device.DefaultOpenLockFile, func(string) {})
	if err != nil {
		_ = pinned.Close()
		return nil, err
	}
	return &fileLockForTest{pinned: pinned, locked: locked}, nil
}

// formatForTest formats path as a minimal PBKDF2 LUKS2 container, the way
// the pre-redesign library's free function Format did
// before B.6 moved Format behind (*luks2.Volume).Format.
func formatForTest(path string, passphrase string) error {
	ctx := context.Background()
	v, err := luks2.Open(ctx, path)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy([]byte(passphrase))
	if err != nil {
		return err
	}
	defer func() { _ = pass.Destroy() }()

	return v.Format(ctx, pass, luks2.FormatParams{
		KDF: luks2.KDFParams{Type: luks2.KDFPBKDF2, IterTime: time.Millisecond},
	})
}

// addKeyForTest adds a PBKDF2 keyslot, the way the pre-redesign library's
// free function AddKey did before B.6 moved AddKey behind
// (*luks2.Volume).AddKeyslot.
func addKeyForTest(path, existing, newPassphrase string) error {
	ctx := context.Background()
	v, err := luks2.Open(ctx, path)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy([]byte(existing))
	if err != nil {
		return err
	}
	defer func() { _ = pass.Destroy() }()

	key, err := v.Unlock(ctx, pass)
	if err != nil {
		return err
	}
	defer key.Destroy()

	newCred, err := enclave.NewMemoryEnclaveCopy([]byte(newPassphrase))
	if err != nil {
		return err
	}
	defer func() { _ = newCred.Destroy() }()

	_, err = v.AddKeyslot(ctx, key, newCred, luks2.KeyslotParams{
		Priority: luks2.PriorityNormal,
		KDF:      luks2.KDFParams{Type: luks2.KDFPBKDF2, IterTime: time.Millisecond},
	})
	return err
}

// #246 against the real kernel and real cryptsetup: wipe verified on the
// medium past the page cache (D1-D3), wipe refusing a device in use (D4),
// and the device lock excluding cryptsetup (D19). See
// laned_integration_test.go (now moved, from pkg/luks2).
//
// readDirectAt and keyslotsAreaBounds reach internal/device.ReadPastCache
// and internal/header.HeaderAreaSize directly -- both already exported and
// importable module-wide -- in place of pkg/luks2's own unexported
// wrappers of the same name.

const laneDPassphrase = "lane-d-passphrase"

func laneDLoop(t *testing.T) (loop, image string) {
	t.Helper()
	requireRoot(t)

	image = filepath.Join(t.TempDir(), "lane-d.img")
	if err := os.WriteFile(image, bytes.Repeat([]byte{0xAA}, 32<<20), 0o600); err != nil {
		t.Fatalf("writing the image: %v", err)
	}
	loop, err := harness.SetupLoopDevice(image)
	if err != nil {
		t.Fatalf("SetupLoopDevice: %v", err)
	}
	t.Cleanup(func() { _ = harness.DetachLoopDevice(loop) })
	if err := formatForTest(loop, laneDPassphrase); err != nil {
		t.Fatalf("Format: %v", err)
	}
	return loop, image
}

func readMedium(t *testing.T, path string, off int64, n int) []byte {
	t.Helper()
	b, err := device.ReadPastCache(context.Background(), "read the device past the page cache", path, off, n, os.OpenFile)
	if err != nil || len(b) != n {
		t.Fatalf("O_DIRECT read of %s at %d: %d bytes, %v", path, off, len(b), err)
	}
	return b
}

// keyslotsAreaBounds returns [start, end) of the keyslots area, the same
// computation as pkg/luks2's own unexported keyslotsAreaBounds.
func keyslotsAreaBounds(t *testing.T, hdr *header.BinaryHeader, metadata *header.Metadata) (int64, int64) {
	t.Helper()
	area, err := header.HeaderAreaSize(hdr)
	if err != nil {
		t.Fatalf("HeaderAreaSize: %v", err)
	}
	start := 2 * int64(area)
	size, err := strconv.ParseInt(metadata.Config.KeyslotsSize, 10, 64)
	if err != nil {
		t.Fatalf("parsing config.keyslots_size %q: %v", metadata.Config.KeyslotsSize, err)
	}
	return start, start + size
}

func TestWipeIsVerifiedOnTheMedium(t *testing.T) {
	loop, image := laneDLoop(t)

	var verified int64
	err := wipe.Sanitize(context.Background(), loop, wipe.Params{
		Standard: wipe.DoD3Pass,
		Progress: func(p wipe.Progress) {
			if p.Verifying {
				verified = p.Written
			}
		},
	})
	if err != nil {
		t.Fatalf("Sanitize dod3: %v", err)
	}
	if verified != 32<<20 {
		t.Fatalf("verification covered %d bytes, want the whole %d-byte device", verified, 32<<20)
	}

	for _, off := range []int64{0, 16 << 20, 32<<20 - 4096} {
		medium := readMedium(t, image, off, 4096)
		if bytes.Equal(medium, bytes.Repeat([]byte{0xAA}, 4096)) || bytes.Equal(medium, make([]byte, 4096)) || bytes.Equal(medium, bytes.Repeat([]byte{0xFF}, 4096)) {
			t.Fatalf("the medium at %d holds a constant after a random final pass", off)
		}
	}

	if err := wipe.Sanitize(context.Background(), loop, wipe.Params{Patterns: []wipe.Pattern{wipe.Zeros}, Verify: wipe.VerifyAlways}); err != nil {
		t.Fatalf("Sanitize zeros: %v", err)
	}
	if medium := readMedium(t, image, 0, 1<<20); !bytes.Equal(medium, make([]byte, 1<<20)) {
		t.Fatal("the medium is not zero after a verified zero pass")
	}
}

func TestHeaderOnlyWipeIsACryptoEraseOnTheMedium(t *testing.T) {
	requireCryptsetupDeclared(t)
	loop, image := laneDLoop(t)

	hdr, metadata, err := harness.ReadHeader(loop)
	if err != nil {
		t.Fatal(err)
	}
	_, keyslotsEnd := keyslotsAreaBounds(t, hdr, metadata)
	backup := readMedium(t, image, 0, int(2*hdr.HeaderSize))

	if err := func() error {
		v, err := luks2.Open(context.Background(), loop)
		if err != nil {
			return err
		}
		defer func() { _ = v.Close() }()
		return v.Erase(context.Background())
	}(); err != nil {
		t.Fatalf("header-only Wipe: %v", err)
	}
	if medium := readMedium(t, image, 0, int(keyslotsEnd)); !bytes.Equal(medium, make([]byte, len(medium))) {
		t.Fatal("the header copies and the keyslots area are not zero on the medium")
	}

	f, err := os.OpenFile(loop, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(backup, 0); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cryptsetup", "open", "--test-passphrase", loop) // #nosec G204 -- a loop device this test made
	cmd.Stdin = strings.NewReader(laneDPassphrase)
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("cryptsetup opened the restored pre-wipe header after a header-only wipe:\n%s", out)
	}
}

func TestWipeRefusesADeviceInUse(t *testing.T) {
	loop, _ := laneDLoop(t)
	if err := addKeyForTest(loop, laneDPassphrase, "a-second-passphrase"); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	name := runVolume(t, "lane-d-busy")
	if err := Unlock(loop, []byte(laneDPassphrase), name); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer releaseVolume(t, name)

	for what, err := range map[string]error{
		"Wipe header-only": func() error {
			v, err := luks2.Open(context.Background(), loop)
			if err != nil {
				return err
			}
			defer func() { _ = v.Close() }()
			return v.Erase(context.Background())
		}(),
		"Wipe full":   wipe.Sanitize(context.Background(), loop, wipe.Params{Patterns: []wipe.Pattern{wipe.Zeros}}),
		"WipeKeyslot": harness.WipeKeyslot(loop, 1),
	} {
		if !errors.Is(err, luks2.ErrDeviceInUse) {
			t.Errorf("%s of an open volume = %v, want ErrDeviceInUse", what, err)
		}
	}
	if err := harness.TestKey(loop, []byte("a-second-passphrase")); err != nil {
		t.Fatalf("the volume was damaged by a refused wipe: %v", err)
	}
}

func lockFileFor(t *testing.T, path string) string {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	rdev := uint64(st.Rdev) // #nosec G115 -- a device number
	return filepath.Join("/run/cryptsetup", "L_"+strconv.FormatUint(uint64(unix.Major(rdev)), 10)+":"+strconv.FormatUint(uint64(unix.Minor(rdev)), 10))
}

func flockWaiterOn(t *testing.T, ino uint64) bool {
	t.Helper()
	f, err := os.Open("/proc/locks")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	suffix := ":" + strconv.FormatUint(ino, 10)
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) > 6 && fields[1] == "->" && fields[2] == "FLOCK" && strings.HasSuffix(fields[6], suffix) {
			return true
		}
	}
	return false
}

func TestCryptsetupWaitsForTheDeviceLock(t *testing.T) {
	requireCryptsetupDeclared(t)
	loop, _ := laneDLoop(t)

	lock, err := acquireFileLockForTest(context.Background(), loop, device.DefaultLockWait)
	if err != nil {
		t.Fatalf("AcquireFileLock: %v", err)
	}
	released := false
	defer func() {
		if !released {
			_ = lock.Release()
		}
	}()
	var st unix.Stat_t
	if err := unix.Stat(lockFileFor(t, loop), &st); err != nil {
		t.Fatalf("the lock does not hold cryptsetup's lock file: %v", err)
	}

	cmd := exec.Command("cryptsetup", "luksDump", loop) // #nosec G204 -- a loop device this test made
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() { _ = cmd.Process.Kill() }()

	for !flockWaiterOn(t, st.Ino) {
		select {
		case err := <-done:
			t.Fatalf("cryptsetup luksDump finished (%v) while this package held the device lock:\n%s", err, out.String())
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	released = true
	if err := lock.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("cryptsetup luksDump after the release: %v\n%s", err, out.String())
	}
	if _, err := os.Lstat(lockFileFor(t, loop)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the lock file survived its release (%v); cryptsetup removes it", err)
	}
}

func TestTheDeviceLockWaitsForCryptsetupsLockFile(t *testing.T) {
	loop, _ := laneDLoop(t)

	if err := os.MkdirAll("/run/cryptsetup", 0o700); err != nil {
		t.Fatal(err)
	}
	holder, err := os.OpenFile(lockFileFor(t, loop), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(holder.Name()); _ = holder.Close() }()
	if err := unix.Flock(int(holder.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}

	if _, err := acquireFileLockForTest(context.Background(), loop, 50*time.Millisecond); !errors.Is(err, device.ErrLockContended) {
		t.Fatalf("AcquireFileLockTimeout while cryptsetup's lock file is held = %v, want ErrLockContended", err)
	}
}
