// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// #246 against the real kernel and real cryptsetup: wipe verified on the
// medium past the page cache (D1-D3), wipe refusing a device in use (D4), and
// the device lock excluding cryptsetup (D19).

const laneDPassphrase = "lane-d-passphrase"

// laneDLoop formats a fresh image attached to a loop device without direct
// I/O -- so the loop reads its backing file through the page cache, the case
// verification has to see past -- and returns the loop device and the image.
func laneDLoop(t *testing.T) (loop, image string) {
	t.Helper()
	requireRoot(t)

	image = filepath.Join(t.TempDir(), "lane-d.img")
	if err := os.WriteFile(image, bytes.Repeat([]byte{0xAA}, 32<<20), 0o600); err != nil {
		t.Fatalf("writing the image: %v", err)
	}
	loop, err := SetupLoopDevice(image)
	if err != nil {
		t.Fatalf("SetupLoopDevice: %v", err)
	}
	t.Cleanup(func() { _ = DetachLoopDevice(loop) })
	if err := Format(FormatOptions{Device: loop, Passphrase: []byte(laneDPassphrase), KDFType: KDFTypePBKDF2, PBKDFIterTime: 1}); err != nil {
		t.Fatalf("Format: %v", err)
	}
	return loop, image
}

// readMedium reads n bytes of path at off with O_DIRECT, past the page cache.
func readMedium(t *testing.T, path string, off int64, n int) []byte {
	t.Helper()
	b, err := readDirectAt(path, off, n)
	if err != nil || len(b) != n {
		t.Fatalf("O_DIRECT read of %s at %d: %d bytes, %v", path, off, len(b), err)
	}
	return b
}

// TestWipeIsVerifiedOnTheMedium is #246 D1 and D2 on a real loop device: a
// DoD 3-pass wipe ends with a random pass, its verification now reads the loop
// device AND its backing file past their caches, and what is on the medium
// afterwards -- read here with O_DIRECT -- is neither the old contents nor a
// constant.
func TestWipeIsVerifiedOnTheMedium(t *testing.T) {
	loop, image := laneDLoop(t)

	var verified int64
	err := Wipe(WipeOptions{Device: loop, Standard: StandardDoD3Pass, ProgressFunc: func(p WipeProgress) {
		if p.IsVerification {
			verified = p.BytesWritten
		}
	}})
	if err != nil {
		t.Fatalf("Wipe dod3: %v", err)
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

	if err := Wipe(WipeOptions{Device: loop, Passes: 1, Verify: true}); err != nil {
		t.Fatalf("Wipe zeros: %v", err)
	}
	if medium := readMedium(t, image, 0, 1<<20); !bytes.Equal(medium, make([]byte, 1<<20)) {
		t.Fatal("the medium is not zero after a verified zero pass")
	}
}

// TestHeaderOnlyWipeIsACryptoEraseOnTheMedium is #246 D3 against cryptsetup:
// after a header-only wipe the keyslots area is zero ON THE MEDIUM, and the
// header copies saved before the wipe -- written back as an attacker holding
// them would -- open nothing.
func TestHeaderOnlyWipeIsACryptoEraseOnTheMedium(t *testing.T) {
	requireCryptsetupDeclared(t)
	loop, image := laneDLoop(t)

	hdr, metadata, err := ReadHeader(loop)
	if err != nil {
		t.Fatal(err)
	}
	_, keyslotsEnd, err := keyslotsAreaBounds(hdr, metadata)
	if err != nil {
		t.Fatal(err)
	}
	backup := readMedium(t, image, 0, int(2*hdr.HeaderSize))

	if err := Wipe(WipeOptions{Device: loop, HeaderOnly: true}); err != nil {
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

// TestWipeRefusesADeviceInUse is #246 D4: with the volume open, its backing
// loop device is held by device-mapper, and Wipe and WipeKeyslot used to
// overwrite it underneath the mapping.
func TestWipeRefusesADeviceInUse(t *testing.T) {
	loop, _ := laneDLoop(t)
	if _, err := AddKey(loop, []byte(laneDPassphrase), []byte("a-second-passphrase"), &AddKeyOptions{KDFType: KDFTypePBKDF2, PBKDFIterTime: 1}); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	name := runVolume(t, "lane-d-busy")
	if err := Unlock(loop, []byte(laneDPassphrase), name); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer releaseVolume(t, name)

	for what, err := range map[string]error{
		"Wipe header-only": Wipe(WipeOptions{Device: loop, HeaderOnly: true}),
		"Wipe full":        Wipe(WipeOptions{Device: loop, Passes: 1}),
		"WipeKeyslot":      WipeKeyslot(loop, 1),
	} {
		if !errors.Is(err, ErrDeviceInUse) {
			t.Errorf("%s of an open volume = %v, want ErrDeviceInUse", what, err)
		}
	}
	if err := TestKey(loop, []byte("a-second-passphrase")); err != nil {
		t.Fatalf("the volume was damaged by a refused wipe: %v", err)
	}
}

// lockFileFor returns cryptsetup's lock file for the block device at path.
func lockFileFor(t *testing.T, path string) string {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	rdev := uint64(st.Rdev) // #nosec G115 -- a device number
	return filepath.Join(cryptsetupLockDir, "L_"+strconv.FormatUint(uint64(unix.Major(rdev)), 10)+":"+strconv.FormatUint(uint64(unix.Minor(rdev)), 10))
}

// flockWaiterOn reports whether /proc/locks shows a process BLOCKED on a
// flock of the file with inode ino -- the "->" lines.
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

// TestCryptsetupWaitsForTheDeviceLock is #246 D19: AcquireFileLock locked the
// device node, which cryptsetup does not look at, so cryptsetup changed the
// metadata of a device this package held locked. Held now, the lock makes a
// real cryptsetup command block on it -- seen in /proc/locks as a waiter on
// cryptsetup's own lock file -- and it runs once the lock is released.
func TestCryptsetupWaitsForTheDeviceLock(t *testing.T) {
	requireCryptsetupDeclared(t)
	loop, _ := laneDLoop(t)

	lock, err := AcquireFileLock(loop)
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
	// Whatever ends this test, the child does not outlive it. The wait below
	// has no wall-clock bound of its own (#233): the test binary's -timeout is
	// the bound, and this cleanup and the deferred Release run on every
	// t.Fatal path.
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

// TestTheDeviceLockWaitsForCryptsetupsLockFile is D19 from the other side: a
// holder of cryptsetup's lock file -- what cryptsetup is while it writes the
// metadata -- keeps AcquireFileLock waiting, and it gives up within its
// budget.
func TestTheDeviceLockWaitsForCryptsetupsLockFile(t *testing.T) {
	loop, _ := laneDLoop(t)

	if err := os.MkdirAll(cryptsetupLockDir, 0o700); err != nil {
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

	if _, err := AcquireFileLockTimeout(loop, 50*time.Millisecond); !errors.Is(err, ErrLockContended) {
		t.Fatalf("AcquireFileLockTimeout while cryptsetup's lock file is held = %v, want ErrLockContended", err)
	}
}
