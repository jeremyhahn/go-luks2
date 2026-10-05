// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The cryptsetup lock protocol, on a lock directory of the test's own. The
// interoperability with cryptsetup itself is proved against the real binary in
// the integration tier (cryptsetuplock_integration_test.go).

// TestCryptsetupLockTakesAndReleasesTheDevicesFile is #246 D19's unit half:
// the file is the one cryptsetup names for the device, it is held LOCK_EX,
// and releasing it unlinks it as cryptsetup's own release does.
func TestCryptsetupLockTakesAndReleasesTheDevicesFile(t *testing.T) {
	defer parallel(t)()

	dir := filepath.Join(t.TempDir(), "cryptsetup")
	clk := newFakeClock(t)
	l, err := acquireCryptsetupLock(dir, unix.Mkdev(7, 3), lockExclusive, clk.Now(), clk.Now(), clk)
	if err != nil {
		t.Fatalf("acquireCryptsetupLock: %v", err)
	}
	want := filepath.Join(dir, "L_7:3")
	if l.path != want {
		t.Fatalf("lock file = %s, want cryptsetup's %s", l.path, want)
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("lock directory = %v, %v; want created 0700 as cryptsetup creates it", st, err)
	}

	other, err := os.OpenFile(want, os.O_RDWR, 0) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	if err := unix.Flock(int(other.Fd()), unix.LOCK_SH|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("a reader's LOCK_SH while the lock is held = %v, want EWOULDBLOCK", err)
	}

	if err := l.release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := os.Lstat(want); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the lock file survived its release (%v); cryptsetup unlinks it", err)
	}
	if err := (*cryptsetupLock)(nil).release(); err != nil {
		t.Fatalf("releasing no lock = %v", err)
	}
}

// TestCryptsetupLockWaitsForAHolderAndTimesOut: a holder of the file -- which
// is what cryptsetup is while it writes the metadata -- makes the acquisition
// wait, within the budget, and then refuse with ErrLockContended.
func TestCryptsetupLockWaitsForAHolderAndTimesOut(t *testing.T) {
	defer parallel(t)()

	dir := t.TempDir()
	holder, err := os.OpenFile(filepath.Join(dir, "L_253:0"), os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close() }()
	if err := unix.Flock(int(holder.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}

	clk := newFakeClock(t)
	_, err = acquireCryptsetupLock(dir, unix.Mkdev(253, 0), lockExclusive, clk.Now(), clk.Now().Add(time.Second), clk)
	var timeout *LockTimeoutError
	if !errors.As(err, &timeout) || !errors.Is(err, ErrLockContended) {
		t.Fatalf("acquireCryptsetupLock against a holder = %v, want a LockTimeoutError", err)
	}
	if timeout.Attempts < 2 || len(clk.slept) == 0 {
		t.Fatalf("gave up after %d attempts and %d sleeps; the budget was not spent", timeout.Attempts, len(clk.slept))
	}
}

// TestCryptsetupLockTakesTheLockWhenTheHolderReleasesIt: the holder releases
// as cryptsetup does, unlinking the file, while this side waits.
func TestCryptsetupLockTakesTheLockWhenTheHolderReleasesIt(t *testing.T) {
	defer parallel(t)()

	dir := t.TempDir()
	path := filepath.Join(dir, "L_7:0")
	holder, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(holder.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}

	clk := newFakeClock(t)
	clk.onSleep = func(time.Time) {
		if holder != nil {
			_ = os.Remove(path)
			_ = holder.Close()
			holder = nil
		}
	}
	l, err := acquireCryptsetupLock(dir, unix.Mkdev(7, 0), lockExclusive, clk.Now(), clk.Now().Add(time.Minute), clk)
	if err != nil {
		t.Fatalf("acquireCryptsetupLock after the holder released = %v", err)
	}
	defer func() { _ = l.release() }()
	if !sameInode(l.file, path) {
		t.Fatal("the lock held is not on the file the path names")
	}
}

// TestCryptsetupLockRetriesAStaleInode: the holder unlinked and released the
// file between this side's open and its flock, so the flock succeeded on an
// inode nobody else will ever open. That is not a lock, and it is retried.
func TestCryptsetupLockRetriesAStaleInode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "L_7:1")

	previous := openCryptsetupLockFile
	t.Cleanup(func() { openCryptsetupLockFile = previous })
	opens := 0
	openCryptsetupLockFile = func(p string) (*os.File, error) {
		f, err := previous(p)
		opens++
		if opens == 1 && err == nil {
			_ = os.Remove(p) // released and unlinked under us
		}
		return f, err
	}

	clk := newFakeClock(t)
	l, err := acquireCryptsetupLock(dir, unix.Mkdev(7, 1), lockExclusive, clk.Now(), clk.Now().Add(time.Minute), clk)
	if err != nil {
		t.Fatalf("acquireCryptsetupLock = %v", err)
	}
	defer func() { _ = l.release() }()
	if opens != 2 || !sameInode(l.file, path) {
		t.Fatalf("opened %d times, holding the named file = %v; want a retry onto the live file", opens, sameInode(l.file, path))
	}

	// With the budget already spent, a stale inode ends the wait.
	opens = 0
	_ = l.release()
	if _, err := acquireCryptsetupLock(dir, unix.Mkdev(7, 1), lockExclusive, clk.Now(), clk.Now(), clk); !errors.Is(err, ErrLockContended) {
		t.Fatalf("a stale inode at the deadline = %v, want ErrLockContended", err)
	}
}

// TestCryptsetupLockReportsWhatItCannotDo: no directory, no file.
func TestCryptsetupLockReportsWhatItCannotDo(t *testing.T) {
	defer parallel(t)()

	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	clk := newFakeClock(t)
	var de *DeviceError
	if _, err := acquireCryptsetupLock(filepath.Join(notADir, "cryptsetup"), 0, lockExclusive, clk.Now(), clk.Now(), clk); !errors.As(err, &de) {
		t.Fatalf("a lock directory that cannot be created = %v, want a DeviceError", err)
	}

	dir := t.TempDir()
	if err := os.Symlink(notADir, filepath.Join(dir, "L_0:0")); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireCryptsetupLock(dir, 0, lockExclusive, clk.Now(), clk.Now(), clk); !errors.As(err, &de) {
		t.Fatalf("a lock file that is a symlink = %v, want a DeviceError (O_NOFOLLOW)", err)
	}
}

// TestCryptsetupLockIsNotTakenForARegularFile: cryptsetup's lock for an image
// file is a flock on the file itself, which AcquireFileLock already holds.
func TestCryptsetupLockIsNotTakenForARegularFile(t *testing.T) {
	defer parallel(t)()

	path := filepath.Join(t.TempDir(), "image")
	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := AcquireFileLock(path)
	if err != nil {
		t.Fatalf("AcquireFileLock: %v", err)
	}
	defer func() { _ = lock.Release() }()
	if lock.cryptsetup != nil {
		t.Fatalf("a regular file took a cryptsetup lock file %s", lock.cryptsetup.path)
	}

	f, err := os.Open(path) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	clk := newFakeClock(t)
	var de *DeviceError
	if _, err := acquireCryptsetupLockFor(f, path, clk.Now(), clk.Now(), clk); !errors.As(err, &de) {
		t.Fatalf("a closed descriptor = %v, want a DeviceError", err)
	}
}

// TestASharedReleaseLeavesTheFileToTheLastHolder: readers share cryptsetup's
// lock file, and a reader leaving while another still holds it must not
// unlink it -- the next writer would lock a fresh file the remaining reader
// is not on, and the two would no longer exclude each other. Release unlinks
// only when it can take the file exclusively, as cryptsetup's
// release_lock_handle does; the last holder out removes it.
func TestASharedReleaseLeavesTheFileToTheLastHolder(t *testing.T) {
	defer parallel(t)()

	dir := t.TempDir()
	path := filepath.Join(dir, "L_7:5")
	clk := newFakeClock(t)
	first, err := acquireCryptsetupLock(dir, unix.Mkdev(7, 5), lockShared, clk.Now(), clk.Now(), clk)
	if err != nil {
		t.Fatalf("first reader: %v", err)
	}
	second, err := acquireCryptsetupLock(dir, unix.Mkdev(7, 5), lockShared, clk.Now(), clk.Now(), clk)
	if err != nil {
		t.Fatalf("a second reader beside the first = %v; readers share the lock", err)
	}
	if _, err := acquireCryptsetupLock(dir, unix.Mkdev(7, 5), lockExclusive, clk.Now(), clk.Now(), clk); !errors.Is(err, ErrLockContended) {
		t.Fatalf("a writer while two readers hold the lock = %v, want ErrLockContended", err)
	}

	if err := first.release(); err != nil {
		t.Fatal(err)
	}
	if !sameInode(second.file, path) {
		t.Fatal("the first reader's release unlinked the file the second reader still holds")
	}
	if _, err := acquireCryptsetupLock(dir, unix.Mkdev(7, 5), lockExclusive, clk.Now(), clk.Now(), clk); !errors.Is(err, ErrLockContended) {
		t.Fatalf("a writer while one reader still holds the lock = %v, want ErrLockContended", err)
	}

	if err := second.release(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the last reader out left the lock file (%v); cryptsetup removes it", err)
	}
}
