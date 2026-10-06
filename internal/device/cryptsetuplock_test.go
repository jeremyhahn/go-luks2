// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package device

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/clock"
)

// The cryptsetup lock protocol, on a lock directory of the test's own. The
// interoperability with cryptsetup itself is proved against the real binary
// in pkg/luks2's integration tier.

// TestCryptsetupLockTakesAndReleasesTheDevicesFile is #246 D19's unit half:
// the file is the one cryptsetup names for the device, it is held LOCK_EX,
// and releasing it unlinks it as cryptsetup's own release does.
func TestCryptsetupLockTakesAndReleasesTheDevicesFile(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "cryptsetup")
	clk := clock.NewFake(t)
	l, err := AcquireCryptsetupLock(dir, unix.Mkdev(7, 3), LockExclusive, clk.Now(), clk.Now(), clk, DefaultOpenLockFile)
	if err != nil {
		t.Fatalf("AcquireCryptsetupLock: %v", err)
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
	if err := (*CryptsetupLock)(nil).release(); err != nil {
		t.Fatalf("releasing no lock = %v", err)
	}
}

// TestCryptsetupLockWaitsForAHolderAndTimesOut: a holder of the file -- which
// is what cryptsetup is while it writes the metadata -- makes the
// acquisition wait, within the budget, and then refuse with
// ErrLockContended.
func TestCryptsetupLockWaitsForAHolderAndTimesOut(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	holder, err := os.OpenFile(filepath.Join(dir, "L_253:0"), os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close() }()
	if err := unix.Flock(int(holder.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}

	clk := clock.NewFake(t)
	_, err = AcquireCryptsetupLock(dir, unix.Mkdev(253, 0), LockExclusive, clk.Now(), clk.Now().Add(time.Second), clk, DefaultOpenLockFile)
	var timeout *LockTimeoutError
	if !errors.As(err, &timeout) || !errors.Is(err, ErrLockContended) {
		t.Fatalf("AcquireCryptsetupLock against a holder = %v, want a LockTimeoutError", err)
	}
	if timeout.Attempts < 2 || len(clk.Waits()) == 0 {
		t.Fatalf("gave up after %d attempts and %d sleeps; the budget was not spent", timeout.Attempts, len(clk.Waits()))
	}
}

// TestCryptsetupLockTakesTheLockWhenTheHolderReleasesIt: the holder releases
// as cryptsetup does, unlinking the file, while this side waits.
func TestCryptsetupLockTakesTheLockWhenTheHolderReleasesIt(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "L_7:0")
	holder, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(holder.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}

	clk := clock.NewFake(t)
	clk.OnWait(func(time.Time) {
		if holder != nil {
			_ = os.Remove(path)
			_ = holder.Close()
			holder = nil
		}
	})
	l, err := AcquireCryptsetupLock(dir, unix.Mkdev(7, 0), LockExclusive, clk.Now(), clk.Now().Add(time.Minute), clk, DefaultOpenLockFile)
	if err != nil {
		t.Fatalf("AcquireCryptsetupLock after the holder released = %v", err)
	}
	defer func() { _ = l.release() }()
	if !l.named() {
		t.Fatal("the lock held is not on the file the path names")
	}
}

// TestCryptsetupLockRetriesAStaleInode: the holder unlinked and released the
// file between this side's open and its flock, so the flock succeeded on an
// inode nobody else will ever open. That is not a lock, and it is retried.
func TestCryptsetupLockRetriesAStaleInode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "L_7:1")

	opens := 0
	openLockFile := func(d *os.File, name string) (*os.File, error) {
		f, err := DefaultOpenLockFile(d, name)
		opens++
		if opens == 1 && err == nil {
			_ = os.Remove(path) // released and unlinked under us
		}
		return f, err
	}

	clk := clock.NewFake(t)
	l, err := AcquireCryptsetupLock(dir, unix.Mkdev(7, 1), LockExclusive, clk.Now(), clk.Now().Add(time.Minute), clk, openLockFile)
	if err != nil {
		t.Fatalf("AcquireCryptsetupLock = %v", err)
	}
	defer func() { _ = l.release() }()
	if opens != 2 || !l.named() {
		t.Fatalf("opened %d times, holding the named file = %v; want a retry onto the live file", opens, l.named())
	}

	// With the budget already spent, a stale inode ends the wait.
	opens = 0
	_ = l.release()
	if _, err := AcquireCryptsetupLock(dir, unix.Mkdev(7, 1), LockExclusive, clk.Now(), clk.Now(), clk, openLockFile); !errors.Is(err, ErrLockContended) {
		t.Fatalf("a stale inode at the deadline = %v, want ErrLockContended", err)
	}
}

// TestCryptsetupLockReportsWhatItCannotDo: no directory, no file.
func TestCryptsetupLockReportsWhatItCannotDo(t *testing.T) {
	t.Parallel()

	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFake(t)
	unavailable := func(what string, err error) {
		t.Helper()
		var de *Error
		if !errors.As(err, &de) || !errors.Is(err, ErrMetadataLockUnavailable) {
			t.Fatalf("%s = %v, want an Error matching ErrMetadataLockUnavailable", what, err)
		}
	}
	_, err := AcquireCryptsetupLock(filepath.Join(notADir, "cryptsetup"), 0, LockExclusive, clk.Now(), clk.Now(), clk, DefaultOpenLockFile)
	unavailable("a lock directory that cannot be created", err)
	if !errors.Is(err, unix.ENOTDIR) {
		t.Fatalf("the cause %v is not reachable through the error", err)
	}

	// A file where the directory should be, and a symlink to a real
	// directory: cryptsetup opens the last component O_NOFOLLOW|O_DIRECTORY
	// and refuses both ("Locking aborted"), so a lock taken through either
	// would exclude no cryptsetup process.
	_, err = AcquireCryptsetupLock(notADir, 0, LockExclusive, clk.Now(), clk.Now(), clk, DefaultOpenLockFile)
	unavailable("a lock directory that is a file", err)
	elsewhere := t.TempDir()
	link := filepath.Join(t.TempDir(), "cryptsetup")
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}
	_, err = AcquireCryptsetupLock(link, 0, LockExclusive, clk.Now(), clk.Now(), clk, DefaultOpenLockFile)
	unavailable("a lock directory that is a symlink", err)
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatalf("the symlink was followed: %d entries in its target", len(entries))
	}

	dir := t.TempDir()
	if err := os.Symlink(notADir, filepath.Join(dir, "L_0:0")); err != nil {
		t.Fatal(err)
	}
	_, err = AcquireCryptsetupLock(dir, 0, LockExclusive, clk.Now(), clk.Now(), clk, DefaultOpenLockFile)
	unavailable("a lock file that is a symlink (O_NOFOLLOW)", err)
}

// TestCryptsetupLockIsNotTakenForARegularFile: cryptsetup's lock for an image
// file is a flock on the file itself, which Pinned.Lock already holds.
func TestCryptsetupLockIsNotTakenForARegularFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "image")
	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	pinned, err := OpenPinned("lock the device", path, os.O_RDWR, os.OpenFile)
	if err != nil {
		t.Fatalf("OpenPinned: %v", err)
	}
	locked, err := pinned.Lock(LockExclusive, DefaultLockWait, clock.System{}, t.TempDir(), DefaultOpenLockFile, nil)
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	defer func() { _ = locked.Unlock(); _ = pinned.Close() }()
	if locked.cryptsetup != nil {
		t.Fatalf("a regular file took a cryptsetup lock file %s", locked.cryptsetup.path)
	}

	f, err := os.Open(path) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	clk := clock.NewFake(t)
	var de *Error
	if _, err := acquireCryptsetupLockFor(f, path, t.TempDir(), LockExclusive, clk.Now(), clk.Now(), clk, DefaultOpenLockFile); !errors.As(err, &de) {
		t.Fatalf("a closed descriptor = %v, want an Error", err)
	}
}

// TestASharedReleaseLeavesTheFileToTheLastHolder: readers share cryptsetup's
// lock file, and a reader leaving while another still holds it must not
// unlink it -- the next writer would lock a fresh file the remaining reader
// is not on, and the two would no longer exclude each other. Release unlinks
// only when it can take the file exclusively, as cryptsetup's
// release_lock_handle does; the last holder out removes it.
func TestASharedReleaseLeavesTheFileToTheLastHolder(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "L_7:5")
	clk := clock.NewFake(t)
	first, err := AcquireCryptsetupLock(dir, unix.Mkdev(7, 5), LockShared, clk.Now(), clk.Now(), clk, DefaultOpenLockFile)
	if err != nil {
		t.Fatalf("first reader: %v", err)
	}
	second, err := AcquireCryptsetupLock(dir, unix.Mkdev(7, 5), LockShared, clk.Now(), clk.Now(), clk, DefaultOpenLockFile)
	if err != nil {
		t.Fatalf("a second reader beside the first = %v; readers share the lock", err)
	}
	if _, err := AcquireCryptsetupLock(dir, unix.Mkdev(7, 5), LockExclusive, clk.Now(), clk.Now(), clk, DefaultOpenLockFile); !errors.Is(err, ErrLockContended) {
		t.Fatalf("a writer while two readers hold the lock = %v, want ErrLockContended", err)
	}

	if err := first.release(); err != nil {
		t.Fatal(err)
	}
	if !second.named() {
		t.Fatal("the first reader's release unlinked the file the second reader still holds")
	}
	if _, err := AcquireCryptsetupLock(dir, unix.Mkdev(7, 5), LockExclusive, clk.Now(), clk.Now(), clk, DefaultOpenLockFile); !errors.Is(err, ErrLockContended) {
		t.Fatalf("a writer while one reader still holds the lock = %v, want ErrLockContended", err)
	}

	if err := second.release(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the last reader out left the lock file (%v); cryptsetup removes it", err)
	}
}
