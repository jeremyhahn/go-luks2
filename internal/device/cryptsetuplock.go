// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package device

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/clock"
	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// Interoperating with cryptsetup's metadata lock.
//
// The node flock excludes this module's own processes, and nothing else:
// cryptsetup does not lock the node. MEASURED in the integration devcontainer
// against cryptsetup 2.7.5 (`cryptsetup --debug` prints each step, and
// /proc/locks shows the holder):
//
//   - For a BLOCK device it flocks /run/cryptsetup/L_<major>:<minor> (decimal
//     device numbers), LOCK_SH to read the metadata and LOCK_EX to write it,
//     creating the directory 0700 and the file if they are missing. A flock
//     held on the device node does not delay it at all; a LOCK_EX held on
//     that file delays every cryptsetup command on the device, and a
//     LOCK_SH delays every write.
//   - Before trusting a lock it compares the inode it locked with the inode
//     the path names now ("Verifying lock handle"), because the holder that
//     releases a lock unlinks the file: a waiter that wakes up holding the
//     unlinked inode has locked nothing and starts again.
//   - For a REGULAR FILE image it flocks the image itself -- which is
//     exactly the node flock, so file containers need nothing more.
//   - The lock is held only while the metadata is read or written.
//
// This is cryptsetup's documented locking (cryptsetup(8): --disable-locks;
// the default locking directory /run/cryptsetup), so the same lock is taken
// here, the same way.

// OpenLockFileFunc opens (creating) the cryptsetup lock file name inside the
// open lock directory dir. A parameter rather than a package var: the window
// in which another holder replaces the file between this open and the flock
// that follows cannot be hit on purpose from a test any other way, and this
// package holds no mutable state of its own for a caller to substitute.
type OpenLockFileFunc func(dir *os.File, name string) (*os.File, error)

// DefaultOpenLockFile is the production OpenLockFileFunc.
func DefaultOpenLockFile(dir *os.File, name string) (*os.File, error) {
	path := filepath.Join(dir.Name(), name)
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, &fs.PathError{Op: "openat", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil // #nosec G115 -- a descriptor the kernel just returned
}

// openCryptsetupLockDir opens cryptsetup's lock directory, creating it 0700
// if it is missing, the way cryptsetup's open_lock_dir does: the last
// component is opened O_NOFOLLOW|O_DIRECTORY, so a symlink or a file there is
// refused rather than followed. Every lock file is then opened, checked and
// unlinked relative to this descriptor, so the directory cannot be swapped
// between those steps.
func openCryptsetupLockDir(dir string) (*os.File, error) {
	open := func() (int, error) {
		return unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	fd, err := open()
	if errors.Is(err, unix.ENOENT) {
		if mkErr := unix.Mkdir(dir, 0o700); mkErr != nil && !errors.Is(mkErr, unix.EEXIST) {
			return nil, metadataLockUnavailable(dir, "create cryptsetup's lock directory", mkErr)
		}
		fd, err = open()
	}
	if err != nil {
		return nil, metadataLockUnavailable(dir, "open cryptsetup's lock directory", err)
	}
	return os.NewFile(uintptr(fd), dir), nil // #nosec G115 -- a descriptor the kernel just returned
}

// metadataLockUnavailable is the error for a lock that cannot be taken at
// all, as opposed to one somebody holds (LockTimeoutError).
func metadataLockUnavailable(path, op string, err error) error {
	return &errs.Error{Kind: ErrMetadataLockUnavailable, Detail: op + " " + path, Err: err}
}

// CryptsetupLock is cryptsetup's lock file for one block device, held in the
// mode it was taken in.
type CryptsetupLock struct {
	path string
	dir  *os.File // the lock directory, open; the file is named relative to it
	name string
	file *os.File
}

// acquireCryptsetupLockFor takes cryptsetup's lock, in mode, for the device
// node open as node, if it is a block device, by the deadline. A regular
// file returns nil: cryptsetup's lock for it is the flock the caller already
// holds.
func acquireCryptsetupLockFor(ctx context.Context, node *os.File, device, lockDir string, mode LockMode, started, deadline time.Time, clk clock.Clock, openLockFile OpenLockFileFunc) (*CryptsetupLock, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(node.Fd()), &st); err != nil {
		return nil, &errs.Error{Kind: errs.ErrIO, Detail: "stat " + device + " to lock it", Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFBLK {
		return nil, nil
	}
	return AcquireCryptsetupLock(ctx, lockDir, uint64(st.Rdev), mode, started, deadline, clk, openLockFile) // #nosec G115 -- Rdev is a device number; its width differs by architecture
}

// AcquireCryptsetupLock takes dir/L_<major>:<minor> in mode, polling with the
// same backoff as a node flock until deadline.
func AcquireCryptsetupLock(ctx context.Context, dir string, rdev uint64, mode LockMode, started, deadline time.Time, clk clock.Clock, openLockFile OpenLockFileFunc) (*CryptsetupLock, error) {
	dirFile, err := openCryptsetupLockDir(dir)
	if err != nil {
		return nil, err
	}
	name := "L_" + strconv.FormatUint(uint64(unix.Major(rdev)), 10) + ":" + strconv.FormatUint(uint64(unix.Minor(rdev)), 10)
	path := filepath.Join(dir, name)
	fail := func(err error) (*CryptsetupLock, error) {
		_ = dirFile.Close()
		return nil, err
	}

	backoff := lockBackoffMin
	for attempt := 1; ; attempt++ {
		f, err := openLockFile(dirFile, name)
		if err != nil {
			return fail(metadataLockUnavailable(path, "open cryptsetup's lock file", err))
		}
		l := &CryptsetupLock{path: path, dir: dirFile, name: name, file: f}

		err = unix.Flock(int(f.Fd()), mode.flockOp())
		switch {
		case err == nil && l.named():
			return l, nil
		case err == nil:
			// The previous holder unlinked the file as it released it, and
			// what was locked is that unlinked inode. Start again on the
			// file the path names now, without sleeping: nobody holds it.
			_ = f.Close()
			if !clk.Now().Before(deadline) {
				return fail(&LockTimeoutError{Path: path, Waited: clk.Now().Sub(started), Attempts: attempt, Err: unix.EWOULDBLOCK})
			}
			continue
		case !errors.Is(err, unix.EWOULDBLOCK):
			_ = f.Close()
			return fail(metadataLockUnavailable(path, "lock", err))
		}
		_ = f.Close()

		remaining := deadline.Sub(clk.Now())
		if remaining <= 0 {
			return fail(&LockTimeoutError{Path: path, Waited: clk.Now().Sub(started), Attempts: attempt, Err: err})
		}
		t := clk.NewTimer(min(backoff, remaining))
		select {
		case <-ctx.Done():
		case <-t.C():
		}
		t.Stop()
		if err := ctx.Err(); err != nil {
			return fail(&errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "waiting to lock " + path, Err: err})
		}
		backoff = min(backoff*2, lockBackoffMax)
	}
}

// named reports whether the lock directory still names the file open as the
// lock, by the name the lock was taken under.
func (l *CryptsetupLock) named() bool {
	var held, named unix.Stat_t
	if unix.Fstat(int(l.file.Fd()), &held) != nil ||
		unix.Fstatat(int(l.dir.Fd()), l.name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return false
	}
	return held.Dev == named.Dev && held.Ino == named.Ino
}

// release gives the lock up the way cryptsetup's release_lock_handle does:
// unlock, then try for the file EXCLUSIVELY without waiting, and unlink it
// only if that succeeds and the directory still names it. The last holder
// out removes the file; a holder that leaves while a reader still holds it --
// or while a writer is queued -- leaves it for them.
func (l *CryptsetupLock) release() error {
	if l == nil {
		return nil
	}
	_ = unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	if unix.Flock(int(l.file.Fd()), unix.LOCK_EX|unix.LOCK_NB) == nil && l.named() {
		_ = unix.Unlinkat(int(l.dir.Fd()), l.name, 0)
	}
	err := l.file.Close()
	_ = l.dir.Close()
	return err
}
