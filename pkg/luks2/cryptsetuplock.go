// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// Interoperating with cryptsetup's metadata lock.
//
// AcquireFileLock's flock on the device node excludes this package's own
// processes, and nothing else: cryptsetup does not lock the node. MEASURED in
// the integration devcontainer against cryptsetup 2.7.5 (`cryptsetup --debug`
// prints each step, and /proc/locks shows the holder):
//
//   - For a BLOCK device it flocks /run/cryptsetup/L_<major>:<minor> (decimal
//     device numbers), LOCK_SH to read the metadata and LOCK_EX to write it,
//     creating the directory 0700 and the file if they are missing. A flock
//     held on the device node does not delay it at all; a LOCK_EX held on that
//     file delays every cryptsetup command on the device, and a LOCK_SH delays
//     every write.
//   - Before trusting a lock it compares the inode it locked with the inode
//     the path names now ("Verifying lock handle"), because the holder that
//     releases a lock unlinks the file: a waiter that wakes up holding the
//     unlinked inode has locked nothing and starts again.
//   - For a REGULAR FILE image it flocks the image itself -- which is exactly
//     the lock AcquireFileLock already takes, so file containers needed nothing.
//   - The lock is held only while the metadata is read or written. A
//     passphrase prompt, and the key derivation behind it, run unlocked.
//
// This is cryptsetup's documented locking (cryptsetup(8): --disable-locks;
// the default locking directory /run/cryptsetup), so the same lock is taken
// here, the same way. It excludes cryptsetup processes that share this
// process's /run: a container with its own /run, or cryptsetup run with
// --disable-locks, is not excluded, and nothing in the kernel can make it so.

// cryptsetupLockDir is cryptsetup's default locking directory. A variable so
// this package's tests can lock in a directory of their own; nothing else
// changes it.
var cryptsetupLockDir = "/run/cryptsetup"

// openCryptsetupLockFile opens (creating) the lock file name in the lock
// directory open as dir. A seam: the window in which another holder replaces
// the file between this open and the flock that follows cannot be hit on
// purpose from a test any other way. Unexported, substituted only by this
// package's tests.
var openCryptsetupLockFile = func(dir *os.File, name string) (*os.File, error) {
	path := filepath.Join(dir.Name(), name)
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, &fs.PathError{Op: "openat", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil // #nosec G115 -- a descriptor the kernel just returned
}

// openCryptsetupLockDir opens cryptsetup's lock directory, creating it 0700 if
// it is missing, the way cryptsetup's open_lock_dir does: the last component
// is opened O_NOFOLLOW|O_DIRECTORY, so a symlink or a file there is refused
// rather than followed -- cryptsetup refuses it too ("Locking aborted. The
// locking path ... is unusable"), and a lock taken somewhere cryptsetup will
// never look excludes nothing. Every lock file is then opened, checked and
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

// metadataLockUnavailable is the error for a lock that cannot be taken at all,
// as opposed to one somebody holds (LockTimeoutError).
func metadataLockUnavailable(path, op string, err error) error {
	return &DeviceError{Device: path, Op: op, Err: &detailError{Kind: ErrMetadataLockUnavailable, Err: err}}
}

// lockMode is how a metadata lock is held: shared to read the metadata,
// exclusive to write it -- cryptsetup's two modes, and flock's.
type lockMode int

const (
	// lockExclusive is a writer's hold: LOCK_EX.
	lockExclusive lockMode = iota

	// lockShared is a reader's hold: LOCK_SH. Readers do not delay each
	// other; every one of them delays a writer.
	lockShared
)

// flockOp is the flock(2) operation that takes the lock without blocking.
func (m lockMode) flockOp() int {
	if m == lockShared {
		return unix.LOCK_SH | unix.LOCK_NB
	}
	return unix.LOCK_EX | unix.LOCK_NB
}

// cryptsetupLock is cryptsetup's lock file for one block device, held in the
// mode it was taken in.
type cryptsetupLock struct {
	path string
	dir  *os.File // the lock directory, open; the file is named relative to it
	name string
	file *os.File
}

// acquireCryptsetupLockFor takes cryptsetup's lock, exclusively, for the
// device node open as node, if it is a block device, by the deadline. A
// regular file returns nil: cryptsetup's lock for it is the flock the caller
// already holds.
func acquireCryptsetupLockFor(node *os.File, device string, started, deadline time.Time, clk clock) (*cryptsetupLock, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(node.Fd()), &st); err != nil {
		return nil, &DeviceError{Device: device, Op: "stat the device to lock it", Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFBLK {
		return nil, nil
	}
	return acquireCryptsetupLock(cryptsetupLockDir, uint64(st.Rdev), lockExclusive, started, deadline, clk) // #nosec G115 -- Rdev is a device number; its width differs by architecture
}

// acquireCryptsetupLock takes dir/L_<major>:<minor> in mode, polling with the
// same backoff as AcquireFileLock until deadline.
func acquireCryptsetupLock(dir string, rdev uint64, mode lockMode, started, deadline time.Time, clk clock) (*cryptsetupLock, error) {
	dirFile, err := openCryptsetupLockDir(dir)
	if err != nil {
		return nil, err
	}
	name := "L_" + strconv.FormatUint(uint64(unix.Major(rdev)), 10) + ":" + strconv.FormatUint(uint64(unix.Minor(rdev)), 10)
	path := filepath.Join(dir, name)
	fail := func(err error) (*cryptsetupLock, error) {
		_ = dirFile.Close()
		return nil, err
	}

	backoff := lockBackoffMin
	for attempt := 1; ; attempt++ {
		f, err := openCryptsetupLockFile(dirFile, name)
		if err != nil {
			return fail(metadataLockUnavailable(path, "open cryptsetup's lock file", err))
		}
		l := &cryptsetupLock{path: path, dir: dirFile, name: name, file: f}

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
		clk.Sleep(min(backoff, remaining))
		backoff = min(backoff*2, lockBackoffMax)
	}
}

// named reports whether the lock directory still names the file open as the
// lock, by the name the lock was taken under.
func (l *cryptsetupLock) named() bool {
	var held, named unix.Stat_t
	if unix.Fstat(int(l.file.Fd()), &held) != nil ||
		unix.Fstatat(int(l.dir.Fd()), l.name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return false
	}
	return held.Dev == named.Dev && held.Ino == named.Ino
}

// release gives the lock up the way cryptsetup's release_lock_handle does
// (measured with strace against cryptsetup 2.7.5): unlock, then try for the
// file EXCLUSIVELY without waiting, and unlink it only if that succeeds and
// the directory still names it. The last holder out removes the file; a holder
// that leaves while a reader still holds it -- or while a writer is queued --
// leaves it for them. A waiter that wakes up on an unlinked file sees that it
// is stale and retries, so no lock file is left behind and none is pulled out
// from under a live holder.
func (l *cryptsetupLock) release() error {
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

// metadataReadLock is what an activation holds while it reads a container's
// metadata: a SHARED flock on the device node, then cryptsetup's lock file
// for the device, shared -- the lock order every writer here takes
// exclusively (AcquireFileLock), so a reader and a writer cannot each hold
// one and wait for the other.
//
// It is cryptsetup's read lock. A cryptsetup command writing the metadata
// holds that file exclusively, and the read waits for it; reads, cryptsetup's
// included, do not delay one another.
type metadataReadLock struct {
	// node is the caller's descriptor, flocked LOCK_SH. The caller owns it
	// and closes it; release only unlocks it.
	node       *os.File
	cryptsetup *cryptsetupLock
	released   bool
}

// metadataReadLockWait is how long an activation waits for a writer to
// release the metadata -- the same budget, for the same reason, as
// AcquireFileLock's DefaultLockWait.
const metadataReadLockWait = DefaultLockWait

// acquireMetadataReadLock takes the read lock on the block device rdev open as
// node, waiting up to wait for a writer to finish.
func acquireMetadataReadLock(node *os.File, device string, rdev uint64, wait time.Duration, clk clock) (*metadataReadLock, error) {
	started := clk.Now()
	deadline := started.Add(wait)
	if err := pollFlock(node, device, lockShared, started, deadline, clk); err != nil {
		return nil, err
	}
	cs, err := acquireCryptsetupLock(cryptsetupLockDir, rdev, lockShared, started, deadline, clk)
	if err != nil {
		_ = unix.Flock(int(node.Fd()), unix.LOCK_UN)
		return nil, err
	}
	return &metadataReadLock{node: node, cryptsetup: cs}, nil
}

// release gives up both locks, cryptsetup's first since it was taken second.
// It is idempotent, so an early release on the success path and a deferred one
// for every other path can both be written.
func (l *metadataReadLock) release() {
	if l == nil || l.released {
		return
	}
	l.released = true
	_ = l.cryptsetup.release()
	_ = unix.Flock(int(l.node.Fd()), unix.LOCK_UN)
}
