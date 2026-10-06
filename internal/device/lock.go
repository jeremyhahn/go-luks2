// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package device

import (
	"errors"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/clock"
)

// LockMode is how a device lock is held: exclusive for a writer, shared for
// a reader -- cryptsetup's two modes, and flock's.
type LockMode int

const (
	// LockExclusive is a writer's hold: LOCK_EX.
	LockExclusive LockMode = iota

	// LockShared is a reader's hold: LOCK_SH. Readers do not delay each
	// other; every one of them delays a writer.
	LockShared
)

// flockOp is the flock(2) operation that takes the lock without blocking.
func (m LockMode) flockOp() int {
	if m == LockShared {
		return unix.LOCK_SH | unix.LOCK_NB
	}
	return unix.LOCK_EX | unix.LOCK_NB
}

// Lock wait budget and backoff schedule.
//
// DefaultLockWait is what Lock spends before giving up. It is a BOUND, not a
// target: an uncontended lock is taken on the first attempt and costs
// nothing, and the budget is consumed only when another holder has the
// device.
const (
	DefaultLockWait = 30 * time.Second

	// The backoff runs from 1ms to 100ms. The floor keeps a lock released
	// microseconds after the first attempt from costing a full sleep; the
	// ceiling keeps a long wait from turning into a handful of samples that
	// overshoot the budget. Doubling between them reaches the ceiling in
	// seven steps, so a 30s wait is roughly 300 attempts rather than 30000.
	LockBackoffMin = time.Millisecond
	LockBackoffMax = 100 * time.Millisecond

	lockBackoffMin = LockBackoffMin
	lockBackoffMax = LockBackoffMax
)

// Pinned is a descriptor opened on a device or file path, not yet locked.
type Pinned struct {
	path string
	file *os.File
}

// OpenPinned opens path with flag and pins the descriptor to it.
func OpenPinned(op, path string, flag int, openFile OpenFunc) (*Pinned, error) {
	f, err := Open(op, path, flag, openFile)
	if err != nil {
		return nil, err
	}
	return &Pinned{path: path, file: f}, nil
}

// Path is the path the descriptor was opened on.
func (p *Pinned) Path() string { return p.path }

// File is the pinned descriptor.
func (p *Pinned) File() *os.File { return p.file }

// Close releases the descriptor without taking any lock.
func (p *Pinned) Close() error { return p.file.Close() }

// Lock takes the node flock on the pinned descriptor in mode, then
// cryptsetup's lock for the same device in lockDir, waiting up to wait and
// measuring the wait on clk. held, if non-nil, runs once both are held,
// before the caller reads or writes anything under them -- a test hook with
// no effect in production.
//
// IT WAITS, AND THAT IS THE POINT: a bare LOCK_NB with no retry turns
// ordinary contention for a host-global device into an immediate failure.
// See pollFlock.
func (p *Pinned) Lock(mode LockMode, wait time.Duration, clk clock.Clock, lockDir string, openLockFile OpenLockFileFunc, held func(string)) (*Locked, error) {
	started := clk.Now()
	deadline := started.Add(wait)
	if err := pollFlock(p.file, p.path, mode, started, deadline, clk); err != nil {
		return nil, err
	}
	cs, err := acquireCryptsetupLockFor(p.file, p.path, lockDir, mode, started, deadline, clk, openLockFile)
	if err != nil {
		_ = unix.Flock(int(p.file.Fd()), unix.LOCK_UN)
		return nil, err
	}
	if held != nil {
		held(p.path)
	}
	return &Locked{path: p.path, file: p.file, cryptsetup: cs}, nil
}

// LockExisting takes the node flock and cryptsetup's lock, in mode, on a
// descriptor the caller already opened for its own reasons and whose device
// number (rdev) it already knows -- the shape an activation's metadata read
// lock needs, as opposed to Lock's, which opens the descriptor itself.
func LockExisting(f *os.File, path string, rdev uint64, mode LockMode, wait time.Duration, clk clock.Clock, lockDir string, openLockFile OpenLockFileFunc) (*Locked, error) {
	started := clk.Now()
	deadline := started.Add(wait)
	if err := pollFlock(f, path, mode, started, deadline, clk); err != nil {
		return nil, err
	}
	cs, err := AcquireCryptsetupLock(lockDir, rdev, mode, started, deadline, clk, openLockFile)
	if err != nil {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		return nil, err
	}
	return &Locked{path: path, file: f, cryptsetup: cs}, nil
}

// pollFlock flocks f in mode, retrying with backoff while another holder has
// it, until deadline. It always makes one attempt, so a lock that is free is
// never reported as contended, whatever the budget.
func pollFlock(f *os.File, path string, mode LockMode, started, deadline time.Time, clk clock.Clock) error {
	backoff := lockBackoffMin
	for attempt := 1; ; attempt++ {
		err := unix.Flock(int(f.Fd()), mode.flockOp())
		if err == nil {
			return nil
		}

		// CLASSIFY, do not assume contention. EWOULDBLOCK means someone else
		// holds it and waiting is the right answer. Anything else -- EBADF,
		// a descriptor closed underneath us -- will not improve by being
		// retried, and retrying it for the whole budget would report a real
		// fault as a timeout.
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return &Error{Device: path, Op: "lock", Err: err}
		}

		// Checked AFTER an attempt, so a zero budget still tries once.
		remaining := deadline.Sub(clk.Now())
		if remaining <= 0 {
			return &LockTimeoutError{Path: path, Waited: clk.Now().Sub(started), Attempts: attempt, Err: err}
		}

		// Never sleep past the deadline: doing so would report a longer
		// wait than the caller allowed, and Waited above is meant to be
		// true.
		<-clk.NewTimer(min(backoff, remaining)).C()
		backoff = min(backoff*2, lockBackoffMax)
	}
}

// Locked is a device whose node flock and cryptsetup lock are both held, in
// the same mode.
type Locked struct {
	path       string
	file       *os.File
	cryptsetup *CryptsetupLock
	released   bool
}

// File is the locked descriptor.
func (l *Locked) File() *os.File { return l.file }

// Path is the path the descriptor was opened on.
func (l *Locked) Path() string { return l.path }

// Unlock gives up both locks. It does not close the descriptor: ownership of
// it stays with whoever opened it (Pinned.Close for Lock's own open, or the
// caller itself for LockExisting). It is idempotent, so an early unlock on a
// success path and a deferred one for every other path can both be written.
func (l *Locked) Unlock() error {
	if l.released {
		return nil
	}
	l.released = true
	// cryptsetup's lock is released first: it was taken second.
	_ = l.cryptsetup.release()
	return unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
}

// Claim reopens the locked descriptor's own inode -- via its /proc/self/fd
// entry, so the claim targets by construction exactly the file that was
// locked, never the operator's path again -- with flag (which must include
// an exclusive-open intent; callers pass os.O_EXCL) added.
//
// The kernel grants an exclusive claim only on an open BY PATH: that is a
// second descriptor beside the locked one, and resolving the operator's path
// again for it would let a retargeted symlink put the lock on one device and
// the claim on another. Reopening the locked descriptor's own fd entry closes
// that window by construction rather than by comparing the two descriptors
// after the fact.
func (l *Locked) Claim(op string, flag int, openFile OpenFunc) (*Claimed, error) {
	fdPath := "/proc/self/fd/" + strconv.Itoa(int(l.file.Fd())) // #nosec G115 -- a descriptor number fits an int
	f, err := Open(op, fdPath, flag, openFile)
	if err != nil {
		return nil, err
	}
	return &Claimed{file: f}, nil
}

// Claimed is a device opened exclusively, on top of a Locked descriptor.
type Claimed struct {
	file *os.File
}

// File is the claimed descriptor. Every write of the operation goes through
// it.
func (c *Claimed) File() *os.File { return c.file }

// Close releases the claimed descriptor. It does not touch the Locked
// descriptor underneath it.
func (c *Claimed) Close() error { return c.file.Close() }
