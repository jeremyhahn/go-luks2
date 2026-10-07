// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package device

import (
	"context"
	"errors"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/clock"
	"github.com/jeremyhahn/go-luks2/internal/errs"
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
//
// flock does not count holders within one open file description: two shared
// holders on this descriptor hold ONE lock, and the first LOCK_UN would drop
// it under the second -- for a file image, where the node flock is
// cryptsetup's only lock, letting a foreign writer in mid-read. mu guards the
// holder count, so the flock is taken by the first holder and released by
// the last, and a writer on this same descriptor waits for the readers
// rather than converting their lock.
type Pinned struct {
	path string
	file *os.File

	mu        sync.Mutex
	shared    int
	exclusive bool
}

// OpenPinned opens path with flag and pins the descriptor to it.
func OpenPinned(ctx context.Context, op, path string, flag int, openFile OpenFunc) (*Pinned, error) {
	f, err := Open(ctx, op, path, flag, openFile)
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
func (p *Pinned) Lock(ctx context.Context, mode LockMode, wait time.Duration, clk clock.Clock, lockDir string, openLockFile OpenLockFileFunc, held func(string)) (*Locked, error) {
	started := clk.Now()
	deadline := started.Add(wait)
	if err := pollLock(ctx, p.path, started, deadline, clk, func() error { return p.acquire(mode) }); err != nil {
		return nil, err
	}
	cs, err := acquireCryptsetupLockFor(ctx, p.file, p.path, lockDir, mode, started, deadline, clk, openLockFile)
	if err != nil {
		_ = p.release(mode)
		return nil, err
	}
	if held != nil {
		held(p.path)
	}
	return &Locked{path: p.path, file: p.file, cryptsetup: cs, pinned: p, mode: mode}, nil
}

// acquire makes one non-blocking attempt at the node flock in mode, counting
// holders on this descriptor. A shared holder joins one already held; any
// other combination with a holder present is contention, reported as
// EWOULDBLOCK so pollLock waits for it like a foreign holder.
func (p *Pinned) acquire(mode LockMode) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.exclusive || (mode == LockExclusive && p.shared > 0) {
		return unix.EWOULDBLOCK
	}
	if mode == LockShared && p.shared > 0 {
		p.shared++
		return nil
	}
	if err := unix.Flock(int(p.file.Fd()), mode.flockOp()); err != nil {
		return err
	}
	if mode == LockShared {
		p.shared = 1
	} else {
		p.exclusive = true
	}
	return nil
}

// release gives up one hold taken by acquire in mode, unlocking the node
// flock only when it was the last.
func (p *Pinned) release(mode LockMode) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if mode == LockShared {
		p.shared--
		if p.shared > 0 {
			return nil
		}
	} else {
		p.exclusive = false
	}
	return unix.Flock(int(p.file.Fd()), unix.LOCK_UN)
}

// LockExisting takes the node flock and cryptsetup's lock, in mode, on a
// descriptor the caller already opened for its own reasons and whose device
// number (rdev) it already knows -- the shape an activation's metadata read
// lock needs, as opposed to Lock's, which opens the descriptor itself.
func LockExisting(ctx context.Context, f *os.File, path string, rdev uint64, mode LockMode, wait time.Duration, clk clock.Clock, lockDir string, openLockFile OpenLockFileFunc) (*Locked, error) {
	started := clk.Now()
	deadline := started.Add(wait)
	if err := pollFlock(ctx, f, path, mode, started, deadline, clk); err != nil {
		return nil, err
	}
	cs, err := AcquireCryptsetupLock(ctx, lockDir, rdev, mode, started, deadline, clk, openLockFile)
	if err != nil {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		return nil, err
	}
	return &Locked{path: path, file: f, cryptsetup: cs}, nil
}

// pollFlock flocks f in mode, retrying with backoff while another holder has
// it, until deadline. It always makes one attempt, so a lock that is free is
// never reported as contended, whatever the budget.
func pollFlock(ctx context.Context, f *os.File, path string, mode LockMode, started, deadline time.Time, clk clock.Clock) error {
	return pollLock(ctx, path, started, deadline, clk, func() error { return unix.Flock(int(f.Fd()), mode.flockOp()) })
}

// pollLock is pollFlock's loop over one non-blocking attempt, try.
func pollLock(ctx context.Context, path string, started, deadline time.Time, clk clock.Clock, try func() error) error {
	backoff := lockBackoffMin
	for attempt := 1; ; attempt++ {
		err := try()
		if err == nil {
			return nil
		}

		// CLASSIFY, do not assume contention. EWOULDBLOCK means someone else
		// holds it and waiting is the right answer. Anything else -- EBADF,
		// a descriptor closed underneath us -- will not improve by being
		// retried, and retrying it for the whole budget would report a real
		// fault as a timeout.
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return &errs.Error{Kind: errs.ErrIO, Detail: "could not lock " + path, Err: err}
		}

		// Checked AFTER an attempt, so a zero budget still tries once.
		remaining := deadline.Sub(clk.Now())
		if remaining <= 0 {
			return &LockTimeoutError{Path: path, Waited: clk.Now().Sub(started), Attempts: attempt, Err: err}
		}

		// Never sleep past the deadline: doing so would report a longer
		// wait than the caller allowed, and Waited above is meant to be
		// true.
		t := clk.NewTimer(min(backoff, remaining))
		select {
		case <-ctx.Done():
		case <-t.C():
		}
		t.Stop()
		if err := ctx.Err(); err != nil {
			return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "waiting to lock " + path, Err: err}
		}
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

	// pinned is the descriptor whose holder count this hold is part of, nil
	// for LockExisting's caller-owned descriptor.
	pinned *Pinned
	mode   LockMode
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
	if l.pinned != nil {
		return l.pinned.release(l.mode)
	}
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
func (l *Locked) Claim(ctx context.Context, op string, flag int, openFile OpenFunc) (*Claimed, error) {
	fdPath := "/proc/self/fd/" + strconv.Itoa(int(l.file.Fd())) // #nosec G115 -- a descriptor number fits an int
	f, err := Open(ctx, op, fdPath, flag, openFile)
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
