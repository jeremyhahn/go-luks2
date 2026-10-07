// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package device

import (
	"context"
	"errors"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/clock"
)

func lockRegular(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "luks-device-lock-*")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

func openAndLock(t *testing.T, ctx context.Context, path string, wait time.Duration, clk clock.Clock) (*Pinned, *Locked, error) {
	t.Helper()
	pinned, err := OpenPinned(ctx, "lock the device", path, os.O_RDWR, os.OpenFile)
	if err != nil {
		return nil, nil, err
	}
	locked, err := pinned.Lock(ctx, LockExclusive, wait, clk, t.TempDir(), DefaultOpenLockFile, nil)
	if err != nil {
		_ = pinned.Close()
		return nil, nil, err
	}
	return pinned, locked, nil
}

// TestLockWaitsForARelease is #107's unit half, on Pinned.Lock directly: a
// held lock makes a second Lock queue and succeed once it is released, noticed
// within one backoff step rather than at the deadline.
func TestLockWaitsForARelease(t *testing.T) {
	path := lockRegular(t)

	_, held, err := openAndLock(t, context.Background(), path, DefaultLockWait, clock.System{})
	if err != nil {
		t.Fatalf("first Lock: %v", err)
	}

	const holdFor = 50 * time.Millisecond
	clk := clock.NewFake(t)
	released := false
	clk.OnWait(func(time.Time) {
		if !released && clk.Elapsed() >= holdFor {
			if err := held.Unlock(); err != nil {
				t.Errorf("Unlock: %v", err)
			}
			released = true
		}
	})

	_, second, err := openAndLock(t, context.Background(), path, 10*time.Second, clk)
	if err != nil {
		t.Fatalf("second Lock: %v, want it to queue and succeed", err)
	}
	defer func() { _ = second.Unlock() }()

	if !released {
		t.Fatal("the second lock was granted while the first was still held")
	}
	if waited := clk.Elapsed(); waited < holdFor || waited > holdFor+LockBackoffMax {
		t.Errorf("acquired after %v, want within %v of the %v release", waited, LockBackoffMax, holdFor)
	}
	if len(clk.Waits()) < 2 || clk.Waits()[0] != LockBackoffMin || clk.Waits()[1] != 2*LockBackoffMin {
		t.Errorf("backoff began %v, want %v then %v", clk.Waits(), LockBackoffMin, 2*LockBackoffMin)
	}
}

// TestLockTimesOutWithATypedError: a holder that never releases produces a
// bounded, typed, actionable failure.
func TestLockTimesOutWithATypedError(t *testing.T) {
	path := lockRegular(t)

	_, held, err := openAndLock(t, context.Background(), path, DefaultLockWait, clock.System{})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	defer func() { _ = held.Unlock() }()

	const budget = 30 * time.Millisecond
	clk := clock.NewFake(t)
	_, _, err = openAndLock(t, context.Background(), path, budget, clk)
	if err == nil {
		t.Fatal("Lock on a held lock = nil, want a timeout")
	}
	if !errors.Is(err, ErrLockContended) {
		t.Errorf("errors.Is(err, ErrLockContended) = false for %#v", err)
	}
	var lockErr *LockTimeoutError
	if !errors.As(err, &lockErr) {
		t.Fatalf("errors.As(err, *LockTimeoutError) = false for %v", err)
	}
	if lockErr.Path != path {
		t.Errorf("LockTimeoutError.Path = %q, want %q", lockErr.Path, path)
	}
	if clk.Elapsed() != budget || lockErr.Waited != budget {
		t.Errorf("waited %v and reported %v against a %v budget", clk.Elapsed(), lockErr.Waited, budget)
	}
	if lockErr.Attempts != len(clk.Waits())+1 {
		t.Errorf("Attempts = %d after %d sleeps", lockErr.Attempts, len(clk.Waits()))
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name the locked path", err.Error())
	}
}

// TestLockZeroBudgetTriesOnce: a non-positive budget is one attempt and no
// sleep.
func TestLockZeroBudgetTriesOnce(t *testing.T) {
	free := lockRegular(t)
	if _, locked, err := openAndLock(t, context.Background(), free, 0, clock.System{}); err != nil {
		t.Fatalf("Lock(free, 0) = %v, want success on the first attempt", err)
	} else {
		defer func() { _ = locked.Unlock() }()
	}

	held := lockRegular(t)
	_, h, err := openAndLock(t, context.Background(), held, DefaultLockWait, clock.System{})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	defer func() { _ = h.Unlock() }()

	clk := clock.NewFake(t)
	if _, _, err := openAndLock(t, context.Background(), held, 0, clk); err == nil {
		t.Fatal("Lock(held, 0) = nil, want a timeout")
	} else if len(clk.Waits()) != 0 {
		t.Errorf("a zero budget slept %d times, want none", len(clk.Waits()))
	}
}

// TestPollFlockClassifiesANonContentionFailure: an error other than
// EWOULDBLOCK (a closed descriptor) is reported as an Error, not retried as
// contention.
func TestPollFlockClassifiesANonContentionFailure(t *testing.T) {
	f, err := os.CreateTemp("", "luks-device-pollflock-*")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	defer func() { _ = os.Remove(path) }()
	_ = f.Close() // closed: flock on it fails EBADF, not EWOULDBLOCK

	clk := clock.NewFake(t)
	err = pollFlock(context.Background(), f, path, LockExclusive, clk.Now(), clk.Now().Add(time.Second), clk)
	var de *errs.Error
	if !errors.As(err, &de) || de.Kind == nil {
		t.Fatalf("pollFlock on a closed descriptor = %v, want a classified *errs.Error", err)
	}
}

// TestClaimReopensTheLockedInode: Claim targets the same file the lock is
// held on, and an exclusive claim of a REGULAR file succeeds even though the
// node is already open, because O_EXCL without O_CREAT has no effect on one.
func TestClaimReopensTheLockedInode(t *testing.T) {
	path := lockRegular(t)
	pinned, locked, err := openAndLock(t, context.Background(), path, DefaultLockWait, clock.System{})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	defer func() { _ = locked.Unlock(); _ = pinned.Close() }()

	claimed, err := locked.Claim(context.Background(), "claim the device", os.O_RDWR|os.O_EXCL, os.OpenFile)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	defer func() { _ = claimed.Close() }()

	var a, b os.FileInfo
	if a, err = locked.File().Stat(); err != nil {
		t.Fatal(err)
	}
	if b, err = claimed.File().Stat(); err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(a, b) {
		t.Fatal("the claimed descriptor is not the file the lock is held on")
	}
}

// TestLockExistingReleasesTheNodeFlockWhenTheCryptsetupLockFails: the node
// flock is taken first; if cryptsetup's lock then fails, LockExisting must
// give the flock back rather than leave it held with no Locked to release it.
func TestLockExistingReleasesTheNodeFlockWhenTheCryptsetupLockFails(t *testing.T) {
	path := lockRegular(t)
	f, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- under lockRegular's TempDir
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	// A lock "directory" that is a plain file: openCryptsetupLockDir refuses
	// it, so AcquireCryptsetupLock fails after the flock is already held.
	notADir := lockRegular(t)
	clk := clock.NewFake(t)
	if _, err := LockExisting(context.Background(), f, path, 0, LockShared, DefaultLockWait, clk, notADir, DefaultOpenLockFile); err == nil {
		t.Fatal("LockExisting with an unusable lock directory = nil, want an error")
	}

	// The flock must have been released: a second shared lock on the same
	// descriptor's node succeeds immediately.
	other, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- under lockRegular's TempDir
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	if err := pollFlock(context.Background(), other, path, LockShared, clk.Now(), clk.Now(), clk); err != nil {
		t.Fatalf("the node flock was not released after the cryptsetup lock failed: %v", err)
	}
}

// TestClaimFailurePropagatesTheOpenError: Claim forwards a classified open
// failure rather than returning a nil Claimed and a nil error.
func TestClaimFailurePropagatesTheOpenError(t *testing.T) {
	path := lockRegular(t)
	pinned, locked, err := openAndLock(t, context.Background(), path, DefaultLockWait, clock.System{})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	defer func() { _ = locked.Unlock(); _ = pinned.Close() }()

	refuse := func(string, int, os.FileMode) (*os.File, error) {
		return nil, errors.New("injected: claim refused")
	}
	if claimed, err := locked.Claim(context.Background(), "claim the device", os.O_RDWR|os.O_EXCL, refuse); err == nil || claimed != nil {
		t.Fatalf("Claim against a refusing opener = %v, %v, want a nil Claimed and an error", claimed, err)
	}
}

// TestLockExistingSharesAcrossReaders: LockExisting is the shared-lock path
// an activation's metadata read takes on a descriptor it already opened
// itself; it does not close that descriptor on Unlock.
func TestLockExistingSharesAcrossReaders(t *testing.T) {
	path := lockRegular(t)
	f, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- under t.TempDir() equivalent
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	clk := clock.NewFake(t)
	locked, err := LockExisting(context.Background(), f, path, 0, LockShared, DefaultLockWait, clk, t.TempDir(), DefaultOpenLockFile)
	if err != nil {
		t.Fatalf("LockExisting: %v", err)
	}
	if err := locked.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	// The descriptor given to LockExisting is still open and usable: Unlock
	// did not close it.
	if _, err := f.Stat(); err != nil {
		t.Fatalf("the descriptor was closed by Unlock: %v", err)
	}
	// Idempotent.
	if err := locked.Unlock(); err != nil {
		t.Fatalf("second Unlock: %v", err)
	}
}

// TestPinnedAccessors covers Path/File/Close and Locked's Path/File, which
// nothing above exercises directly.
func TestPinnedAccessors(t *testing.T) {
	path := lockRegular(t)
	pinned, err := OpenPinned(context.Background(), "lock the device", path, os.O_RDWR, os.OpenFile)
	if err != nil {
		t.Fatalf("OpenPinned: %v", err)
	}
	if pinned.Path() != path {
		t.Errorf("Path() = %q, want %q", pinned.Path(), path)
	}
	if pinned.File() == nil {
		t.Fatal("File() = nil")
	}
	locked, err := pinned.Lock(context.Background(), LockExclusive, DefaultLockWait, clock.System{}, t.TempDir(), DefaultOpenLockFile, nil)
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	defer func() { _ = locked.Unlock() }()
	if locked.Path() != path {
		t.Errorf("Locked.Path() = %q, want %q", locked.Path(), path)
	}
	if locked.File() == nil {
		t.Fatal("Locked.File() = nil")
	}
}

// TestOpenPinnedFailure: OpenPinned surfaces a classified open failure and
// returns no Pinned.
func TestOpenPinnedFailure(t *testing.T) {
	if _, err := OpenPinned(context.Background(), "lock the device", "/nonexistent/path/for/sure", os.O_RDWR, os.OpenFile); err == nil {
		t.Fatal("OpenPinned(nonexistent) = nil, want an error")
	}
}

// TestLockCancelledDuringNodeFlockWaitReturnsCtxErr is D.2's "Node flock,
// cryptsetup lock" row: a ctx canceled while Lock is backed off waiting for
// the node flock surfaces ctx.Err()'s kind, not a LockTimeoutError, and the
// canceled waiter leaves no trace -- the flock is free again as soon as the
// real holder releases it.
func TestLockCancelledDuringNodeFlockWaitReturnsCtxErr(t *testing.T) {
	path := lockRegular(t)

	_, held, err := openAndLock(t, context.Background(), path, DefaultLockWait, clock.System{})
	if err != nil {
		t.Fatalf("first Lock: %v", err)
	}

	clk := clock.NewFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	clk.OnWait(func(time.Time) { cancel() })

	pinned, locked, err := openAndLock(t, ctx, path, 10*time.Second, clk)
	if locked != nil {
		t.Fatal("Lock canceled mid-wait returned a non-nil Locked")
	}
	if pinned != nil {
		t.Fatal("Lock canceled mid-wait returned a non-nil Pinned")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Lock canceled mid-wait = %v, want context.Canceled", err)
	}
	var lockErr *LockTimeoutError
	if errors.As(err, &lockErr) {
		t.Fatalf("Lock canceled mid-wait returned a LockTimeoutError (%v), want ctx.Err()'s kind", err)
	}

	// State left behind: the canceled waiter holds nothing, so the flock is
	// free the instant the real holder releases it.
	if err := held.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	freePinned, freeLocked, err := openAndLock(t, context.Background(), path, DefaultLockWait, clock.System{})
	if err != nil {
		t.Fatalf("a fresh Lock after the real holder released = %v, want success", err)
	}
	_ = freeLocked.Unlock()
	_ = freePinned.Close()
}

// Two shared holders on ONE pinned descriptor share one open file
// description, and flock does not count holders on it: the first LOCK_UN
// would drop the lock the second still believes it holds. For a file image
// the node flock is cryptsetup's only lock, so a foreign writer
// (luksKillSlot) could then write under the second reader. The lock must stay
// until the last shared holder releases it.
func TestPinnedSharedLockHeldUntilTheLastReaderReleases(t *testing.T) {
	ctx := context.Background()
	path := lockRegular(t)
	clk := clock.NewFake(t)
	pinned, err := OpenPinned(ctx, "lock the device", path, os.O_RDWR, os.OpenFile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pinned.Close() }()

	lockDir := t.TempDir()
	a, err := pinned.Lock(ctx, LockShared, 0, clk, lockDir, DefaultOpenLockFile, nil)
	if err != nil {
		t.Fatalf("reader A: %v", err)
	}
	b, err := pinned.Lock(ctx, LockShared, 0, clk, lockDir, DefaultOpenLockFile, nil)
	if err != nil {
		t.Fatalf("reader B: %v", err)
	}

	foreign, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = foreign.Close() }()
	tryWriter := func() error { return unix.Flock(int(foreign.Fd()), unix.LOCK_EX|unix.LOCK_NB) }

	if err := a.Unlock(); err != nil {
		t.Fatalf("reader A unlock: %v", err)
	}
	if err := tryWriter(); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("foreign LOCK_EX while reader B still holds the shared lock = %v, want EWOULDBLOCK", err)
	}

	if err := b.Unlock(); err != nil {
		t.Fatalf("reader B unlock: %v", err)
	}
	if err := tryWriter(); err != nil {
		t.Fatalf("foreign LOCK_EX after the last reader released = %v, want success", err)
	}
	_ = unix.Flock(int(foreign.Fd()), unix.LOCK_UN)
}

// A writer on the same pinned descriptor as a shared holder must wait for
// it: LOCK_EX on the reader's own open file description would silently
// convert the reader's lock rather than exclude it.
func TestPinnedExclusiveWaitsForASharedHolderOnTheSameDescriptor(t *testing.T) {
	ctx := context.Background()
	path := lockRegular(t)
	clk := clock.NewFake(t)
	pinned, err := OpenPinned(ctx, "lock the device", path, os.O_RDWR, os.OpenFile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pinned.Close() }()

	lockDir := t.TempDir()
	r, err := pinned.Lock(ctx, LockShared, 0, clk, lockDir, DefaultOpenLockFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pinned.Lock(ctx, LockExclusive, 0, clk, lockDir, DefaultOpenLockFile, nil)
	var te *LockTimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("exclusive lock over a shared holder on the same descriptor = %v, want a LockTimeoutError", err)
	}
	if err := r.Unlock(); err != nil {
		t.Fatal(err)
	}
	w, err := pinned.Lock(ctx, LockExclusive, 0, clk, lockDir, DefaultOpenLockFile, nil)
	if err != nil {
		t.Fatalf("exclusive lock after the reader released: %v", err)
	}
	_ = w.Unlock()
}
