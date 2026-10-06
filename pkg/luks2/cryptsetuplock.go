// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"os"
	"time"

	"github.com/jeremyhahn/go-luks2/internal/clock"
	"github.com/jeremyhahn/go-luks2/internal/device"
)

// cryptsetupLockDir is cryptsetup's default locking directory. A variable so
// this package's tests can lock in a directory of their own; nothing else
// changes it. The real locking (node flock, cryptsetup's own lock file,
// O_DIRECT medium reads) lives in internal/device; this file keeps only the
// metadata READ lock, which unlock.go takes on a descriptor it already
// opened for other reasons.
var cryptsetupLockDir = "/run/cryptsetup"

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
	locked   *device.Locked
	released bool
}

// metadataReadLockWait is how long an activation waits for a writer to
// release the metadata -- the same budget, for the same reason, as
// AcquireFileLock's DefaultLockWait.
const metadataReadLockWait = DefaultLockWait

// acquireMetadataReadLock takes the read lock on the block device rdev open as
// node, waiting up to wait for a writer to finish.
func acquireMetadataReadLock(node *os.File, device_ string, rdev uint64, wait time.Duration, clk clock.Clock) (*metadataReadLock, error) {
	locked, err := device.LockExisting(node, device_, rdev, device.LockShared, wait, clk, cryptsetupLockDir, device.DefaultOpenLockFile)
	if err != nil {
		return nil, err
	}
	return &metadataReadLock{locked: locked}, nil
}

// release gives up both locks, cryptsetup's first since it was taken second.
// It does not close node: the caller that opened it owns it. It is
// idempotent, so an early release on the success path and a deferred one for
// every other path can both be written.
func (l *metadataReadLock) release() {
	if l == nil || l.released {
		return
	}
	l.released = true
	_ = l.locked.Unlock()
}
