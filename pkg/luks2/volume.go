// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/internal/clock"
	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// volumeSys carries Volume's seams as fields of the handle rather than
// package-level variables, so no production path can flip one and tests can
// run in parallel. They are defaulted once at construction (Open, or a free function's
// own entry point) and never reassigned afterwards. A test that needs one
// different builds its own volumeSys (defaultVolumeSys with one field
// overridden) and either constructs a Volume carrying it directly or calls
// the unexported sys-taking core a public free function wraps -- there is no
// package-level var left to mutate.
type volumeSys struct {
	clock        clock.Clock
	lockWait     time.Duration
	openFile     device.OpenFunc
	lockDir      string
	openLockFile device.OpenLockFileFunc
	lockHeld     func(string)
	custody      secret.Custody
	cryptoRand   io.Reader
	fipsMode     func() fips.Mode

	blockDeviceOf        func(*os.File) (uint64, error)
	calibratedCountFloor func(string, keyslotCostPolicy) int
	digestIterationsFor  func(string) (int, error)
	dropDeviceCache      func(*os.File) error
	importToken          func(context.Context, *keyslotDevice, int, *LegacyToken) error
	keyslotWriteStep     func(context.Context, *keyslotDevice, string) error
	killKeyslot          func(context.Context, *keyslotDevice, int) error
	measureDeviceSize    func(*os.File) (int64, error)
	newUUID              func() uuid.UUID
	nodeRdev             func(string) (uint64, error)
	pinnedDeviceReader   func(*os.File) io.ReaderAt
	readDeviceDirect     func(context.Context, string, int64, int) ([]byte, error)
	removeFile           func(string) error
	sha1CostTimer        pbkdf2Timer
	syncDevice           func(*os.File) error
	syncKeyslotArea      func(*os.File) error

	// passphraseKDFOverride, when set, replaces the keyslot derivation
	// (volumeSys.passphraseKDF). Nil outside tests.
	passphraseKDFOverride func(context.Context, []byte, *header.KDF, int) (enclave.ByteAccess, error)
}

func defaultVolumeSys() volumeSys {
	return volumeSys{
		clock:        clock.System{},
		lockWait:     DefaultLockWait,
		openFile:     os.OpenFile,
		lockDir:      cryptsetupLockDir,
		openLockFile: device.DefaultOpenLockFile,
		lockHeld:     func(string) {},
		custody:      custody,
		cryptoRand:   rand.Reader,
		fipsMode:     fips.Probe,

		blockDeviceOf:        statBlockDeviceOf,
		calibratedCountFloor: pbkdf2FloorFor,
		digestIterationsFor:  calibrateDigestIterations,
		dropDeviceCache:      device.DropCache,
		importToken:          importTokenLocked,
		keyslotWriteStep:     func(ctx context.Context, _ *keyslotDevice, _ string) error { return ctx.Err() },
		killKeyslot:          killKeyslotLocked,
		measureDeviceSize:    deviceSizeFromFile,
		newUUID:              uuid.New,
		nodeRdev:             statRdev,
		pinnedDeviceReader:   func(f *os.File) io.ReaderAt { return f },
		readDeviceDirect: func(ctx context.Context, path string, off int64, n int) ([]byte, error) {
			return readDirectAt(ctx, path, off, n, os.OpenFile)
		},
		removeFile:      os.Remove,
		sha1CostTimer:   wallClockPBKDF2,
		syncDevice:      (*os.File).Sync,
		syncKeyslotArea: (*os.File).Sync,
	}
}

// options is what Open's variadic Option values accumulate into.
type options struct {
	readOnly    bool
	lockWait    time.Duration
	lockWaitSet bool
	sys         *volumeSys
}

// Option configures Open.
type Option func(*options)

// WithReadOnly opens the volume O_RDONLY. Every mutating method on the
// resulting Volume returns ErrReadOnly instead of touching the device.
func WithReadOnly() Option {
	return func(o *options) { o.readOnly = true }
}

// WithLockWait overrides DefaultLockWait for every lock this Volume takes.
// Zero is one non-blocking attempt; a negative d makes Open fail with
// ErrInvalidArgument.
func WithLockWait(d time.Duration) Option {
	return func(o *options) { o.lockWait, o.lockWaitSet = d, true }
}

// withTestSys replaces the sys Open would otherwise default, for a test in
// this package that needs a seam Open's public options have no room for.
// Unexported: there is no route to it outside pkg/luks2.
func withTestSys(sys volumeSys) Option {
	return func(o *options) { o.sys = &sys }
}

// Volume is a pinned descriptor on one LUKS2 device or file, and nothing
// else: Open does not require a valid header, because RestorePrimaryHeader
// and Erase must work on a damaged one. Every method takes the lock it
// needs, does its I/O and releases the lock; no lock is held between calls.
//
// A Volume is safe for concurrent use. flock does not exclude within one
// open file description, so mu serializes operations here: shared for
// reads, exclusive for writes. Concurrent readers share one node flock,
// which the pinned descriptor counts and releases only when the last of
// them leaves.
type Volume struct {
	pinned   *device.Pinned
	path     string
	readOnly bool

	mu     sync.RWMutex
	closed bool

	sys volumeSys
}

// Open pins a descriptor on path. The pin is not a lock: concurrent Volumes
// on the same path, in this process or another, are only ever excluded by
// the per-method lock each operation takes.
func Open(ctx context.Context, path string, opts ...Option) (*Volume, error) {
	if err := ctx.Err(); err != nil {
		return nil, errAt("Open", path, &errs.Error{Kind: err})
	}
	if err := validateDevicePath(path); err != nil {
		return nil, errAt("Open", path, err)
	}

	var o options
	for _, opt := range opts {
		opt(&o)
	}

	sys := defaultVolumeSys()
	if o.sys != nil {
		sys = *o.sys
	}
	if o.lockWaitSet {
		if o.lockWait < 0 {
			return nil, errAt("Open", path, &errs.Error{Kind: ErrInvalidArgument, Detail: "the lock wait must not be negative"})
		}
		sys.lockWait = o.lockWait
	}

	flag := os.O_RDWR
	if o.readOnly {
		flag = os.O_RDONLY
	}
	pinned, err := device.OpenPinned(ctx, "open the volume", path, flag, sys.openFile)
	if err != nil {
		return nil, errAt("Open", path, err)
	}

	return &Volume{pinned: pinned, path: path, readOnly: o.readOnly, sys: sys}, nil
}

// Path is the path Open pinned.
func (v *Volume) Path() string { return v.path }

// Close releases the pinned descriptor. It does not take any lock: nothing
// else needs excluding to close a descriptor nobody else can reach. It is
// idempotent.
func (v *Volume) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	v.closed = true
	if err := v.pinned.Close(); err != nil {
		return errAt("Volume.Close", v.path, &errs.Error{Kind: ErrIO, Detail: "close the device", Err: err})
	}
	return nil
}

// checkOpen reports ErrClosed, as op, if Close has already run. Callers hold
// mu (either way) for the duration of the method it guards, and name
// themselves: op is the exported method, not a helper it shares.
func (v *Volume) checkOpen(op string) error {
	if v.closed {
		return errAt(op, v.path, &errs.Error{Kind: ErrClosed})
	}
	return nil
}

// checkOpenNow is checkOpen for a method that must do work -- calling a
// KeyProvider -- before it takes mu: it refuses a closed Volume up front,
// under mu only for the check. The method checks again once it holds mu.
func (v *Volume) checkOpenNow(op string) error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.checkOpen(op)
}

// checkWritable reports ErrReadOnly, as op, if the Volume was opened with
// WithReadOnly. Callers hold mu for the duration of the method it guards.
func (v *Volume) checkWritable(op string) error {
	if v.readOnly {
		return errAt(op, v.path, &errs.Error{Kind: ErrReadOnly})
	}
	return nil
}

// lockFor takes the node flock and the cryptsetup lock on the pinned
// descriptor in mode. ctx is checked first so a call that is
// already canceled never starts waiting; Pinned.Lock takes the ctx too.
func (v *Volume) lockFor(ctx context.Context, mode device.LockMode) (*device.Locked, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return v.pinned.Lock(ctx, mode, v.sys.lockWait, v.sys.clock, v.sys.lockDir, v.sys.openLockFile, v.sys.lockHeld)
}

// errAt is this package's boundary call into errs.At: every new exported
// Volume method calls it exactly once, on the way out, naming its own Op.
// errs.At fills Op and Path only where they are empty and never stacks a
// second wrapper.
func errAt(op, path string, err error) error {
	// Nothing leaves the API unclassified or unstamped: an error that is not itself an *errs.Error -- a bare sentinel, a
	// context error, a typed error from below such as *FIPSMigrationError --
	// is wrapped here, with the kind its chain already carries or, failing
	// that, the kind errors.Is reports for it. A typed error that only holds
	// a classified cause is wrapped too: At stamps the outermost *errs.Error
	// alone, and that is the one a caller's errors.As finds.
	if _, ok := err.(*errs.Error); err != nil && !ok {
		kind := unclassifiedKind(err)
		if err == kind {
			err = &errs.Error{Kind: kind}
		} else {
			err = &errs.Error{Kind: kind, Err: err}
		}
	}
	return errs.At("luks2", op, path, err)
}

// unclassifiedKind names the kind of an error that is not itself an
// *errs.Error: ErrFIPSMigration if it is a *FIPSMigrationError (even one a
// canceled context stopped), the context error if it is one, the kind its
// chain already carries, the first sentinel
// of this package it matches, or ErrIO.
func unclassifiedKind(err error) error {
	// A migration that stopped is a migration failure whatever stopped it,
	// a canceled context included, so this is asked first: the cause stays
	// reachable through errors.Is, and the stage and state through
	// *FIPSMigrationError.
	var migration *FIPSMigrationError
	if errors.As(err, &migration) {
		return ErrFIPSMigration
	}
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	}
	if kind := errs.KindOf(err, nil); kind != nil {
		return kind
	}
	for _, kind := range []error{
		ErrInvalidArgument, ErrInvalidCredential, ErrDeviceNotFound, ErrPermissionDenied,
		ErrLockContended, ErrDeviceInUse, ErrDeviceChanged, ErrDeviceCacheStale,
		ErrUnsupported, ErrInvalidHeader, ErrWrongKey, ErrNoSpace, ErrProtectedMemory,
		ErrFIPSNotApproved, ErrClosed, ErrReadOnly,
	} {
		if errors.Is(err, kind) {
			return kind
		}
	}
	return ErrIO
}
