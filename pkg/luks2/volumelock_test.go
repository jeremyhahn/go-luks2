// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"crypto/fips140"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-enclave"
)

// foreignExclusiveProbe is what a cryptsetup writer (luksKillSlot) does
// first on a file image: LOCK_EX on its own open file description. nil means
// a writer would get in now.
func foreignExclusiveProbe(path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err
	}
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}

// holdForeignExclusive holds LOCK_EX on path from another open file
// description until the test ends -- a cryptsetup writer mid-operation.
func holdForeignExclusive(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
}

// L1: two concurrent readers on ONE Volume. The first to leave must not drop
// the shared lock the second still holds: on a file image that flock is
// cryptsetup's only lock.
func TestVolumeConcurrentReadersHoldTheLockUntilTheLastLeaves(t *testing.T) {
	path := formattedVolumeImage(t, "readers.img", "", "")

	var calls atomic.Int32
	secondHolds := make(chan struct{})
	firstLeft := make(chan struct{}, 2)
	var probe error
	sys := testVolumeSys()
	sys.lockHeld = func(string) {
		switch calls.Add(1) {
		case 1:
			<-secondHolds
		case 2:
			close(secondHolds)
			<-firstLeft
			probe = foreignExclusiveProbe(path)
		}
	}
	v, err := Open(context.Background(), path, withTestSys(sys))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = v.Header(context.Background())
			firstLeft <- struct{}{}
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("reader %d: %v", i, err)
		}
	}
	if !errors.Is(probe, unix.EWOULDBLOCK) {
		t.Fatalf("a foreign LOCK_EX while the second reader held the volume = %v, want EWOULDBLOCK", probe)
	}
}

// probingProvider calls back into the Volume and probes the device's lock
// from Passphrase -- what a FIDO2 or command provider that blocks, or that
// reads the header itself, does.
type probingProvider struct {
	fakeKeyProvider
	v         *Volume
	path      string
	headerErr error
	flockErr  error
}

// Passphrase calls Header only when it can: a Volume holding mu for writing
// would deadlock it, and a hung suite proves nothing a refusal does not.
func (p *probingProvider) Passphrase(ctx context.Context) (*enclave.Memory, error) {
	if p.v.mu.TryRLock() {
		p.v.mu.RUnlock()
		_, p.headerErr = p.v.Header(ctx)
	} else {
		p.headerErr = errors.New("deadlock: the provider was called while the Volume held its mutex for writing")
	}
	p.flockErr = foreignExclusiveProbe(p.path)
	return p.fakeKeyProvider.Passphrase(ctx)
}

func openUnlocked(t *testing.T, path string, sys volumeSys, opts ...Option) (*Volume, *Key) {
	t.Helper()
	v, err := Open(context.Background(), path, append([]Option{withTestSys(sys)}, opts...)...)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	pass := newTestPassphrase(t)
	t.Cleanup(func() { _ = pass.Destroy() })
	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	t.Cleanup(key.Destroy)
	return v, key
}

// L2: Enroll asks the provider for its credential before taking either the
// Volume's mutex or the device lock.
func TestVolumeEnrollCallsTheProviderBeforeLocking(t *testing.T) {
	path := formattedVolumeImage(t, "enroll-order.img", "", "")
	v, key := openUnlocked(t, path, testVolumeSys())

	p := &probingProvider{
		fakeKeyProvider: fakeKeyProvider{credential: []byte("a-provider-credential"), token: Token{Type: "x-provider"}},
		v:               v,
		path:            path,
	}
	if _, err := v.Enroll(context.Background(), key, p, cheapKeyslotParams()); err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
	if p.headerErr != nil {
		t.Errorf("Header from inside Passphrase: %v", p.headerErr)
	}
	if p.flockErr != nil {
		t.Errorf("a foreign writer was locked out while the provider ran: %v", p.flockErr)
	}
}

// L2: UnlockWithProvider likewise holds no lock while the provider runs.
func TestVolumeUnlockWithProviderCallsTheProviderBeforeLocking(t *testing.T) {
	path := formattedVolumeImage(t, "unlock-order.img", "", "")
	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	p := &probingProvider{
		fakeKeyProvider: fakeKeyProvider{credential: []byte(testPassphraseText), token: Token{Type: "x-provider", Keyslots: []int{0}}},
		v:               v,
		path:            path,
	}
	key, err := v.UnlockWithProvider(context.Background(), p)
	if err != nil {
		t.Fatalf("UnlockWithProvider failed: %v", err)
	}
	defer key.Destroy()
	if p.headerErr != nil {
		t.Errorf("Header from inside Passphrase: %v", p.headerErr)
	}
	if p.flockErr != nil {
		t.Errorf("a foreign writer was locked out while the provider ran: %v", p.flockErr)
	}
}

// L3: a context canceled during the token write must not also cancel the
// rollback of the keyslot just added.
func TestVolumeEnrollRollsBackUnderACanceledContext(t *testing.T) {
	path := formattedVolumeImage(t, "enroll-cancel.img", "", "")
	v, key := openUnlocked(t, path, testVolumeSys())

	before, err := listKeyslotsForTest(path)
	if err != nil {
		t.Fatalf("ListKeyslots failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v.sys.importToken = func(context.Context, *keyslotDevice, int, *LegacyToken) error {
		cancel()
		return errors.New("token slot unwritable")
	}
	provider := &fakeKeyProvider{credential: []byte("a-credential-that-must-not-survive"), token: Token{Type: "x-provider"}}

	_, err = v.Enroll(ctx, key, provider, cheapKeyslotParams())
	if err == nil {
		t.Fatal("Enroll succeeded with an unwritable token")
	}
	var orphan *OrphanedKeyslotError
	if errors.As(err, &orphan) {
		t.Fatalf("Enroll left an orphaned keyslot: %v", err)
	}
	after, err := listKeyslotsForTest(path)
	if err != nil {
		t.Fatalf("ListKeyslots failed: %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("keyslot count = %d, want %d: the rollback left a slot behind", len(after), len(before))
	}
}

// refuseExclusiveOpens makes every O_EXCL open fail EBUSY, as the kernel
// refuses one on a block device that is mapped or mounted.
func refuseExclusiveOpens(sys volumeSys) volumeSys {
	sys.openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		if flag&os.O_EXCL != 0 {
			return nil, &os.PathError{Op: "open", Path: name, Err: unix.EBUSY}
		}
		return os.OpenFile(name, flag, perm) // #nosec G304 -- a test image
	}
	return sys
}

// L4: the token writes and Enroll work on a volume in use, as AddKeyslot
// and cryptsetup token import do: the exclusive flock is what excludes
// other writers, not an exclusive open.
func TestVolumeTokenWritesWorkOnAVolumeInUse(t *testing.T) {
	path := formattedVolumeImage(t, "in-use.img", "", "")
	v, key := openUnlocked(t, path, refuseExclusiveOpens(testVolumeSys()))
	ctx := context.Background()

	id, err := v.AddToken(ctx, Token{Type: "x-in-use"})
	if err != nil {
		t.Fatalf("AddToken on a volume in use: %v", err)
	}
	if err := v.SetToken(ctx, id, Token{Type: "x-in-use-2"}); err != nil {
		t.Fatalf("SetToken on a volume in use: %v", err)
	}
	if err := v.RemoveToken(ctx, id); err != nil {
		t.Fatalf("RemoveToken on a volume in use: %v", err)
	}
	provider := &fakeKeyProvider{credential: []byte("a-provider-credential"), token: Token{Type: "x-provider"}}
	if _, err := v.Enroll(ctx, key, provider, cheapKeyslotParams()); err != nil {
		t.Fatalf("Enroll on a volume in use: %v", err)
	}
}

// L5: MigrateToFIPS works on the descriptor Open pinned, not on whatever the
// path names by the time it runs.
func TestVolumeMigrateToFIPSStaysOnThePinnedDevice(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	pinned := argon2VolumeImage(t, "pinned.img")
	other := argon2VolumeImage(t, "other.img")
	otherBefore := fileDigest(t, other)

	link := filepath.Join(t.TempDir(), "device")
	if err := os.Symlink(pinned, link); err != nil {
		t.Fatal(err)
	}
	v, err := Open(context.Background(), link, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, link); err != nil {
		t.Fatal(err)
	}

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()
	migration, err := v.MigrateToFIPS(context.Background(), pass, MigrateParams{KDF: cheapMigrationParams()})
	if err != nil {
		t.Fatalf("MigrateToFIPS failed: %v", err)
	}
	if !migration.Complete {
		t.Fatalf("the migration is incomplete: %+v", migration)
	}
	if fileDigest(t, other) != otherBefore {
		t.Fatal("MigrateToFIPS wrote to the device the path was re-pointed at, not the one Open pinned")
	}
	assertFIPSReady(t, pinned)
}

// L5: MigrateToFIPS honors WithLockWait like every other Volume method.
func TestVolumeMigrateToFIPSHonorsWithLockWait(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	path := argon2VolumeImage(t, "migrate-lockwait.img")
	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()), WithLockWait(10*time.Millisecond))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()
	holdForeignExclusive(t, path)

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()
	started := time.Now()
	_, err = v.MigrateToFIPS(context.Background(), pass, MigrateParams{KDF: cheapMigrationParams()})
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("MigrateToFIPS waited %v for a contended lock, want the 10ms WithLockWait gave it", elapsed)
	}
	var lte *LockTimeoutError
	if !errors.As(err, &lte) {
		t.Fatalf("MigrateToFIPS on a contended volume = %v, want a LockTimeoutError", err)
	}
}

// L6: Enroll refuses what AddKeyslot refuses -- an out-of-range Argon2 cost,
// a credential outside the passphrase bounds -- before it locks anything.
func TestVolumeEnrollRunsAddKeyslotsCreationChecks(t *testing.T) {
	path := formattedVolumeImage(t, "enroll-checks.img", "", "")
	var locks atomic.Int32
	sys := testVolumeSys()
	sys.lockHeld = func(string) { locks.Add(1) }
	v, key := openUnlocked(t, path, sys)
	ctx := context.Background()

	cases := []struct {
		name       string
		credential string
		params     KeyslotParams
		check      func(error) bool
	}{
		{"argon2 memory below the floor", "a-provider-credential",
			KeyslotParams{KDF: KDFParams{Type: KDFArgon2id, Time: 1, MemoryKiB: 8, Parallel: 1}},
			func(err error) bool {
				// A FIPS process refuses argon2 before it judges the cost.
				if fips140.Enabled() {
					return errors.Is(err, ErrFIPSNotApproved)
				}
				var ce *KDFCostError
				return errors.As(err, &ce)
			}},
		{"one-byte credential", "x", cheapKeyslotParams(),
			func(err error) bool { return errors.Is(err, ErrInvalidCredential) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			locks.Store(0)
			provider := &fakeKeyProvider{credential: []byte(tc.credential), token: Token{Type: "x-provider"}}
			_, err := v.Enroll(ctx, key, provider, tc.params)
			if !tc.check(err) {
				t.Fatalf("Enroll = %v, want the refusal AddKeyslot gives", err)
			}
			if n := locks.Load(); n != 0 {
				t.Errorf("Enroll took the device lock %d time(s) before refusing", n)
			}
		})
	}
}

// L7: WithLockWait(0) is one non-blocking attempt, not the 30s default.
func TestWithLockWaitZeroTriesOnce(t *testing.T) {
	path := formattedVolumeImage(t, "lockwait-zero.img", "", "")
	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()), WithLockWait(0))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()
	if v.sys.lockWait != 0 {
		t.Fatalf("lockWait = %v, want 0", v.sys.lockWait)
	}
	holdForeignExclusive(t, path)

	started := time.Now()
	_, err = v.Header(context.Background())
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("Header waited %v with WithLockWait(0)", elapsed)
	}
	var lte *LockTimeoutError
	if !errors.As(err, &lte) {
		t.Fatalf("Header on a contended volume = %v, want a LockTimeoutError", err)
	}
	if lte.Attempts != 1 {
		t.Errorf("attempts = %d, want exactly one", lte.Attempts)
	}
}

// L7: a negative wait is a caller error, not a silent default.
func TestWithLockWaitNegativeIsInvalid(t *testing.T) {
	path := formattedVolumeImage(t, "lockwait-negative.img", "", "")
	_, err := Open(context.Background(), path, WithLockWait(-time.Second))
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Open with WithLockWait(-1s) = %v, want ErrInvalidArgument", err)
	}
}
