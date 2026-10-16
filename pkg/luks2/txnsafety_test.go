// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// The write-transaction suite: every mutating call either leaves the volume as
// it found it or runs to its next consistent state, and never
// leaves a durable header naming material that is not on the device.

// txnVolume opens path through the cheap test seams.
func txnVolume(t *testing.T, path string) *Volume {
	t.Helper()
	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

// txnKey unlocks v with the test passphrase.
func txnKey(t *testing.T, v *Volume) *Key {
	t.Helper()
	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	t.Cleanup(key.Destroy)
	return key
}

// txnPassphrase is newPassphraseEnclave, destroyed at cleanup.
func txnPassphrase(t *testing.T, text string) enclave.ByteAccess {
	t.Helper()
	e := newPassphraseEnclave(t, text)
	t.Cleanup(func() { _ = e.Destroy() })
	return e
}

// cancelAfterAreaWrite returns a keyslotWriteStep that lets the keyslot-area
// write through and cancels the operation's context immediately after, so
// every later step sees a canceled context: the window between the area write
// and the header write that names it.
func cancelAfterAreaWrite(cancel context.CancelFunc) func(context.Context, *keyslotDevice, string) error {
	return func(ctx context.Context, _ *keyslotDevice, op string) error {
		err := ctx.Err()
		if op == "write the keyslot area" {
			cancel()
		}
		return err
	}
}

// T1: Format makes keyslot 0's material durable before either header copy
// names it. Every sync is a point a crash can land after; at none of them may
// a header be on the device without the material it names.
func TestVolumeFormatMakesKeyslotZeroDurableBeforeTheHeaderNamesIt(t *testing.T) {
	path := newImage(t, "format-commit-order.img")
	v := txnVolume(t, path)

	const keyslotsOffset = 0x8000 // twice the default 16 KiB header area
	type syncPoint struct{ header, material bool }
	var points []syncPoint
	observe := func(f *os.File) error {
		magic := make([]byte, len(header.Magic))
		area := make([]byte, 64)
		if _, err := f.ReadAt(magic, 0); err != nil {
			return err
		}
		if _, err := f.ReadAt(area, keyslotsOffset); err != nil {
			return err
		}
		points = append(points, syncPoint{
			header:   string(magic) == header.Magic,
			material: !bytes.Equal(area, make([]byte, len(area))),
		})
		return f.Sync()
	}
	v.sys.syncDevice = observe
	v.sys.syncKeyslotArea = observe

	pass := txnPassphrase(t, testPassphraseText)
	if err := v.Format(context.Background(), pass, FormatParams{KDF: KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond}}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if got := metadata.Keyslots["0"].Area.Offset; got != "32768" {
		t.Fatalf("keyslot 0 sits at %s, the test watches 32768", got)
	}

	if len(points) == 0 || points[0].header {
		t.Fatalf("the first durable point already carries a header (%+v): a crash there names an unwritten keyslot", points)
	}
	sawHeader, materialDurable := false, false
	for i, p := range points {
		if p.header && !materialDurable {
			t.Fatalf("sync %d has a header on the device before keyslot 0's material was made durable (%+v)", i, points)
		}
		materialDurable = materialDurable || p.material
		sawHeader = sawHeader || p.header
	}
	if !sawHeader {
		t.Fatalf("no sync point ever saw the header (%+v)", points)
	}
}

// T2: a context canceled between the keyslot-area write and the header write
// does not strand the new material; AddKeyslot runs to its commit.
func TestVolumeAddKeyslotRunsToItsCommitWhenCanceledAfterTheAreaWrite(t *testing.T) {
	v := txnVolume(t, formattedVolumeImage(t, "addkeyslot-cancel.img", "", ""))
	key := txnKey(t, v)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v.sys.keyslotWriteStep = cancelAfterAreaWrite(cancel)

	newPass := txnPassphrase(t, "a credential added under a deadline")
	info, err := v.AddKeyslot(ctx, key, newPass, KeyslotParams{KDF: KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond}})
	if err != nil {
		t.Fatalf("AddKeyslot canceled after its first write = %v, want it to run to its commit", err)
	}
	recovered, err := v.UnlockKeyslot(context.Background(), info.ID, newPass)
	if err != nil {
		t.Fatalf("the keyslot AddKeyslot committed does not open: %v", err)
	}
	recovered.Destroy()
}

// T2: the same for ChangeKeyslot, through to the wipe of the old area.
func TestVolumeChangeKeyslotRunsToItsCommitWhenCanceledAfterTheAreaWrite(t *testing.T) {
	defer parallel(t)()
	v := txnVolume(t, formattedVolumeImage(t, "changekeyslot-cancel.img", "", ""))
	key := txnKey(t, v)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v.sys.keyslotWriteStep = cancelAfterAreaWrite(cancel)

	rotated := txnPassphrase(t, "a credential rotated under a deadline")
	cheap := KeyslotParams{KDF: KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond}}
	if _, err := v.ChangeKeyslot(ctx, key, rotated, cheap); err != nil {
		t.Fatalf("ChangeKeyslot canceled after its first write = %v, want it to run to its commit", err)
	}
	v.sys.keyslotWriteStep = defaultVolumeSys().keyslotWriteStep

	recovered, err := v.Unlock(context.Background(), rotated)
	if err != nil {
		t.Fatalf("the rotated passphrase does not open the volume: %v", err)
	}
	recovered.Destroy()
	original := txnPassphrase(t, testPassphraseText)
	if old, err := v.Unlock(context.Background(), original); err == nil {
		old.Destroy()
		t.Fatal("the old passphrase still opens the volume: the rotation did not run to its end")
	}
}

// T3: ChangeKeyslot refuses a key the volume's digests do not attest before
// anything is derived or written.
func TestVolumeChangeKeyslotRefusesAKeyFromAnotherVolumeBeforeWriting(t *testing.T) {
	a := txnVolume(t, formattedVolumeImage(t, "changekeyslot-volume-a.img", "", ""))
	b := txnVolume(t, formattedVolumeImage(t, "changekeyslot-volume-b.img", "", ""))
	keyA := txnKey(t, a)

	steps := 0
	b.sys.keyslotWriteStep = func(ctx context.Context, _ *keyslotDevice, _ string) error {
		steps++
		return ctx.Err()
	}

	rotated := txnPassphrase(t, "a credential for the wrong volume")
	_, err := b.ChangeKeyslot(context.Background(), keyA, rotated, KeyslotParams{})
	if !errors.Is(err, ErrWrongKey) {
		t.Fatalf("ChangeKeyslot with another volume's key = %v, want ErrWrongKey", err)
	}
	if steps != 0 {
		t.Fatalf("ChangeKeyslot with another volume's key took %d write steps, want none", steps)
	}
	txnKey(t, b) // b still opens with its own passphrase
}

// T4: the keyslot AddRecoveryKey takes back out when its token cannot be
// recorded is taken out even if the caller's context is gone by then.
func TestVolumeAddRecoveryKeyRollsBackEvenWhenCanceledDuringTheTokenWrite(t *testing.T) {
	path := formattedVolumeImage(t, "addrecoverykey-cancel.img", "", "")
	v := txnVolume(t, path)
	key := txnKey(t, v)

	rk, err := NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey failed: %v", err)
	}
	defer rk.Destroy()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v.sys.importToken = func(ctx context.Context, _ *keyslotDevice, _ int, _ *LegacyToken) error {
		cancel()
		return &errs.Error{Kind: errs.ErrIO, Detail: "injected token write failure", Err: ctx.Err()}
	}

	_, err = v.AddRecoveryKey(ctx, key, rk, KeyslotParams{KDF: argon2TestKDF()})
	if err == nil {
		t.Fatal("AddRecoveryKey succeeded despite the injected token failure")
	}
	var orphan *OrphanedKeyslotError
	if errors.As(err, &orphan) {
		t.Fatalf("AddRecoveryKey left keyslot %d orphaned: the rollback ran under the canceled context (%v)", orphan.Keyslot, err)
	}
	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if got := len(metadata.Keyslots); got != 1 {
		t.Fatalf("keyslots after a rolled-back enrollment: %d, want 1", got)
	}
}

// T5: ChangeKeyslot keeps the slot's priority unless the caller names one.
func TestVolumeChangeKeyslotKeepsThePriorityUnlessOneIsGiven(t *testing.T) {
	defer parallel(t)()
	v := txnVolume(t, formattedVolumeImage(t, "changekeyslot-keep-priority.img", "", ""))
	key := txnKey(t, v)
	ctx := context.Background()
	kdf := KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond}

	if _, err := v.ChangeKeyslot(ctx, key, txnPassphrase(t, "first rotation"), KeyslotParams{Priority: PriorityPrefer, KDF: kdf}); err != nil {
		t.Fatalf("ChangeKeyslot(prefer) failed: %v", err)
	}
	info, err := v.ChangeKeyslot(ctx, key, txnPassphrase(t, "second rotation"), KeyslotParams{})
	if err != nil {
		t.Fatalf("ChangeKeyslot(zero params) failed: %v", err)
	}
	if info.Priority != PriorityPrefer {
		t.Fatalf("ChangeKeyslot with no priority reset prefer to %v", info.Priority)
	}
	h, err := v.Header(ctx)
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}
	for _, s := range h.Keyslots() {
		if s.ID == info.ID && s.Priority != PriorityPrefer {
			t.Fatalf("re-read priority = %v, want PriorityPrefer kept", s.Priority)
		}
	}

	info, err = v.ChangeKeyslot(ctx, key, txnPassphrase(t, "third rotation"), KeyslotParams{Priority: PriorityNormal, KDF: kdf})
	if err != nil {
		t.Fatalf("ChangeKeyslot(normal) failed: %v", err)
	}
	if info.Priority != PriorityNormal {
		t.Fatalf("an explicit PriorityNormal left priority %v", info.Priority)
	}
}

// T6: AddRecoveryKey validates its KDF parameters before it takes the lock.
func TestVolumeAddRecoveryKeyValidatesTheKDFBeforeTakingTheLock(t *testing.T) {
	v := txnVolume(t, formattedVolumeImage(t, "addrecoverykey-badkdf.img", "", ""))
	key := txnKey(t, v)

	rk, err := NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey failed: %v", err)
	}
	defer rk.Destroy()

	locks := 0
	v.sys.lockHeld = func(string) { locks++ }

	if _, err := v.AddRecoveryKey(context.Background(), key, rk, KeyslotParams{KDF: KDFParams{Type: KDFPBKDF2, Iterations: -1}}); err == nil {
		t.Fatal("AddRecoveryKey accepted a negative iteration count")
	}
	if locks != 0 {
		t.Fatalf("AddRecoveryKey took the device lock %d times before refusing invalid KDF parameters", locks)
	}
}

// T7: AddKeyslot and ChangeKeyslot derive the new area key through the
// volume's injected passphrase KDF, not a package default.
func TestVolumeKeyslotWritesDeriveThroughTheInjectedKDF(t *testing.T) {
	defer parallel(t)()
	v := txnVolume(t, formattedVolumeImage(t, "keyslot-injected-kdf.img", "", ""))
	key := txnKey(t, v)

	calls := 0
	real := v.sys.passphraseKDF
	v.sys.passphraseKDFOverride = func(ctx context.Context, p []byte, kdf *header.KDF, n int) (enclave.ByteAccess, error) {
		calls++
		return real(ctx, p, kdf, n)
	}

	if _, err := v.AddKeyslot(context.Background(), key, txnPassphrase(t, "a credential added through the seam"), KeyslotParams{KDF: KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond}}); err != nil {
		t.Fatalf("AddKeyslot failed: %v", err)
	}
	if calls == 0 {
		t.Fatal("AddKeyslot derived its area key around the injected passphraseKDF")
	}
	calls = 0
	if _, err := v.ChangeKeyslot(context.Background(), key, txnPassphrase(t, "a credential changed through the seam"), KeyslotParams{}); err != nil {
		t.Fatalf("ChangeKeyslot failed: %v", err)
	}
	if calls == 0 {
		t.Fatal("ChangeKeyslot derived its area key around the injected passphraseKDF")
	}
}

// T8: Format holds the passphrase only for the derivation, not across the
// device writes. An enclave's Destroy waits out an open borrow, so a Destroy
// that cannot finish during the writes means the borrow is still open.
func TestVolumeFormatReleasesThePassphraseBeforeTheDeviceWrites(t *testing.T) {
	v := txnVolume(t, newImage(t, "format-borrow-window.img"))
	pass := newPassphraseEnclave(t, testPassphraseText)
	defer func() { _ = pass.Destroy() }()

	observed, borrowed := false, false
	observe := func(f *os.File) error {
		if !observed {
			observed = true
			done := make(chan struct{})
			go func() { _ = pass.Destroy(); close(done) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				borrowed = true
			}
		}
		return f.Sync()
	}
	v.sys.syncDevice = observe
	v.sys.syncKeyslotArea = observe

	if err := v.Format(context.Background(), pass, FormatParams{KDF: KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond}}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}
	if !observed {
		t.Fatal("Format synced nothing through the seams")
	}
	if borrowed {
		t.Fatal("the passphrase was still borrowed while Format wrote the device")
	}
}
