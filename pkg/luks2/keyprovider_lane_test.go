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
	"path/filepath"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// enrollRecoveryKeyForTest opens image, unlocks it with existing and enrolls
// a fresh NewRecoveryKey, the way the pre-redesign library's
// AddRecoveryKey(image, existing, &RecoveryKeyOptions{...}) did before B.6
// moved it behind (*Volume).AddRecoveryKey. It returns the enrolled
// credential's formatted text alongside the keyslot and token it was
// recorded under.
func enrollRecoveryKeyForTest(t *testing.T, image string, existing []byte, opts ...Option) (credential string, keyslot, tokenID int, err error) {
	t.Helper()

	ctx := context.Background()
	v, err := Open(ctx, image, cheapOpts(opts)...)
	if err != nil {
		return "", -1, -1, err
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryCopy(existing)
	if err != nil {
		return "", -1, -1, err
	}
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(ctx, pass)
	if err != nil {
		return "", -1, -1, err
	}
	defer key.Destroy()

	rk, err := NewRecoveryKey()
	if err != nil {
		return "", -1, -1, err
	}
	defer rk.Destroy()

	enrollment, err := v.AddRecoveryKey(ctx, key, rk, KeyslotParams{KDF: KDFParams{Type: KDFPBKDF2, Iterations: recoveryTestIterations}})
	if err != nil {
		return "", -1, -1, err
	}

	var buf bytes.Buffer
	if _, err := rk.WriteTo(&buf); err != nil {
		return "", -1, -1, err
	}
	return buf.String(), enrollment.Keyslot.ID, enrollment.Token, nil
}

// Regression tests for #246 D8-D9: two enrollments at once, and a device
// lock's own refusals. The exec-helper regressions (#246 D5-D7: how a helper
// is found and what it inherits, a helper whose output outlives it, the
// FIDO2 device argument) moved to pkg/keyprovider with the code they pin
// (#271).

// TestConcurrentEnrollmentsKeepBothTokens is #246 D8. The token slot was
// chosen before the keyslot was written, and each step took the device lock
// on its own, so a second enrollment running while the first had written its
// keyslot but not yet its token found the same slot free -- and one token
// overwrote the other, leaving a keyslot nothing describes.
//
// The interleaving is forced rather than hoped for: the first enrollment is
// held at its token write, the second is started, and the first is released
// only once the second has opened the device for writing. Under one lock the
// second waits there for the first; without it, it has already chosen the
// first's token slot.
func TestConcurrentEnrollmentsKeepBothTokens(t *testing.T) {
	image := newImage(t, "concurrent-enroll.img")
	formatWithLibrary(t, image)

	// The existing credential both enrollments unlock with is made cheap
	// first -- a minimum-cost keyslot, and the formatted one removed -- so
	// the test pays one full derivation rather than one per enrollment.
	existing, _, openerToken, err := enrollRecoveryKeyForTest(t, image, []byte(conformancePassphrase))
	if err != nil {
		t.Fatal(err)
	}
	if err := killKeyslotForTest(image, 0); err != nil {
		t.Fatal(err)
	}
	if err := removeTokenForTest(image, openerToken); err != nil {
		t.Fatal(err)
	}

	held := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	sys := testVolumeSys()
	previousImport := sys.importToken
	sys.importToken = func(ctx context.Context, dev *keyslotDevice, id int, token *LegacyToken) error {
		first := false
		once.Do(func() { first = true })
		if first {
			close(held)
			<-release
		}
		return previousImport(ctx, dev, id, token)
	}

	var armed sync.Once
	opened := make(chan struct{})
	watching := make(chan struct{})
	previousOpen := sys.openFile
	sys.openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		select {
		case <-watching:
			if name == image && flag&(os.O_RDWR|os.O_WRONLY) != 0 {
				armed.Do(func() { close(opened) })
			}
		default:
		}
		return previousOpen(name, flag, perm)
	}

	// Enrolled through AddRecoveryKey, which shares enrollWithToken with
	// (*Volume).Enroll and, holding a credential this package drew, may use
	// the minimum iteration count: the subject is the token slot, not the KDF.
	enroll := func(string) (int, int, error) {
		_, slot, tok, err := enrollRecoveryKeyForTest(t, image, []byte(existing), withTestSys(sys))
		return slot, tok, err
	}

	type result struct {
		slot, token int
		err         error
	}
	first := make(chan result, 1)
	go func() {
		s, tok, err := enroll("first-credential")
		first <- result{s, tok, err}
	}()
	<-held

	close(watching)
	second := make(chan result, 1)
	go func() {
		s, tok, err := enroll("second-credential")
		second <- result{s, tok, err}
	}()
	<-opened
	close(release)

	a, b := <-first, <-second
	if a.err != nil || b.err != nil {
		t.Fatalf("enrollments failed: %v / %v", a.err, b.err)
	}
	if a.token == b.token {
		t.Fatalf("both enrollments were given token %d", a.token)
	}
	tokens, err := listTokensForTest(image)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []result{a, b} {
		tok, ok := tokens[r.token]
		if !ok || len(tok.Keyslots) != 1 || tok.Keyslots[0] != r.slot {
			t.Fatalf("token %d = %+v, want it to name keyslot %d (all tokens: %+v)", r.token, tok, r.slot, tokens)
		}
	}
}

// TestEnrollmentRefusesATokenSlotTakenUnderItsLock: the locked token write
// will not overwrite a slot it finds occupied, and refuses what
// (*Volume).SetToken refuses.
func TestEnrollmentRefusesATokenSlotTakenUnderItsLock(t *testing.T) {
	defer parallel(t)()

	image := newImage(t, "taken.img")
	formatWithLibrary(t, image)
	if err := setTokenForTest(image, 0, Token{Type: "x-existing", Keyslots: []int{0}}); err != nil {
		t.Fatal(err)
	}

	// The locked helpers act only on a device pinned to its locked descriptor
	// (#255); there is no device without one to hand them.
	dev := lockedDevice(t, image)
	if err := importTokenLocked(context.Background(), dev, 0, &LegacyToken{Type: "x-new"}); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("importTokenLocked over a taken slot = %v, want ErrNoSpace", err)
	}
	if err := importTokenLocked(context.Background(), dev, MaxTokens, &LegacyToken{Type: "x-new"}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("importTokenLocked out of range = %v, want ErrInvalidHeader", err)
	}
	if err := importTokenLocked(context.Background(), dev, 1, nil); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("importTokenLocked of no token = %v, want ErrInvalidHeader", err)
	}
	if err := killKeyslotLocked(context.Background(), dev, 7); !errors.Is(err, ErrKeyslotNotFound) {
		t.Fatalf("killKeyslotLocked of an absent slot = %v, want ErrInvalidKeyslot", err)
	}
	if _, _, err := lockKeyslotDevice(context.Background(), filepath.Join(t.TempDir(), "absent"), testVolumeSys()); err == nil {
		t.Fatal("a device that does not exist was locked and pinned")
	}
}

// TestEnrollmentRollbackStaysOnTheEnrolledDevice: the rollback of a keyslot
// whose token could not be written removes it through the locked descriptor
// the enrollment wrote with. Here the path is retargeted at the moment the
// token write fails; a rollback that reopened the path would act on the
// replacement and leave the new credential live, orphaned, on the original.
func TestEnrollmentRollbackStaysOnTheEnrolledDevice(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join(dir, "enrolled.img")
	if err := os.WriteFile(image, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(image, conformanceImageSize); err != nil {
		t.Fatal(err)
	}
	formatWithLibrary(t, image)
	before, err := listKeyslotsForTest(image)
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(dir, "moved.img")
	pristine, err := os.ReadFile(image) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}

	sys := testVolumeSys()
	sys.importToken = func(context.Context, *keyslotDevice, int, *LegacyToken) error {
		if err := os.Rename(image, moved); err != nil {
			return err
		}
		if err := os.WriteFile(image, pristine, 0o600); err != nil {
			return err
		}
		return errors.New("the header could not be written")
	}

	_, _, _, err = enrollRecoveryKeyForTest(t, image, []byte(conformancePassphrase), withTestSys(sys))
	if err == nil || errors.Is(err, ErrOrphanedKeyslot) {
		t.Fatalf("AddRecoveryKey = %v, want a rolled-back failure", err)
	}
	after, err := listKeyslotsForTest(moved)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("the enrolled device has %d keyslots after the rollback, want %d: the rollback acted on the path, not the descriptor", len(after), len(before))
	}
	if got, _ := os.ReadFile(image); !bytes.Equal(got, pristine) { // #nosec G304 -- under t.TempDir()
		t.Fatal("the rollback wrote to the file that replaced the path")
	}
}
