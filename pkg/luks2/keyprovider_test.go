// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// Tests for (*Volume).Enroll and UnlockWithProvider's own bookkeeping: the
// keyslot/token sequencing, the rollback on an unwritable token, and the
// error vocabulary. The exec mechanics -- a real helper, FIDO2, the base64
// round trip -- moved to pkg/keyprovider with the code that implements them
// (#271), along with their own tests.

// fakeKeyProvider is a minimal KeyProvider test double: it hands back a
// fixed credential (or a fixed failure) and a fixed token, with none of the
// process exec machinery a real provider needs.
type fakeKeyProvider struct {
	credential []byte
	token      Token
	err        error
}

func (p *fakeKeyProvider) Token() Token { return p.token }

func (p *fakeKeyProvider) Passphrase(context.Context) (*enclave.MemoryEnclave, error) {
	if p.err != nil {
		return nil, p.err
	}
	return custody.Clone("fake provider credential", p.credential)
}

// shellQuote renders s as a single-quoted shell word. Used by this package's
// other fixture-building tests (filesystem_test.go, activation_test.go) that
// write their own throwaway shell scripts; the FIDO2/helper fixture builders
// that used to live here moved to pkg/keyprovider's own tests (#271).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// enrollForTest opens image, unlocks it with existing and enrolls provider
// via (*Volume).Enroll at the fixtures' cheap PBKDF2-sha512 cost, the way
// the pre-redesign library's free-function enroll (image, existing, provider,
// opts) did before B.6 moved it behind the Volume. It returns the enrolled
// keyslot and token id.
func enrollForTest(t *testing.T, image string, existing []byte, provider KeyProvider, opts ...Option) (slot, tokenID int, err error) {
	t.Helper()

	ctx := context.Background()
	v, err := Open(ctx, image, cheapOpts(opts)...)
	if err != nil {
		return -1, -1, err
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy(existing)
	if err != nil {
		return -1, -1, err
	}
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(ctx, pass)
	if err != nil {
		return -1, -1, err
	}
	defer key.Destroy()

	enrollment, err := v.Enroll(ctx, key, provider, cheapKeyslotParams())
	if err != nil {
		return -1, -1, err
	}
	return enrollment.Keyslot.ID, enrollment.Token, nil
}

// TestVolumeEnrollWritesTheKeyslotAndTheTokenThatNamesIt is the
// end-to-end statement, against a real container and checked with cryptsetup.
//
// The credential the provider hands back must open the volume for the THIRD
// PARTY, not merely for this package: a keyslot only this library can use is
// exactly the failure the conformance suite exists to catch.
func TestVolumeEnrollWritesTheKeyslotAndTheTokenThatNamesIt(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	image := newImage(t, "enroll.img")
	formatWithLibrary(t, image)

	const credential = "a-credential-from-somewhere-else"
	provider := &fakeKeyProvider{
		credential: []byte(credential),
		token: Token{Type: "systemd-fido2", Members: map[string]json.RawMessage{
			"fido2-credential": json.RawMessage(`"AAAA"`),
			"fido2-salt":       json.RawMessage(`"AAAA"`),
		}},
	}

	slot, tokenID, err := enrollForTest(t, image, []byte(conformancePassphrase), provider)
	if err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}
	if slot < 0 {
		t.Fatalf("keyslot = %d, want a real slot", slot)
	}

	// The token names the slot that was actually used -- read from where addKey
	// chose it, not inferred from the header afterwards (#42).
	token, ok, err := getTokenForTest(image, tokenID)
	if err != nil {
		t.Fatalf("getTokenForTest(%d) error = %v", tokenID, err)
	}
	if !ok {
		t.Fatalf("Tokens()[%d] missing after Enroll", tokenID)
	}
	if len(token.Keyslots) != 1 || token.Keyslots[0] != slot {
		t.Errorf("token keyslots = %v, want [%d]", token.Keyslots, slot)
	}
	if token.Type != "systemd-fido2" {
		t.Errorf("token type = %q, want %q", token.Type, "systemd-fido2")
	}

	// cryptsetup, not this package, decides whether the credential works.
	if code, out := runCryptsetup(t, credential, "luksOpen", "--test-passphrase", image); code != 0 {
		t.Fatalf("cryptsetup rejected the enrolled credential (exit %d): %s", code, out)
	}

	// And the credential the caller started with still opens it: enrolling adds
	// a keyslot, it does not replace one.
	if code, out := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", image); code != 0 {
		t.Fatalf("cryptsetup rejected the original passphrase (exit %d): %s", code, out)
	}
}

// TestVolumeEnrollRollsBackAKeyslotItCannotIdentify is the orphan
// guarantee, checked against a REAL THIRD PARTY: a keyslot whose token could
// not be written must not survive, and cryptsetup -- not just this
// package's own Unlock -- must agree the rolled-back credential is gone.
// TestVolumeEnrollRollsBackTheKeyslotIfTheTokenWriteFails covers the same
// property without cryptsetup.
func TestVolumeEnrollRollsBackAKeyslotItCannotIdentify(t *testing.T) {
	// Not parallel: it overwrites the package-level importToken seam, which a
	// parallel sibling (e.g. TestVolumeEnrollWritesTheKeyslotAndTheTokenThatNamesIt)
	// reads through addKeyslotWithMasterKey while running concurrently (#246
	// D8 class of bug).
	requireCryptsetup(t)

	image := newImage(t, "rollback.img")
	formatWithLibrary(t, image)

	const credential = "a-credential-that-must-not-survive"
	provider := &fakeKeyProvider{
		credential: []byte(credential),
		token:      Token{Type: TokenTypeRecovery},
	}

	// importToken is forced to fail, which is the failure this arranges: the
	// keyslot is already written by then. A real token write has nothing
	// left to refuse once it has a type (Token has no members this
	// package validates), so the old "a token with no type"
	// trigger is no longer reachable here -- the seam importToken exists
	// for exactly this, per its own doc comment.
	sys := testVolumeSys()
	sys.importToken = func(context.Context, *keyslotDevice, int, *LegacyToken) error {
		return errors.New("token slot unwritable")
	}

	before, err := listKeyslotsForTest(image)
	if err != nil {
		t.Fatalf("ListKeyslots() error = %v", err)
	}

	_, _, err = enrollForTest(t, image, []byte(conformancePassphrase), provider, withTestSys(sys))
	if err == nil {
		t.Fatal("Enroll() succeeded with an unwritable token")
	}
	if errors.Is(err, ErrOrphanedKeyslot) {
		t.Fatalf("the keyslot was orphaned rather than rolled back: %v", err)
	}

	after, err := listKeyslotsForTest(image)
	if err != nil {
		t.Fatalf("ListKeyslots() error = %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("keyslot count = %d, want %d: the rollback left a slot behind", len(after), len(before))
	}

	// The decisive check: the credential must no longer open the volume.
	if code, _ := runCryptsetup(t, credential, "luksOpen", "--test-passphrase", image); code == 0 {
		t.Error("the rolled-back credential still opens the volume")
	}
}

// TestVolumeEnrollReportsAnOrphanItCannotRemove covers the one outcome
// that needs a human.
func TestVolumeEnrollReportsAnOrphanItCannotRemove(t *testing.T) {
	requireCryptsetup(t)

	image := newImage(t, "orphan.img")
	formatWithLibrary(t, image)

	sys := testVolumeSys()
	sys.killKeyslot = func(context.Context, *keyslotDevice, int) error { return errors.New("device is read-only") }
	sys.importToken = func(context.Context, *keyslotDevice, int, *LegacyToken) error {
		return errors.New("token slot unwritable")
	}

	provider := &fakeKeyProvider{credential: []byte("orphaned-credential"), token: Token{Type: TokenTypeRecovery}}

	_, _, err := enrollForTest(t, image, []byte(conformancePassphrase), provider, withTestSys(sys))
	if err == nil {
		t.Fatal("Enroll() succeeded, want an orphan report")
	}
	if !errors.Is(err, ErrOrphanedKeyslot) {
		t.Fatalf("error = %v, want errors.Is(_, ErrOrphanedKeyslot)", err)
	}

	var orphan *OrphanedKeyslotError
	if !errors.As(err, &orphan) {
		t.Fatalf("error = %v, want an *OrphanedKeyslotError", err)
	}
	// The one keyslot the formatted fixture does not already hold is 1.
	if orphan.Keyslot != 1 {
		t.Errorf("orphan keyslot = %d, want 1", orphan.Keyslot)
	}
	// The slot number is the only record of the credential that exists, so the
	// message has to carry it.
	if !strings.Contains(orphan.Error(), strconv.Itoa(orphan.Keyslot)) {
		t.Errorf("Error() = %q, want it to name keyslot %d", orphan.Error(), orphan.Keyslot)
	}
}

// TestVolumeEnrollRefusesBadInput covers edge cases
// TestVolumeEnrollRefusesANilProvider/RefusesOnAReadOnlyVolume do not: a
// device that cannot be opened at all, a provider that itself refuses, and
// an existing credential that does not open the volume.
func TestVolumeEnrollRefusesBadInput(t *testing.T) {
	image := newImage(t, "refuse.img")
	formatWithLibrary(t, image)

	t.Run("no device", func(t *testing.T) {
		provider := &fakeKeyProvider{credential: []byte("x")}
		if _, _, err := enrollForTest(t, filepath.Join(t.TempDir(), "absent"), []byte(conformancePassphrase), provider); err == nil {
			t.Error("Enroll() accepted a device that does not exist")
		}
	})

	t.Run("the provider refused", func(t *testing.T) {
		wantErr := errors.New("the authenticator refused")
		provider := &fakeKeyProvider{err: wantErr}
		if _, _, err := enrollForTest(t, image, []byte(conformancePassphrase), provider); !errors.Is(err, wantErr) {
			t.Errorf("error = %v, want errors.Is(_, wantErr)", err)
		}
	})

	t.Run("the wrong existing passphrase", func(t *testing.T) {
		provider := &fakeKeyProvider{credential: []byte("x")}
		if _, _, err := enrollForTest(t, image, []byte(conformanceWrongPassphrase), provider); !errors.Is(err, ErrWrongKey) {
			t.Errorf("error = %v, want errors.Is(_, ErrWrongKey)", err)
		}
	})
}

// TestKeyProviderErrorVocabulary covers what a CALLER does with these errors:
// match a sentinel without knowing the type, reach the cause through Unwrap,
// and read a message that says which step failed.
func TestKeyProviderErrorVocabulary(t *testing.T) {
	cause := errors.New("the underlying reason")

	t.Run("KeyProviderError", func(t *testing.T) {
		err := &errs.Error{Kind: ErrKeyProvider, Detail: "enroll", Err: cause}

		if !errors.Is(err, ErrKeyProvider) {
			t.Error("a key provider error does not match ErrKeyProvider")
		}
		if !errors.Is(err, cause) {
			t.Error("the cause is not reachable through Unwrap")
		}
		if !strings.Contains(err.Error(), "enroll") || !strings.Contains(err.Error(), cause.Error()) {
			t.Errorf("Error() = %q, want the step and the cause", err.Error())
		}
	})

	t.Run("OrphanedKeyslotError", func(t *testing.T) {
		err := &OrphanedKeyslotError{Keyslot: 3, Err: cause, Cause: errors.New("read-only")}

		if !errors.Is(err, ErrOrphanedKeyslot) {
			t.Error("an OrphanedKeyslotError does not match ErrOrphanedKeyslot")
		}
		if !errors.Is(err, ErrKeyProvider) {
			t.Error("an OrphanedKeyslotError does not match ErrKeyProvider")
		}
		if !errors.Is(err, cause) {
			t.Error("the token-write failure is not reachable through Unwrap")
		}
		// The remedy has to be in the message: this slot number is the only
		// record of the credential that exists anywhere.
		if !strings.Contains(err.Error(), "killslot") {
			t.Errorf("Error() = %q, want it to say how to remove the slot", err.Error())
		}
	})
}
