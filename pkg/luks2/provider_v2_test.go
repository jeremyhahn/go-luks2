// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"
)

// cheapKeyslotParams keeps Enroll's keyslot at the fixtures' cost, so these
// tests stay fast rather than paying argon2id's default.
func cheapKeyslotParams() KeyslotParams {
	return KeyslotParams{KDF: KDFParams{Type: KDFPBKDF2, Hash: crypto.SHA512, IterTime: time.Millisecond}}
}

func TestVolumeEnrollAddsAKeyslotAndWritesTheToken(t *testing.T) {
	path := formattedVolumeImage(t, "enroll.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	const providerCredential = "a-credential-from-somewhere-else"
	provider := &fakeKeyProvider{
		credential: []byte(providerCredential),
		token:      Token{Type: "x-provider", Keyslots: []int{99}}, // overwritten by Enroll
	}

	enrollment, err := v.Enroll(context.Background(), key, provider, cheapKeyslotParams())
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
	if enrollment.Keyslot.ID == 0 {
		t.Errorf("Enroll's keyslot = 0, want a NEW slot (0 is the formatted passphrase's)")
	}
	if enrollment.Token < 0 {
		t.Fatalf("Enroll's token id = %d, want a real slot", enrollment.Token)
	}

	// The token names the slot Enroll actually used, not what the provider
	// asked for.
	token, ok, err := getTokenForTest(path, enrollment.Token)
	if err != nil {
		t.Fatalf("getTokenForTest(%d) failed: %v", enrollment.Token, err)
	}
	if !ok {
		t.Fatalf("Tokens()[%d] missing after Enroll", enrollment.Token)
	}
	if token.Type != "x-provider" {
		t.Errorf("token type = %q, want %q", token.Type, "x-provider")
	}
	if len(token.Keyslots) != 1 || token.Keyslots[0] != enrollment.Keyslot.ID {
		t.Errorf("token keyslots = %v, want [%d]", token.Keyslots, enrollment.Keyslot.ID)
	}

	// The provider's credential actually opens the new slot.
	newPass, err := enclave.NewMemoryEnclaveCopy([]byte(providerCredential))
	if err != nil {
		t.Fatalf("could not build the enrolled-credential enclave: %v", err)
	}
	defer func() { _ = newPass.Destroy() }()
	unlocked, err := v.UnlockKeyslot(context.Background(), enrollment.Keyslot.ID, newPass)
	if err != nil {
		t.Fatalf("UnlockKeyslot(%d) with the enrolled credential failed: %v", enrollment.Keyslot.ID, err)
	}
	unlocked.Destroy()

	// And the original credential still works: Enroll adds a keyslot, it
	// does not replace one.
	original := newTestPassphrase(t)
	defer func() { _ = original.Destroy() }()
	stillUnlocked, err := v.Unlock(context.Background(), original)
	if err != nil {
		t.Fatalf("Unlock with the original passphrase failed after Enroll: %v", err)
	}
	stillUnlocked.Destroy()
}

// TestVolumeEnrollWithPriorityPreferWritesIt is
// TestVolumeAddKeyslotWithPriorityPreferWritesIt's counterpart for Enroll:
// kp.Priority reaches the keyslot Enroll writes (onDiskPriority), not just
// the KDF cost cheapKeyslotParams names.
func TestVolumeEnrollWithPriorityPreferWritesIt(t *testing.T) {
	path := formattedVolumeImage(t, "enroll-prefer.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	provider := &fakeKeyProvider{
		credential: []byte("a-prioritized-credential"),
		token:      Token{Type: "x-provider"},
	}
	kp := cheapKeyslotParams()
	kp.Priority = PriorityPrefer

	enrollment, err := v.Enroll(context.Background(), key, provider, kp)
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
	if enrollment.Keyslot.Priority != PriorityPrefer {
		t.Errorf("Enroll returned Priority %v, want PriorityPrefer", enrollment.Keyslot.Priority)
	}

	// The write must be durable, not just reflected in the return value.
	h, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}
	for _, s := range h.Keyslots() {
		if s.ID == enrollment.Keyslot.ID && s.Priority != PriorityPrefer {
			t.Errorf("re-read Priority = %v, want PriorityPrefer", s.Priority)
		}
	}
}

func TestVolumeEnrollAnonymousProviderWritesNoToken(t *testing.T) {
	path := formattedVolumeImage(t, "enroll-anonymous.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	provider := &fakeKeyProvider{credential: []byte("anonymous-credential")}

	enrollment, err := v.Enroll(context.Background(), key, provider, cheapKeyslotParams())
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
	if enrollment.Token != -1 {
		t.Errorf("Enroll's token id = %d, want -1 for an anonymous provider", enrollment.Token)
	}

	count, err := countTokensForTest(path)
	if err != nil {
		t.Fatalf("countTokensForTest failed: %v", err)
	}
	if count != 0 {
		t.Errorf("token count = %d, want 0", count)
	}
}

func TestVolumeEnrollRollsBackTheKeyslotIfTheTokenWriteFails(t *testing.T) {
	path := formattedVolumeImage(t, "enroll-rollback.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	before, err := listKeyslotsForTest(path)
	if err != nil {
		t.Fatalf("ListKeyslots failed: %v", err)
	}

	v.sys.importToken = func(context.Context, *keyslotDevice, int, *LegacyToken) error {
		return errors.New("token slot unwritable")
	}

	provider := &fakeKeyProvider{credential: []byte("a-credential-that-must-not-survive"), token: Token{Type: "x-provider"}}

	if _, err := v.Enroll(context.Background(), key, provider, cheapKeyslotParams()); err == nil {
		t.Fatal("Enroll succeeded with an unwritable token")
	}

	after, err := listKeyslotsForTest(path)
	if err != nil {
		t.Fatalf("ListKeyslots failed: %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("keyslot count = %d, want %d: the rollback left a slot behind", len(after), len(before))
	}
}

func TestVolumeEnrollRefusesANilProvider(t *testing.T) {
	path := formattedVolumeImage(t, "enroll-nilprovider.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	if _, err := v.Enroll(context.Background(), key, nil, cheapKeyslotParams()); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("Enroll(nil provider) = %v, want ErrInvalidArgument", err)
	}
}

func TestVolumeEnrollRefusesOnAReadOnlyVolume(t *testing.T) {
	path := formattedVolumeImage(t, "enroll-readonly.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()), WithReadOnly())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	provider := &fakeKeyProvider{credential: []byte("x")}
	if _, err := v.Enroll(context.Background(), nil, provider, cheapKeyslotParams()); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Enroll on a read-only Volume = %v, want ErrReadOnly", err)
	}
}

func TestVolumeUnlockWithProviderOpensTheNamedKeyslot(t *testing.T) {
	path := formattedVolumeImage(t, "unlockwithprovider.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	const providerCredential = "a-provider-credential"
	enrollProvider := &fakeKeyProvider{credential: []byte(providerCredential), token: Token{Type: "x-provider"}}
	enrollment, err := v.Enroll(context.Background(), key, enrollProvider, cheapKeyslotParams())
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}

	unlockProvider := &fakeKeyProvider{
		credential: []byte(providerCredential),
		token:      Token{Type: "x-provider", Keyslots: []int{enrollment.Keyslot.ID}},
	}

	unlocked, err := v.UnlockWithProvider(context.Background(), unlockProvider)
	if err != nil {
		t.Fatalf("UnlockWithProvider failed: %v", err)
	}
	defer unlocked.Destroy()

	if got := unlocked.Keyslot(); got != enrollment.Keyslot.ID {
		t.Errorf("header.Keyslot() = %d, want %d", got, enrollment.Keyslot.ID)
	}
}

// TestVolumeUnlockWithProviderTriesTheTokensKeyslotsByPriority: one credential
// opens a normal, a prefer and an ignore keyslot, and the token lists them out
// of priority order. As cryptsetup does for a token named with --token-id, the
// prefer keyslot opens before the normal one, the normal one before the ignore
// one, and the ignore one still opens when it is all the token names.
func TestVolumeUnlockWithProviderTriesTheTokensKeyslotsByPriority(t *testing.T) {
	path := formattedVolumeImage(t, "unlockwithprovider-priority.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	const credential = "one-credential-for-every-slot"
	slots := map[Priority]int{}
	for _, priority := range []Priority{PriorityNormal, PriorityPrefer, PriorityIgnore} {
		kp := cheapKeyslotParams()
		kp.Priority = priority
		enrollment, err := v.Enroll(context.Background(), key, &fakeKeyProvider{credential: []byte(credential)}, kp)
		if err != nil {
			t.Fatalf("Enroll(%v) failed: %v", priority, err)
		}
		slots[priority] = enrollment.Keyslot.ID
	}

	for _, tc := range []struct {
		name  string
		token []int
		want  int
	}{
		{"prefer before normal", []int{slots[PriorityNormal], slots[PriorityPrefer]}, slots[PriorityPrefer]},
		{"normal before ignore", []int{slots[PriorityIgnore], slots[PriorityNormal]}, slots[PriorityNormal]},
		{"prefer before ignore and normal", []int{slots[PriorityIgnore], slots[PriorityNormal], slots[PriorityPrefer]}, slots[PriorityPrefer]},
		{"an ignore keyslot the named token holds alone", []int{slots[PriorityIgnore]}, slots[PriorityIgnore]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &fakeKeyProvider{credential: []byte(credential), token: Token{Type: "x-provider", Keyslots: tc.token}}
			unlocked, err := v.UnlockWithProvider(context.Background(), provider)
			if err != nil {
				t.Fatalf("UnlockWithProvider(%v) failed: %v", tc.token, err)
			}
			defer unlocked.Destroy()
			if got := unlocked.Keyslot(); got != tc.want {
				t.Errorf("UnlockWithProvider(%v) opened keyslot %d, want %d", tc.token, got, tc.want)
			}
		})
	}
}

func TestVolumeUnlockWithProviderRefusesATokenWithNoKeyslots(t *testing.T) {
	path := formattedVolumeImage(t, "unlockwithprovider-nokeyslots.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	provider := &fakeKeyProvider{credential: []byte("x")}
	if _, err := v.UnlockWithProvider(context.Background(), provider); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("UnlockWithProvider(no keyslots) = %v, want ErrInvalidArgument", err)
	}
}

func TestVolumeUnlockWithProviderRefusesAnUnboundKeyslot(t *testing.T) {
	path := formattedVolumeImage(t, "unlockwithprovider-unbound.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	provider := &fakeKeyProvider{credential: []byte("x"), token: Token{Keyslots: []int{7}}}
	if _, err := v.UnlockWithProvider(context.Background(), provider); !errors.Is(err, ErrKeyslotNotFound) {
		t.Errorf("UnlockWithProvider(unbound slot) = %v, want ErrInvalidKeyslot", err)
	}
}

func TestVolumeUnlockWithProviderRefusesANilProvider(t *testing.T) {
	path := formattedVolumeImage(t, "unlockwithprovider-nilprovider.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if _, err := v.UnlockWithProvider(context.Background(), nil); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("UnlockWithProvider(nil) = %v, want ErrInvalidArgument", err)
	}
}
