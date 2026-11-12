// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// newPassphraseEnclave is newTestPassphrase, parameterized on the text: used
// here for the SECOND credential a keyslot test enrolls or rotates to.
func newPassphraseEnclave(t *testing.T, text string) enclave.ByteAccess {
	t.Helper()
	e, err := enclave.NewMemoryCopy([]byte(text))
	if err != nil {
		t.Fatalf("could not build a passphrase enclave: %v", err)
	}
	return e
}

func TestVolumeAddKeyslotAddsAWorkingCredential(t *testing.T) {
	path := formattedVolumeImage(t, "addkeyslot.img", "", "")

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

	newPass := newPassphraseEnclave(t, "a second credential")
	defer func() { _ = newPass.Destroy() }()

	info, err := v.AddKeyslot(context.Background(), key, newPass, KeyslotParams{
		Priority: PriorityNormal,
		KDF:      KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond},
	})
	if err != nil {
		t.Fatalf("AddKeyslot failed: %v", err)
	}
	if info.ID != 1 {
		t.Errorf("AddKeyslot returned slot %d, want 1 (the lowest free slot)", info.ID)
	}
	if info.KDF.Type != KDFPBKDF2 {
		t.Errorf("KDF.Type = %q, want %q", info.KDF.Type, KDFPBKDF2)
	}
	if info.KDF.Iterations < minPBKDF2Iterations {
		t.Errorf("KDF.Iterations = %d, want at least the test floor %d", info.KDF.Iterations, minPBKDF2Iterations)
	}

	// The new keyslot must actually open the volume.
	recovered, err := v.UnlockKeyslot(context.Background(), info.ID, newPass)
	if err != nil {
		t.Fatalf("UnlockKeyslot on the new slot failed: %v", err)
	}
	defer recovered.Destroy()

	// Reading it back through the header must agree with what AddKeyslot
	// returned: there is exactly one source of truth, listKeyslotsFrom.
	h, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}
	slots := h.Keyslots()
	if len(slots) != 2 {
		t.Fatalf("Keyslots() returned %d slots, want 2", len(slots))
	}
}

func TestVolumeAddKeyslotWithAnExplicitSlot(t *testing.T) {
	path := formattedVolumeImage(t, "addkeyslot-explicit.img", "", "")

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

	newPass := newPassphraseEnclave(t, "slot five's credential")
	defer func() { _ = newPass.Destroy() }()

	slot := 5
	info, err := v.AddKeyslot(context.Background(), key, newPass, KeyslotParams{
		Slot: &slot,
		KDF:  KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond},
	})
	if err != nil {
		t.Fatalf("AddKeyslot failed: %v", err)
	}
	if info.ID != 5 {
		t.Errorf("AddKeyslot returned slot %d, want the requested 5", info.ID)
	}
}

// TestVolumeAddKeyslotReportsTheSlotItWroteAcrossAGap pins keyslots
// engineering.md, Invariants: AddKeyslot returns the slot it wrote, and slots
// need not be contiguous. With slots 0 and 5 in use the next automatic slot is
// 1, not one past the highest, and the returned ID is the one that opens.
func TestVolumeAddKeyslotReportsTheSlotItWroteAcrossAGap(t *testing.T) {
	path := formattedVolumeImage(t, "addkeyslot-gap.img", "", "")

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

	fast := KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond}
	fivePass := newPassphraseEnclave(t, "slot five's credential")
	defer func() { _ = fivePass.Destroy() }()
	five := 5
	if _, err := v.AddKeyslot(context.Background(), key, fivePass, KeyslotParams{Slot: &five, KDF: fast}); err != nil {
		t.Fatalf("AddKeyslot(slot 5) failed: %v", err)
	}

	gapPass := newPassphraseEnclave(t, "the gap's credential")
	defer func() { _ = gapPass.Destroy() }()
	info, err := v.AddKeyslot(context.Background(), key, gapPass, KeyslotParams{KDF: fast})
	if err != nil {
		t.Fatalf("AddKeyslot failed: %v", err)
	}
	if info.ID != 1 {
		t.Fatalf("AddKeyslot returned slot %d, want 1 (the lowest free slot, below slot 5)", info.ID)
	}
	recovered, err := v.UnlockKeyslot(context.Background(), info.ID, gapPass)
	if err != nil {
		t.Fatalf("the returned slot %d does not open with the new passphrase: %v", info.ID, err)
	}
	recovered.Destroy()
	if _, err := v.UnlockKeyslot(context.Background(), 6, gapPass); !errors.Is(err, ErrKeyslotNotFound) {
		t.Fatalf("slot 6 (one past the highest) answered %v, want ErrKeyslotNotFound", err)
	}
}

// TestVolumeKeyslotSaltsAre32RandomBytes pins keyslots engineering.md, KDF:
// "Salts are 32 random bytes". Each keyslot written, by Format and by
// AddKeyslot, carries a KDF salt that decodes to 32 bytes, and no two are
// alike.
func TestVolumeKeyslotSaltsAre32RandomBytes(t *testing.T) {
	path := formattedVolumeImage(t, "keyslot-salts.img", "", "")

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

	for _, credential := range []string{"a second credential", "a third credential"} {
		newPass := newPassphraseEnclave(t, credential)
		defer func() { _ = newPass.Destroy() }()
		kdf := KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond}
		if _, err := v.AddKeyslot(context.Background(), key, newPass, KeyslotParams{KDF: kdf}); err != nil {
			t.Fatalf("AddKeyslot(%q) failed: %v", credential, err)
		}
	}

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if len(metadata.Keyslots) != 3 {
		t.Fatalf("the header holds %d keyslots, want 3", len(metadata.Keyslots))
	}
	seen := map[string]string{}
	for id, ks := range metadata.Keyslots {
		salt, err := decodeBase64(ks.KDF.Salt)
		if err != nil {
			t.Fatalf("keyslot %s salt does not decode: %v", id, err)
		}
		if len(salt) != 32 {
			t.Errorf("keyslot %s salt is %d bytes, want 32", id, len(salt))
		}
		if other, dup := seen[string(salt)]; dup {
			t.Errorf("keyslots %s and %s share a salt", other, id)
		}
		seen[string(salt)] = id
	}
}

// TestVolumeAddKeyslotDefaultsThePBKDF2PRF pins keyslots engineering.md, KDF:
// the PBKDF2 PRF is SHA-256 when KDFParams.Hash is zero, and SHA-512 when the
// type was left empty and FIPS mode defaulted it to PBKDF2.
func TestVolumeAddKeyslotDefaultsThePBKDF2PRF(t *testing.T) {
	cases := []struct {
		name     string
		fips     bool
		kdf      KDFParams
		wantHash string
	}{
		{"named pbkdf2, zero hash", false, KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond}, "sha256"},
		{"named pbkdf2, zero hash, FIPS policy", true, KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond}, "sha256"},
		{"empty type, FIPS policy", true, KDFParams{IterTime: time.Millisecond}, "sha512"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := formattedVolumeImage(t, "addkeyslot-prf.img", "", "")
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

			if tc.fips {
				v.sys.fipsMode = forceFIPSPolicy(t)
			} else {
				v.sys.fipsMode = forceNonFIPSPolicy(t)
			}
			newPass := newPassphraseEnclave(t, "a PRF-defaulted credential")
			defer func() { _ = newPass.Destroy() }()
			info, err := v.AddKeyslot(context.Background(), key, newPass, KeyslotParams{KDF: tc.kdf})
			if err != nil {
				t.Fatalf("AddKeyslot failed: %v", err)
			}

			_, metadata, err := readHeaderForTest(path)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			kdf := metadata.Keyslots[strconv.Itoa(info.ID)].KDF
			if kdf.Type != kdfTypePBKDF2 || kdf.Hash != tc.wantHash {
				t.Fatalf("keyslot %d written as %s/%s, want %s/%s", info.ID, kdf.Type, kdf.Hash, kdfTypePBKDF2, tc.wantHash)
			}
		})
	}
}

// TestVolumeRemoveKeyslotForgetsItInEveryDigestAndToken pins keyslots
// engineering.md, Persistence: removing a keyslot drops its number from every
// digest and token in the same write, and a token left naming no keyslot is
// kept.
func TestVolumeRemoveKeyslotForgetsItInEveryDigestAndToken(t *testing.T) {
	path := formattedVolumeImage(t, "removekeyslot-refs.img", "", "")

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

	newPass := newPassphraseEnclave(t, "a credential to remove")
	defer func() { _ = newPass.Destroy() }()
	info, err := v.AddKeyslot(context.Background(), key, newPass, KeyslotParams{
		KDF: KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond},
	})
	if err != nil {
		t.Fatalf("AddKeyslot failed: %v", err)
	}
	only, err := v.AddToken(context.Background(), Token{Type: "x-only", Keyslots: []int{info.ID}})
	if err != nil {
		t.Fatalf("AddToken(only) failed: %v", err)
	}
	shared, err := v.AddToken(context.Background(), Token{Type: "x-shared", Keyslots: []int{0, info.ID}})
	if err != nil {
		t.Fatalf("AddToken(shared) failed: %v", err)
	}

	if err := v.RemoveKeyslot(context.Background(), info.ID); err != nil {
		t.Fatalf("RemoveKeyslot failed: %v", err)
	}

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	removed := strconv.Itoa(info.ID)
	for id, digest := range metadata.Digests {
		if slices.Contains(digest.Keyslots, removed) {
			t.Errorf("digest %s still names removed keyslot %s: %v", id, removed, digest.Keyslots)
		}
	}
	onlyToken, ok := metadata.Tokens[strconv.Itoa(only)]
	if !ok {
		t.Fatalf("token %d, left naming no keyslot, was deleted; it must be kept", only)
	}
	if len(onlyToken.Keyslots) != 0 {
		t.Errorf("token %d still names keyslots %v", only, onlyToken.Keyslots)
	}
	sharedToken, ok := metadata.Tokens[strconv.Itoa(shared)]
	if !ok || !slices.Equal(sharedToken.Keyslots, []string{"0"}) {
		t.Errorf("token %d keyslots = %v (present %v), want [0]", shared, sharedToken, ok)
	}
}

func TestVolumeAddKeyslotWithPriorityPreferWritesIt(t *testing.T) {
	path := formattedVolumeImage(t, "addkeyslot-prefer.img", "", "")

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

	newPass := newPassphraseEnclave(t, "the preferred credential")
	defer func() { _ = newPass.Destroy() }()

	info, err := v.AddKeyslot(context.Background(), key, newPass, KeyslotParams{
		Priority: PriorityPrefer,
		KDF:      KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond},
	})
	if err != nil {
		t.Fatalf("AddKeyslot failed: %v", err)
	}
	if info.Priority != PriorityPrefer {
		t.Errorf("AddKeyslot returned Priority %v, want PriorityPrefer", info.Priority)
	}

	// The write must be durable, not just reflected in the return value.
	h, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}
	for _, s := range h.Keyslots() {
		if s.ID == info.ID && s.Priority != PriorityPrefer {
			t.Errorf("re-read Priority = %v, want PriorityPrefer", s.Priority)
		}
	}
}

func TestVolumeAddKeyslotOnAReadOnlyVolumeFails(t *testing.T) {
	path := formattedVolumeImage(t, "addkeyslot-readonly.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()), WithReadOnly())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	rw, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open (rw, for Unlock) failed: %v", err)
	}
	defer func() { _ = rw.Close() }()
	key, err := rw.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	newPass := newPassphraseEnclave(t, "should never be written")
	defer func() { _ = newPass.Destroy() }()

	if _, err := v.AddKeyslot(context.Background(), key, newPass, KeyslotParams{}); !errors.Is(err, ErrReadOnly) {
		t.Errorf("AddKeyslot on a read-only Volume = %v, want ErrReadOnly", err)
	}
}

func TestVolumeChangeKeyslotRotatesThePassphrase(t *testing.T) {
	defer parallel(t)()
	path := formattedVolumeImage(t, "changekeyslot.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	original := newTestPassphrase(t)
	defer func() { _ = original.Destroy() }()
	key, err := v.Unlock(context.Background(), original)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	rotated := newPassphraseEnclave(t, "the rotated credential")
	defer func() { _ = rotated.Destroy() }()

	info, err := v.ChangeKeyslot(context.Background(), key, rotated, KeyslotParams{})
	if err != nil {
		t.Fatalf("ChangeKeyslot failed: %v", err)
	}
	if info.ID != key.Keyslot() {
		t.Errorf("ChangeKeyslot reported slot %d, want the key's own slot %d", info.ID, key.Keyslot())
	}

	if _, err := v.UnlockKeyslot(context.Background(), key.Keyslot(), rotated); err != nil {
		t.Fatalf("UnlockKeyslot with the rotated credential failed: %v", err)
	}

	stale, err := enclave.NewMemoryCopy([]byte(testPassphraseText))
	if err != nil {
		t.Fatalf("could not build the stale-passphrase enclave: %v", err)
	}
	defer func() { _ = stale.Destroy() }()
	if _, err := v.UnlockKeyslot(context.Background(), key.Keyslot(), stale); err == nil {
		t.Error("UnlockKeyslot with the old passphrase still succeeded after ChangeKeyslot")
	}
}

// TestVolumeChangeKeyslotWithPriorityPreferWritesIt is
// TestVolumeAddKeyslotWithPriorityPreferWritesIt's counterpart for a
// rotation: ChangeKeyslot's p.Priority is written (onDiskPriority), even
// though p.KDF is not -- see the method's own doc comment.
func TestVolumeChangeKeyslotWithPriorityPreferWritesIt(t *testing.T) {
	defer parallel(t)()
	path := formattedVolumeImage(t, "changekeyslot-prefer.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	original := newTestPassphrase(t)
	defer func() { _ = original.Destroy() }()
	key, err := v.Unlock(context.Background(), original)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	rotated := newPassphraseEnclave(t, "the re-prioritized credential")
	defer func() { _ = rotated.Destroy() }()

	info, err := v.ChangeKeyslot(context.Background(), key, rotated, KeyslotParams{Priority: PriorityPrefer, KDF: KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond}})
	if err != nil {
		t.Fatalf("ChangeKeyslot failed: %v", err)
	}
	if info.Priority != PriorityPrefer {
		t.Errorf("ChangeKeyslot returned Priority %v, want PriorityPrefer", info.Priority)
	}

	// The write must be durable, not just reflected in the return value.
	h, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}
	for _, s := range h.Keyslots() {
		if s.ID == info.ID && s.Priority != PriorityPrefer {
			t.Errorf("re-read Priority = %v, want PriorityPrefer", s.Priority)
		}
	}
}

// TestVolumeChangeKeyslotPreservesTheExistingPBKDF2Cost is changeKeyslotCore's
// "a passphrase rotation is not a request to re-cost the keyslot" contract,
// the same one the old ChangeKey keeps. iterations sits above the sha256
// caller-credential floor (600,000) on purpose: ChangeKeyslot must carry it
// through UNCHANGED rather than recalibrate, and a recalibration would almost
// certainly not land on this exact number.
func TestVolumeChangeKeyslotPreservesTheExistingPBKDF2Cost(t *testing.T) {
	defer parallel(t)()
	const iterations = 700_000

	path := newImage(t, "changekeyslot-cost.img")
	if err := formatForTest(formatOptionsForTest{
		Device:          path,
		Passphrase:      []byte(testPassphraseText),
		Cipher:          "aes",
		CipherMode:      "xts-plain64",
		KeySize:         512,
		HashAlgo:        "sha256",
		SectorSize:      512,
		KDFType:         kdfTypePBKDF2,
		PBKDFIterations: iterations,
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newPassphraseEnclave(t, testPassphraseText)
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	rotated := newPassphraseEnclave(t, "cost-preserving rotation")
	defer func() { _ = rotated.Destroy() }()

	info, err := v.ChangeKeyslot(context.Background(), key, rotated, KeyslotParams{})
	if err != nil {
		t.Fatalf("ChangeKeyslot failed: %v", err)
	}
	if info.KDF.Iterations != iterations {
		t.Errorf("ChangeKeyslot's reported iterations = %d, want the preserved %d", info.KDF.Iterations, iterations)
	}
}

// changeKeyslotOnDiskKDF formats a PBKDF2-SHA256 volume at iterations, changes
// keyslot 0's passphrase with p, and returns the keyslot's KDF as re-read
// from the device -- what a later open will use, not what the call reported.
func changeKeyslotOnDiskKDF(t *testing.T, iterations int, p KeyslotParams) *header.KDF {
	t.Helper()
	path := newImage(t, "changekeyslot-recost.img")
	if err := formatForTest(formatOptionsForTest{
		Device:          path,
		Passphrase:      []byte(testPassphraseText),
		Cipher:          "aes",
		CipherMode:      "xts-plain64",
		KeySize:         512,
		HashAlgo:        "sha256",
		SectorSize:      512,
		KDFType:         kdfTypePBKDF2,
		PBKDFIterations: iterations,
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	pass := newPassphraseEnclave(t, testPassphraseText)
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		_ = v.Close()
		t.Fatalf("Unlock failed: %v", err)
	}
	rotated := newPassphraseEnclave(t, "re-costing rotation")
	defer func() { _ = rotated.Destroy() }()
	_, err = v.ChangeKeyslot(context.Background(), key, rotated, p)
	key.Destroy()
	_ = v.Close()
	if err != nil {
		t.Fatalf("ChangeKeyslot failed: %v", err)
	}

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("readHeaderForTest failed: %v", err)
	}
	slot, ok := metadata.Keyslots["0"]
	if !ok || slot.KDF == nil || slot.KDF.Iterations == nil {
		t.Fatalf("keyslot 0 has no PBKDF2 KDF on disk after ChangeKeyslot: %+v", slot)
	}
	return slot.KDF
}

// An explicit KDF is a request to re-cost the slot, as cryptsetup
// luksChangeKey's --pbkdf-force-iterations is: the count asked for is the
// count on disk afterwards.
func TestVolumeChangeKeyslotWithAnExplicitKDFRecostsTheSlot(t *testing.T) {
	defer parallel(t)()
	const before, after = 700_000, 800_000
	kdf := changeKeyslotOnDiskKDF(t, before, KeyslotParams{KDF: KDFParams{Type: KDFPBKDF2, Iterations: after}})
	if kdf.Type != kdfTypePBKDF2 || *kdf.Iterations != after {
		t.Errorf("on-disk KDF after ChangeKeyslot = %s/%d, want %s/%d", kdf.Type, *kdf.Iterations, kdfTypePBKDF2, after)
	}
}

// A zero KDF keeps the slot's own cost, re-read from the device rather than
// taken from ChangeKeyslot's report.
func TestVolumeChangeKeyslotWithAZeroKDFKeepsTheOnDiskCost(t *testing.T) {
	defer parallel(t)()
	const iterations = 700_000
	kdf := changeKeyslotOnDiskKDF(t, iterations, KeyslotParams{})
	if kdf.Type != kdfTypePBKDF2 || *kdf.Iterations != iterations {
		t.Errorf("on-disk KDF after ChangeKeyslot = %s/%d, want the preserved %s/%d", kdf.Type, *kdf.Iterations, kdfTypePBKDF2, iterations)
	}
}

// TestVolumeChangeKeyslotRefusesAnExplicitKDFLikeAddKeyslot: an explicit KDF
// is validated as AddKeyslot validates it, so a request AddKeyslot refuses is
// refused here too, and the refusal writes nothing -- the image is byte for
// byte what it was.
func TestVolumeChangeKeyslotRefusesAnExplicitKDFLikeAddKeyslot(t *testing.T) {
	defer parallel(t)()
	cases := []struct {
		name  string
		fips  bool
		kdf   KDFParams
		wantA error
	}{
		{"argon2id under the FIPS policy", true,
			KDFParams{Type: KDFArgon2id, Time: 1, MemoryKiB: minArgon2MemoryKB, Parallel: 1}, ErrFIPSNotApproved},
		{"argon2i under the FIPS policy", true,
			KDFParams{Type: KDFArgon2i, Time: 1, MemoryKiB: minArgon2MemoryKB, Parallel: 1}, ErrFIPSNotApproved},
		{"pbkdf2 with sha1", false,
			KDFParams{Type: KDFPBKDF2, Hash: crypto.SHA1, IterTime: time.Millisecond}, ErrInvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := formattedVolumeImage(t, "changekeyslot-refused.img", "", "")
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

			rotated := newPassphraseEnclave(t, "never written")
			defer func() { _ = rotated.Destroy() }()

			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("could not snapshot the image: %v", err)
			}

			// AddKeyslot is the reference: it must refuse the same request.
			v.sys.fipsMode = func() fips.Mode { return fips.Mode(tc.fips) }
			_, addErr := v.AddKeyslot(context.Background(), key, rotated, KeyslotParams{KDF: tc.kdf})
			if !errors.Is(addErr, tc.wantA) {
				t.Fatalf("AddKeyslot = %v, want %v (the reference refusal)", addErr, tc.wantA)
			}

			_, err = v.ChangeKeyslot(context.Background(), key, rotated, KeyslotParams{KDF: tc.kdf})
			if !errors.Is(err, tc.wantA) {
				t.Fatalf("ChangeKeyslot = %v, want %v", err, tc.wantA)
			}

			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("could not re-read the image: %v", err)
			}
			if !bytes.Equal(before, after) {
				t.Error("a refused ChangeKeyslot changed the image")
			}
		})
	}
}

// TestVolumeKeyslotWritesJudgeAnExplicitKDFByTheVolumePolicy pins that the
// preflight of AddKeyslot, ChangeKeyslot and Enroll reads the Volume's FIPS
// policy, not the process's: with the policy forced on, an explicit Argon2
// KDF is refused before the lock is taken, and the image -- the keyslot
// included -- is byte for byte what it was.
func TestVolumeKeyslotWritesJudgeAnExplicitKDFByTheVolumePolicy(t *testing.T) {
	defer parallel(t)()
	argon2 := KeyslotParams{KDF: KDFParams{Type: KDFArgon2id, Time: 1, MemoryKiB: minArgon2MemoryKB, Parallel: 1}}
	cases := []struct {
		name  string
		write func(v *Volume, key *Key, pass enclave.ByteAccess) error
	}{
		{"AddKeyslot", func(v *Volume, key *Key, pass enclave.ByteAccess) error {
			_, err := v.AddKeyslot(context.Background(), key, pass, argon2)
			return err
		}},
		{"ChangeKeyslot", func(v *Volume, key *Key, pass enclave.ByteAccess) error {
			_, err := v.ChangeKeyslot(context.Background(), key, pass, argon2)
			return err
		}},
		{"Enroll", func(v *Volume, key *Key, _ enclave.ByteAccess) error {
			_, err := v.Enroll(context.Background(), key, &fakeKeyProvider{credential: []byte("a provider credential"), token: Token{Type: "x-provider"}}, argon2)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := formattedVolumeImage(t, "keyslot-volume-policy.img", "", "")
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

			rotated := newPassphraseEnclave(t, "never written")
			defer func() { _ = rotated.Destroy() }()

			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("could not snapshot the image: %v", err)
			}

			v.sys.fipsMode = forceFIPSPolicy(t)
			locks := 0
			v.sys.lockHeld = func(string) { locks++ }

			if err := tc.write(v, key, rotated); !errors.Is(err, ErrFIPSNotApproved) {
				t.Fatalf("%s with an Argon2 KDF under the volume's FIPS policy = %v, want ErrFIPSNotApproved", tc.name, err)
			}
			if locks != 0 {
				t.Errorf("%s took the lock %d time(s): the volume's policy must refuse the KDF in the preflight", tc.name, locks)
			}

			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("could not re-read the image: %v", err)
			}
			if !bytes.Equal(before, after) {
				t.Errorf("a refused %s changed the image", tc.name)
			}
		})
	}
}

func TestVolumeChangeKeyslotOnAReadOnlyVolumeFails(t *testing.T) {
	path := formattedVolumeImage(t, "changekeyslot-readonly.img", "", "")

	rw, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open (rw, for Unlock) failed: %v", err)
	}
	defer func() { _ = rw.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()
	key, err := rw.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()), WithReadOnly())
	if err != nil {
		t.Fatalf("Open (ro) failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	rotated := newPassphraseEnclave(t, "should never be written")
	defer func() { _ = rotated.Destroy() }()

	if _, err := v.ChangeKeyslot(context.Background(), key, rotated, KeyslotParams{}); !errors.Is(err, ErrReadOnly) {
		t.Errorf("ChangeKeyslot on a read-only Volume = %v, want ErrReadOnly", err)
	}
}

func TestVolumeRemoveKeyslotRemovesItWithoutDisturbingOthers(t *testing.T) {
	path := formattedVolumeImage(t, "removekeyslot.img", "", "")

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

	newPass := newPassphraseEnclave(t, "the doomed credential")
	defer func() { _ = newPass.Destroy() }()
	added, err := v.AddKeyslot(context.Background(), key, newPass, KeyslotParams{
		KDF: KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond},
	})
	if err != nil {
		t.Fatalf("AddKeyslot failed: %v", err)
	}

	if err := v.RemoveKeyslot(context.Background(), added.ID); err != nil {
		t.Fatalf("RemoveKeyslot failed: %v", err)
	}

	if _, err := v.UnlockKeyslot(context.Background(), added.ID, newPass); !errors.Is(err, ErrKeyslotNotFound) {
		t.Errorf("UnlockKeyslot on the removed slot = %v, want ErrInvalidKeyslot", err)
	}
	// The original keyslot must still work.
	if _, err := v.UnlockKeyslot(context.Background(), 0, pass); err != nil {
		t.Errorf("UnlockKeyslot on the surviving slot 0 failed: %v", err)
	}
}

// TestKeyslotChangesLeaveTheDataAreaUntouched pins the keyslots feature's
// core promise: credentials are added, rotated and revoked without
// re-encrypting data. AddKeyslot, ChangeKeyslot and RemoveKeyslot write only
// the header and the keyslots area, so every byte of the data segment reads
// back as it was, and the volume's original credential still opens it.
func TestKeyslotChangesLeaveTheDataAreaUntouched(t *testing.T) {
	ctx := context.Background()
	path := formattedVolumeImage(t, "keyslot-data-untouched.img", "", "")

	v := txnVolume(t, path)
	h, err := v.Header(ctx)
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}
	segments := h.Segments()
	if len(segments) != 1 {
		t.Fatalf("the fixture has %d data segments, want 1", len(segments))
	}
	offset := segments[0].Offset

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("opening the image failed: %v", err)
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if st.Size() <= offset {
		t.Fatalf("the image (%d bytes) has no data area past offset %d", st.Size(), offset)
	}
	// A recognizable pattern, so an unchanged all-zero area cannot pass by
	// accident of a sparse file.
	pattern := bytes.Repeat([]byte("ciphertext-stand-in."), int((st.Size()-offset)/20)+1)[:st.Size()-offset]
	if _, err := f.WriteAt(pattern, offset); err != nil {
		t.Fatalf("writing the data pattern failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing the image failed: %v", err)
	}

	kdf := KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond}
	key := txnKey(t, v)
	added, err := v.AddKeyslot(ctx, key, txnPassphrase(t, "an added credential"), KeyslotParams{KDF: kdf})
	if err != nil {
		t.Fatalf("AddKeyslot failed: %v", err)
	}
	rotated, err := v.UnlockKeyslot(ctx, added.ID, txnPassphrase(t, "an added credential"))
	if err != nil {
		t.Fatalf("UnlockKeyslot(%d) failed: %v", added.ID, err)
	}
	defer rotated.Destroy()
	if _, err := v.ChangeKeyslot(ctx, rotated, txnPassphrase(t, "a rotated credential"), KeyslotParams{KDF: kdf}); err != nil {
		t.Fatalf("ChangeKeyslot failed: %v", err)
	}
	if err := v.RemoveKeyslot(ctx, added.ID); err != nil {
		t.Fatalf("RemoveKeyslot(%d) failed: %v", added.ID, err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the image back failed: %v", err)
	}
	if int64(len(raw)) != st.Size() {
		t.Fatalf("the image is %d bytes after the keyslot changes, want %d", len(raw), st.Size())
	}
	if !bytes.Equal(raw[offset:], pattern) {
		t.Fatal("a keyslot change wrote into the data segment")
	}
	txnKey(t, v) // the original credential still opens the volume
}

// TestRemoveKeyslotDropsTheSlotFromEveryDigestAndTokenInOneWrite pins the
// keyslot persistence rule: removing a keyslot drops its number from every
// digest and token, and a token left naming no keyslot is kept. It also pins
// that AddKeyslot reports the slot it wrote when the slots are not contiguous.
func TestRemoveKeyslotDropsTheSlotFromEveryDigestAndTokenInOneWrite(t *testing.T) {
	ctx := context.Background()
	path := formattedVolumeImage(t, "keyslot-remove-references.img", "", "")
	v := txnVolume(t, path)

	slot := 5
	added, err := v.AddKeyslot(ctx, txnKey(t, v), txnPassphrase(t, "an added credential"),
		KeyslotParams{Slot: &slot, KDF: KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond}})
	if err != nil {
		t.Fatalf("AddKeyslot failed: %v", err)
	}
	if added.ID != slot {
		t.Fatalf("AddKeyslot reported slot %d, want %d (the slots are 0 and %d)", added.ID, slot, slot)
	}
	only, err := v.AddToken(ctx, Token{Type: "x-only-the-removed-slot", Keyslots: []int{slot}})
	if err != nil {
		t.Fatalf("AddToken failed: %v", err)
	}
	both, err := v.AddToken(ctx, Token{Type: "x-both-slots", Keyslots: []int{0, slot}})
	if err != nil {
		t.Fatalf("AddToken failed: %v", err)
	}

	if err := v.RemoveKeyslot(ctx, slot); err != nil {
		t.Fatalf("RemoveKeyslot(%d) failed: %v", slot, err)
	}

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("reading the header back failed: %v", err)
	}
	if len(metadata.Digests) == 0 {
		t.Fatal("the header has no digests")
	}
	for id, d := range metadata.Digests {
		for _, ks := range d.Keyslots {
			if ks == "5" {
				t.Errorf("digest %s still names the removed keyslot: %v", id, d.Keyslots)
			}
		}
	}
	h, err := v.Header(ctx)
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}
	for _, ks := range h.Keyslots() {
		if ks.ID == slot {
			t.Fatalf("keyslot %d is still in the header", slot)
		}
	}
	tokens := h.Tokens()
	kept, ok := tokens[only]
	if !ok {
		t.Fatalf("the token that named only the removed keyslot was dropped; tokens %v", tokens)
	}
	if len(kept.Keyslots) != 0 {
		t.Errorf("token %d names keyslots %v after the removal, want none", only, kept.Keyslots)
	}
	if got := tokens[both].Keyslots; len(got) != 1 || got[0] != 0 {
		t.Errorf("token %d names keyslots %v after the removal, want [0]", both, got)
	}
}

// TestEveryWrittenKDFSaltIsThirtyTwoFreshRandomBytes pins "Salts are 32
// random bytes": every keyslot Format and AddKeyslot write, and the digest,
// carries a 32-byte salt, and no two of them share one.
func TestEveryWrittenKDFSaltIsThirtyTwoFreshRandomBytes(t *testing.T) {
	ctx := context.Background()
	path := formattedVolumeImage(t, "keyslot-salts.img", "", "")
	v := txnVolume(t, path)
	for _, cred := range []string{"a second credential", "a third credential"} {
		if _, err := v.AddKeyslot(ctx, txnKey(t, v), txnPassphrase(t, cred),
			KeyslotParams{KDF: KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond}}); err != nil {
			t.Fatalf("AddKeyslot failed: %v", err)
		}
	}

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("reading the header back failed: %v", err)
	}
	if len(metadata.Keyslots) != 3 {
		t.Fatalf("the fixture has %d keyslots, want 3", len(metadata.Keyslots))
	}
	seen := map[string]string{}
	check := func(what, encoded string) {
		t.Helper()
		salt, err := decodeBase64(encoded)
		if err != nil {
			t.Fatalf("%s salt %q is not base64: %v", what, encoded, err)
		}
		if len(salt) != 32 {
			t.Errorf("%s salt is %d bytes, want 32", what, len(salt))
		}
		if bytes.Equal(salt, make([]byte, len(salt))) {
			t.Errorf("%s salt is all zero", what)
		}
		if prev, dup := seen[string(salt)]; dup {
			t.Errorf("%s reuses the salt of %s", what, prev)
		}
		seen[string(salt)] = what
	}
	for id, ks := range metadata.Keyslots {
		if ks.KDF == nil {
			t.Fatalf("keyslot %s has no KDF", id)
		}
		check("keyslot "+id, ks.KDF.Salt)
	}
	for id, d := range metadata.Digests {
		check("digest "+id, d.Salt)
	}
}

func TestVolumeRemoveKeyslotRefusesTheLastKeyslot(t *testing.T) {
	path := formattedVolumeImage(t, "removekeyslot-last.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if err := v.RemoveKeyslot(context.Background(), 0); !errors.Is(err, ErrLastKeyslot) {
		t.Errorf("RemoveKeyslot on the only keyslot = %v, want ErrLastKeyslot", err)
	}
}

func TestVolumeRemoveKeyslotOnAMissingSlotFails(t *testing.T) {
	path := formattedVolumeImage(t, "removekeyslot-missing.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if err := v.RemoveKeyslot(context.Background(), 7); !errors.Is(err, ErrKeyslotNotFound) {
		t.Errorf("RemoveKeyslot on an unused slot = %v, want ErrInvalidKeyslot", err)
	}
}

func TestVolumeRemoveKeyslotOnAReadOnlyVolumeFails(t *testing.T) {
	path := formattedVolumeImage(t, "removekeyslot-readonly.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()), WithReadOnly())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if err := v.RemoveKeyslot(context.Background(), 0); !errors.Is(err, ErrReadOnly) {
		t.Errorf("RemoveKeyslot on a read-only Volume = %v, want ErrReadOnly", err)
	}
}

// TestVolumeRemoveKeyslotRefusesAnInUseDevice is #246 D4 for the no-credential
// removal path: RemoveKeyslot takes no passphrase, so the exclusive claim
// (locked.Claim, the same call Format and Erase already make) is the only
// thing refusing it on a volume that is open, or a device something else
// holds. This substitutes the openFile seam the claim's O_EXCL reopen goes
// through, rather than a real mapping, so it needs no root and no loop
// device; the kernel's own EBUSY is proved against a real device in
// TestWipeKeyslotRefusesAnActiveDeviceDespiteARetarget (integration).
func TestVolumeRemoveKeyslotRefusesAnInUseDevice(t *testing.T) {
	path := formattedVolumeImage(t, "removekeyslot-inuse.img", "", "")

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

	newPass := newPassphraseEnclave(t, "the slot a refused RemoveKeyslot must not touch")
	defer func() { _ = newPass.Destroy() }()
	added, err := v.AddKeyslot(context.Background(), key, newPass, KeyslotParams{
		KDF: KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond},
	})
	if err != nil {
		t.Fatalf("AddKeyslot failed: %v", err)
	}

	real := v.sys.openFile
	v.sys.openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		// The exclusive claim reopens the locked descriptor's own
		// /proc/self/fd entry (device.Locked.Claim); intercepting that
		// exact open stands in for the kernel's EBUSY on an active mapping.
		if strings.HasPrefix(name, "/proc/self/fd/") && flag&os.O_EXCL != 0 {
			return nil, &fs.PathError{Op: "open", Path: name, Err: syscall.EBUSY}
		}
		return real(name, flag, perm)
	}

	if err := v.RemoveKeyslot(context.Background(), added.ID); !errors.Is(err, ErrDeviceInUse) {
		t.Fatalf("RemoveKeyslot of an in-use device = %v, want ErrDeviceInUse", err)
	}

	// Nothing written: the keyslot a refused removal targeted must still
	// open with its own credential.
	if _, err := v.UnlockKeyslot(context.Background(), added.ID, newPass); err != nil {
		t.Errorf("UnlockKeyslot on the slot a refused RemoveKeyslot targeted failed: %v", err)
	}
}
