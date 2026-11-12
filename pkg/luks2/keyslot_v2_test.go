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
