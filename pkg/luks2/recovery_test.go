// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

func TestParseRecoveryKey(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectLen int
		expectErr bool
	}{
		{
			name:      "dashed format",
			input:     "AABBCC-DDEEFF-112233-445566",
			expectLen: 12,
			expectErr: false,
		},
		{
			name:      "hex format",
			input:     "aabbccddeeff112233445566",
			expectLen: 12,
			expectErr: false,
		},
		{
			name:      "base64 format",
			input:     "qrvM3e7/ESIzRFVm",
			expectLen: 12,
			expectErr: false,
		},
		{
			name:      "hex with spaces (trimmed)",
			input:     "  aabbccddeeff  ",
			expectLen: 6,
			expectErr: false,
		},
		{
			name:      "invalid hex",
			input:     "gghhii",
			expectLen: 0,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := parseLegacyRecoveryKey(tt.input)

			if tt.expectErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			defer mustDestroy(t, key)

			// ParseRecoveryKey hands back an ENCLAVE, so the decoded key is
			// never a slice the caller has to remember to wipe.
			if key.Size() != tt.expectLen {
				t.Errorf("expected length %d, got %d", tt.expectLen, key.Size())
			}
		})
	}
}

func TestRecoveryKeyRoundTrip(t *testing.T) {
	original, err := NewRecoveryKey(WithRecoveryFormat(RecoveryDashed))
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	defer original.Destroy()

	var buf bytes.Buffer
	if _, err := original.WriteTo(&buf); err != nil {
		t.Fatalf("failed to materialize the formatted key: %v", err)
	}

	// Parse it back
	parsed, err := parseLegacyRecoveryKey(buf.String())
	if err != nil {
		t.Fatalf("failed to parse key: %v", err)
	}
	defer mustDestroy(t, parsed)

	// The decode still yields the 32 bytes behind the rendering, which is what
	// parseLegacyRecoveryKey is for. It is no longer the credential: see
	// TestTheCredentialIsThePrintedText below.
	if parsed.Size() != 32 {
		t.Errorf("round-trip failed: decoded %d bytes, want 32", parsed.Size())
	}
}

// TestTheCredentialIsThePrintedText is the property the whole design rests on:
// the string an operator writes down is the passphrase, so it must come back
// out of the enclave and out of RecoveryCredential unchanged.
//
// The cross-check against cryptsetup lives in the CLI tests, where a real
// container can be opened with it.
func TestTheCredentialIsThePrintedText(t *testing.T) {
	for _, format := range []RecoveryKeyFormat{RecoveryDashed, RecoveryHex, RecoveryBase64} {
		t.Run(format.String(), func(t *testing.T) {
			key, err := NewRecoveryKey(WithRecoveryFormat(format))
			if err != nil {
				t.Fatalf("NewRecoveryKey failed: %v", err)
			}
			defer key.Destroy()

			var buf bytes.Buffer
			if _, err := key.WriteTo(&buf); err != nil {
				t.Fatalf("WriteTo failed: %v", err)
			}
			printed := buf.String()

			// The hash published alongside the key identifies THAT string, so
			// a transcription can be checked without touching the volume.
			sum := sha256.Sum256([]byte(printed))
			if key.Hash() != hex.EncodeToString(sum[:]) {
				t.Error("Hash() is not the hash of the printed text")
			}
		})
	}
}

// AddRecoveryKey used to REPORT a keyslot it had not used (#42).
//
// AddKey chooses a slot and does not report which, so AddRecoveryKey inferred
// it afterwards as the HIGHEST-numbered slot in the header. AddKey fills the
// FIRST FREE slot, so the inference is wrong on any volume with a gap -- which
// is the ordinary state of one where a credential has ever been revoked.
//
// The number is written into the saved recovery-key file. An operator revoking
// "the recovery key" months later therefore destroys a different, live
// credential AND leaves the recovery key working: data loss and a failed
// revocation from one wrong integer.

// fipsSafeAddKeyOptions selects PBKDF2 explicitly.
//
// AddKey with nil options defaults to argon2id, which the Go Cryptographic
// Module refuses under GODEBUG=fips140=on -- so a fixture that passed nil built
// its volume fine in the default build and failed the FIPS leg with
// "algorithm not approved in FIPS 140-3 mode". Measured: the race leg and
// govulncheck were both green while all four of these tests were broken under
// FIPS. formatWithLibrary makes the same choice for the same reason.
//
// The iteration time is the minimum, because these fixtures add several
// credentials each and the KDF cost is not what any of them is about.
func fipsSafeAddKeyOptions() *addKeyOptionsForTest {
	return &addKeyOptionsForTest{KDFType: kdfTypePBKDF2, PBKDFIterTime: 1}
}

// recoveryTestIterations is the explicit PBKDF2 count the AddRecoveryKey tests
// enroll with, where the subject is which keyslot and token get written, not
// what the keyslot costs.
//
// Left to calibrate, every one of those keyslots was stretched to the default
// iteration time, and each test then pays that derivation again for every
// probe that opens it -- keyslotOpenedBy tries every slot. That was the single
// largest cost in the package (#92). The floor is minPBKDF2Iterations because
// a recovery key is library-generated and RecoveryKeyOptions.PBKDFIterations
// admits exactly that. Calibration itself is exercised by the Format and AddKey
// tests and the exemption by keyslotcostpolicy_test.go; per-function coverage
// of the package was identical before and after this switch.
const recoveryTestIterations = minPBKDF2Iterations

// volumeWithAKeyslotGap returns a container holding keyslots {0, 2} -- the
// shape any volume takes once a credential has been revoked -- together with
// the passphrases that open them.
func volumeWithAKeyslotGap(t *testing.T) (device string, primary, third []byte) {
	t.Helper()

	device = newImage(t, "keyslot-gap.img")
	formatWithLibrary(t, device)

	primary = []byte(conformancePassphrase)
	second := []byte("second-credential-passphrase")
	third = []byte("third-credential-passphrase")

	if _, err := addKeyForTest(device, primary, second, fipsSafeAddKeyOptions()); err != nil {
		t.Fatalf("AddKey for slot 1: %v", err)
	}
	if _, err := addKeyForTest(device, primary, third, fipsSafeAddKeyOptions()); err != nil {
		t.Fatalf("AddKey for slot 2: %v", err)
	}
	if err := removeKeyForTest(device, second, 1); err != nil {
		t.Fatalf("removeKeyForTest(1): %v", err)
	}

	assertKeyslotIDs(t, device, []string{"0", "2"})
	return device, primary, third
}

// assertKeyslotIDs fails unless the container holds exactly these keyslots.
// The fixture above is only meaningful if the gap is really there, and a
// silently-different keyslot layout would make every assertion below vacuous.
func assertKeyslotIDs(t *testing.T, device string, want []string) {
	t.Helper()

	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	got := header.KeyslotIDsInScanOrder(metadata.Keyslots)
	if len(got) != len(want) {
		t.Fatalf("keyslots are %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("keyslots are %v, want %v", got, want)
		}
	}
}

// keyslotOpenedBy returns the id of the single keyslot this credential opens,
// or "" if it opens none. It tries every slot rather than stopping at the
// first, so a credential that opens more than one is a failure rather than a
// silently-taken first answer.
func keyslotOpenedBy(t *testing.T, device string, passphrase []byte) string {
	t.Helper()

	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}

	opened := ""
	for _, id := range header.KeyslotIDsInScanOrder(metadata.Keyslots) {
		key, err := unlockKeyslot(context.Background(), device, id, passphrase, metadata.Keyslots[id], metadata.Digests, testVolumeSys())
		if err != nil {
			continue
		}
		mustDestroy(t, key)
		if opened != "" {
			t.Fatalf("one credential opened both keyslot %s and keyslot %s", opened, id)
		}
		opened = id
	}
	return opened
}

// TestAddRecoveryKeyReportsTheKeyslotItActuallyUsed is the #42 regression test.
//
// Before the fix, on this fixture: the recovery key landed in slot 1 and was
// reported as slot 2.
func TestAddRecoveryKeyReportsTheKeyslotItActuallyUsed(t *testing.T) {
	defer parallel(t)()

	device, primary, third := volumeWithAKeyslotGap(t)

	credential, keyslot, _, err := enrollRecoveryKeyForTest(t, device, primary)
	if err != nil {
		t.Fatalf("AddRecoveryKey: %v", err)
	}

	// The report has to name the slot the recovery key actually opens.
	actual := keyslotOpenedBy(t, device, []byte(credential))
	if actual == "" {
		t.Fatal("the recovery key opens no keyslot at all")
	}
	if got := strconv.Itoa(keyslot); got != actual {
		t.Fatalf("AddRecoveryKey reports keyslot %s; the recovery key opens keyslot %s. Revoking as reported destroys a different credential and leaves the recovery key live",
			got, actual)
	}

	// The damage plane, stated as the operator's action: revoking the reported
	// slot must not take a credential a human still uses with it.
	for name, credential := range map[string][]byte{"primary": primary, "third": third} {
		if opened := keyslotOpenedBy(t, device, credential); opened == strconv.Itoa(keyslot) {
			t.Fatalf("the %s passphrase opens keyslot %s, which is the slot reported for the recovery key; revoking it would destroy a live credential",
				name, opened)
		}
	}
}

// TestAddRecoveryKeyHonoursAnExplicitKeyslot covers the other branch, which was
// always correct and must stay so: a caller naming a slot gets that slot, and
// the report agrees.
func TestAddRecoveryKeyHonoursAnExplicitKeyslot(t *testing.T) {
	defer parallel(t)()

	device, primary, _ := volumeWithAKeyslotGap(t)

	requested := 7

	ctx := context.Background()
	v, err := Open(ctx, device, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryCopy(primary)
	if err != nil {
		t.Fatalf("could not build a test passphrase enclave: %v", err)
	}
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(ctx, pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	rk, err := NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey failed: %v", err)
	}
	defer rk.Destroy()

	enrollment, err := v.AddRecoveryKey(ctx, key, rk, KeyslotParams{Slot: &requested, KDF: KDFParams{Type: KDFPBKDF2, Iterations: recoveryTestIterations}})
	if err != nil {
		t.Fatalf("AddRecoveryKey: %v", err)
	}

	if enrollment.Keyslot.ID != requested {
		t.Fatalf("AddRecoveryKey reports keyslot %d, want the requested %d", enrollment.Keyslot.ID, requested)
	}

	var buf bytes.Buffer
	if _, err := rk.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	actual := keyslotOpenedBy(t, device, buf.Bytes())
	if actual != strconv.Itoa(requested) {
		t.Fatalf("the recovery key opens keyslot %s, but slot %d was requested", actual, requested)
	}
}

// TestAddRecoveryKeyPicksTheFreeSlotEvenWhenTheGapIsFilledFirst pins that the
// answer comes from the CHOICE and not from the shape of the header.
//
// The gap at slot 1 is occupied before the call, so the recovery key must land
// somewhere else -- and the report must follow it there. A rule that
// reconstructed the slot from the header would have to get this right by a
// second piece of reasoning; reading the choice gets it right by construction.
func TestAddRecoveryKeyPicksTheFreeSlotEvenWhenTheGapIsFilledFirst(t *testing.T) {
	defer parallel(t)()

	device, primary, _ := volumeWithAKeyslotGap(t)

	occupied := 1
	occupyOpts := fipsSafeAddKeyOptions()
	occupyOpts.Keyslot = &occupied
	if _, err := addKeyForTest(device, primary, []byte("occupies-the-gap-slot"), occupyOpts); err != nil {
		t.Fatalf("AddKey into the gap: %v", err)
	}
	assertKeyslotIDs(t, device, []string{"0", "1", "2"})

	credential, keyslot, _, err := enrollRecoveryKeyForTest(t, device, primary)
	if err != nil {
		t.Fatalf("AddRecoveryKey: %v", err)
	}

	actual := keyslotOpenedBy(t, device, []byte(credential))
	if actual == "" {
		t.Fatal("the recovery key opens no keyslot at all")
	}
	if got := strconv.Itoa(keyslot); got != actual {
		t.Fatalf("AddRecoveryKey reports keyslot %s; the recovery key opens keyslot %s", got, actual)
	}
	// And it must not have taken a slot that was already someone else's.
	if actual == "1" {
		t.Fatal("the recovery key took the occupied slot 1")
	}
}

// TestAddKeyReportsTheSlotItChose covers the seam directly: AddKey returns the
// slot it used (#101), read from where it was chosen rather than inferred.
func TestAddKeyReportsTheSlotItChose(t *testing.T) {
	defer parallel(t)()

	device, primary, _ := volumeWithAKeyslotGap(t)

	assigned, err := addKeyForTest(device, primary, []byte("a-new-credential-here"), fipsSafeAddKeyOptions())
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	// The FIRST FREE slot, which is the gap -- not the highest, which is what
	// the deleted inference would have said.
	if assigned != 1 {
		t.Fatalf("AddKey reported slot %d, want the first free slot 1", assigned)
	}
	if opened := keyslotOpenedBy(t, device, []byte("a-new-credential-here")); opened != "1" {
		t.Fatalf("the new credential opens keyslot %s, but slot %d was reported", opened, assigned)
	}

	// With the gap filled the next free slot is past the occupied ones, and
	// the report must follow the choice rather than repeat the last answer.
	next, err := addKeyForTest(device, primary, []byte("another-new-credential"), fipsSafeAddKeyOptions())
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	if opened := keyslotOpenedBy(t, device, []byte("another-new-credential")); opened != strconv.Itoa(next) {
		t.Fatalf("the second credential opens keyslot %s, but slot %d was reported", opened, next)
	}
}

// TestAddKeyReportsNoSlotOnFailure pins the contract a caller relies on when it
// records the number: an error comes with -1, never a slot that was chosen but
// not written.
func TestAddKeyReportsNoSlotOnFailure(t *testing.T) {
	defer parallel(t)()

	device, _, _ := volumeWithAKeyslotGap(t)

	slot, err := addKeyForTest(device, []byte("not-the-primary-passphrase"), []byte("a-new-credential-here"), fipsSafeAddKeyOptions())
	if err == nil {
		t.Fatal("AddKey with a wrong existing passphrase succeeded")
	}
	if slot != -1 {
		t.Fatalf("AddKey reported slot %d alongside an error, want -1", slot)
	}
}

// TestAddRecoveryKeyWritesTheSystemdRecoveryToken.
//
// Without the token the header says a keyslot exists and nothing says what it
// is, which is indistinguishable from somebody's forgotten second passphrase --
// and the difference decides whether an operator revokes it.
func TestAddRecoveryKeyWritesTheSystemdRecoveryToken(t *testing.T) {
	defer parallel(t)()

	device, primary, _ := volumeWithAKeyslotGap(t)

	_, keyslot, tokenID, err := enrollRecoveryKeyForTest(t, device, primary)
	if err != nil {
		t.Fatalf("AddRecoveryKey: %v", err)
	}

	if tokenID < 0 {
		t.Fatal("AddRecoveryKey wrote no token")
	}

	token, ok, err := getTokenForTest(device, tokenID)
	if err != nil {
		t.Fatalf("getTokenForTest(%d): %v", tokenID, err)
	}
	if !ok {
		t.Fatalf("Tokens()[%d] missing after AddRecoveryKey", tokenID)
	}
	if token.Type != recoveryTokenType {
		t.Errorf("token type is %q, want %q", token.Type, recoveryTokenType)
	}
	// It names the slot the library CHOSE, on a container whose slots are not
	// contiguous -- which is the case an inferred number gets wrong (#42).
	if len(token.Keyslots) != 1 || token.Keyslots[0] != keyslot {
		t.Errorf("token names keyslots %v, want [%d]", token.Keyslots, keyslot)
	}

	// systemd's recovery token carries NOTHING ELSE. There is no material to
	// record, and a member of our own invention here would be a token systemd
	// reads differently from the way it was written.
	encoded, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var members map[string]any
	if err := json.Unmarshal(encoded, &members); err != nil {
		t.Fatalf("the token is not JSON: %v", err)
	}
	if len(members) != 2 {
		t.Errorf("the token carries %v, want only type and keyslots", members)
	}
}

// TestAddRecoveryKeyRollsBackAKeyslotItCannotIdentify.
//
// A keyslot with no token is an orphan: it opens the volume, nothing on the
// device says what opens it, and nobody inspecting the container later can tell
// it from a credential still in use.
func TestAddRecoveryKeyRollsBackAKeyslotItCannotIdentify(t *testing.T) {
	defer parallel(t)()
	device, primary, _ := volumeWithAKeyslotGap(t)

	sys := testVolumeSys()
	sys.importToken = func(context.Context, *keyslotDevice, int, *LegacyToken) error {
		return errors.New("the header could not be written")
	}

	if _, _, _, err := enrollRecoveryKeyForTest(t, device, primary, withTestSys(sys)); err == nil {
		t.Fatal("AddRecoveryKey reported success with an unwritable token")
	} else if errors.Is(err, ErrOrphanedKeyslot) {
		t.Fatalf("the keyslot was orphaned rather than rolled back: %v", err)
	}

	// The container is as it was: no extra slot, and the primary still opens it.
	assertKeyslotIDs(t, device, []string{"0", "2"})
	if err := testKeyForTest(device, primary); err != nil {
		t.Fatalf("the volume no longer opens with the primary passphrase: %v", err)
	}
}

// TestAddRecoveryKeyReportsAnOrphanItCannotRemove is the one outcome that needs
// a human, and the slot number in the message is the only record of it.
func TestAddRecoveryKeyReportsAnOrphanItCannotRemove(t *testing.T) {
	defer parallel(t)()
	device, primary, _ := volumeWithAKeyslotGap(t)

	sys := testVolumeSys()
	sys.importToken = func(context.Context, *keyslotDevice, int, *LegacyToken) error {
		return errors.New("the header could not be written")
	}
	sys.killKeyslot = func(context.Context, *keyslotDevice, int) error { return errors.New("the device is read-only") }

	_, _, _, err := enrollRecoveryKeyForTest(t, device, primary, withTestSys(sys))
	if err == nil {
		t.Fatal("AddRecoveryKey reported success")
	}
	if !errors.Is(err, ErrOrphanedKeyslot) {
		t.Fatalf("error = %v, want errors.Is(_, ErrOrphanedKeyslot)", err)
	}

	var orphan *OrphanedKeyslotError
	if !errors.As(err, &orphan) {
		t.Fatalf("error = %v, want an *OrphanedKeyslotError", err)
	}
	// The slot is real, and it is the one the credential went into.
	if orphan.Keyslot != 1 {
		t.Errorf("orphaned keyslot = %d, want 1 -- the free slot in the gap", orphan.Keyslot)
	}
	if !strings.Contains(orphan.Error(), strconv.Itoa(orphan.Keyslot)) {
		t.Errorf("Error() = %q, want it to name the slot", orphan.Error())
	}
}

// TestAddRecoveryKeyRefusesWhenNoTokenSlotIsFree checks the cheap order: the
// token slot is claimed BEFORE key material is written, so running out costs
// nothing rather than costing a rollback.
func TestAddRecoveryKeyRefusesWhenNoTokenSlotIsFree(t *testing.T) {
	defer parallel(t)()

	device, primary, _ := volumeWithAKeyslotGap(t)

	for id := 0; id < MaxTokens; id++ {
		if err := setTokenForTest(device, id, Token{Type: "occupied"}); err != nil {
			t.Fatalf("SetToken(%d): %v", id, err)
		}
	}

	if _, _, _, err := enrollRecoveryKeyForTest(t, device, primary); err == nil {
		t.Fatal("AddRecoveryKey succeeded with every token slot occupied")
	} else if !errors.Is(err, ErrNoSpace) {
		t.Errorf("error = %v, want errors.Is(_, ErrNoSpace)", err)
	}

	// No key material was written.
	assertKeyslotIDs(t, device, []string{"0", "2"})
}

// TestRecoveryCredentialDoesNotNormalize.
//
// The keyslot holds the characters that were printed. A "helpful"
// canonicalization on the way back in produces bytes the volume has never seen,
// and the operator is told their correctly transcribed key is wrong.
func TestRecoveryCredentialDoesNotNormalize(t *testing.T) {
	tests := []struct {
		name  string
		typed string
		want  string
	}{
		{name: "dashed, as printed", typed: "9F3A2C-4B81DE-07C5A6", want: "9F3A2C-4B81DE-07C5A6"},
		{name: "case is preserved", typed: "9f3a2c-4b81de-07c5a6", want: "9f3a2c-4b81de-07c5a6"},
		{name: "dashes are preserved", typed: "9F3A2C4B81DE07C5A6", want: "9F3A2C4B81DE07C5A6"},
		{name: "base64 padding is preserved", typed: "nzosS4HeB8Wm=", want: "nzosS4HeB8Wm="},
		{name: "surrounding whitespace is not part of it", typed: "  9F3A2C-4B81DE  ", want: "9F3A2C-4B81DE"},
		{name: "a trailing newline is not part of it", typed: "9F3A2C-4B81DE\n", want: "9F3A2C-4B81DE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typed, err := enclave.NewMemoryCopy([]byte(tt.typed))
			if err != nil {
				t.Fatalf("could not build a test enclave: %v", err)
			}
			defer func() { _ = typed.Destroy() }()

			credential, err := ParseRecoveryKey(typed)
			if err != nil {
				t.Fatalf("ParseRecoveryKey(%q): %v", tt.typed, err)
			}
			defer mustDestroy(t, credential)

			if got := string(openSecret(t, credential)); got != tt.want {
				t.Errorf("ParseRecoveryKey(%q) = %q, want %q", tt.typed, got, tt.want)
			}
		})
	}
}

func TestRecoveryCredentialRefusesWhatCannotBeOne(t *testing.T) {
	tests := []struct {
		name  string
		typed string
	}{
		{name: "empty", typed: ""},
		{name: "only whitespace", typed: "   \n\t"},
		{name: "more than one line", typed: "9F3A2C-4B81DE\nAABBCC-DDEEFF\n"},
		{name: "a whole saved file", typed: "# LUKS Recovery Key\n# Keyslot: 1\n9F3A2C-4B81DE\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typed, err := enclave.NewMemoryCopy([]byte(tt.typed))
			if err != nil {
				// Refused before ParseRecoveryKey even runs -- an empty
				// enclave is refused at the enclave boundary itself, which
				// still satisfies "cannot be a recovery key".
				return
			}
			defer func() { _ = typed.Destroy() }()

			credential, err := ParseRecoveryKey(typed)
			if err == nil {
				mustDestroy(t, credential)
				t.Fatalf("ParseRecoveryKey(%q) accepted something that cannot be a recovery key", tt.typed)
			}
		})
	}
}

// TestTheTwoParsersDecodeDifferently pins the difference between
// ParseRecoveryKey and parseLegacyRecoveryKey, which is the whole reason
// both exist: a keyslot this package enrolls holds the printed TEXT, and one
// enrolled before that change holds the DECODED bytes behind it. B.6 moved
// the two loaders' file I/O to internal/cli (LoadRecoveryCredential,
// LoadRecoveryKey), but the parsing distinction itself is still the
// library's to keep.
func TestTheTwoParsersDecodeDifferently(t *testing.T) {
	key, err := NewRecoveryKey(WithRecoveryFormat(RecoveryDashed))
	if err != nil {
		t.Fatalf("NewRecoveryKey: %v", err)
	}
	defer key.Destroy()

	var buf bytes.Buffer
	if _, err := key.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	printed := buf.String()

	typed, err := enclave.NewMemoryCopy(buf.Bytes())
	if err != nil {
		t.Fatalf("could not build a test enclave: %v", err)
	}
	defer func() { _ = typed.Destroy() }()

	credential, err := ParseRecoveryKey(typed)
	if err != nil {
		t.Fatalf("ParseRecoveryKey: %v", err)
	}
	defer mustDestroy(t, credential)

	if got := string(openSecret(t, credential)); got != printed {
		t.Error("ParseRecoveryKey did not return the credential verbatim")
	}

	// The other parser decodes the same line, and the two must NOT agree --
	// if they did, one of them is not doing what its name says.
	decoded, err := parseLegacyRecoveryKey(printed)
	if err != nil {
		t.Fatalf("parseLegacyRecoveryKey: %v", err)
	}
	defer mustDestroy(t, decoded)

	if decoded.Size() != 32 {
		t.Errorf("parseLegacyRecoveryKey returned %d bytes, want the 32 behind the rendering", decoded.Size())
	}
	if string(openSecret(t, decoded)) == printed {
		t.Error("parseLegacyRecoveryKey returned the credential rather than its decoding")
	}
}
