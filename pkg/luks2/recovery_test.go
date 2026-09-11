// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

func TestGenerateRecoveryKey(t *testing.T) {
	tests := []struct {
		name      string
		length    int
		format    RecoveryKeyFormat
		expectLen int
		expectErr bool
	}{
		{
			name:      "default length hex format",
			length:    0, // Will use default
			format:    RecoveryKeyFormatHex,
			expectLen: RecoveryKeyLength,
			expectErr: false,
		},
		{
			name:      "32 bytes hex format",
			length:    32,
			format:    RecoveryKeyFormatHex,
			expectLen: 32,
			expectErr: false,
		},
		{
			name:      "64 bytes base64 format",
			length:    64,
			format:    RecoveryKeyFormatBase64,
			expectLen: 64,
			expectErr: false,
		},
		{
			name:      "32 bytes dashed format",
			length:    32,
			format:    RecoveryKeyFormatDashed,
			expectLen: 32,
			expectErr: false,
		},
		{
			name:      "empty format defaults to dashed",
			length:    32,
			format:    "",
			expectLen: 32,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateRecoveryKey(tt.length, tt.format)

			if tt.expectErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			defer key.Clear()

			if key.Key.Size() != tt.expectLen {
				t.Errorf("expected key length %d, got %d", tt.expectLen, key.Key.Size())
			}

			// The key is held in an ENCLAVE, not a slice: it can be destroyed,
			// and reading it afterwards fails rather than returning stale bytes.
			if !key.Key.IsAlive() {
				t.Error("the generated key is not held in live protected memory")
			}

			if key.Formatted.Size() == 0 {
				t.Error("expected formatted key to be non-empty")
			}

			if key.KeyHash == "" {
				t.Error("expected key hash to be non-empty")
			}

			if key.CreatedAt.IsZero() {
				t.Error("expected created at to be set")
			}

			// Verify format
			expectedFormat := tt.format
			if expectedFormat == "" {
				expectedFormat = RecoveryKeyFormatDashed
			}
			if key.Format != expectedFormat {
				t.Errorf("expected format %s, got %s", expectedFormat, key.Format)
			}
		})
	}
}

// TestFormatDashedKey pins the dashed rendering byte for byte.
//
// It matters more than it looks: the rendering is now built IN PLACE inside
// locked memory, by encoding the hex right-aligned in the destination and
// expanding it leftward around the separators, rather than by joining strings.
// These fixtures are what stands between that rewrite and a recovery key that
// prints differently from the one that was stored.
func TestFormatDashedKey(t *testing.T) {
	tests := []struct {
		name     string
		key      []byte
		expected string
	}{
		{
			name:     "simple 6 bytes",
			key:      []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			expected: "010203-040506",
		},
		{
			name:     "12 bytes",
			key:      []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			expected: "AABBCC-DDEEFF-112233-445566",
		},
		{
			name:     "uneven bytes",
			key:      []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expected: "010203-0405",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dst := make([]byte, formattedLen(len(tt.key), RecoveryKeyFormatDashed))
			formatRecoveryKeyInto(dst, tt.key, RecoveryKeyFormatDashed)

			if result := string(dst); result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

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
			key, err := ParseRecoveryKey(tt.input)

			if tt.expectErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			defer key.Destroy()

			// ParseRecoveryKey hands back an ENCLAVE, so the decoded key is
			// never a slice the caller has to remember to wipe.
			if key.Size() != tt.expectLen {
				t.Errorf("expected length %d, got %d", tt.expectLen, key.Size())
			}
		})
	}
}

func TestRecoveryKeyRoundTrip(t *testing.T) {
	// Generate a key
	original, err := GenerateRecoveryKey(32, RecoveryKeyFormatDashed)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	defer original.Clear()

	formatted, err := original.FormattedString()
	if err != nil {
		t.Fatalf("failed to materialize the formatted key: %v", err)
	}

	// Parse it back
	parsed, err := ParseRecoveryKey(formatted)
	if err != nil {
		t.Fatalf("failed to parse key: %v", err)
	}
	defer parsed.Destroy()

	// Compare
	if hex.EncodeToString(openSecret(t, original.Key)) != hex.EncodeToString(openSecret(t, parsed)) {
		t.Error("round-trip failed: keys don't match")
	}
}

func TestSaveAndLoadRecoveryKey(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "luks-recovery-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Generate key
	key, err := GenerateRecoveryKey(32, RecoveryKeyFormatDashed)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	key.VolumeUUID = "test-uuid-1234"
	key.Keyslot = 2

	// Save to file
	keyPath := filepath.Join(tmpDir, "recovery-key.txt")
	if err := SaveRecoveryKey(key, keyPath); err != nil {
		t.Fatalf("failed to save key: %v", err)
	}

	// Verify file permissions
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("failed to stat key file: %v", err)
	}
	if info.Mode().Perm() != 0400 {
		t.Errorf("expected file permissions 0400, got %o", info.Mode().Perm())
	}

	// Load and verify
	loaded, err := LoadRecoveryKey(keyPath)
	if err != nil {
		t.Fatalf("failed to load key: %v", err)
	}

	defer loaded.Destroy()

	if hex.EncodeToString(openSecret(t, key.Key)) != hex.EncodeToString(openSecret(t, loaded)) {
		t.Error("loaded key doesn't match original")
	}
}

func TestSaveRecoveryKeyContent(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "luks-recovery-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Generate key with specific values
	key := &RecoveryKey{
		Key:        enclaveFrom(t, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}),
		Formatted:  enclaveFrom(t, []byte("010203-040506")),
		Format:     RecoveryKeyFormatDashed,
		KeyHash:    "testhash",
		VolumeUUID: "test-uuid",
		Keyslot:    1,
	}

	keyPath := filepath.Join(tmpDir, "recovery-key.txt")
	if err := SaveRecoveryKey(key, keyPath); err != nil {
		t.Fatalf("failed to save key: %v", err)
	}

	// Verify the file carries the expected elements. This searches the file
	// in locked memory rather than copying it into a plain heap string --
	// see savedFileContains -- because the file holds a USABLE CREDENTIAL.
	if !savedFileContains(t, keyPath, "LUKS Recovery Key") {
		t.Error("expected header in file")
	}
	if !savedFileContains(t, keyPath, "test-uuid") {
		t.Error("expected UUID in file")
	}
	if !savedFileContains(t, keyPath, "Keyslot: 1") {
		t.Error("expected keyslot in file")
	}
	if !savedFileContains(t, keyPath, "010203-040506") {
		t.Error("expected recovery key in file")
	}
}

func TestRecoveryKeyClear(t *testing.T) {
	key, err := GenerateRecoveryKey(32, RecoveryKeyFormatHex)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Verify key is set
	if key.Key.Size() == 0 {
		t.Fatal("key should not be empty")
	}
	if key.Formatted.Size() == 0 {
		t.Fatal("formatted key should not be empty")
	}

	held, rendered := key.Key, key.Formatted

	// Clear the key
	key.Clear()

	// Verify key is cleared. Both halves matter: the handle is dropped AND the
	// locked region behind it is destroyed, so a copy of the handle taken
	// before Clear cannot still read the key.
	if key.Key != nil {
		t.Error("key should be nil after clear")
	}
	if key.Formatted != nil {
		t.Error("formatted should be nil after clear")
	}
	if held.IsAlive() {
		t.Error("the key's locked region survived Clear")
	}
	if rendered.IsAlive() {
		t.Error("the rendering's locked region survived Clear")
	}
	if err := held.WithBytes(func([]byte) error { return nil }); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Errorf("a cleared key is still readable: %v", err)
	}

	// Clear is idempotent, because error paths call it after a partial setup.
	key.Clear()
}

func TestRecoveryKeyFormats(t *testing.T) {
	// Test each format constant
	if RecoveryKeyFormatHex != "hex" {
		t.Errorf("expected 'hex', got %s", RecoveryKeyFormatHex)
	}
	if RecoveryKeyFormatBase64 != "base64" {
		t.Errorf("expected 'base64', got %s", RecoveryKeyFormatBase64)
	}
	if RecoveryKeyFormatDashed != "dashed" {
		t.Errorf("expected 'dashed', got %s", RecoveryKeyFormatDashed)
	}
}

func TestRecoveryKeyLength(t *testing.T) {
	if RecoveryKeyLength != 32 {
		t.Errorf("expected RecoveryKeyLength to be 32, got %d", RecoveryKeyLength)
	}
}

func TestRecoveryKeyOptions(t *testing.T) {
	opts := &RecoveryKeyOptions{
		Length:         64,
		Format:         RecoveryKeyFormatHex,
		Keyslot:        intPtr(5),
		OutputPath:     "/tmp/test-key.txt",
		KDFType:        "argon2id",
		Argon2Time:     4,
		Argon2Memory:   1048576,
		Argon2Parallel: 4,
	}

	if opts.Length != 64 {
		t.Errorf("expected Length 64, got %d", opts.Length)
	}
	if opts.Format != RecoveryKeyFormatHex {
		t.Errorf("expected Format hex, got %s", opts.Format)
	}
	if *opts.Keyslot != 5 {
		t.Errorf("expected Keyslot 5, got %d", *opts.Keyslot)
	}
	if opts.OutputPath != "/tmp/test-key.txt" {
		t.Errorf("expected OutputPath /tmp/test-key.txt, got %s", opts.OutputPath)
	}
}

func TestDecodeHex(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  []byte
		expectErr bool
	}{
		{
			name:     "lowercase hex",
			input:    "aabbccdd",
			expected: []byte{0xAA, 0xBB, 0xCC, 0xDD},
		},
		{
			name:     "uppercase hex",
			input:    "AABBCCDD",
			expected: []byte{0xAA, 0xBB, 0xCC, 0xDD},
		},
		{
			name:     "with whitespace",
			input:    "  aabbccdd  ",
			expected: []byte{0xAA, 0xBB, 0xCC, 0xDD},
		},
		{
			name:      "invalid hex chars",
			input:     "gghhii",
			expectErr: true,
		},
		{
			name:      "odd length",
			input:     "aabbc",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// decodeHexSecret takes bytes and expects them already trimmed and
			// lower-cased -- the caller normalises in place inside locked
			// memory rather than through strings.TrimSpace/ToLower, which each
			// yield an unwipeable copy of the credential. The test does the
			// same normalisation the parser does.
			normalized := []byte(tt.input)
			normalized = trimASCIISpace(normalized)
			lowerASCII(normalized)

			result, err := decodeHexSecret(normalized)

			if tt.expectErr {
				if err == nil {
					result.Destroy()
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer result.Destroy()

			// The decode writes straight into locked memory, so what is
			// asserted on here is a test-only copy taken back out of it.
			if got := openSecret(t, result); hex.EncodeToString(got) != hex.EncodeToString(tt.expected) {
				t.Errorf("expected %x, got %x", tt.expected, got)
			}
		})
	}
}

func TestLoadRecoveryKeyNonExistent(t *testing.T) {
	_, err := LoadRecoveryKey("/nonexistent/path/key.txt")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestLoadRecoveryKeyEmptyFile(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "luks-recovery-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create empty file
	keyPath := filepath.Join(tmpDir, "empty-key.txt")
	if err := os.WriteFile(keyPath, []byte("# Comment only\n"), 0400); err != nil {
		t.Fatalf("failed to create empty file: %v", err)
	}

	_, err = LoadRecoveryKey(keyPath)
	if err == nil {
		t.Error("expected error for empty/comment-only file")
	}
}

func TestRecoveryKeySaveError(t *testing.T) {
	// Test that SaveError field can be set and checked
	key := &RecoveryKey{
		Key:        enclaveFrom(t, []byte{0x01, 0x02, 0x03}),
		Formatted:  enclaveFrom(t, []byte("010203")),
		Format:     RecoveryKeyFormatHex,
		VolumeUUID: "test-uuid",
		Keyslot:    0,
	}

	// Initially SaveError should be nil
	if key.SaveError != nil {
		t.Error("expected SaveError to be nil initially")
	}

	// Set SaveError
	key.SaveError = os.ErrPermission

	// Verify SaveError is set
	if key.SaveError == nil {
		t.Error("expected SaveError to be set")
	}
	if key.SaveError != os.ErrPermission {
		t.Errorf("expected SaveError to be ErrPermission, got %v", key.SaveError)
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
func fipsSafeAddKeyOptions() *AddKeyOptions {
	return &AddKeyOptions{KDFType: KDFTypePBKDF2, PBKDFIterTime: 1}
}

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

	if err := AddKey(device, primary, second, fipsSafeAddKeyOptions()); err != nil {
		t.Fatalf("AddKey for slot 1: %v", err)
	}
	if err := AddKey(device, primary, third, fipsSafeAddKeyOptions()); err != nil {
		t.Fatalf("AddKey for slot 2: %v", err)
	}
	if err := RemoveKey(device, second, 1); err != nil {
		t.Fatalf("RemoveKey(1): %v", err)
	}

	assertKeyslotIDs(t, device, []string{"0", "2"})
	return device, primary, third
}

// assertKeyslotIDs fails unless the container holds exactly these keyslots.
// The fixture above is only meaningful if the gap is really there, and a
// silently-different keyslot layout would make every assertion below vacuous.
func assertKeyslotIDs(t *testing.T, device string, want []string) {
	t.Helper()

	_, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	got := keyslotIDsInScanOrder(metadata.Keyslots)
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

	_, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}

	opened := ""
	for _, id := range keyslotIDsInScanOrder(metadata.Keyslots) {
		key, err := unlockKeyslot(device, id, passphrase, metadata.Keyslots[id], metadata.Digests)
		if err != nil {
			continue
		}
		key.Destroy()
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
	device, primary, third := volumeWithAKeyslotGap(t)

	saved := filepath.Join(t.TempDir(), "recovery.key")
	recoveryKey, err := AddRecoveryKey(device, primary, &RecoveryKeyOptions{OutputPath: saved, KDFType: KDFTypePBKDF2})
	if err != nil {
		t.Fatalf("AddRecoveryKey: %v", err)
	}
	defer recoveryKey.Clear()
	if recoveryKey.SaveError != nil {
		t.Fatalf("saving the recovery key failed: %v", recoveryKey.SaveError)
	}

	// The report has to name the slot the recovery key actually opens.
	var actual string
	if err := borrowSecret("recovery key", recoveryKey.Key, func(raw []byte) error {
		actual = keyslotOpenedBy(t, device, raw)
		return nil
	}); err != nil {
		t.Fatalf("could not borrow the recovery key: %v", err)
	}
	if actual == "" {
		t.Fatal("the recovery key opens no keyslot at all")
	}
	if got := strconv.Itoa(recoveryKey.Keyslot); got != actual {
		t.Fatalf("AddRecoveryKey reports keyslot %s; the recovery key opens keyslot %s. Revoking as reported destroys a different credential and leaves the recovery key live",
			got, actual)
	}

	// The damage plane, stated as the operator's action: revoking the reported
	// slot must not take a credential a human still uses with it.
	for name, credential := range map[string][]byte{"primary": primary, "third": third} {
		if opened := keyslotOpenedBy(t, device, credential); opened == strconv.Itoa(recoveryKey.Keyslot) {
			t.Fatalf("the %s passphrase opens keyslot %s, which is the slot reported for the recovery key; revoking it would destroy a live credential",
				name, opened)
		}
	}

	// The number is PERSISTED, and the file is what an operator reads months
	// later. A correct in-memory struct and a wrong file would be the same
	// defect with an extra step.
	if !savedFileRecordsKeyslot(t, saved, actual) {
		t.Fatalf("the saved recovery key file does not record keyslot %s", actual)
	}
}

// savedFileContains reports whether the saved recovery-key file contains substr.
//
// It reads the file into LOCKED memory and searches it in place, which is not
// ceremony: that file contains a USABLE CREDENTIAL. An earlier version of a
// test in this package used os.ReadFile plus string(contents) -- two
// unwipeable heap copies of the recovery key -- and printed the whole file in
// its failure message, which would have put the credential in CI logs. Codex
// blocked it on PR #103 and was right; it violates the protected-memory
// mandate and the prohibition on secrets reaching logs.
//
// The idiom is LoadRecoveryKey's own: allocate an enclave sized from the file,
// fill it inside a borrow, and locate what is wanted by SEARCH rather than
// copying anything out. Nothing here returns or logs file contents -- only a
// bool -- so no caller can leak them either.
func savedFileContains(t *testing.T, path, substr string) bool {
	t.Helper()

	f, err := os.Open(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("opening the saved recovery key: %v", err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		t.Fatalf("stat on the saved recovery key: %v", err)
	}

	contents, err := newSecretEnclave("recovery key file", int(info.Size()))
	if err != nil {
		t.Fatalf("could not obtain protected memory for the saved file: %v", err)
	}
	defer contents.Destroy()

	found := false
	if err := borrowSecret("recovery key file", contents, func(b []byte) error {
		if _, err := io.ReadFull(f, b); err != nil {
			return err
		}
		found = bytes.Contains(b, []byte(substr))
		return nil
	}); err != nil {
		t.Fatalf("reading the saved recovery key: %v", err)
	}
	return found
}

// savedFileRecordsKeyslot reports whether the saved recovery-key file carries
// the "# Keyslot: <id>" preamble line.
func savedFileRecordsKeyslot(t *testing.T, path, keyslotID string) bool {
	t.Helper()
	return savedFileContains(t, path, "# Keyslot: "+keyslotID+"\n")
}

// TestAddRecoveryKeyHonoursAnExplicitKeyslot covers the other branch, which was
// always correct and must stay so: a caller naming a slot gets that slot, and
// the report agrees.
func TestAddRecoveryKeyHonoursAnExplicitKeyslot(t *testing.T) {
	device, primary, _ := volumeWithAKeyslotGap(t)

	requested := 7
	recoveryKey, err := AddRecoveryKey(device, primary, &RecoveryKeyOptions{Keyslot: &requested, KDFType: KDFTypePBKDF2})
	if err != nil {
		t.Fatalf("AddRecoveryKey: %v", err)
	}
	defer recoveryKey.Clear()

	if recoveryKey.Keyslot != requested {
		t.Fatalf("AddRecoveryKey reports keyslot %d, want the requested %d", recoveryKey.Keyslot, requested)
	}

	var actual string
	if err := borrowSecret("recovery key", recoveryKey.Key, func(raw []byte) error {
		actual = keyslotOpenedBy(t, device, raw)
		return nil
	}); err != nil {
		t.Fatalf("could not borrow the recovery key: %v", err)
	}
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
	device, primary, _ := volumeWithAKeyslotGap(t)

	occupied := 1
	occupyOpts := fipsSafeAddKeyOptions()
	occupyOpts.Keyslot = &occupied
	if err := AddKey(device, primary, []byte("occupies-the-gap-slot"), occupyOpts); err != nil {
		t.Fatalf("AddKey into the gap: %v", err)
	}
	assertKeyslotIDs(t, device, []string{"0", "1", "2"})

	recoveryKey, err := AddRecoveryKey(device, primary, &RecoveryKeyOptions{KDFType: KDFTypePBKDF2})
	if err != nil {
		t.Fatalf("AddRecoveryKey: %v", err)
	}
	defer recoveryKey.Clear()

	var actual string
	if err := borrowSecret("recovery key", recoveryKey.Key, func(raw []byte) error {
		actual = keyslotOpenedBy(t, device, raw)
		return nil
	}); err != nil {
		t.Fatalf("could not borrow the recovery key: %v", err)
	}
	if actual == "" {
		t.Fatal("the recovery key opens no keyslot at all")
	}
	if got := strconv.Itoa(recoveryKey.Keyslot); got != actual {
		t.Fatalf("AddRecoveryKey reports keyslot %s; the recovery key opens keyslot %s", got, actual)
	}
	// And it must not have taken a slot that was already someone else's.
	if actual == "1" {
		t.Fatal("the recovery key took the occupied slot 1")
	}
}

// TestAddKeyReportsTheSlotItChose covers the seam directly: AddKey's exported
// signature is unchanged, and the unexported variant reports.
func TestAddKeyReportsTheSlotItChose(t *testing.T) {
	device, primary, _ := volumeWithAKeyslotGap(t)

	assigned := -1
	if err := addKey(device, primary, []byte("a-new-credential-here"), fipsSafeAddKeyOptions(), &assigned); err != nil {
		t.Fatalf("addKey: %v", err)
	}
	// The FIRST FREE slot, which is the gap -- not the highest, which is what
	// the deleted inference would have said.
	if assigned != 1 {
		t.Fatalf("addKey reported slot %d, want the first free slot 1", assigned)
	}
	if opened := keyslotOpenedBy(t, device, []byte("a-new-credential-here")); opened != "1" {
		t.Fatalf("the new credential opens keyslot %s, but slot %d was reported", opened, assigned)
	}

	// AddKey itself must still work, and still return only an error.
	if err := AddKey(device, primary, []byte("another-new-credential"), fipsSafeAddKeyOptions()); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
}
