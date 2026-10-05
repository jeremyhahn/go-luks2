// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// boolPtr is the integration build's copy of the helper the unit build keeps
// in unknownfields_test.go. The two builds never compile together, so one
// definition cannot serve both.
func boolPtr(b bool) *bool { return &b }

// intsPtr is the integration build's copy of the []int analog of boolPtr,
// kept in unknownfields_test.go for the unit build.
func intsPtr(v []int) *[]int { return &v }

func TestTokenOperations_Integration(t *testing.T) {
	// Integration tests run in the container, as root, under the scoped
	// privilege set in test/integration/cmd/docker-run. No root check needed.

	// Create a temporary file for testing
	device := "/tmp/luks2-token-test.img"
	defer os.Remove(device)

	// Create a 32MB file for LUKS
	f, err := os.Create(device)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	if err := f.Truncate(32 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("failed to truncate test file: %v", err)
	}
	f.Close()

	// Format as LUKS2
	opts := FormatOptions{
		Device:        device,
		Passphrase:    []byte("test-passphrase"),
		Label:         "token-test",
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1, // keyslot cost is not what this test exercises (#52)
	}
	if err := Format(opts); err != nil {
		t.Fatalf("failed to format LUKS device: %v", err)
	}

	t.Run("initially no tokens", func(t *testing.T) {
		tokens, err := ListTokens(device)
		if err != nil {
			t.Fatalf("failed to list tokens: %v", err)
		}
		if len(tokens) != 0 {
			t.Errorf("expected 0 tokens, got %d", len(tokens))
		}

		count, err := CountTokens(device)
		if err != nil {
			t.Fatalf("failed to count tokens: %v", err)
		}
		if count != 0 {
			t.Errorf("expected count 0, got %d", count)
		}
	})

	t.Run("find free slot when empty", func(t *testing.T) {
		slot, err := FindFreeTokenSlot(device)
		if err != nil {
			t.Fatalf("failed to find free slot: %v", err)
		}
		if slot != 0 {
			t.Errorf("expected first free slot to be 0, got %d", slot)
		}
	})

	t.Run("import FIDO2 token", func(t *testing.T) {
		token := &Token{
			Type:            TokenTypeSystemdFIDO2,
			Keyslots:        []string{"0"},
			FIDO2Credential: "dGVzdC1jcmVkZW50aWFs",
			FIDO2Salt:       "dGVzdC1zYWx0",
			FIDO2RP:         "test.example.com",
			FIDO2UPRequired: boolPtr(true),
		}

		if err := ImportToken(device, 0, token); err != nil {
			t.Fatalf("failed to import token: %v", err)
		}

		// Verify token was imported
		exists, err := TokenExists(device, 0)
		if err != nil {
			t.Fatalf("failed to check token exists: %v", err)
		}
		if !exists {
			t.Error("token should exist after import")
		}
	})

	t.Run("get imported token", func(t *testing.T) {
		token, err := GetToken(device, 0)
		if err != nil {
			t.Fatalf("failed to get token: %v", err)
		}

		if token.Type != TokenTypeSystemdFIDO2 {
			t.Errorf("unexpected token type: %s", token.Type)
		}
		if token.FIDO2RP != "test.example.com" {
			t.Errorf("unexpected FIDO2RP: %s", token.FIDO2RP)
		}
		if token.FIDO2Credential != "dGVzdC1jcmVkZW50aWFs" {
			t.Errorf("unexpected FIDO2Credential: %s", token.FIDO2Credential)
		}
		if token.FIDO2UPRequired == nil || !*token.FIDO2UPRequired {
			t.Error("FIDO2UPRequired should be true")
		}
	})

	t.Run("export token as JSON", func(t *testing.T) {
		jsonData, err := ExportToken(device, 0)
		if err != nil {
			t.Fatalf("failed to export token: %v", err)
		}

		if len(jsonData) == 0 {
			t.Error("exported JSON should not be empty")
		}

		// Verify it contains expected fields
		jsonStr := string(jsonData)
		if !strings.Contains(jsonStr, TokenTypeSystemdFIDO2) {
			t.Error("JSON should contain token type")
		}
		if !strings.Contains(jsonStr, "test.example.com") {
			t.Error("JSON should contain FIDO2 RP")
		}
	})

	t.Run("find free slot after import", func(t *testing.T) {
		slot, err := FindFreeTokenSlot(device)
		if err != nil {
			t.Fatalf("failed to find free slot: %v", err)
		}
		if slot != 1 {
			t.Errorf("expected first free slot to be 1, got %d", slot)
		}
	})

	// Decoded from JSON, not built from typed fields: this package models no
	// TPM2 member (#189) and carries them through the passthrough, so a
	// realistic token arrives the way a real one does. The members are the ones
	// libsystemd-shared-255.so actually contains.
	t.Run("import TPM2 token", func(t *testing.T) {
		// It names keyslot 0, the one this volume has: a reference to a keyslot
		// the header does not have is refused, as cryptsetup refuses it (#248).
		const real = `{"type":"systemd-tpm2","keyslots":["0"],` +
			`"tpm2-blob":"dGVzdC1ibG9i","tpm2-pcrs":[0,1,2,3,7],` +
			`"tpm2-pcr-bank":"sha256","tpm2-primary-alg":"ecc",` +
			`"tpm2-policy-hash":"dGVzdC1wb2xpY3ktaGFzaA=="}`

		var token Token
		if err := json.Unmarshal([]byte(real), &token); err != nil {
			t.Fatalf("decoding the token: %v", err)
		}

		if err := ImportToken(device, 5, &token); err != nil {
			t.Fatalf("failed to import TPM2 token: %v", err)
		}

		// It must come back off the device with every unmodeled member intact:
		// that is the whole basis for not modeling them.
		back, err := GetToken(device, 5)
		if err != nil {
			t.Fatalf("reading the token back: %v", err)
		}
		encoded, err := json.Marshal(*back)
		if err != nil {
			t.Fatalf("re-encoding the token: %v", err)
		}
		for _, member := range []string{
			`"tpm2-blob":"dGVzdC1ibG9i"`,
			`"tpm2-pcrs":[0,1,2,3,7]`,
			`"tpm2-pcr-bank":"sha256"`,
			`"tpm2-primary-alg":"ecc"`,
			`"tpm2-policy-hash":"dGVzdC1wb2xpY3ktaGFzaA=="`,
		} {
			if !strings.Contains(string(encoded), member) {
				t.Errorf("%s did not survive a real header round trip\n got: %s", member, encoded)
			}
		}
	})

	t.Run("list tokens", func(t *testing.T) {
		tokens, err := ListTokens(device)
		if err != nil {
			t.Fatalf("failed to list tokens: %v", err)
		}
		if len(tokens) != 2 {
			t.Errorf("expected 2 tokens, got %d", len(tokens))
		}

		if _, ok := tokens[0]; !ok {
			t.Error("token 0 should exist")
		}
		if _, ok := tokens[5]; !ok {
			t.Error("token 5 should exist")
		}
	})

	t.Run("count tokens", func(t *testing.T) {
		count, err := CountTokens(device)
		if err != nil {
			t.Fatalf("failed to count tokens: %v", err)
		}
		if count != 2 {
			t.Errorf("expected count 2, got %d", count)
		}
	})

	t.Run("import token from JSON", func(t *testing.T) {
		tokenJSON := []byte(`{
			"type": "custom-token",
			"keyslots": ["0"],
			"fido2-rp": "json-import.example.com"
		}`)

		if err := ImportTokenJSON(device, 10, tokenJSON); err != nil {
			t.Fatalf("failed to import token from JSON: %v", err)
		}

		token, err := GetToken(device, 10)
		if err != nil {
			t.Fatalf("failed to get imported token: %v", err)
		}
		if token.Type != "custom-token" {
			t.Errorf("unexpected token type: %s", token.Type)
		}
	})

	t.Run("remove token", func(t *testing.T) {
		if err := RemoveToken(device, 5); err != nil {
			t.Fatalf("failed to remove token: %v", err)
		}

		exists, err := TokenExists(device, 5)
		if err != nil {
			t.Fatalf("failed to check token exists: %v", err)
		}
		if exists {
			t.Error("token should not exist after removal")
		}
	})

	t.Run("remove nonexistent token", func(t *testing.T) {
		err := RemoveToken(device, 5)
		if err != ErrTokenNotFound {
			t.Errorf("expected ErrTokenNotFound, got: %v", err)
		}
	})

	t.Run("get nonexistent token", func(t *testing.T) {
		_, err := GetToken(device, 31)
		if err != ErrTokenNotFound {
			t.Errorf("expected ErrTokenNotFound, got: %v", err)
		}
	})

	t.Run("update existing token", func(t *testing.T) {
		// Update token 0 with new values
		token := &Token{
			Type:            TokenTypeSystemdFIDO2,
			Keyslots:        []string{"0"},
			FIDO2Credential: "dXBkYXRlZC1jcmVk",
			FIDO2Salt:       "dXBkYXRlZC1zYWx0",
			FIDO2RP:         "updated.example.com",
			FIDO2UPRequired: boolPtr(false),
		}

		if err := ImportToken(device, 0, token); err != nil {
			t.Fatalf("failed to update token: %v", err)
		}

		// Verify update
		updated, err := GetToken(device, 0)
		if err != nil {
			t.Fatalf("failed to get updated token: %v", err)
		}
		if updated.FIDO2RP != "updated.example.com" {
			t.Errorf("token was not updated: %s", updated.FIDO2RP)
		}
		if updated.FIDO2UPRequired == nil {
			t.Error("FIDO2UPRequired was dropped by the header rewrite; false must be written, not omitted")
		} else if *updated.FIDO2UPRequired {
			t.Error("FIDO2UPRequired should be false after update")
		}
	})

	t.Run("final token count", func(t *testing.T) {
		count, err := CountTokens(device)
		if err != nil {
			t.Fatalf("failed to count tokens: %v", err)
		}
		// Should have tokens 0 and 10 (5 was removed)
		if count != 2 {
			t.Errorf("expected 2 tokens, got %d", count)
		}
	})
}

// TestCryptsetupCannotReachAnUnaddressableTokenID is the measurement #35 was
// blocked on, kept as a test so the ruling cannot be silently reversed.
//
// # Why this is in the INTEGRATION tier
//
// It shells out to cryptsetup, and it does so with t.Fatalf rather than a skip
// guard: a conformance measurement that reports success on a host with no third
// party to check against converts "unverified" into "verified", which is #90.
//
// Those two facts together decide the tier. A hard failure on a missing binary
// is correct only where the binary is a DECLARED dependency, and here it is --
// test/integration/Dockerfile installs cryptsetup-bin, and the entrypoint runs
// `go test -tags=integration ./pkg/luks2`. In the unit tier the same test made
// `go test ./...` depend on an undocumented system binary, which is the defect
// this move fixes.
//
// This is the SECOND of the two remedies this project allows for a test that
// cannot run everywhere -- a build tag, which is a declared, greppable
// compile-time decision -- rather than the skip guard, which is a runtime
// excuse that reports success.
// Both properties are kept: the unit tier needs no system binary, and absence
// still cannot reverse the ruling, because in the tier that runs this the
// binary is not optional.
//
// # What it establishes
//
// #35 offered two answers -- reject the header at the parse if cryptsetup
// refuses it, or make the listing faithful if cryptsetup accepts it -- and the
// real answer is neither. cryptsetup 2.7.0 ACCEPTS these headers (so refusing
// them would be the bricking direction) and cannot REACH the entries (so there
// is no working token to strand). It addresses tokens by the canonical spelling
// of each slot number, from 0 to LUKS2_TOKENS_MAX-1.
func TestCryptsetupCannotReachAnUnaddressableTokenID(t *testing.T) {
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		t.Fatalf("cryptsetup is not installed (%v). This tier declares it -- "+
			"test/integration/Dockerfile installs cryptsetup-bin -- so its absence is a broken "+
			"environment, not a reason to report success. The measurement #35's fix rests on "+
			"cannot be assumed.", err)
	}

	dump := func(t *testing.T, path string) (int, string) {
		t.Helper()
		out, err := exec.Command("cryptsetup", "luksDump", path).CombinedOutput() // #nosec G204 -- arguments are test constants
		var exitErr *exec.ExitError
		if err != nil && !errors.As(err, &exitErr) {
			t.Fatalf("failed to run cryptsetup: %v", err)
		}
		if err != nil {
			return exitErr.ExitCode(), string(out)
		}
		return 0, string(out)
	}

	// Every key cryptsetup accepts-but-cannot-reach, and the control that shows
	// the boundary is real rather than assumed. Without "31" passing, a fix that
	// simply rejected every two-digit id would look correct here.
	//
	// The boundary cases are spelled from MaxTokenSlots rather than hardcoded,
	// so this measures OUR constant against cryptsetup's LUKS2_TOKENS_MAX
	// instead of restating a number both sides happen to agree on today. If
	// MaxTokenSlots ever diverges, the pair below goes red.
	for _, tc := range []struct {
		name      string
		key       string
		reachable bool
	}{
		{"a non-canonical spelling", "01", false},
		{"one past MaxTokenSlots-1", strconv.Itoa(MaxTokenSlots), false},
		{"far past the highest slot", "999", false},
		{"MaxTokenSlots-1, the highest slot this library admits", strconv.Itoa(MaxTokenSlots - 1), true},
		{"the lowest legal slot", "0", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out := dump(t, tokenIDVolume(t, "cs-range.img", tc.key))
			if code != 0 {
				t.Fatalf("cryptsetup luksDump exited %d on a header carrying token id %q; it must ACCEPT the header, not refuse it\n%s",
					code, tc.key, out)
			}

			marker := "written-as-" + tc.key
			reached := strings.Contains(out, marker)
			switch {
			case tc.reachable && !reached:
				t.Fatalf("cryptsetup did not reach the token at %q, so this library must not list it either\n%s", tc.key, out)
			case !tc.reachable && reached:
				t.Fatalf("cryptsetup reached the token at %q, so this library must list it rather than skip it\n%s", tc.key, out)
			}
		})
	}

	// The collision, which is the defect #35 was filed about: the canonical
	// spelling is reached and the other is not, so folding them onto one int
	// key could hide a working token.
	t.Run("a collision resolves to the canonical spelling", func(t *testing.T) {
		code, out := dump(t, tokenIDVolume(t, "cs-both.img", "1", "01"))
		if code != 0 {
			t.Fatalf("cryptsetup luksDump exited %d\n%s", code, out)
		}
		if !strings.Contains(out, "written-as-1\n") && !strings.Contains(out, "written-as-1 ") {
			t.Fatalf("cryptsetup did not reach the canonically-spelled token\n%s", out)
		}
		if strings.Contains(out, "written-as-01") {
			t.Fatalf("cryptsetup reached the token written under %q\n%s", "01", out)
		}
	})

	// A negative id is the one case where cryptsetup refuses the whole
	// container. It does not change what this library does -- the header is
	// still readable here, which is the point of tolerating a damaged token --
	// but it is the strongest possible evidence that such a key is not a token,
	// so it is pinned rather than left as a remark.
	t.Run("a negative id makes the container invalid to cryptsetup", func(t *testing.T) {
		code, out := dump(t, tokenIDVolume(t, "cs-negative.img", "-1"))
		if code == 0 {
			t.Fatalf("cryptsetup accepted a header carrying token id %q\n%s", "-1", out)
		}
		if !strings.Contains(out, "not a valid LUKS device") {
			t.Fatalf("cryptsetup exited %d but not with the expected refusal\n%s", code, out)
		}

		// And this library still reads it, so an operator can inspect a
		// container cryptsetup will not open.
		if _, _, err := ReadHeader(tokenIDVolume(t, "cs-negative-read.img", "-1")); err != nil {
			t.Fatalf("the header no longer reads: %v", err)
		}
	})
}
