// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/keyprovider"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

func boolPtr(b bool) *bool { return &b }

func TestTokenOperations_Integration(t *testing.T) {
	device := "/tmp/luks2-token-test.img"
	defer os.Remove(device)

	f, err := os.Create(device)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	if err := f.Truncate(32 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("failed to truncate test file: %v", err)
	}
	f.Close()

	opts := FormatOptions{
		Device:        device,
		Passphrase:    []byte("test-passphrase"),
		Label:         "token-test",
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1,
	}
	if err := Format(opts); err != nil {
		t.Fatalf("failed to format LUKS device: %v", err)
	}

	ctx := context.Background()
	v, err := luks2.Open(ctx, device)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	tokens := func(t *testing.T) map[int]luks2.Token {
		t.Helper()
		hdr, err := v.Header(ctx)
		if err != nil {
			t.Fatalf("Header failed: %v", err)
		}
		return hdr.Tokens()
	}

	t.Run("initially no tokens", func(t *testing.T) {
		got := tokens(t)
		if len(got) != 0 {
			t.Errorf("expected 0 tokens, got %d", len(got))
		}
	})

	t.Run("add FIDO2 token at the first free slot", func(t *testing.T) {
		id, err := v.AddToken(ctx, luks2.Token{
			Type:     keyprovider.TokenTypeFIDO2,
			Keyslots: []int{0},
			Members: map[string]json.RawMessage{
				"fido2-credential":  json.RawMessage(`"dGVzdC1jcmVkZW50aWFs"`),
				"fido2-salt":        json.RawMessage(`"dGVzdC1zYWx0"`),
				"fido2-rp":          json.RawMessage(`"test.example.com"`),
				"fido2-up-required": json.RawMessage(`true`),
			},
		})
		if err != nil {
			t.Fatalf("AddToken failed: %v", err)
		}
		if id != 0 {
			t.Errorf("expected the first free slot to be 0, got %d", id)
		}

		got, ok := tokens(t)[0]
		if !ok {
			t.Fatal("token should exist after AddToken")
		}
		if got.Type != keyprovider.TokenTypeFIDO2 {
			t.Errorf("unexpected token type: %s", got.Type)
		}
		if string(got.Members["fido2-rp"]) != `"test.example.com"` {
			t.Errorf("unexpected fido2-rp: %s", got.Members["fido2-rp"])
		}
		if string(got.Members["fido2-credential"]) != `"dGVzdC1jcmVkZW50aWFs"` {
			t.Errorf("unexpected fido2-credential: %s", got.Members["fido2-credential"])
		}
	})

	t.Run("add TPM2 token at the next free slot", func(t *testing.T) {
		const real = `{"type":"systemd-tpm2","keyslots":["0"],` +
			`"tpm2-blob":"dGVzdC1ibG9i","tpm2-pcrs":[0,1,2,3,7],` +
			`"tpm2-pcr-bank":"sha256","tpm2-primary-alg":"ecc",` +
			`"tpm2-policy-hash":"dGVzdC1wb2xpY3ktaGFzaA=="}`

		var tok luks2.Token
		if err := json.Unmarshal([]byte(real), &tok); err != nil {
			t.Fatalf("decoding the token: %v", err)
		}

		id, err := v.AddToken(ctx, tok)
		if err != nil {
			t.Fatalf("AddToken failed: %v", err)
		}
		if id != 1 {
			t.Errorf("expected the next free slot to be 1, got %d", id)
		}

		back, ok := tokens(t)[1]
		if !ok {
			t.Fatal("token should exist after AddToken")
		}
		encoded, err := json.Marshal(back)
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

	t.Run("list and count tokens", func(t *testing.T) {
		got := tokens(t)
		if len(got) != 2 {
			t.Errorf("expected 2 tokens, got %d", len(got))
		}
		if _, ok := got[0]; !ok {
			t.Error("token 0 should exist")
		}
		if _, ok := got[1]; !ok {
			t.Error("token 1 should exist")
		}
	})

	t.Run("set token from JSON at an explicit slot", func(t *testing.T) {
		tokenJSON := []byte(`{
			"type": "custom-token",
			"keyslots": ["0"],
			"fido2-rp": "json-import.example.com"
		}`)
		var tok luks2.Token
		if err := json.Unmarshal(tokenJSON, &tok); err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}
		if err := v.SetToken(ctx, 10, tok); err != nil {
			t.Fatalf("SetToken failed: %v", err)
		}

		got, ok := tokens(t)[10]
		if !ok {
			t.Fatal("token should exist after SetToken")
		}
		if got.Type != "custom-token" {
			t.Errorf("unexpected token type: %s", got.Type)
		}
	})

	t.Run("remove token", func(t *testing.T) {
		if err := v.RemoveToken(ctx, 1); err != nil {
			t.Fatalf("RemoveToken failed: %v", err)
		}
		if _, ok := tokens(t)[1]; ok {
			t.Error("token should not exist after removal")
		}
	})

	t.Run("remove nonexistent token", func(t *testing.T) {
		if err := v.RemoveToken(ctx, 1); !errors.Is(err, luks2.ErrTokenNotFound) {
			t.Errorf("expected ErrTokenNotFound, got: %v", err)
		}
	})

	t.Run("get nonexistent token", func(t *testing.T) {
		if _, ok := tokens(t)[31]; ok {
			t.Error("slot 31 should report no token")
		}
	})

	t.Run("update existing token", func(t *testing.T) {
		if err := v.SetToken(ctx, 0, luks2.Token{
			Type:     keyprovider.TokenTypeFIDO2,
			Keyslots: []int{0},
			Members: map[string]json.RawMessage{
				"fido2-credential":  json.RawMessage(`"dXBkYXRlZC1jcmVk"`),
				"fido2-salt":        json.RawMessage(`"dXBkYXRlZC1zYWx0"`),
				"fido2-rp":          json.RawMessage(`"updated.example.com"`),
				"fido2-up-required": json.RawMessage(`false`),
			},
		}); err != nil {
			t.Fatalf("SetToken (update) failed: %v", err)
		}

		updated, ok := tokens(t)[0]
		if !ok {
			t.Fatal("token 0 should still exist after update")
		}
		if string(updated.Members["fido2-rp"]) != `"updated.example.com"` {
			t.Errorf("token was not updated: %s", updated.Members["fido2-rp"])
		}
		if string(updated.Members["fido2-up-required"]) != "false" {
			t.Error("fido2-up-required was dropped by the header rewrite; false must be written, not omitted")
		}
	})

	t.Run("final token count", func(t *testing.T) {
		got := tokens(t)
		if len(got) != 2 {
			t.Errorf("expected 2 tokens, got %d", len(got))
		}
	})
}

// TestCryptsetupCannotReachAnUnaddressableTokenID is the measurement #35 was
// blocked on. See pkg/luks2's own (now-moved)
// token_integration_test.go for the full history.
func TestCryptsetupCannotReachAnUnaddressableTokenID(t *testing.T) {
	requireCryptsetupDeclared(t)

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

	for _, tc := range []struct {
		name      string
		key       string
		reachable bool
	}{
		{"a non-canonical spelling", "01", false},
		{"one past MaxTokens-1", strconv.Itoa(luks2.MaxTokens), false},
		{"far past the highest slot", "999", false},
		{"MaxTokens-1, the highest slot this library admits", strconv.Itoa(luks2.MaxTokens - 1), true},
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

	t.Run("a negative id makes the container invalid to cryptsetup", func(t *testing.T) {
		code, out := dump(t, tokenIDVolume(t, "cs-negative.img", "-1"))
		if code == 0 {
			t.Fatalf("cryptsetup accepted a header carrying token id %q\n%s", "-1", out)
		}
		if !strings.Contains(out, "not a valid LUKS device") {
			t.Fatalf("cryptsetup exited %d but not with the expected refusal\n%s", code, out)
		}

		if _, _, err := harness.ReadHeader(tokenIDVolume(t, "cs-negative-read.img", "-1")); err != nil {
			t.Fatalf("the header no longer reads: %v", err)
		}
	})
}
