// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"os"
	"strings"
	"testing"
)

func TestTokenOperations_Integration(t *testing.T) {
	// Integration tests run in Docker container with --privileged flag
	// No root check needed - Docker handles permissions

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
		Device:     device,
		Passphrase: []byte("test-passphrase"),
		Label:      "token-test",
		KDFType:    "pbkdf2", // Faster for tests
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
			Type:            "fido2-manual",
			Keyslots:        []string{"0"},
			FIDO2Credential: "dGVzdC1jcmVkZW50aWFs",
			FIDO2Salt:       "dGVzdC1zYWx0",
			FIDO2RP:         "test.example.com",
			FIDO2UPRequired: true,
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

		if token.Type != "fido2-manual" {
			t.Errorf("unexpected token type: %s", token.Type)
		}
		if token.FIDO2RP != "test.example.com" {
			t.Errorf("unexpected FIDO2RP: %s", token.FIDO2RP)
		}
		if token.FIDO2Credential != "dGVzdC1jcmVkZW50aWFs" {
			t.Errorf("unexpected FIDO2Credential: %s", token.FIDO2Credential)
		}
		if !token.FIDO2UPRequired {
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
		if !strings.Contains(jsonStr, "fido2-manual") {
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

	t.Run("import TPM2 token", func(t *testing.T) {
		token := &Token{
			Type:           "systemd-tpm2",
			Keyslots:       []string{"1"},
			TPM2Hash:       "sha256",
			TPM2PolicyHash: "dGVzdC1wb2xpY3ktaGFzaA==",
			TPM2PCRBank:    "sha256",
			TPM2PCRs:       []int{0, 1, 2, 3, 7},
			TPM2Blob:       "dGVzdC1ibG9i",
		}

		if err := ImportToken(device, 5, token); err != nil {
			t.Fatalf("failed to import TPM2 token: %v", err)
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
			"keyslots": ["2"],
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
			Type:            "fido2-manual",
			Keyslots:        []string{"0"},
			FIDO2Credential: "dXBkYXRlZC1jcmVk",
			FIDO2Salt:       "dXBkYXRlZC1zYWx0",
			FIDO2RP:         "updated.example.com",
			FIDO2UPRequired: false,
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
		if updated.FIDO2UPRequired {
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
