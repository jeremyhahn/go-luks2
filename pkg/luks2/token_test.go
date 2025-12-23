// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"encoding/json"
	"testing"
)

func TestGetToken_InvalidTokenID(t *testing.T) {
	tests := []struct {
		name    string
		tokenID int
	}{
		{"negative ID", -1},
		{"ID too large", MaxTokenSlots},
		{"ID way too large", 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetToken("/dev/null", tt.tokenID)
			if err == nil {
				t.Error("expected error for invalid token ID")
			}
		})
	}
}

func TestGetToken_InvalidDevice(t *testing.T) {
	_, err := GetToken("/nonexistent/device", 0)
	if err == nil {
		t.Error("expected error for nonexistent device")
	}
}

func TestListTokens_InvalidDevice(t *testing.T) {
	_, err := ListTokens("/nonexistent/device")
	if err == nil {
		t.Error("expected error for nonexistent device")
	}
}

func TestExportToken_InvalidDevice(t *testing.T) {
	_, err := ExportToken("/nonexistent/device", 0)
	if err == nil {
		t.Error("expected error for nonexistent device")
	}
}

func TestImportToken_InvalidTokenID(t *testing.T) {
	token := &Token{Type: "test"}
	tests := []struct {
		name    string
		tokenID int
	}{
		{"negative ID", -1},
		{"ID too large", MaxTokenSlots},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ImportToken("/dev/null", tt.tokenID, token)
			if err == nil {
				t.Error("expected error for invalid token ID")
			}
		})
	}
}

func TestImportToken_NilToken(t *testing.T) {
	err := ImportToken("/dev/null", 0, nil)
	if err == nil {
		t.Error("expected error for nil token")
	}
}

func TestImportToken_EmptyType(t *testing.T) {
	token := &Token{Type: ""}
	err := ImportToken("/dev/null", 0, token)
	if err == nil {
		t.Error("expected error for empty token type")
	}
}

func TestImportToken_InvalidDevice(t *testing.T) {
	token := &Token{Type: "test", Keyslots: []string{"0"}}
	err := ImportToken("/nonexistent/device", 0, token)
	if err == nil {
		t.Error("expected error for invalid device")
	}
}

func TestImportTokenJSON_InvalidJSON(t *testing.T) {
	err := ImportTokenJSON("/dev/null", 0, []byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestRemoveToken_InvalidTokenID(t *testing.T) {
	tests := []struct {
		name    string
		tokenID int
	}{
		{"negative ID", -1},
		{"ID too large", MaxTokenSlots},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RemoveToken("/dev/null", tt.tokenID)
			if err == nil {
				t.Error("expected error for invalid token ID")
			}
		})
	}
}

func TestRemoveToken_InvalidDevice(t *testing.T) {
	err := RemoveToken("/nonexistent/device", 0)
	if err == nil {
		t.Error("expected error for invalid device")
	}
}

func TestFindFreeTokenSlot_InvalidDevice(t *testing.T) {
	_, err := FindFreeTokenSlot("/nonexistent/device")
	if err == nil {
		t.Error("expected error for invalid device")
	}
}

func TestTokenExists_InvalidTokenID(t *testing.T) {
	tests := []struct {
		name    string
		tokenID int
	}{
		{"negative ID", -1},
		{"ID too large", MaxTokenSlots},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := TokenExists("/dev/null", tt.tokenID)
			if err == nil {
				t.Error("expected error for invalid token ID")
			}
		})
	}
}

func TestTokenExists_InvalidDevice(t *testing.T) {
	_, err := TokenExists("/nonexistent/device", 0)
	if err == nil {
		t.Error("expected error for invalid device")
	}
}

func TestCountTokens_InvalidDevice(t *testing.T) {
	_, err := CountTokens("/nonexistent/device")
	if err == nil {
		t.Error("expected error for invalid device")
	}
}

func TestTokenJSONMarshal(t *testing.T) {
	token := &Token{
		Type:            "fido2-manual",
		Keyslots:        []string{"1"},
		FIDO2Credential: "dGVzdC1jcmVkZW50aWFs",
		FIDO2Salt:       "dGVzdC1zYWx0",
		FIDO2RP:         "test.example.com",
		FIDO2UPRequired: true,
	}

	data, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("failed to marshal token: %v", err)
	}

	var parsed Token
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal token: %v", err)
	}

	if parsed.Type != token.Type {
		t.Errorf("type mismatch: got %s, want %s", parsed.Type, token.Type)
	}
	if len(parsed.Keyslots) != len(token.Keyslots) {
		t.Errorf("keyslots length mismatch: got %d, want %d", len(parsed.Keyslots), len(token.Keyslots))
	}
	if parsed.FIDO2Credential != token.FIDO2Credential {
		t.Errorf("FIDO2Credential mismatch: got %s, want %s", parsed.FIDO2Credential, token.FIDO2Credential)
	}
	if parsed.FIDO2Salt != token.FIDO2Salt {
		t.Errorf("FIDO2Salt mismatch: got %s, want %s", parsed.FIDO2Salt, token.FIDO2Salt)
	}
	if parsed.FIDO2RP != token.FIDO2RP {
		t.Errorf("FIDO2RP mismatch: got %s, want %s", parsed.FIDO2RP, token.FIDO2RP)
	}
	if parsed.FIDO2UPRequired != token.FIDO2UPRequired {
		t.Errorf("FIDO2UPRequired mismatch: got %v, want %v", parsed.FIDO2UPRequired, token.FIDO2UPRequired)
	}
}

func TestTPM2TokenJSONMarshal(t *testing.T) {
	token := &Token{
		Type:           "systemd-tpm2",
		Keyslots:       []string{"2"},
		TPM2Hash:       "sha256",
		TPM2PolicyHash: "dGVzdC1wb2xpY3ktaGFzaA==",
		TPM2PCRBank:    "sha256",
		TPM2PCRs:       []int{0, 1, 2, 3, 7},
		TPM2Blob:       "dGVzdC1ibG9i",
		TPM2PublicKey:  "dGVzdC1wdWJrZXk=",
	}

	data, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("failed to marshal token: %v", err)
	}

	var parsed Token
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal token: %v", err)
	}

	if parsed.Type != token.Type {
		t.Errorf("type mismatch: got %s, want %s", parsed.Type, token.Type)
	}
	if parsed.TPM2Hash != token.TPM2Hash {
		t.Errorf("TPM2Hash mismatch: got %s, want %s", parsed.TPM2Hash, token.TPM2Hash)
	}
	if len(parsed.TPM2PCRs) != len(token.TPM2PCRs) {
		t.Errorf("TPM2PCRs length mismatch: got %d, want %d", len(parsed.TPM2PCRs), len(token.TPM2PCRs))
	}
}

func TestMaxTokenSlots(t *testing.T) {
	if MaxTokenSlots != 32 {
		t.Errorf("MaxTokenSlots should be 32, got %d", MaxTokenSlots)
	}
}

func TestErrTokenNotFound(t *testing.T) {
	if ErrTokenNotFound == nil {
		t.Error("ErrTokenNotFound should not be nil")
	}
	if ErrTokenNotFound.Error() != "token not found" {
		t.Errorf("unexpected error message: %s", ErrTokenNotFound.Error())
	}
}

func TestErrNoFreeTokenSlot(t *testing.T) {
	if ErrNoFreeTokenSlot == nil {
		t.Error("ErrNoFreeTokenSlot should not be nil")
	}
	if ErrNoFreeTokenSlot.Error() != "no free token slots available" {
		t.Errorf("unexpected error message: %s", ErrNoFreeTokenSlot.Error())
	}
}
