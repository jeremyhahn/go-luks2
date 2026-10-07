// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTokenMarshalJSONWritesKeyslotsAsCanonicalStrings(t *testing.T) {
	token := Token{Type: "x-test", Keyslots: []int{0, 7}}

	data, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if !strings.Contains(string(data), `"keyslots":["0","7"]`) {
		t.Errorf("encoded token = %s, want keyslots as a string array", data)
	}
	if !strings.Contains(string(data), `"type":"x-test"`) {
		t.Errorf("encoded token = %s, want the type member", data)
	}
}

func TestTokenMarshalJSONWritesAnEmptyKeyslotsArrayNeverNull(t *testing.T) {
	// LUKS2 requires a token's keyslots member to be an ARRAY: a nil slice
	// encoding as "keyslots":null is a header cryptsetup refuses (token.go's
	// ImportToken documents the same rule for the old path).
	data, err := json.Marshal(Token{Type: "x-test"})
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if !strings.Contains(string(data), `"keyslots":[]`) {
		t.Errorf("encoded token = %s, want an empty keyslots array, not null", data)
	}
}

func TestTokenRoundTripsMembersAndKeyslots(t *testing.T) {
	original := Token{
		Type:     "x-test",
		Keyslots: []int{3, 1},
		Members: map[string]json.RawMessage{
			"custom-string": json.RawMessage(`"value"`),
			"custom-number": json.RawMessage(`42`),
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var round Token
	if err := json.Unmarshal(data, &round); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if round.Type != original.Type {
		t.Errorf("Type = %q, want %q", round.Type, original.Type)
	}
	if len(round.Keyslots) != 2 || round.Keyslots[0] != 3 || round.Keyslots[1] != 1 {
		t.Errorf("Keyslots = %v, want [3 1]", round.Keyslots)
	}
	if string(round.Members["custom-string"]) != `"value"` {
		t.Errorf("Members[custom-string] = %s, want %q", round.Members["custom-string"], `"value"`)
	}
	if string(round.Members["custom-number"]) != "42" {
		t.Errorf("Members[custom-number] = %s, want 42", round.Members["custom-number"])
	}
	if _, ok := round.Members["type"]; ok {
		t.Error("Members carries the type member, which should have been consumed into Type")
	}
	if _, ok := round.Members["keyslots"]; ok {
		t.Error("Members carries the keyslots member, which should have been consumed into Keyslots")
	}
}

func TestTokenUnmarshalRefusesNonCanonicalKeyslots(t *testing.T) {
	var token Token
	err := json.Unmarshal([]byte(`{"type":"x-test","keyslots":["not-a-number"]}`), &token)
	if err == nil {
		t.Fatal("Unmarshal accepted a non-numeric keyslot entry")
	}
}

func TestTokenToLegacyTokenRoundTripsThroughTheOnDiskShape(t *testing.T) {
	token := Token{Type: TokenTypeRecovery, Keyslots: []int{2}}

	legacy, err := token.toLegacyToken()
	if err != nil {
		t.Fatalf("toLegacyToken failed: %v", err)
	}
	if legacy.Type != TokenTypeRecovery {
		t.Errorf("legacy.Type = %q, want %q", legacy.Type, TokenTypeRecovery)
	}
	if len(legacy.Keyslots) != 1 || legacy.Keyslots[0] != "2" {
		t.Errorf("legacy.Keyslots = %v, want [2]", legacy.Keyslots)
	}

	back, err := tokenFromLegacy(legacy)
	if err != nil {
		t.Fatalf("tokenFromLegacy failed: %v", err)
	}
	if back.Type != token.Type || len(back.Keyslots) != 1 || back.Keyslots[0] != 2 {
		t.Errorf("tokenFromLegacy(toLegacyToken(token)) = %+v, want %+v", back, token)
	}
}
