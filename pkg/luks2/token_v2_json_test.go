// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/errs"
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

// TestTokenUnmarshalRefusesAMalformedTokenAsInvalidHeader pins tokens
// engineering.md, Exported surface: UnmarshalJSON returns an *Error of kind
// ErrInvalidHeader when the input is not a JSON object, when type is not a
// string, or when keyslots is not an array of decimal strings. JSON null is
// none of those, as cryptsetup's token validation also holds.
func TestTokenUnmarshalRefusesAMalformedTokenAsInvalidHeader(t *testing.T) {
	for name, input := range map[string]string{
		"an array":              `["type","x-test"]`,
		"a string":              `"x-test"`,
		"type a number":         `{"type":1,"keyslots":[]}`,
		"type null":             `{"type":null,"keyslots":[]}`,
		"keyslots a string":     `{"type":"x-test","keyslots":"1"}`,
		"keyslots of numbers":   `{"type":"x-test","keyslots":[1]}`,
		"keyslots null":         `{"type":"x-test","keyslots":null}`,
		"keyslots not decimal":  `{"type":"x-test","keyslots":["one"]}`,
		"keyslots with a blank": `{"type":"x-test","keyslots":[""]}`,
	} {
		t.Run(name, func(t *testing.T) {
			var token Token
			err := token.UnmarshalJSON([]byte(input))
			var e *errs.Error
			if !errors.As(err, &e) || !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("UnmarshalJSON(%s) = %v, want an *Error of kind ErrInvalidHeader", input, err)
			}
		})
	}
}

// TestTokenUnmarshalLeavesMissingFieldsZero pins tokens engineering.md: a
// missing type or keyslots is not an error, the field is left zero, Members
// is nil when there is nothing else, and "01" reads as keyslot 1.
func TestTokenUnmarshalLeavesMissingFieldsZero(t *testing.T) {
	var token Token
	if err := json.Unmarshal([]byte(`{}`), &token); err != nil {
		t.Fatalf("Unmarshal({}) = %v, want no error", err)
	}
	if token.Type != "" || token.Keyslots != nil || token.Members != nil {
		t.Errorf("Unmarshal({}) = %+v, want the zero Token", token)
	}

	token = Token{}
	if err := json.Unmarshal([]byte(`{"type":"x-test","keyslots":["01","2"]}`), &token); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if token.Members != nil {
		t.Errorf("Members = %v, want nil when the token has no other member", token.Members)
	}
	if !slices.Equal(token.Keyslots, []int{1, 2}) {
		t.Errorf("Keyslots = %v, want [1 2] (\"01\" is keyslot 1)", token.Keyslots)
	}
}

// TestTokenMarshalJSONWritesTypeAndKeyslotsOverMembers pins tokens
// engineering.md: MarshalJSON writes Members, then type and keyslots over
// them, so a Members entry named type or keyslots never reaches the disk.
func TestTokenMarshalJSONWritesTypeAndKeyslotsOverMembers(t *testing.T) {
	data, err := json.Marshal(Token{
		Type:     "x-test",
		Keyslots: []int{1},
		Members: map[string]json.RawMessage{
			"type":     json.RawMessage(`"x-shadow"`),
			"keyslots": json.RawMessage(`["7"]`),
			"other":    json.RawMessage(`true`),
		},
	})
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("the output is not an object: %v", err)
	}
	if string(raw["type"]) != `"x-test"` || string(raw["keyslots"]) != `["1"]` || string(raw["other"]) != "true" {
		t.Fatalf("Marshal wrote %s, want type x-test, keyslots [\"1\"] and other true", data)
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
