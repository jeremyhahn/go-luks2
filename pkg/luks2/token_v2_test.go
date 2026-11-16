// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestVolumeAddTokenWritesToTheFirstFreeSlot(t *testing.T) {
	path := formattedVolumeImage(t, "addtoken.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	id, err := v.AddToken(context.Background(), Token{Type: "x-test", Keyslots: []int{0}})
	if err != nil {
		t.Fatalf("AddToken failed: %v", err)
	}
	if id != 0 {
		t.Errorf("AddToken id = %d, want 0 (the first free slot)", id)
	}

	hdr, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}
	got, ok := hdr.Tokens()[id]
	if !ok {
		t.Fatalf("Tokens()[%d] missing after AddToken", id)
	}
	if got.Type != "x-test" {
		t.Errorf("token type = %q, want %q", got.Type, "x-test")
	}
	if len(got.Keyslots) != 1 || got.Keyslots[0] != 0 {
		t.Errorf("token keyslots = %v, want [0]", got.Keyslots)
	}
}

func TestVolumeAddTokenRoundTripsMembers(t *testing.T) {
	path := formattedVolumeImage(t, "addtoken-members.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	id, err := v.AddToken(context.Background(), Token{
		Type: "x-test",
		Members: map[string]json.RawMessage{
			"custom-field": json.RawMessage(`"custom-value"`),
		},
	})
	if err != nil {
		t.Fatalf("AddToken failed: %v", err)
	}

	hdr, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}
	got, ok := hdr.Tokens()[id]
	if !ok {
		t.Fatalf("Tokens()[%d] missing after AddToken", id)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal(%d) failed: %v", id, err)
	}
	if !jsonContains(t, raw, `"custom-field":"custom-value"`) {
		t.Errorf("exported token %s does not carry the custom member", raw)
	}
}

func jsonContains(t *testing.T, data []byte, want string) bool {
	t.Helper()
	compact := map[string]any{}
	if err := json.Unmarshal(data, &compact); err != nil {
		t.Fatalf("exported token is not valid JSON: %v\n%s", err, data)
	}
	reencoded, err := json.Marshal(compact)
	if err != nil {
		t.Fatalf("re-encoding the exported token: %v", err)
	}
	for i := 0; i+len(want) <= len(reencoded); i++ {
		if string(reencoded[i:i+len(want)]) == want {
			return true
		}
	}
	return false
}

func TestVolumeAddTokenRefusesAnEmptyType(t *testing.T) {
	path := formattedVolumeImage(t, "addtoken-empty.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	// The caller's mistake, not a bad header: nothing was read.
	if _, err := v.AddToken(context.Background(), Token{}); !errors.Is(err, ErrInvalidArgument) || errors.Is(err, ErrInvalidHeader) {
		t.Errorf("AddToken(empty type) = %v, want ErrInvalidArgument", err)
	}
}

func TestVolumeAddTokenRefusesOnAReadOnlyVolume(t *testing.T) {
	path := formattedVolumeImage(t, "addtoken-readonly.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()), WithReadOnly())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if _, err := v.AddToken(context.Background(), Token{Type: "x-test"}); !errors.Is(err, ErrReadOnly) {
		t.Errorf("AddToken on a read-only Volume = %v, want ErrReadOnly", err)
	}
}

func TestVolumeAddTokenRefusesOnAClosedVolume(t *testing.T) {
	path := formattedVolumeImage(t, "addtoken-closed.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if _, err := v.AddToken(context.Background(), Token{Type: "x-test"}); !errors.Is(err, ErrClosed) {
		t.Errorf("AddToken on a closed Volume = %v, want ErrClosed", err)
	}
}

func TestVolumeSetTokenReplacesWhatIsThere(t *testing.T) {
	path := formattedVolumeImage(t, "settoken.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	id, err := v.AddToken(context.Background(), Token{Type: "x-original"})
	if err != nil {
		t.Fatalf("AddToken failed: %v", err)
	}

	if err := v.SetToken(context.Background(), id, Token{Type: "x-replaced", Keyslots: []int{0}}); err != nil {
		t.Fatalf("SetToken failed: %v", err)
	}

	hdr, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}
	got, ok := hdr.Tokens()[id]
	if !ok {
		t.Fatalf("Tokens()[%d] missing after SetToken", id)
	}
	if got.Type != "x-replaced" {
		t.Errorf("token type after SetToken = %q, want %q", got.Type, "x-replaced")
	}
}

func TestVolumeSetTokenRefusesAnEmptyType(t *testing.T) {
	path := formattedVolumeImage(t, "settoken-empty.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if err := v.SetToken(context.Background(), 0, Token{}); !errors.Is(err, ErrInvalidArgument) || errors.Is(err, ErrInvalidHeader) {
		t.Errorf("SetToken(empty type) = %v, want ErrInvalidArgument", err)
	}
}

func TestVolumeSetTokenRefusesAnOutOfRangeID(t *testing.T) {
	path := formattedVolumeImage(t, "settoken-range.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	for _, id := range []int{-1, MaxTokens, MaxTokens + 8} {
		if err := v.SetToken(context.Background(), id, Token{Type: "x-test"}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("SetToken(%d) = %v, want ErrInvalidArgument", id, err)
		}
	}
	hdr, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header: %v", err)
	}
	if n := len(hdr.Tokens()); n != 0 {
		t.Errorf("a refused SetToken wrote a token: %d tokens", n)
	}
}

// Token slots are 0-31: RemoveToken refuses an id outside that range with
// ErrInvalidArgument before it reads or locks the header, and never reports
// ErrTokenNotFound for it.
func TestVolumeRemoveTokenRefusesAnOutOfRangeID(t *testing.T) {
	path := formattedVolumeImage(t, "removetoken-range.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	for _, id := range []int{-1, MaxTokens, MaxTokens + 8} {
		err := v.RemoveToken(context.Background(), id)
		if !errors.Is(err, ErrInvalidArgument) || errors.Is(err, ErrTokenNotFound) {
			t.Errorf("RemoveToken(%d) = %v, want ErrInvalidArgument", id, err)
		}
	}
	if err := v.RemoveToken(context.Background(), MaxTokens-1); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("RemoveToken(%d) on an empty slot = %v, want ErrTokenNotFound", MaxTokens-1, err)
	}
}

// TestVolumeAddTokenRefusesWhenAllSlotsAreFull fills every token slot, 0
// through MaxTokens-1, and checks that one more AddToken is refused with
// ErrNoSpace and leaves the 32 tokens as they were.
func TestVolumeAddTokenRefusesWhenAllSlotsAreFull(t *testing.T) {
	path := formattedVolumeImage(t, "addtoken-full.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	for i := 0; i < MaxTokens; i++ {
		id, err := v.AddToken(context.Background(), Token{Type: "x-test", Keyslots: []int{0}})
		if err != nil {
			t.Fatalf("AddToken #%d failed: %v", i, err)
		}
		if id != i {
			t.Fatalf("AddToken #%d id = %d, want %d", i, id, i)
		}
	}

	if id, err := v.AddToken(context.Background(), Token{Type: "x-test", Keyslots: []int{0}}); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("AddToken with all %d slots in use = %d, %v, want ErrNoSpace", MaxTokens, id, err)
	}

	hdr, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}
	if got := len(hdr.Tokens()); got != MaxTokens {
		t.Errorf("token count after the refused AddToken = %d, want %d", got, MaxTokens)
	}
}

func TestVolumeRemoveTokenRemovesIt(t *testing.T) {
	path := formattedVolumeImage(t, "removetoken.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	id, err := v.AddToken(context.Background(), Token{Type: "x-test"})
	if err != nil {
		t.Fatalf("AddToken failed: %v", err)
	}

	if err := v.RemoveToken(context.Background(), id); err != nil {
		t.Fatalf("RemoveToken failed: %v", err)
	}

	hdr, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}
	if _, ok := hdr.Tokens()[id]; ok {
		t.Errorf("Tokens()[%d] still present after RemoveToken", id)
	}
}

func TestVolumeRemoveTokenRefusesOnAReadOnlyVolume(t *testing.T) {
	defer parallel(t)()
	path := formattedVolumeImage(t, "removetoken-readonly.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()), WithReadOnly())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if err := v.RemoveToken(context.Background(), 0); !errors.Is(err, ErrReadOnly) {
		t.Errorf("RemoveToken on a read-only Volume = %v, want ErrReadOnly", err)
	}
}
