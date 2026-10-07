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

	if err := v.SetToken(context.Background(), MaxTokens, Token{Type: "x-test"}); err == nil {
		t.Error("SetToken(MaxTokens) succeeded, want a range error")
	}
	if err := v.SetToken(context.Background(), -1, Token{Type: "x-test"}); err == nil {
		t.Error("SetToken(-1) succeeded, want a range error")
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

func TestVolumeRemoveTokenRefusesAMissingSlot(t *testing.T) {
	path := formattedVolumeImage(t, "removetoken-missing.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if err := v.RemoveToken(context.Background(), 5); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("RemoveToken(5) on an empty token map = %v, want ErrTokenNotFound", err)
	}
}

func TestVolumeRemoveTokenRefusesOnAReadOnlyVolume(t *testing.T) {
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
