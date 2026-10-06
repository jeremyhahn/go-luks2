// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDroppedEntryString(t *testing.T) {
	e := DroppedEntry{Kind: DroppedKindKeyslot, ID: "3"}
	if got, want := e.String(), `keyslot "3"`; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestSegmentUnknownMemberHelpers(t *testing.T) {
	s := &Segment{}
	if s.HasIntegrity() {
		t.Fatal("a fresh segment has no integrity member")
	}
	s.SetUnknownMember("integrity", json.RawMessage(`{"type":"hmac(sha256)"}`))
	if !s.HasIntegrity() {
		t.Fatal("SetUnknownMember(\"integrity\", ...) did not register")
	}
	s.ClearUnknownMembers()
	if s.HasIntegrity() {
		t.Fatal("ClearUnknownMembers left the integrity member in place")
	}
}

func TestCheckRequirementsImplementedIsNilSafe(t *testing.T) {
	var m *Metadata
	if err := m.CheckRequirementsImplemented(); err != nil {
		t.Errorf("nil Metadata: got %v, want nil", err)
	}
	m = &Metadata{}
	if err := m.CheckRequirementsImplemented(); err != nil {
		t.Errorf("no Config: got %v, want nil", err)
	}
	m.Config = &Config{}
	if err := m.CheckRequirementsImplemented(); err != nil {
		t.Errorf("no Requirements: got %v, want nil", err)
	}
}

func TestAntiForensicRoundTripsUnknownMembers(t *testing.T) {
	data := []byte(`{"type":"luks1","stripes":4000,"hash":"sha256","future_field":"kept"}`)
	var af AntiForensic
	if err := json.Unmarshal(data, &af); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	out, err := json.Marshal(af)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var roundTripped map[string]any
	if err := json.Unmarshal(out, &roundTripped); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if roundTripped["future_field"] != "kept" {
		t.Errorf("round trip lost future_field: %s", out)
	}
}

func TestKDFRoundTripsUnknownMembers(t *testing.T) {
	data := []byte(`{"type":"pbkdf2","hash":"sha256","iterations":1000,"salt":"c2FsdA==","future_field":"kept"}`)
	var k KDF
	if err := json.Unmarshal(data, &k); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	out, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var roundTripped map[string]any
	if err := json.Unmarshal(out, &roundTripped); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if roundTripped["future_field"] != "kept" {
		t.Errorf("round trip lost future_field: %s", out)
	}
}

func TestMetadataJSONError(t *testing.T) {
	cause := errors.New("boom")
	e := &MetadataJSONError{Object: metadataObjectKDF, Op: metadataJSONDecode, Member: "salt", Err: cause}
	if !strings.Contains(e.Error(), "kdf") || !strings.Contains(e.Error(), "salt") {
		t.Errorf("Error() = %q", e.Error())
	}
	if !errors.Is(e, ErrMetadataJSON) {
		t.Error("does not match ErrMetadataJSON")
	}
	if !errors.Is(e, cause) {
		t.Error("Unwrap does not reach the cause")
	}

	noMember := &MetadataJSONError{Object: metadataObjectKDF, Op: metadataJSONEncode, Err: cause}
	if strings.Contains(noMember.Error(), "member") {
		t.Errorf("Error() with no Member = %q", noMember.Error())
	}
}

func TestRequirementsRoundTripsUnknownMembers(t *testing.T) {
	data := []byte(`{"mandatory":["opal"],"future_field":"kept"}`)
	var r Requirements
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var roundTripped map[string]any
	if err := json.Unmarshal(out, &roundTripped); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if roundTripped["future_field"] != "kept" {
		t.Errorf("round trip lost future_field: %s", out)
	}
}
