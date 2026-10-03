// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// realSystemdFIDO2Token is the token systemd-cryptenroll writes, member for
// member, in the order it writes them.
//
// It is not a sketch of one. The eight member names were read out of the
// systemd 255 binary's own string table (`fido2-clientPin-required` included,
// with exactly that camelCase), the credential and salt are standard base64
// with padding, the salt decodes to 32 raw bytes, and `fido2-rp` carries the
// constant systemd hardcodes. The whole point of the passthrough is that a
// token like this one comes back off the disk unchanged, so a fixture that is
// only approximately a real token would prove approximately nothing.
const realSystemdFIDO2Token = `{
	"type": "systemd-fido2",
	"keyslots": ["1"],
	"fido2-credential": "H8Dr2V30mX4ofJ9PCM69PhtnL3abgvQJm/z99FurO9LnG7z4Pd9dlqfilOBwexlvqEe/Nju9bE2O/IJarDVRgw==",
	"fido2-salt": "0VzT3vYlabI+BXN0Pn1FiYmp66CPmZ3mxKtVeH1ByQs=",
	"fido2-rp": "io.systemd.cryptsetup",
	"fido2-clientPin-required": true,
	"fido2-up-required": true,
	"fido2-uv-required": false
}`

// realReencryptKeyslot is the shape cryptsetup gives the keyslot it allocates
// for an online reencryption. `mode`, `direction`, and the area's `hash`,
// `sector_size` and `shift_size` are all members this package does not model;
// every one of them is named in libcryptsetup's string table and in the LUKS2
// on-disk format specification's reencryption section.
//
// It is here because a reencrypting container is the case where losing an
// unmodeled member is not cosmetic: cryptsetup resumes an interrupted
// reencryption from exactly these values.
const realReencryptKeyslot = `{
	"type": "reencrypt",
	"key_size": 1,
	"mode": "reencrypt",
	"direction": "forward",
	"area": {
		"type": "datashift-checksum",
		"offset": "32768",
		"size": "4096",
		"hash": "sha256",
		"sector_size": 4096,
		"shift_size": "33554432"
	}
}`

func boolPtr(b bool) *bool { return &b }

// intsPtr is the []int analog of boolPtr, needed for the same reason:
// TPM2PCRs distinguishes "not set" (nil) from "set to no PCRs" (a non-nil
// pointer to an empty slice), and a composite literal cannot take the address
// of a slice expression directly.
func intsPtr(v []int) *[]int { return &v }

// asObject parses JSON into a generic map so two encodings can be compared by
// VALUE rather than by bytes. Member order and insignificant whitespace are
// not part of what a passthrough promises to preserve; the members are.
func asObject(t *testing.T, data []byte) map[string]any {
	t.Helper()

	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatalf("not a JSON object: %v\n%s", err, data)
	}
	return obj
}

// memberOrder returns the member names of a JSON object in the order they
// appear on the wire, which is the one thing a map cannot tell us.
func memberOrder(t *testing.T, data []byte) []string {
	t.Helper()

	dec := json.NewDecoder(strings.NewReader(string(data)))
	tok, err := dec.Token()
	if err != nil {
		t.Fatalf("failed to read the opening token: %v\n%s", err, data)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		t.Fatalf("expected a JSON object, got %v\n%s", tok, data)
	}

	var names []string
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			t.Fatalf("failed to read a member name: %v\n%s", err, data)
		}
		name, ok := key.(string)
		if !ok {
			t.Fatalf("member name is not a string: %v\n%s", key, data)
		}
		names = append(names, name)

		var discard json.RawMessage
		if err := dec.Decode(&discard); err != nil {
			t.Fatalf("failed to read the value of %q: %v\n%s", name, err, data)
		}
	}
	return names
}

// TestTokenSurvivesAMetadataRewrite is the bug this mechanism exists for.
//
// writeHeaderInternal re-marshals the WHOLE metadata blob on every mutation,
// so a token nobody touched is rewritten from whatever the Go struct managed
// to hold. Before the passthrough, a complete systemd-fido2 token went in with
// eight members and came back with six.
func TestTokenSurvivesAMetadataRewrite(t *testing.T) {
	var token Token
	if err := json.Unmarshal([]byte(realSystemdFIDO2Token), &token); err != nil {
		t.Fatalf("failed to parse the systemd token: %v", err)
	}

	metadata := &LUKS2Metadata{Tokens: map[string]*Token{"0": &token}}
	metadata.ensureRequiredObjects()

	// The rewrite: marshal the whole blob, as writeHeaderInternal does, then
	// read it back, as ReadHeader does.
	blob, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("failed to marshal metadata: %v", err)
	}

	var reread LUKS2Metadata
	if err := json.Unmarshal(blob, &reread); err != nil {
		t.Fatalf("failed to parse the rewritten metadata: %v", err)
	}

	rewritten, err := json.Marshal(reread.Tokens["0"])
	if err != nil {
		t.Fatalf("failed to marshal the rewritten token: %v", err)
	}

	want := asObject(t, []byte(realSystemdFIDO2Token))
	got := asObject(t, rewritten)
	if !reflect.DeepEqual(want, got) {
		t.Errorf("the token did not survive the rewrite\n want %v\n  got %v", want, got)
	}
}

// TestTokenMarshalJSONFiresThroughAMapOfPointers pins the failure mode that
// makes a passthrough look like it works and silently do nothing.
//
// metadata.Tokens is map[string]*Token. A MarshalJSON declared so that it is
// not in the method set reached at that site is never called, the unmodeled
// members are dropped exactly as before, and every direct test of MarshalJSON
// still passes. So the assertion is made at the site that matters, and at the
// two others a caller can reach.
func TestTokenMarshalJSONFiresThroughAMapOfPointers(t *testing.T) {
	var token Token
	if err := json.Unmarshal([]byte(`{"type":"acme-widget","keyslots":["0"],"widget-serial":"XJ-11"}`), &token); err != nil {
		t.Fatalf("failed to parse the token: %v", err)
	}

	cases := map[string]any{
		"map of pointers, as LUKS2Metadata holds them": map[string]*Token{"0": &token},
		"slice of values": []Token{token},
		"bare value":      token,
		"bare pointer":    &token,
	}

	for name, subject := range cases {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(subject)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			if !strings.Contains(string(encoded), `"widget-serial":"XJ-11"`) {
				t.Errorf("MarshalJSON did not fire -- the unmodeled member is gone: %s", encoded)
			}
		})
	}
}

// TestKeyslotMarshalJSONFiresOnABareValue is the Keyslot half of the receiver
// check. json.Marshal does not take the address of the value it is handed, so
// a pointer-receiver marshaler is not in the method set reached here and is
// simply never called -- the unmodeled members go missing and every test that
// marshals a *Keyslot still passes.
func TestKeyslotMarshalJSONFiresOnABareValue(t *testing.T) {
	var keyslot Keyslot
	if err := json.Unmarshal([]byte(`{"type":"reencrypt","key_size":1,"mode":"reencrypt"}`), &keyslot); err != nil {
		t.Fatalf("failed to parse the keyslot: %v", err)
	}

	encoded, err := json.Marshal(keyslot)
	if err != nil {
		t.Fatalf("failed to marshal the keyslot: %v", err)
	}
	if !strings.Contains(string(encoded), `"mode":"reencrypt"`) {
		t.Errorf("MarshalJSON did not fire -- the unmodeled member is gone: %s", encoded)
	}
}

// TestKeyslotSurvivesAMetadataRewrite covers the same loss on the other type,
// with the case where it costs the most: a keyslot cryptsetup is using to
// track an interrupted reencryption.
func TestKeyslotSurvivesAMetadataRewrite(t *testing.T) {
	var keyslot Keyslot
	if err := json.Unmarshal([]byte(realReencryptKeyslot), &keyslot); err != nil {
		t.Fatalf("failed to parse the reencrypt keyslot: %v", err)
	}

	metadata := &LUKS2Metadata{Keyslots: map[string]*Keyslot{"1": &keyslot}}
	metadata.ensureRequiredObjects()

	blob, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("failed to marshal metadata: %v", err)
	}

	var reread LUKS2Metadata
	if err := json.Unmarshal(blob, &reread); err != nil {
		t.Fatalf("failed to parse the rewritten metadata: %v", err)
	}

	rewritten, err := json.Marshal(reread.Keyslots["1"])
	if err != nil {
		t.Fatalf("failed to marshal the rewritten keyslot: %v", err)
	}

	// The WHOLE object, not a chosen subset. A reencrypt keyslot must come
	// back with the members it had and no others -- nothing dropped, and
	// equally nothing invented.
	//
	// The second half is what the passthrough alone does not buy. It carries
	// the members the struct does not model, but the typed half can still add
	// members of its own: af, kdf, area.encryption and area.key_size are all
	// fields a reencrypt keyslot does not have, and without omitempty they
	// serialize as `null`, `null`, `""` and `0`. Inventing four members on a
	// foreign object is the same corruption as deleting five, so it is
	// asserted the same way.
	want := asObject(t, []byte(realReencryptKeyslot))
	got := asObject(t, rewritten)
	if !reflect.DeepEqual(want, got) {
		t.Errorf("the keyslot did not survive the rewrite\n want %v\n  got %v", want, got)
	}
}

// TestLuks2KeyslotStillRequiresItsAfAndKdf is the other half of removing the
// `"af": null` emission.
//
// The invariant it used to gesture at is real and is still enforced -- just
// where invariants belong. validateKeyslot refuses a luks2 keyslot with no kdf
// or no af as ErrInvalidKeyslot, which is the value the keyslot scan reads as
// "this slot is unusable, try the next one"; a null member in the JSON never
// refused anything. The exemption for other types is what makes a container
// mid-reencryption still readable.
func TestLuks2KeyslotStillRequiresItsAfAndKdf(t *testing.T) {
	area := &KeyslotArea{Type: "raw", Offset: "32768", Size: "258048", Encryption: "aes-xts-plain64", KeySize: 64}

	tests := []struct {
		name    string
		keyslot *Keyslot
		wantErr bool
	}{
		{
			name:    "luks2 with no af",
			keyslot: &Keyslot{Type: "luks2", KeySize: 64, Area: area, KDF: &KDF{Type: "pbkdf2", Hash: "sha256", Salt: "c2FsdA=="}},
			wantErr: true,
		},
		{
			name:    "luks2 with no kdf",
			keyslot: &Keyslot{Type: "luks2", KeySize: 64, Area: area, AF: &AntiForensic{Type: "luks1", Stripes: 4000, Hash: "sha256"}},
			wantErr: true,
		},
		{
			name: "luks2 with both",
			keyslot: &Keyslot{Type: "luks2", KeySize: 64, Area: area,
				KDF: &KDF{Type: "pbkdf2", Hash: "sha256", Salt: "c2FsdA=="},
				AF:  &AntiForensic{Type: "luks1", Stripes: 4000, Hash: "sha256"}},
			wantErr: false,
		},
		{
			name: "reencrypt with neither is fine",
			keyslot: &Keyslot{Type: "reencrypt", KeySize: 1,
				Area: &KeyslotArea{Type: "datashift-checksum", Offset: "32768", Size: "4096"}},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKeyslot("1", tt.keyslot)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected the keyslot to be refused")
				}
				if !errors.Is(err, ErrInvalidKeyslot) {
					t.Errorf("refusal must be ErrInvalidKeyslot so the scan tries the next slot, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Errorf("keyslot was refused: %v", err)
			}
		})
	}
}

// TestUnmodeledNumbersSurviveByteExact is why the unknown members are held as
// json.RawMessage and not as interface{}.
//
// Decoded into interface{}, a JSON number becomes a float64. 2^64-1 is not
// representable as a float64, so it comes back as 18446744073709552000 -- a
// DIFFERENT number, silently. A TPM key handle, a byte offset and a shift size
// are all values a LUKS2 object can carry that far up.
func TestUnmodeledNumbersSurviveByteExact(t *testing.T) {
	const source = `{"type":"acme","keyslots":[],` +
		`"big":18446744073709551615,` +
		`"exponent":1e3,` +
		`"negative-zero":-0.0,` +
		`"precise":0.1000000000000000055511151231257827}`

	var token Token
	if err := json.Unmarshal([]byte(source), &token); err != nil {
		t.Fatalf("failed to parse the token: %v", err)
	}

	encoded, err := json.Marshal(&token)
	if err != nil {
		t.Fatalf("failed to marshal the token: %v", err)
	}

	for _, want := range []string{
		`"big":18446744073709551615`,
		`"exponent":1e3`,
		`"negative-zero":-0.0`,
		`"precise":0.1000000000000000055511151231257827`,
	} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("number was not preserved byte for byte: expected %s in %s", want, encoded)
		}
	}
}

// TestTypedFieldWinsOverAnUnmodeledMemberOfTheSameName pins the merge rule.
//
// splitKnown should make this unreachable by construction, so the check is
// made against a hand-built unknownFields: if the two halves ever do disagree,
// the value the package actually understands is the one that reaches the disk,
// and the object is still a legal JSON object with no duplicate member.
func TestTypedFieldWinsOverAnUnmodeledMemberOfTheSameName(t *testing.T) {
	token := Token{
		Type:    "systemd-recovery",
		unknown: unknownFields{"type": json.RawMessage(`"impostor"`)},
	}

	encoded, err := json.Marshal(&token)
	if err != nil {
		t.Fatalf("failed to marshal the token: %v", err)
	}

	if strings.Contains(string(encoded), "impostor") {
		t.Errorf("the unmodeled member overwrote the typed field: %s", encoded)
	}

	names := memberOrder(t, encoded)
	seen := make(map[string]int, len(names))
	for _, name := range names {
		seen[name]++
	}
	if seen["type"] != 1 {
		t.Errorf("expected exactly one \"type\" member, got %d: %s", seen["type"], encoded)
	}
}

// TestSplitKnownKeepsOnlyWhatTheStructDoesNotModel keeps the same value from
// being stored twice -- once typed and once raw -- which is the defect in the
// Keyslot.Custom field this mechanism replaced.
func TestSplitKnownKeepsOnlyWhatTheStructDoesNotModel(t *testing.T) {
	raw := map[string]json.RawMessage{
		"type":     json.RawMessage(`"systemd-fido2"`),
		"keyslots": json.RawMessage(`["1"]`),
		"fido2-rp": json.RawMessage(`"io.systemd.cryptsetup"`),
		"vendor-x": json.RawMessage(`{"nested":true}`),
	}

	unknown := splitKnown(raw, tokenKnownMembers)

	if len(unknown) != 1 {
		t.Fatalf("expected exactly the one unmodeled member, got %v", unknown)
	}
	if string(unknown["vendor-x"]) != `{"nested":true}` {
		t.Errorf("unmodeled member was not carried verbatim: %s", unknown["vendor-x"])
	}
	if len(raw) != 4 {
		t.Errorf("splitKnown modified the caller's map: %v", raw)
	}
}

// TestSplitKnownReturnsNilWhenEverythingIsModelled keeps the common case free
// of an allocation, and keeps a token this package fully understands free of a
// passthrough map that would only ever be empty.
func TestSplitKnownReturnsNilWhenEverythingIsModelled(t *testing.T) {
	raw := map[string]json.RawMessage{
		"type":     json.RawMessage(`"systemd-recovery"`),
		"keyslots": json.RawMessage(`["3"]`),
	}

	if unknown := splitKnown(raw, tokenKnownMembers); unknown != nil {
		t.Errorf("expected nil, got %v", unknown)
	}
}

// TestSplitKnownIsCaseInsensitive matches encoding/json's own decode rule:
// json.Unmarshal binds a member to a struct field case-INSENSITIVELY when no
// exact match exists, so "Type" decodes into Keyslot.Type exactly as "type"
// does. splitKnown used a case-sensitive comparison, so a differently-cased
// member was bound to the typed field by the decoder AND retained verbatim by
// splitKnown -- both halves reaching the wire, and disagreeing the moment a
// caller sets the typed field to something else. That is exactly the
// "two halves come to disagree about what the object says" state this
// mechanism exists to prevent (see the package comment above).
func TestSplitKnownIsCaseInsensitive(t *testing.T) {
	raw := map[string]json.RawMessage{
		"Type":     json.RawMessage(`"luks2"`),
		"key_size": json.RawMessage(`64`),
	}

	unknown := splitKnown(raw, keyslotKnownMembers)

	if unknown != nil {
		t.Errorf("case-insensitive match for a known member should leave nothing unknown, got %v", unknown)
	}
}

// TestKeyslotCaseInsensitiveTypeDoesNotDuplicate is the reviewer's repro for
// #153 finding 2: a keyslot decoded from a header that spells the member
// "Type" must not re-emit both "type" (the typed field, which encoding/json
// bound "Type" to on decode) and "Type" (retained as unmodeled) on the next
// write.
func TestKeyslotCaseInsensitiveTypeDoesNotDuplicate(t *testing.T) {
	const in = `{"Type":"luks2","key_size":64,"area":{"type":"raw","offset":"1","size":"2"}}`

	var keyslot Keyslot
	if err := json.Unmarshal([]byte(in), &keyslot); err != nil {
		t.Fatalf("failed to unmarshal keyslot: %v", err)
	}
	if keyslot.Type != "luks2" {
		t.Fatalf("expected Type to be bound from the differently-cased member, got %q", keyslot.Type)
	}

	encoded, err := json.Marshal(&keyslot)
	if err != nil {
		t.Fatalf("failed to marshal keyslot: %v", err)
	}

	// Compare the TOP-LEVEL members only -- the nested area object has its
	// own, unrelated "type" member, so counting substrings across the whole
	// encoding would also count that one.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &top); err != nil {
		t.Fatalf("failed to unmarshal the re-encoded keyslot: %v", err)
	}
	if _, ok := top["Type"]; ok {
		t.Errorf("Type survived as unmodeled alongside type: %s", encoded)
	}
	if _, ok := top["type"]; !ok {
		t.Errorf("expected the typed field on the wire as type: %s", encoded)
	}
}

// TestKnownMembersAreDerivedFromTheStructTags is what stops the two halves
// drifting. A hand-maintained list of member names goes stale the first time
// somebody adds a field, and the symptom is that the new field is stored
// twice: once typed, once as an "unknown".
func TestKnownMembersAreDerivedFromTheStructTags(t *testing.T) {
	tests := []struct {
		name    string
		members []string
		want    []string
	}{
		{
			name:    "token",
			members: tokenKnownMembers,
			want: []string{
				"type", "keyslots",
				"fido2-credential", "fido2-salt", "fido2-rp",
				"fido2-clientPin-required", "fido2-up-required", "fido2-uv-required",
				// No tpm2-* members: go-xkms owns TPM2 and this package models
				// none of them (#189). A systemd-tpm2 token reaches the
				// passthrough intact instead.
			},
		},
		{
			name:    "keyslot",
			members: keyslotKnownMembers,
			want:    []string{"type", "key_size", "af", "area", "kdf", "priority"},
		},
		{
			name:    "keyslot area",
			members: keyslotAreaKnownMembers,
			want:    []string{"type", "offset", "size", "encryption", "key_size"},
		},
		{
			name:    "kdf",
			members: kdfKnownMembers,
			want:    []string{"type", "hash", "iterations", "time", "memory", "cpus", "salt"},
		},
		{
			name:    "af",
			members: antiForensicKnownMembers,
			want:    []string{"type", "stripes", "hash"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, want := range tt.want {
				if !containsMember(tt.members, want) {
					t.Errorf("member %q is modeled by the struct but missing from the known list: %v", want, tt.members)
				}
			}
			if len(tt.members) != len(tt.want) {
				t.Errorf("known list does not match the struct's members\n want %v\n  got %v", tt.want, tt.members)
			}
		})
	}
}

// TestJSONMemberNamesSkipsWhatIsNotOnTheWire covers the two ways a Go field
// produces no JSON member. Either one listed as "known" would let a real
// member of that name be dropped instead of carried.
func TestJSONMemberNamesSkipsWhatIsNotOnTheWire(t *testing.T) {
	type sample struct {
		Tagged   string `json:"tagged"`
		Omitted  string `json:"omitted,omitempty"`
		Excluded string `json:"-"`
		Untagged string
		hidden   string //nolint:unused // present precisely to prove it is skipped
	}

	got := jsonMemberNames(reflect.TypeOf(sample{}))
	want := []string{"tagged", "omitted", "Untagged"}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("wrong member names\n want %v\n  got %v", want, got)
	}
}

// TestFIDO2TokenMatchesWhatSystemdWrites is the correctness half of the FIDO2
// fix: the type string, the two members that were missing, and the exact
// camelCase of fido2-clientPin-required.
//
// A token spelled `fido2-manual` is not a systemd token at all --
// systemd-cryptsetup dispatches on the type string and would not look at it.
func TestFIDO2TokenMatchesWhatSystemdWrites(t *testing.T) {
	token := Token{
		Type:                   TokenTypeSystemdFIDO2,
		Keyslots:               []string{"1"},
		FIDO2Credential:        "H8Dr2V30mX4ofJ9PCM69PhtnL3abgvQJm/z99FurO9LnG7z4Pd9dlqfilOBwexlvqEe/Nju9bE2O/IJarDVRgw==",
		FIDO2Salt:              "0VzT3vYlabI+BXN0Pn1FiYmp66CPmZ3mxKtVeH1ByQs=",
		FIDO2RP:                "io.systemd.cryptsetup",
		FIDO2ClientPinRequired: boolPtr(true),
		FIDO2UPRequired:        boolPtr(true),
		FIDO2UVRequired:        boolPtr(false),
	}

	encoded, err := json.Marshal(&token)
	if err != nil {
		t.Fatalf("failed to marshal the token: %v", err)
	}

	if TokenTypeSystemdFIDO2 != "systemd-fido2" {
		t.Errorf("wrong token type constant: %q", TokenTypeSystemdFIDO2)
	}

	want := asObject(t, []byte(realSystemdFIDO2Token))
	got := asObject(t, encoded)
	if !reflect.DeepEqual(want, got) {
		t.Errorf("the marshaled token is not what systemd writes\n want %v\n  got %v", want, got)
	}

	// systemd emits the members in this order. Nothing rejects a different
	// order, but matching it makes a header this package wrote and one
	// systemd wrote diffable, which is how the missing members were found.
	wantOrder := []string{
		"type", "keyslots",
		"fido2-credential", "fido2-salt", "fido2-rp",
		"fido2-clientPin-required", "fido2-up-required", "fido2-uv-required",
	}
	if gotOrder := memberOrder(t, encoded); !reflect.DeepEqual(wantOrder, gotOrder) {
		t.Errorf("wrong member order\n want %v\n  got %v", wantOrder, gotOrder)
	}
}

// TestFIDO2BooleansCanSayFalse is why the three flags are *bool.
//
// `omitempty` on a plain bool cannot express false: the zero value and "not
// set" are the same value, so the member vanishes. systemd writes
// fido2-uv-required:false meaningfully -- it is what
// --fido2-with-user-verification=no records -- and an absent member is read by
// systemd-cryptsetup as the same false, so the round trip LOOKS lossless while
// the header this package writes stops matching the one it read.
func TestFIDO2BooleansCanSayFalse(t *testing.T) {
	tests := []struct {
		name string
		set  *bool
		want string
	}{
		{name: "false is emitted", set: boolPtr(false), want: `"fido2-up-required":false`},
		{name: "true is emitted", set: boolPtr(true), want: `"fido2-up-required":true`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := Token{Type: TokenTypeSystemdFIDO2, Keyslots: []string{"0"}, FIDO2UPRequired: tt.set}
			encoded, err := json.Marshal(&token)
			if err != nil {
				t.Fatalf("failed to marshal the token: %v", err)
			}
			if !strings.Contains(string(encoded), tt.want) {
				t.Errorf("expected %s in %s", tt.want, encoded)
			}
		})
	}

	t.Run("unset is absent", func(t *testing.T) {
		token := Token{Type: TokenTypeSystemdRecovery, Keyslots: []string{"0"}}
		encoded, err := json.Marshal(&token)
		if err != nil {
			t.Fatalf("failed to marshal the token: %v", err)
		}
		if string(encoded) != `{"type":"systemd-recovery","keyslots":["0"]}` {
			t.Errorf("a recovery token is minimal; got %s", encoded)
		}
	})
}

// TestEmptyTPM2PCRsSurvivesUnmodeled is the property the old typed TPM2PCRs
// field existed to protect, carried over to the passthrough that replaced it
// (#189).
//
// `systemd-cryptenroll --tpm2-pcrs=""` writes "tpm2-pcrs": [] ON PURPOSE -- it
// is how a token enrolls with no PCR binding, leaving the policy to the signed
// public key alone. Absent and empty are different enrollments, and because
// every mutation re-marshals the whole header, anything that flattens one into
// the other silently converts a volume away from what systemd wrote.
//
// A pointer field used to express that. Now nothing models the member at all,
// so the question is whether the passthrough preserves the distinction. It
// must, and for a stronger reason than before: the passthrough carries the
// member's ORIGINAL BYTES, so there is no re-encoding step in which an empty
// array could become an absent one.
func TestEmptyTPM2PCRsSurvivesUnmodeled(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		want       string
		wantAbsent bool
	}{
		{
			name: "explicitly empty stays empty",
			in:   `{"type":"systemd-tpm2","keyslots":["0"],"tpm2-pcrs":[]}`,
			want: `"tpm2-pcrs":[]`,
		},
		{
			name: "populated stays populated",
			in:   `{"type":"systemd-tpm2","keyslots":["0"],"tpm2-pcrs":[0,7]}`,
			want: `"tpm2-pcrs":[0,7]`,
		},
		{
			name:       "absent stays absent",
			in:         `{"type":"systemd-tpm2","keyslots":["0"]}`,
			wantAbsent: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var token Token
			if err := json.Unmarshal([]byte(tt.in), &token); err != nil {
				t.Fatalf("decoding: %v", err)
			}

			encoded, err := json.Marshal(token)
			if err != nil {
				t.Fatalf("re-encoding: %v", err)
			}

			if tt.wantAbsent {
				if strings.Contains(string(encoded), "tpm2-pcrs") {
					t.Errorf("tpm2-pcrs was invented for a token that never had it: %s", encoded)
				}
				return
			}
			if !strings.Contains(string(encoded), tt.want) {
				t.Errorf("expected %s in %s", tt.want, encoded)
			}
		})
	}
}

// TestKeyslotMemberOrderMatchesCryptsetup pins the declaration order against
// what cryptsetup 2.7.0 emits, measured with
// `cryptsetup luksDump --dump-json-metadata`. encoding/json marshals struct
// fields in declaration order, so this is the only thing holding it.
func TestKeyslotMemberOrderMatchesCryptsetup(t *testing.T) {
	priority := 2
	keyslot := Keyslot{
		Type:     "luks2",
		KeySize:  64,
		Priority: &priority,
		Area:     &KeyslotArea{Type: "raw", KeySize: 64, Offset: "32768", Size: "258048", Encryption: "aes-xts-plain64"},
		KDF:      &KDF{Type: "pbkdf2", Hash: "sha256", Salt: "c2FsdA==", Iterations: intPtr(1000)},
		AF:       &AntiForensic{Type: "luks1", Stripes: 4000, Hash: "sha256"},
	}

	encoded, err := json.Marshal(&keyslot)
	if err != nil {
		t.Fatalf("failed to marshal the keyslot: %v", err)
	}

	// cryptsetup puts priority LAST, after kdf, and only when it is not the
	// default -- measured by setting each of ignore/normal/prefer in turn.
	want := []string{"type", "key_size", "af", "area", "kdf", "priority"}
	if got := memberOrder(t, encoded); !reflect.DeepEqual(want, got) {
		t.Errorf("wrong keyslot member order\n want %v\n  got %v", want, got)
	}

	var nested struct {
		Area json.RawMessage `json:"area"`
		KDF  json.RawMessage `json:"kdf"`
		AF   json.RawMessage `json:"af"`
	}
	if err := json.Unmarshal(encoded, &nested); err != nil {
		t.Fatalf("failed to reach the nested objects: %v", err)
	}

	wantArea := []string{"type", "offset", "size", "encryption", "key_size"}
	if got := memberOrder(t, nested.Area); !reflect.DeepEqual(wantArea, got) {
		t.Errorf("wrong area member order\n want %v\n  got %v", wantArea, got)
	}

	wantKDF := []string{"type", "hash", "iterations", "salt"}
	if got := memberOrder(t, nested.KDF); !reflect.DeepEqual(wantKDF, got) {
		t.Errorf("wrong pbkdf2 member order\n want %v\n  got %v", wantKDF, got)
	}

	wantAF := []string{"type", "stripes", "hash"}
	if got := memberOrder(t, nested.AF); !reflect.DeepEqual(wantAF, got) {
		t.Errorf("wrong af member order\n want %v\n  got %v", wantAF, got)
	}
}

// TestArgon2KDFMemberOrderMatchesCryptsetup covers the other KDF shape. Salt
// is last in both, which is what makes ONE declaration order serve both.
func TestArgon2KDFMemberOrderMatchesCryptsetup(t *testing.T) {
	kdf := KDF{
		Type:   "argon2id",
		Salt:   "c2FsdA==",
		Time:   intPtr(4),
		Memory: intPtr(1048576),
		CPUs:   intPtr(4),
	}

	encoded, err := json.Marshal(&kdf)
	if err != nil {
		t.Fatalf("failed to marshal the kdf: %v", err)
	}

	want := []string{"type", "time", "memory", "cpus", "salt"}
	if got := memberOrder(t, encoded); !reflect.DeepEqual(want, got) {
		t.Errorf("wrong argon2 member order\n want %v\n  got %v", want, got)
	}
}

// TestUnmarshalRejectsMalformedJSON covers the error half. The typed error
// says which object failed, and still reaches the encoding/json cause, so a
// caller that already matched on *json.SyntaxError does not break.
func TestUnmarshalRejectsMalformedJSON(t *testing.T) {
	tests := []struct {
		name   string
		into   json.Unmarshaler
		object string
		input  string
	}{
		{name: "token truncated", into: &Token{}, object: metadataObjectToken, input: `{"type":"systemd-fido2"`},
		{name: "token not an object", into: &Token{}, object: metadataObjectToken, input: `["systemd-fido2"]`},
		{name: "token member has the wrong type", into: &Token{}, object: metadataObjectToken, input: `{"keyslots":"0"}`},
		{name: "keyslot truncated", into: &Keyslot{}, object: metadataObjectKeyslot, input: `{"type":"luks2"`},
		{name: "keyslot not an object", into: &Keyslot{}, object: metadataObjectKeyslot, input: `42`},
		{name: "keyslot member has the wrong type", into: &Keyslot{}, object: metadataObjectKeyslot, input: `{"key_size":"64"}`},
		{name: "area not an object", into: &KeyslotArea{}, object: metadataObjectKeyslotArea, input: `"raw"`},
		{name: "kdf member has the wrong type", into: &KDF{}, object: metadataObjectKDF, input: `{"iterations":"many"}`},
		{name: "af not an object", into: &AntiForensic{}, object: metadataObjectAntiForensic, input: `"luks1"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.into.UnmarshalJSON([]byte(tt.input))
			if err == nil {
				t.Fatalf("expected an error for %s", tt.input)
			}

			if !errors.Is(err, ErrMetadataJSON) {
				t.Errorf("error does not match the sentinel: %v", err)
			}

			var decodeErr *MetadataJSONError
			if !errors.As(err, &decodeErr) {
				t.Fatalf("error is not a *MetadataJSONError: %v", err)
			}
			if decodeErr.Object != tt.object {
				t.Errorf("wrong object: got %q, want %q", decodeErr.Object, tt.object)
			}
			if decodeErr.Op != metadataJSONDecode {
				t.Errorf("wrong op: got %q, want %q", decodeErr.Op, metadataJSONDecode)
			}
			if decodeErr.Unwrap() == nil {
				t.Error("the encoding/json cause is not reachable")
			}
			if !strings.Contains(decodeErr.Error(), tt.object) {
				t.Errorf("the message does not name the object: %s", decodeErr.Error())
			}
		})
	}
}

// TestMetadataJSONErrorMatchesOnlyItsOwnSentinel keeps the Is shortcut from
// swallowing an unrelated match, which would make errors.Is useless for
// telling a metadata decode failure from anything else in this package.
func TestMetadataJSONErrorMatchesOnlyItsOwnSentinel(t *testing.T) {
	err := &MetadataJSONError{Object: metadataObjectToken, Op: metadataJSONDecode, Err: errors.New("cause")}

	if !errors.Is(err, ErrMetadataJSON) {
		t.Error("expected a match against ErrMetadataJSON")
	}
	if errors.Is(err, ErrInvalidHeader) {
		t.Error("must not match an unrelated sentinel")
	}
}

// TestMergeIntoRefusesAValueThatIsNotJSON is the encode-side error path. It is
// unreachable through the exported API -- unknownFields is only ever populated
// from a successful decode -- so it is asserted directly rather than left as a
// branch nothing has ever executed.
func TestMergeIntoRefusesAValueThatIsNotJSON(t *testing.T) {
	unknown := unknownFields{"broken": json.RawMessage(`{oops`)}

	if _, err := unknown.mergeInto([]byte(`{"type":"acme"}`), metadataObjectToken); err == nil {
		t.Fatal("expected an error for a member that is not JSON")
	} else if !errors.Is(err, ErrMetadataJSON) {
		t.Errorf("error does not match the sentinel: %v", err)
	}

	var encodeErr *MetadataJSONError
	_, err := unknown.mergeInto([]byte(`{"type":"acme"}`), metadataObjectToken)
	if !errors.As(err, &encodeErr) {
		t.Fatalf("error is not a *MetadataJSONError: %v", err)
	}
	if encodeErr.Member != "broken" {
		t.Errorf("the error does not name the member: %q", encodeErr.Member)
	}
	if encodeErr.Op != metadataJSONEncode {
		t.Errorf("wrong op: %q", encodeErr.Op)
	}

	// The message has to name the member as well as the object. "failed to
	// encode token" sends a reader looking at the token; the fault is one
	// member of it.
	message := encodeErr.Error()
	for _, want := range []string{metadataObjectToken, `"broken"`} {
		if !strings.Contains(message, want) {
			t.Errorf("the message does not mention %s: %s", want, message)
		}
	}
}

// TestMergeIntoRefusesATypedHalfThatIsNotAnObject guards the other encode
// branch: the merge splices members into an existing JSON object and has no
// meaning for anything else.
func TestMergeIntoRefusesATypedHalfThatIsNotAnObject(t *testing.T) {
	unknown := unknownFields{"extra": json.RawMessage(`1`)}

	if _, err := unknown.mergeInto([]byte(`["not an object"]`), metadataObjectKeyslot); err == nil {
		t.Fatal("expected an error for a typed half that is not an object")
	}
}

// TestMergeIntoIsDeterministic keeps a header's bytes from changing when
// nothing about it changed. Go map iteration is randomized, so an
// unsorted merge would rewrite the same metadata differently on every call --
// and this package's sequence-ID and checksum handling is easier to reason
// about when identical metadata produces identical bytes.
func TestMergeIntoIsDeterministic(t *testing.T) {
	source := `{"type":"acme","keyslots":[],"z":1,"a":2,"m":3,"b":4,"y":5}`

	var first string
	for i := 0; i < 16; i++ {
		var token Token
		if err := json.Unmarshal([]byte(source), &token); err != nil {
			t.Fatalf("failed to parse the token: %v", err)
		}
		encoded, err := json.Marshal(&token)
		if err != nil {
			t.Fatalf("failed to marshal the token: %v", err)
		}
		if i == 0 {
			first = string(encoded)
			continue
		}
		if string(encoded) != first {
			t.Fatalf("marshaling is not deterministic\n first %s\n  then %s", first, encoded)
		}
	}

	if want := `{"type":"acme","keyslots":[],"a":2,"b":4,"m":3,"y":5,"z":1}`; first != want {
		t.Errorf("unmodeled members are not in sorted order\n want %s\n  got %s", want, first)
	}
}

// TestUnmodeledMembersAreDroppedWhenTheObjectIsReplaced states the boundary
// of the promise. The passthrough carries what a DECODE put there; a keyslot a
// caller constructs from scratch carries nothing, because there is nothing it
// could truthfully carry.
func TestUnmodeledMembersAreDroppedWhenTheObjectIsReplaced(t *testing.T) {
	var decoded Token
	if err := json.Unmarshal([]byte(`{"type":"acme","keyslots":["0"],"vendor":"x"}`), &decoded); err != nil {
		t.Fatalf("failed to parse the token: %v", err)
	}

	replacement := Token{Type: decoded.Type, Keyslots: decoded.Keyslots}
	encoded, err := json.Marshal(&replacement)
	if err != nil {
		t.Fatalf("failed to marshal the token: %v", err)
	}

	if strings.Contains(string(encoded), "vendor") {
		t.Errorf("a freshly built token invented an unmodeled member: %s", encoded)
	}
}

// Conformance checks for the passthrough, asserted against cryptsetup 2.7.0.
//
// A round trip through this package alone cannot show that a token survives,
// because this package's reader and writer share every assumption they make
// about what a token contains. So cryptsetup writes the token, this package
// performs an UNRELATED mutation, and cryptsetup reads the token back. See the
// header of conformance_test.go for the rest of the rationale, and
// requireCryptsetup for what happens on a host without the third party.

// systemdFIDO2TokenOnKeyslot0 is realSystemdFIDO2Token bound to the keyslot a
// standard conformance container actually has. `cryptsetup token import`
// refuses a token naming a keyslot that does not exist.
const systemdFIDO2TokenOnKeyslot0 = `{"type":"systemd-fido2","keyslots":["0"],` +
	`"fido2-credential":"H8Dr2V30mX4ofJ9PCM69PhtnL3abgvQJm/z99FurO9LnG7z4Pd9dlqfilOBwexlvqEe/Nju9bE2O/IJarDVRgw==",` +
	`"fido2-salt":"0VzT3vYlabI+BXN0Pn1FiYmp66CPmZ3mxKtVeH1ByQs=",` +
	`"fido2-rp":"io.systemd.cryptsetup",` +
	`"fido2-clientPin-required":true,"fido2-up-required":true,"fido2-uv-required":false}`

// writeTokenFile puts a token where `cryptsetup token import --json-file` can
// read it.
func writeTokenFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "token.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("failed to write the token file: %v", err)
	}
	return path
}

// readHeaderJSONArea returns the JSON metadata of a container's primary header
// as it is ON DISK, up to its null terminator.
//
// It reads the bytes rather than asking cryptsetup to print them, because the
// question here is what this package WROTE -- member order included -- and
// anything that parses and re-prints the object first is answering a different
// question.
func readHeaderJSONArea(t *testing.T, path string) []byte {
	t.Helper()

	f, err := os.Open(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	var binary LUKS2BinaryHeader
	if err := binaryRead(f, &binary); err != nil {
		t.Fatalf("failed to read the binary header of %s: %v", path, err)
	}
	if binary.HeaderSize <= LUKS2HeaderSize {
		t.Fatalf("header size %d leaves no JSON area", binary.HeaderSize)
	}

	area := make([]byte, binary.HeaderSize-LUKS2HeaderSize)
	if _, err := f.ReadAt(area, LUKS2HeaderSize); err != nil {
		t.Fatalf("failed to read the JSON area of %s: %v", path, err)
	}
	if end := bytes.IndexByte(area, 0); end != -1 {
		area = area[:end]
	}
	return area
}

// binaryRead decodes the fixed-size LUKS2 binary header. It is spelled out
// here so the helper above does not depend on which of this package's readers
// happens to be exported.
func binaryRead(r io.Reader, hdr *LUKS2BinaryHeader) error {
	return binary.Read(r, binary.BigEndian, hdr)
}

// TestConformance_TokenSurvivesAnUnrelatedKeyslotChange is the measured bug,
// end to end, with cryptsetup on both sides of the token.
//
// Before the passthrough this failed with six members where eight went in:
// fido2-clientPin-required and fido2-uv-required were gone, deleted by a
// header rewrite performed for a keyslot the token has nothing to do with.
func TestConformance_TokenSurvivesAnUnrelatedKeyslotChange(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	const secondPassphrase = "second-conformance-passphrase"

	mutations := map[string]func(t *testing.T, path string){
		"AddKey": func(t *testing.T, path string) {
			if _, err := AddKey(path, []byte(conformancePassphrase), []byte(secondPassphrase), &AddKeyOptions{
				KDFType:       KDFTypePBKDF2,
				Hash:          "sha256",
				PBKDFIterTime: 1,
			}); err != nil {
				t.Fatalf("AddKey failed: %v", err)
			}
		},
		"ImportToken into another slot": func(t *testing.T, path string) {
			if err := ImportToken(path, 5, &Token{Type: TokenTypeSystemdRecovery, Keyslots: []string{"0"}}); err != nil {
				t.Fatalf("ImportToken failed: %v", err)
			}
		},
		"RemoveToken from another slot": func(t *testing.T, path string) {
			if err := ImportToken(path, 5, &Token{Type: TokenTypeSystemdRecovery, Keyslots: []string{"0"}}); err != nil {
				t.Fatalf("ImportToken failed: %v", err)
			}
			if err := RemoveToken(path, 5); err != nil {
				t.Fatalf("RemoveToken failed: %v", err)
			}
		},
	}

	tokenFile := writeTokenFile(t, systemdFIDO2TokenOnKeyslot0)

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			path := newImage(t, "token-passthrough.img")
			formatWithLibrary(t, path)

			// cryptsetup writes the token, so nothing about it originates in
			// the code under test.
			if code, out := runCryptsetup(t, "", "token", "import", "--token-id", "0", "--json-file", tokenFile, path); code != 0 {
				t.Fatalf("cryptsetup token import failed (exit %d)\n%s", code, out)
			}

			mutate(t, path)

			// cryptsetup reads it back.
			code, out := runCryptsetup(t, "", "token", "export", "--token-id", "0", path)
			if code != 0 {
				t.Fatalf("cryptsetup token export failed after %s (exit %d)\n%s", name, code, out)
			}

			want := asObject(t, []byte(systemdFIDO2TokenOnKeyslot0))
			got := asObject(t, []byte(out))
			if !reflect.DeepEqual(want, got) {
				t.Errorf("%s changed a token it never touched\n want %v\n  got %v", name, want, got)
			}

			// And the container is still one cryptsetup will open, so the
			// passthrough did not buy the token back at the cost of the
			// header.
			if code, out := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", path); code != 0 {
				t.Fatalf("after %s, cryptsetup rejected the passphrase (exit %d)\n%s", name, code, out)
			}
		})
	}
}

// TestConformance_UnmodeledTokenMembersSurviveOurRewrite covers the general
// case rather than the one token type this package happens to model.
//
// The token types that matter are defined outside this repository -- systemd
// adds members between releases, and a vendor may define its own type
// entirely. A passthrough that only preserved members this package already
// knows about would preserve nothing that was actually at risk.
func TestConformance_UnmodeledTokenMembersSurviveOurRewrite(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	const vendorToken = `{"type":"com.example.vendor","keyslots":["0"],` +
		`"vendor-handle":18446744073709551615,` +
		`"vendor-nested":{"a":[1,2,3],"b":{"c":null}},` +
		`"vendor-flag":false,` +
		`"vendor-text":"a \" quote and a \\ backslash"}`

	path := newImage(t, "vendor-token.img")
	formatWithLibrary(t, path)

	tokenFile := writeTokenFile(t, vendorToken)
	if code, out := runCryptsetup(t, "", "token", "import", "--token-id", "3", "--json-file", tokenFile, path); code != 0 {
		t.Fatalf("cryptsetup token import failed (exit %d)\n%s", code, out)
	}

	if _, err := AddKey(path, []byte(conformancePassphrase), []byte("another-passphrase"), &AddKeyOptions{
		KDFType:       KDFTypePBKDF2,
		Hash:          "sha256",
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}

	code, out := runCryptsetup(t, "", "token", "export", "--token-id", "3", path)
	if code != 0 {
		t.Fatalf("cryptsetup token export failed (exit %d)\n%s", code, out)
	}

	want := asObject(t, []byte(vendorToken))
	got := asObject(t, []byte(out))
	if !reflect.DeepEqual(want, got) {
		t.Errorf("a vendor token did not survive an unrelated AddKey\n want %v\n  got %v", want, got)
	}

	// The 64-bit handle is the case a map[string]interface{} passthrough gets
	// wrong: decoded as a float64 it comes back as 18446744073709552000. The
	// comparison above cannot catch that, because BOTH sides went through the
	// same float64. So the raw bytes are checked too.
	if !strings.Contains(out, "18446744073709551615") {
		t.Errorf("the 64-bit member was rounded: %s", out)
	}
}

// TestConformance_HeaderMemberOrderMatchesCryptsetup asserts the order this
// package WRITES against the order cryptsetup writes, both read straight off
// the disk.
//
// Member order is not a compatibility requirement -- JSON objects are
// unordered and cryptsetup parses ours either way, which the passphrase check
// at the end confirms. What it buys is that two headers can be diffed. The
// eight-member token that came back with six was found by diffing; matching
// the order is what makes that a usable technique instead of a wall of
// reordering noise.
func TestConformance_HeaderMemberOrderMatchesCryptsetup(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	ours := newImage(t, "ours.img")
	formatWithLibrary(t, ours)

	theirs := newImage(t, "theirs.img")
	if code, out := runCryptsetup(t, conformancePassphrase, "luksFormat", "--type", "luks2",
		"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--batch-mode", theirs); code != 0 {
		t.Fatalf("cryptsetup luksFormat failed (exit %d)\n%s", code, out)
	}

	type object struct {
		name string
		at   func(t *testing.T, area []byte) []byte
	}

	keyslot := func(t *testing.T, area []byte) []byte {
		t.Helper()
		var top struct {
			Keyslots map[string]json.RawMessage `json:"keyslots"`
		}
		if err := json.Unmarshal(area, &top); err != nil {
			t.Fatalf("failed to parse the JSON area: %v", err)
		}
		return top.Keyslots["0"]
	}
	nested := func(member string) func(t *testing.T, area []byte) []byte {
		return func(t *testing.T, area []byte) []byte {
			t.Helper()
			var inner map[string]json.RawMessage
			if err := json.Unmarshal(keyslot(t, area), &inner); err != nil {
				t.Fatalf("failed to parse keyslot 0: %v", err)
			}
			return inner[member]
		}
	}

	objects := []object{
		{name: "top level", at: func(_ *testing.T, area []byte) []byte { return area }},
		{name: "keyslots.0", at: keyslot},
		{name: "keyslots.0.area", at: nested("area")},
		{name: "keyslots.0.af", at: nested("af")},
	}

	ourArea := readHeaderJSONArea(t, ours)
	theirArea := readHeaderJSONArea(t, theirs)

	for _, obj := range objects {
		t.Run(obj.name, func(t *testing.T) {
			want := withoutPriority(memberOrder(t, obj.at(t, theirArea)))
			got := withoutPriority(memberOrder(t, obj.at(t, ourArea)))
			if !reflect.DeepEqual(want, got) {
				t.Errorf("member order differs from cryptsetup's\n cryptsetup %v\n         us %v", want, got)
			}
		})
	}

	// Whether a priority member is emitted at all is decided in
	// createMetadata, not here, so the comparison above is made without it --
	// otherwise this test fails on a defect it does not own and cannot fix.
	// What this file IS responsible for is where the member goes when there is
	// one, so that is asserted directly: cryptsetup emits priority last, after
	// kdf, and the declaration order in types.go is the only thing holding it.
	if order := memberOrder(t, keyslot(t, ourArea)); containsMember(order, "priority") && order[len(order)-1] != "priority" {
		t.Errorf("priority is emitted, but not last as cryptsetup emits it: %v", order)
	}

	// The keyslot KDFs are deliberately NOT compared: this package formats
	// with pbkdf2 here and the two sides would have to be pinned to the same
	// KDF for the comparison to mean anything. TestKeyslotMemberOrderMatchesCryptsetup
	// and TestArgon2KDFMemberOrderMatchesCryptsetup pin both shapes against
	// the measured orders instead.

	// priority is deliberately NOT compared. cryptsetup writes no member at
	// all for a normal keyslot; whether this package does is decided in
	// createMetadata, which is not this file's to change. What IS asserted
	// here is that when a priority exists it is emitted where cryptsetup
	// emits one -- last -- which TestKeyslotMemberOrderMatchesCryptsetup pins
	// against the measured order.
	if bytes.Contains(theirArea, []byte(`"priority"`)) {
		t.Fatalf("premise broken: cryptsetup wrote a priority member for a default keyslot\n%s", theirArea)
	}

	if code, out := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", ours); code != 0 {
		t.Fatalf("cryptsetup rejected our container (exit %d)\n%s", code, out)
	}
}

// withoutPriority drops the priority member from a member-order listing.
//
// See TestConformance_HeaderMemberOrderMatchesCryptsetup for why the
// comparison is made without it.
func withoutPriority(order []string) []string {
	filtered := make([]string, 0, len(order))
	for _, name := range order {
		if name == "priority" {
			continue
		}
		filtered = append(filtered, name)
	}
	return filtered
}

// TestConformance_ReencryptKeyslotSurvivesOnDisk takes the reencrypt keyslot
// all the way through the real write path and reads it back off the platter.
//
// The in-memory test proves the marshaler; this proves the thing that
// actually happens: cryptsetup leaves a reencrypt keyslot in a header, an
// unrelated operation rewrites the whole metadata blob, and the keyslot has
// to be on disk afterwards exactly as it was. Nothing dropped by the
// passthrough, and nothing invented by the typed half.
//
// WHAT THIS TEST CANNOT DO, and why it is not cryptsetup that reads the
// result: #152. LUKS2 spells config.requirements as an OBJECT with a
// mandatory array and Config models it as []string, so ReadHeader fails
// outright on any container that is mid-reencryption -- measured against a
// GENUINE one, produced unprivileged with `cryptsetup reencrypt --init-only`:
//
//	json: cannot unmarshal object into Go struct field
//	Config.config.requirements of type []string
//
// and a reencrypt keyslot written without that flag is refused from the other
// side too, `luksDump --debug` reporting "Missing reencryption requirement
// flag". So the third-party reader is unavailable for this one case until
// #152 lands, and the assertion is made against the bytes instead. The
// fixture here is hand-built for that reason; a real cryptsetup reencrypt
// keyslot is trivial to produce and the conformance test belongs on #152, not
// a synthesized one here. The container WITHOUT the reencrypt keyslot is
// still checked with cryptsetup, so the write path itself is not taken on
// trust.
//
// #152 also carries the second half a resume actually depends on: cryptsetup
// flags the backup segments `backup-previous` and `backup-final`, Segment has
// no Flags field and no passthrough, and those flags are dropped on any
// rewrite.
func TestConformance_ReencryptKeyslotSurvivesOnDisk(t *testing.T) {
	requireCryptsetup(t)

	path := newImage(t, "reencrypt-on-disk.img")
	formatWithLibrary(t, path)

	// The write path is sound before the reencrypt keyslot is introduced.
	if code, out := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", path); code != 0 {
		t.Fatalf("premise broken: cryptsetup rejected the freshly formatted container (exit %d)\n%s", code, out)
	}

	var injected Keyslot
	if err := json.Unmarshal([]byte(realReencryptKeyslot), &injected); err != nil {
		t.Fatalf("failed to parse the reencrypt keyslot: %v", err)
	}
	// Clear of keyslot 0's area, which runs from 32768 for 258048 bytes.
	injected.Area.Offset = "294912"

	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Keyslots["1"] = &injected
	hdr.SequenceID++
	if err := writeHeaderInternal(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the header carrying the reencrypt keyslot: %v", err)
	}

	want := asObject(t, readHeaderJSONArea(t, path))["keyslots"].(map[string]any)["1"]

	// The unrelated mutation: a token import has nothing to do with keyslot 1
	// and rewrites the whole blob anyway.
	if err := ImportToken(path, 2, &Token{Type: TokenTypeSystemdRecovery, Keyslots: []string{"0"}}); err != nil {
		t.Fatalf("ImportToken failed: %v", err)
	}

	got := asObject(t, readHeaderJSONArea(t, path))["keyslots"].(map[string]any)["1"]
	if !reflect.DeepEqual(want, got) {
		t.Errorf("a header write changed a reencrypt keyslot it never touched\n want %v\n  got %v", want, got)
	}

	// And the shape on disk is the one that went in, member for member --
	// which is the assertion that fails if af, kdf, area.encryption or
	// area.key_size lose their omitempty.
	expected := asObject(t, []byte(realReencryptKeyslot))
	expected["area"].(map[string]any)["offset"] = "294912"
	if !reflect.DeepEqual(expected, got) {
		t.Errorf("the reencrypt keyslot on disk is not the one that was written\n want %v\n  got %v", expected, got)
	}
	for _, invented := range []string{"af", "kdf"} {
		if _, present := got.(map[string]any)[invented]; present {
			t.Errorf("a %q member was invented on a keyslot that has none: %v", invented, got)
		}
	}
}

// TestConformance_CryptsetupKeyslotRoundTripsUnchanged reads a container
// cryptsetup made, writes it back with this package, and requires the keyslot
// object to be byte-identical.
//
// It is the check that the member reordering above is a reordering and not a
// rewrite: a keyslot cryptsetup wrote must come back out exactly as it went
// in, or something in this package is inventing or dropping a member on a
// container it did not create.
func TestConformance_CryptsetupKeyslotRoundTripsUnchanged(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	path := newImage(t, "theirs-roundtrip.img")
	if code, out := runCryptsetup(t, conformancePassphrase, "luksFormat", "--type", "luks2",
		"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--batch-mode", path); code != 0 {
		t.Fatalf("cryptsetup luksFormat failed (exit %d)\n%s", code, out)
	}

	before := asObject(t, readHeaderJSONArea(t, path))

	if err := ImportToken(path, 0, &Token{Type: TokenTypeSystemdRecovery, Keyslots: []string{"0"}}); err != nil {
		t.Fatalf("ImportToken failed: %v", err)
	}

	after := asObject(t, readHeaderJSONArea(t, path))

	if !reflect.DeepEqual(before["keyslots"], after["keyslots"]) {
		t.Errorf("importing a token changed the keyslots object\n before %v\n  after %v",
			before["keyslots"], after["keyslots"])
	}
	if !reflect.DeepEqual(before["digests"], after["digests"]) {
		t.Errorf("importing a token changed the digests object\n before %v\n  after %v",
			before["digests"], after["digests"])
	}
	if !reflect.DeepEqual(before["segments"], after["segments"]) {
		t.Errorf("importing a token changed the segments object\n before %v\n  after %v",
			before["segments"], after["segments"])
	}

	if code, out := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", path); code != 0 {
		t.Fatalf("cryptsetup rejected the rewritten container (exit %d)\n%s", code, out)
	}
}
