// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

func intPtr(i int) *int { return &i }

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
// WriteHeaderTo re-marshals the WHOLE metadata blob on every mutation, so a
// token nobody touched is rewritten from whatever the Go struct managed to
// hold. Before the passthrough, a complete systemd-fido2 token went in with
// eight members and came back with six.
func TestTokenSurvivesAMetadataRewrite(t *testing.T) {
	var token Token
	if err := json.Unmarshal([]byte(realSystemdFIDO2Token), &token); err != nil {
		t.Fatalf("failed to parse the systemd token: %v", err)
	}

	metadata := &Metadata{Tokens: map[string]*Token{"0": &token}}
	metadata.ensureRequiredObjects()

	// The rewrite: marshal the whole blob, as WriteHeaderTo does, then read
	// it back, as ReadHeader does.
	blob, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("failed to marshal metadata: %v", err)
	}

	var reread Metadata
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
		"map of pointers, as Metadata holds them": map[string]*Token{"0": &token},
		"slice of values":                         []Token{token},
		"bare value":                              token,
		"bare pointer":                            &token,
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

	metadata := &Metadata{Keyslots: map[string]*Keyslot{"1": &keyslot}}
	metadata.ensureRequiredObjects()

	blob, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("failed to marshal metadata: %v", err)
	}

	var reread Metadata
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
// where invariants belong. ValidateKeyslot refuses a luks2 keyslot with no kdf
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
			err := ValidateKeyslot("1", tt.keyslot)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected the keyslot to be refused")
				}
				if !errors.Is(err, errs.ErrInvalidKeyslot) {
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
// does.
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

// TestKeyslotCaseVariantMemberIsRefused is the #153 finding 2 repro, with the
// answer #248 changed. A keyslot spelling its type member "Type" used to be
// bound to the typed field by encoding/json's case-insensitive match and
// re-emitted as "type". cryptsetup's json-c is case-sensitive and sees no type
// at all, so the two implementations read different keyslots out of the same
// bytes, and this package's next write silently rewrote the member into the
// one cryptsetup reads. Such an object is now refused, never interpreted.
func TestKeyslotCaseVariantMemberIsRefused(t *testing.T) {
	const in = `{"Type":"luks2","key_size":64,"area":{"type":"raw","offset":"1","size":"2"}}`

	var keyslot Keyslot
	err := json.Unmarshal([]byte(in), &keyslot)
	if !errors.Is(err, ErrAmbiguousJSONMember) {
		t.Fatalf("decoding a keyslot spelled \"Type\": got %v, want ErrAmbiguousJSONMember", err)
	}
	var merr *MetadataJSONError
	if !errors.As(err, &merr) || merr.Object != metadataObjectKeyslot || merr.Member != "Type" {
		t.Fatalf("the refusal does not name the keyslot member \"Type\": %v", err)
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

	got := JSONMemberNames(reflect.TypeOf(sample{}))
	want := []string{"tagged", "omitted", "Untagged"}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("wrong member names\n want %v\n  got %v", want, got)
	}
}

// TestFIDO2TokenMatchesWhatSystemdWrites is the correctness half of the FIDO2
// fix: the type string, the two members that were missing, and the exact
// camelCase of fido2-clientPin-required.
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
// `cryptsetup luksDump --dump-json-metadata`.
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
	if errors.Is(err, errs.ErrInvalidHeader) {
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
// nothing about it changed. Go map iteration is randomized, so an unsorted
// merge would rewrite the same metadata differently on every call.
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
