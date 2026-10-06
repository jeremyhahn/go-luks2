// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Tests for the on-disk JSON ENCODING itself: the LUKS2 metadata area holds
// compact, unescaped JSON terminated by a single NUL, and every property that
// makes that sentence true is asserted here.
//
// These are deliberately separate from the cryptsetup conformance tests,
// which live in pkg/luks2. What the encoder does is decidable without a
// third party -- compactness, escaping and the terminator are properties of
// the bytes -- and a test that needs no external binary should not be made
// to depend on one.

// TestCanonicalJSONIsCompact pins the property the 12288-byte metadata area
// actually depends on.
//
// json.MarshalIndent was producing 1193 bytes for the metadata json-c writes
// in 775. That is not a cosmetic difference: EncodeMetadataForHeader REFUSES
// metadata that does not fit and cannot enlarge the area (the keyslots and
// the data segment are already placed), so 54% of the area was being spent
// on whitespace and the refusal fired at a keyslot count well below
// cryptsetup's.
func TestCanonicalJSONIsCompact(t *testing.T) {
	encoded, err := MarshalCanonicalJSON(sampleMetadata())
	if err != nil {
		t.Fatalf("MarshalCanonicalJSON failed: %v", err)
	}

	for _, forbidden := range []struct {
		b    byte
		name string
	}{{'\n', "newline"}, {'\t', "tab"}} {
		if bytes.IndexByte(encoded, forbidden.b) >= 0 {
			t.Errorf("the encoding contains a %s; the on-disk metadata is compact JSON\n%s", forbidden.name, encoded)
		}
	}

	// Indentation shows up as a space after a structural character. A space
	// INSIDE a string value is legal and must not be flagged, so the check is
	// on the pairs the pretty-printer introduces.
	for _, forbidden := range []string{"{ ", " }", "[ ", ", ", ": "} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Errorf("the encoding contains %q, which only a pretty-printer emits\n%s", forbidden, encoded)
		}
	}

	indented, err := json.MarshalIndent(sampleMetadata(), "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent failed: %v", err)
	}
	if len(encoded) >= len(indented) {
		t.Errorf("the canonical encoding is %d bytes and the indented one %d; compaction did not happen", len(encoded), len(indented))
	}
}

// TestCanonicalJSONHasNoTrailingNewline covers the one hazard of reaching for
// json.Encoder: Encode appends a newline that json.Marshal does not, and it
// would land between the closing brace and the NUL terminator -- one byte of
// divergence at a position every LUKS2 implementation reads.
func TestCanonicalJSONHasNoTrailingNewline(t *testing.T) {
	encoded, err := MarshalCanonicalJSON(sampleMetadata())
	if err != nil {
		t.Fatalf("MarshalCanonicalJSON failed: %v", err)
	}

	if len(encoded) == 0 {
		t.Fatal("the encoding is empty")
	}
	if got := encoded[len(encoded)-1]; got != '}' {
		t.Fatalf("the last byte of the encoding is %q, want '}'", got)
	}
}

// TestCanonicalJSONDoesNotEscapeHTML asserts the divergence that is latent
// today and would be silent tomorrow.
//
// encoding/json escapes the characters < > and & as six-character escape sequences by default;
// json-c does not. Nothing this package writes carries one of those
// characters right now -- the label and subsystem label are BINARY header
// fields, not JSON -- so this is asserted through a token, which is where a
// caller-supplied string first reaches the metadata.
func TestCanonicalJSONDoesNotEscapeHTML(t *testing.T) {
	metadata := sampleMetadata()
	metadata.Tokens["0"] = &Token{
		Type:     "fido2-manual",
		Keyslots: []string{"0"},
		FIDO2RP:  "a<b>c&d",
	}

	encoded, err := MarshalCanonicalJSON(metadata)
	if err != nil {
		t.Fatalf("MarshalCanonicalJSON failed: %v", err)
	}

	for _, escape := range []string{"\\u003c", "\\u003e", "\\u0026"} {
		if bytes.Contains(encoded, []byte(escape)) {
			t.Errorf("the encoding contains the HTML escape %s; json-c writes the character literally\n%s", escape, encoded)
		}
	}
	if !bytes.Contains(encoded, []byte("a<b>c&d")) {
		t.Errorf("the literal string did not survive the encoding\n%s", encoded)
	}

	// Proof that the assertion above is not vacuous: the default encoder --
	// the one this package used -- really does escape these characters, so
	// the test would fail if MarshalCanonicalJSON stopped calling
	// SetEscapeHTML.
	escaped, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if !bytes.Contains(escaped, []byte("\\u003c")) {
		t.Fatal("encoding/json no longer HTML-escapes by default, so this test proves nothing; revisit MarshalCanonicalJSON")
	}
}

// TestNoObjectWithACustomMarshalerEscapesHTML covers EVERY object that
// implements MarshalJSON, not just the one that was broken when this was
// written.
//
// The drift this prevents has already happened once. MarshalCanonicalJSON
// turns escaping off on the outer encoder, but a type implementing
// Marshaler is encoded by the bytes it RETURNS -- the outer encoder compacts
// them and, with escaping off, neither adds escapes nor removes ones
// already there. So any of these methods that reaches for json.Marshal
// internally reintroduces exactly the escapes this package turned off, and
// does it on the members most likely to carry those characters: a foreign
// object's strings and the names of members this package does not model.
func TestNoObjectWithACustomMarshalerEscapesHTML(t *testing.T) {
	// The value carries all three characters encoding/json escapes by default.
	const hostile = `a<b>c&d`

	// The hostile string goes in a MODELED field, because that is the half the
	// typed marshal encodes. An unmodeled member would NOT catch this: its raw
	// bytes are carried through mergeInto with json.Compact, which does not
	// escape, so the value never passes through json.Marshal at all.
	//
	// Each case also carries an unmodeled member, so the merge path is
	// exercised in the same pass.
	tests := []struct {
		name string
		in   string
		into func() any
	}{
		{"keyslot", `{"type":"` + hostile + `","key_size":64,"vendor":"v"}`,
			func() any { return new(Keyslot) }},
		{"keyslot area", `{"type":"raw","offset":"0","size":"1","encryption":"` + hostile + `","vendor":"v"}`,
			func() any { return new(KeyslotArea) }},
		{"kdf", `{"type":"pbkdf2","hash":"` + hostile + `","salt":"AAAA","vendor":"v"}`,
			func() any { return new(KDF) }},
		{"af", `{"type":"luks1","stripes":4000,"hash":"` + hostile + `","vendor":"v"}`,
			func() any { return new(AntiForensic) }},
		{"token", `{"type":"fido2","fido2-rp":"` + hostile + `","vendor":"v"}`,
			func() any { return new(Token) }},
		{"segment", `{"type":"crypt","offset":"0","size":"1","encryption":"` + hostile + `","vendor":"v"}`,
			func() any { return new(Segment) }},
		{"digest", `{"type":"pbkdf2","hash":"` + hostile + `","salt":"AAAA","vendor":"v"}`,
			func() any { return new(Digest) }},
		{"config", `{"json_size":"12288","keyslots_size":"1","flags":["` + hostile + `"],"vendor":"v"}`,
			func() any { return new(Config) }},
		{"requirements", `{"mandatory":["` + hostile + `"],"vendor":"v"}`,
			func() any { return new(Requirements) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			object := tt.into()
			if err := json.Unmarshal([]byte(tt.in), object); err != nil {
				t.Fatalf("decoding: %v", err)
			}

			encoded, err := MarshalCanonicalJSON(object)
			if err != nil {
				t.Fatalf("MarshalCanonicalJSON failed: %v", err)
			}

			for _, escape := range []string{"\\u003c", "\\u003e", "\\u0026"} {
				if bytes.Contains(encoded, []byte(escape)) {
					t.Errorf("%s contains the HTML escape %s; json-c writes the character literally.\n"+
						"Its MarshalJSON is encoding with json.Marshal instead of MarshalCanonicalJSON.\n%s",
						tt.name, escape, encoded)
				}
			}
			if !bytes.Contains(encoded, []byte(hostile)) {
				t.Errorf("%s: the literal string did not survive the encoding\n%s", tt.name, encoded)
			}
		})
	}
}

// TestEveryMarshalerIsCovered keeps the table above honest: a new object
// with a custom MarshalJSON must be added to it rather than silently not
// being tested.
func TestEveryMarshalerIsCovered(t *testing.T) {
	// Derived from the source rather than from memory, for the same reason
	// the table exists.
	raw, err := os.ReadFile("unknownfields.go")
	if err != nil {
		t.Fatalf("reading unknownfields.go: %v", err)
	}

	found := regexp.MustCompile(`func \((?:[a-z] )?([A-Za-z]+)\) MarshalJSON\(`).FindAllSubmatch(raw, -1)
	if len(found) == 0 {
		t.Fatal("no MarshalJSON methods found; this test is not reading what it thinks it is")
	}

	covered := map[string]bool{
		"Keyslot": true, "KeyslotArea": true, "KDF": true, "AntiForensic": true,
		"Token": true, "Segment": true, "Digest": true, "Config": true,
		"Requirements": true,
	}
	for _, m := range found {
		object := string(m[1])
		if !covered[object] {
			t.Errorf("%s implements MarshalJSON but is not in TestNoObjectWithACustomMarshalerEscapesHTML; "+
				"add it there, because an object that is not enumerated is an object that can ship escaping HTML", object)
		}
	}
	if len(found) != len(covered) {
		t.Errorf("found %d MarshalJSON methods but the covered set names %d; they must match exactly",
			len(found), len(covered))
	}
}

func TestCanonicalJSONPreservesLUKS2Typing(t *testing.T) {
	encoded, err := MarshalCanonicalJSON(sampleMetadata())
	if err != nil {
		t.Fatalf("MarshalCanonicalJSON failed: %v", err)
	}

	quoted := []string{
		`"offset":"32768"`,
		`"size":"258048"`,
		`"offset":"16777216"`,
		`"size":"dynamic"`,
		`"iv_tweak":"0"`,
		`"json_size":"12288"`,
		`"keyslots_size":"16744448"`,
	}
	bare := []string{
		`"key_size":64`,
		`"iterations":210000`,
		`"stripes":4000`,
		`"sector_size":512`,
	}

	for _, want := range append(quoted, bare...) {
		if !bytes.Contains(encoded, []byte(want)) {
			t.Errorf("the encoding is missing %s\n%s", want, encoded)
		}
	}
}

// TestMarshalCanonicalJSONReportsAnUnencodableValue covers the error path:
// the helper must surface a marshal failure rather than returning half an
// object.
func TestMarshalCanonicalJSONReportsAnUnencodableValue(t *testing.T) {
	encoded, err := MarshalCanonicalJSON(make(chan int))
	if err == nil {
		t.Fatalf("MarshalCanonicalJSON accepted an unencodable value and returned %q", encoded)
	}
	if encoded != nil {
		t.Errorf("MarshalCanonicalJSON returned %d bytes alongside its error; a partial encoding must never reach the header", len(encoded))
	}
	if !strings.Contains(err.Error(), "chan") {
		t.Errorf("the error does not name the unencodable type: %v", err)
	}
}

// sampleMetadata is the metadata shape Format writes for the default
// geometry, with every value fixed. The numbers are the ones a 64 MiB
// container carries: keyslot 0 at 0x8000 for 258048 bytes, data at
// 16777216, keyslots area 16744448.
func sampleMetadata() *Metadata {
	return &Metadata{
		Keyslots: map[string]*Keyslot{"0": sampleKeyslot(0)},
		Tokens:   map[string]*Token{},
		Segments: map[string]*Segment{
			"0": {
				Type:       "crypt",
				Offset:     "16777216",
				Size:       "dynamic",
				IVTweak:    "0",
				Encryption: "aes-xts-plain64",
				SectorSize: 512,
			},
		},
		Digests: map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Keyslots:   []string{"0"},
				Segments:   []string{"0"},
				Hash:       "sha512",
				Iterations: 210000,
				Salt:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				Digest:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			},
		},
		Config: &Config{
			JSONSize:     "12288",
			KeyslotsSize: "16744448",
		},
	}
}

// sampleKeyslot returns keyslot i with the geometry Format lays out for it.
func sampleKeyslot(i int) *Keyslot {
	iterations := 210000
	return &Keyslot{
		Type:    "luks2",
		KeySize: 64,
		Area: &KeyslotArea{
			Type:       "raw",
			KeySize:    64,
			Offset:     fmt.Sprint(0x8000 + i*258048),
			Size:       "258048",
			Encryption: "aes-xts-plain64",
		},
		KDF: &KDF{
			Type:       "pbkdf2",
			Hash:       "sha512",
			Salt:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			Iterations: &iterations,
		},
		AF: &AntiForensic{
			Type:    "luks1",
			Stripes: 4000,
			Hash:    "sha512",
		},
	}
}
