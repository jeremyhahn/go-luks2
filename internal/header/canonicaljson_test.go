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

// Tests for the on-disk JSON encoding: compact, unescaped, terminated by one NUL.

// TestCanonicalJSONIsCompact pins compact encoding, which the fixed metadata area depends on.
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

	// Indentation shows as a space after a structural character; spaces inside strings are legal.
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

// TestCanonicalJSONDoesNotEscapeHTML checks < > & are not escaped, as json-c does not escape them, through a token.
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

// TestNoObjectWithACustomMarshalerEscapesHTML covers every type implementing MarshalJSON, since a Marshaler's own bytes are kept as returned.
func TestNoObjectWithACustomMarshalerEscapesHTML(t *testing.T) {
	// The value carries all three characters encoding/json escapes by default.
	const hostile = `a<b>c&d`

	// The hostile string goes in a modeled field; each case also carries an unmodeled member to exercise the merge path.
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
