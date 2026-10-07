// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// Unknown-member passthrough for the three objects #143 did not reach:
// Segment, Digest and Config (#151).
//
// A closed struct DELETES what it does not model. The consequence is not a
// cosmetic diff: this package reads a header another implementation wrote,
// mutates one keyslot, and writes the whole thing back, so every member it
// cannot name is dropped from a container it does not own.

// segmentWithExtras is the shape cryptsetup writes for a reencryption segment:
// the modeled members plus ones this package has no field for.
const segmentWithExtras = `{
	"type": "crypt",
	"offset": "16777216",
	"size": "dynamic",
	"iv_tweak": "0",
	"encryption": "aes-xts-plain64",
	"sector_size": 512,
	"integrity": {"type": "hmac(sha256)", "journal_encryption": "none"},
	"flags": ["in-reencryption"]
}`

const digestWithExtras = `{
	"type": "pbkdf2",
	"keyslots": ["0"],
	"segments": ["0"],
	"hash": "sha512",
	"iterations": 180539,
	"salt": "7CrDjZXur1vj553pW+/6o6MwhEh7u9eOWo+Y71cTzvA=",
	"digest": "jLQsnNE3fxejne3Xf3hoWE5wF0/fXBLTzUY1689x5B31QTWHKmqETjsclJ+uiUIh9f759Czul/DxiZSEPtYQeg==",
	"vendor-attestation": {"scheme": "v2", "nonce": "AAAA"}
}`

const configWithExtras = `{
	"json_size": "12288",
	"keyslots_size": "16744448",
	"flags": ["allow-discards"],
	"vendor-policy": {"rotate-after-days": 90}
}`

func TestUnmodeledMembersSurviveARoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		decode func(t *testing.T, data []byte) any
		// members that must come back out, with the values they went in with
		want map[string]string
	}{
		{
			name: "segment",
			in:   segmentWithExtras,
			decode: func(t *testing.T, data []byte) any {
				var v header.Segment
				if err := json.Unmarshal(data, &v); err != nil {
					t.Fatalf("decoding the segment: %v", err)
				}
				if v.Type != "crypt" || v.SectorSize != 512 {
					t.Fatalf("the typed half did not decode: %+v", v)
				}
				return v
			},
			want: map[string]string{
				`"integrity"`: `"hmac(sha256)"`,
				`"flags"`:     `"in-reencryption"`,
			},
		},
		{
			name: "digest",
			in:   digestWithExtras,
			decode: func(t *testing.T, data []byte) any {
				var v rawDigest
				if err := json.Unmarshal(data, &v); err != nil {
					t.Fatalf("decoding the digest: %v", err)
				}
				if v.Type != "pbkdf2" || v.Iterations != 180539 {
					t.Fatalf("the typed half did not decode: %+v", v)
				}
				return v
			},
			want: map[string]string{
				`"vendor-attestation"`: `"v2"`,
			},
		},
		{
			name: "config",
			in:   configWithExtras,
			decode: func(t *testing.T, data []byte) any {
				var v rawConfig
				if err := json.Unmarshal(data, &v); err != nil {
					t.Fatalf("decoding the config: %v", err)
				}
				if v.JSONSize != "12288" || v.KeyslotsSize != "16744448" {
					t.Fatalf("the typed half did not decode: %+v", v)
				}
				return v
			},
			want: map[string]string{
				`"vendor-policy"`: `"rotate-after-days"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// VALUE, not pointer. This is the hazard #143 measured and #151
			// asked to be pinned per type: a pointer-receiver MarshalJSON is
			// not in the method set json.Marshal reaches for a bare value, so
			// it silently stops firing while every pointer-holding test passes.
			value := tt.decode(t, []byte(tt.in))

			out, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("re-encoding: %v", err)
			}

			for member, content := range tt.want {
				if !strings.Contains(string(out), member) {
					t.Errorf("%s was dropped by the round trip\n got: %s", member, out)
					continue
				}
				if !strings.Contains(string(out), content) {
					t.Errorf("%s survived but its content %s did not\n got: %s", member, content, out)
				}
			}
		})
	}
}

// TestUnmodeledMembersSurviveAMutation is the defect's real shape: read a
// foreign object, change a member this package DOES model, write it back.
func TestUnmodeledMembersSurviveAMutation(t *testing.T) {
	var segment header.Segment
	if err := json.Unmarshal([]byte(segmentWithExtras), &segment); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	segment.SectorSize = 4096

	out, err := json.Marshal(segment)
	if err != nil {
		t.Fatalf("re-encoding: %v", err)
	}
	if !strings.Contains(string(out), `"sector_size":4096`) {
		t.Errorf("the mutation did not survive\n got: %s", out)
	}
	if !strings.Contains(string(out), `"integrity"`) {
		t.Errorf("the unmodeled member was dropped by the mutation\n got: %s", out)
	}
}

// TestAMarshalerIsReachedThroughTheEnclosingMetadata proves the passthrough
// works where it actually matters -- these objects are encoded as part of
// header.Metadata, not on their own.
func TestAMarshalerIsReachedThroughTheEnclosingMetadata(t *testing.T) {
	var (
		segment header.Segment
		digest  rawDigest
		config  rawConfig
	)
	for _, p := range []struct {
		in string
		to any
	}{{segmentWithExtras, &segment}, {digestWithExtras, &digest}, {configWithExtras, &config}} {
		if err := json.Unmarshal([]byte(p.in), p.to); err != nil {
			t.Fatalf("decoding: %v", err)
		}
	}

	metadata := &header.Metadata{
		Keyslots: map[string]*header.Keyslot{},
		Tokens:   map[string]*LegacyToken{},
		Segments: map[string]*header.Segment{"0": &segment},
		Digests:  map[string]*rawDigest{"0": &digest},
		Config:   &config,
	}

	out, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("encoding the metadata: %v", err)
	}
	for _, member := range []string{`"integrity"`, `"vendor-attestation"`, `"vendor-policy"`} {
		if !strings.Contains(string(out), member) {
			t.Errorf("%s was dropped when encoded through header.Metadata\n got: %s", member, out)
		}
	}
}
