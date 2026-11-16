// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// minimalValidMetadata is a default-geometry (16 KiB) header with no
// keyslots: one crypt segment at 16 MiB, attested by a digest naming no
// keyslot.
func minimalValidMetadata() *Metadata {
	return &Metadata{
		Keyslots: map[string]*Keyslot{},
		Tokens:   map[string]*Token{},
		Segments: map[string]*Segment{"0": {
			Type: "crypt", Offset: "16777216", Size: "dynamic", IVTweak: "0",
			Encryption: "aes-xts-plain64", SectorSize: 512,
		}},
		Digests: map[string]*Digest{"0": {
			Type: "pbkdf2", Keyslots: []string{}, Segments: []string{"0"}, Hash: "sha256", Iterations: 1000,
		}},
		Config: &Config{JSONSize: "12288", KeyslotsSize: "16744448"},
	}
}

// structureFixture is a complete, valid default-geometry header's metadata: one
// luks2 keyslot, one token naming it, one crypt segment, one digest binding the
// two. Each case below breaks exactly one thing about it.
func structureFixture() *Metadata {
	m := minimalValidMetadata()
	m.Keyslots["0"] = &Keyslot{Type: "luks2", KeySize: 64, Area: &KeyslotArea{Type: "raw", Offset: "32768", Size: "258048"}}
	m.Digests["0"].Keyslots = []string{"0"}
	m.Tokens["0"] = &Token{Type: "systemd-recovery", Keyslots: []string{"0"}}
	return m
}

// withUnknown sets a member Segment does not model, as the decoder would
// have carried it in.
func withUnknown(s *Segment, name, raw string) {
	if s.unknown == nil {
		s.unknown = unknownFields{}
	}
	s.unknown[name] = json.RawMessage(raw)
}

// reencryptFixture is a valid header in online reencryption: a regular segment
// and the backup-final and backup-previous segments cryptsetup keeps.
func reencryptFixture() *Metadata {
	m := structureFixture()
	m.Config.Requirements = &Requirements{Mandatory: []string{"online-reencrypt-v2"}}
	for _, b := range []struct{ id, flag string }{{"1", "backup-final"}, {"2", "backup-previous"}} {
		backup := *m.Segments["0"]
		withUnknown(&backup, "flags", `["`+b.flag+`"]`)
		m.Segments[b.id] = &backup
	}
	m.Digests["0"].Segments = []string{"0", "1", "2"}
	m.Keyslots["1"] = &Keyslot{Type: "reencrypt", KeySize: 1, Area: &KeyslotArea{Type: "checksum", Offset: "290816", Size: "4096"}}
	return m
}

// opalFixture is a valid header whose data segment is an OPAL locking range.
func opalFixture(segmentType string) *Metadata {
	m := structureFixture()
	s := m.Segments["0"]
	s.Type, s.Size = segmentType, "1048576"
	withUnknown(s, "opal_segment_number", `1`)
	withUnknown(s, "opal_key_size", `32`)
	withUnknown(s, "opal_segment_size", `"1048576"`)
	return m
}

// TestValidateHeaderStructureFollowsCryptsetup pins each rule of
// LUKS2_hdr_validate that validation.go reproduces, one broken rule per case,
// against a fixture that passes all of them. The integration suite in
// pkg/luks2 proves the same rules against the cryptsetup binary.
func TestValidateHeaderStructureFollowsCryptsetup(t *testing.T) {
	t.Parallel()

	const hdrSize = HeaderMinSize
	var wide int64 = math.MaxUint32 + 1

	tests := []struct {
		name    string
		build   func() *Metadata
		mutate  func(*Metadata)
		wantErr string // empty: the header is valid
	}{
		{name: "the fixture itself", mutate: func(*Metadata) {}},
		{name: "no metadata at all", build: func() *Metadata { return nil }, wantErr: "no JSON metadata"},

		// hdr_validate_requirements
		{name: "two online reencryptions", mutate: func(m *Metadata) {
			m.Config.Requirements = &Requirements{Mandatory: []string{"online-reencrypt-v2", "online-reencrypt-v3"}}
		}, wantErr: "at most one"},
		{name: "an unrelated requirement", mutate: func(m *Metadata) {
			m.Config.Requirements = &Requirements{Mandatory: []string{"online-reencrypt-vx", "opal"}}
		}},

		// hdr_validate_tokens
		{name: "token id not a number", mutate: func(m *Metadata) { m.Tokens["x"] = m.Tokens["0"] }, wantErr: `token id "x"`},
		{name: "null token", mutate: func(m *Metadata) { m.Tokens["1"] = nil }, wantErr: `token "1" is null`},
		{name: "token without a type", mutate: func(m *Metadata) { m.Tokens["0"].Type = "" }, wantErr: "declares no type"},
		{name: "token without a keyslots array", mutate: func(m *Metadata) { m.Tokens["0"].Keyslots = nil }, wantErr: "no keyslots array"},
		{name: "token naming no keyslot", mutate: func(m *Metadata) { m.Tokens["0"].Keyslots = []string{} }},
		{name: "token naming a missing keyslot", mutate: func(m *Metadata) { m.Tokens["0"].Keyslots = []string{"7"} }, wantErr: "does not have"},
		{name: "token naming a keyslot by a non-canonical id", mutate: func(m *Metadata) {
			m.Keyslots["00"] = m.Keyslots["0"]
			delete(m.Keyslots, "0")
			m.Digests["0"].Keyslots = []string{"00"}
			m.Tokens["0"].Keyslots = []string{"00"}
		}, wantErr: "not a canonical keyslot id"},
		{name: "token naming a keyslot past 31", mutate: func(m *Metadata) {
			m.Keyslots["32"] = m.Keyslots["0"]
			m.Tokens["0"].Keyslots = []string{"32"}
		}, wantErr: "not a canonical keyslot id (0..31)"},
		{name: "token naming a negative keyslot", mutate: func(m *Metadata) { m.Tokens["0"].Keyslots = []string{"-1"} }, wantErr: "not a canonical keyslot id"},

		// hdr_validate_digests
		{name: "digest id not a number", mutate: func(m *Metadata) { m.Digests["d"] = m.Digests["0"] }, wantErr: `digest id "d"`},
		{name: "null digest", mutate: func(m *Metadata) { m.Digests["1"] = nil }, wantErr: `digest "1" is null`},
		{name: "digest without a type", mutate: func(m *Metadata) { m.Digests["0"].Type = "" }, wantErr: "declares no type"},
		{name: "digest without a keyslots array", mutate: func(m *Metadata) { m.Digests["0"].Keyslots = nil }, wantErr: "keyslots array and a segments array"},
		{name: "digest without a segments array", mutate: func(m *Metadata) { m.Digests["0"].Segments = nil }, wantErr: "keyslots array and a segments array"},
		{name: "digest naming a missing keyslot", mutate: func(m *Metadata) { m.Digests["0"].Keyslots = []string{"5"} }, wantErr: `keyslot "5"`},
		{name: "digest naming a missing segment", mutate: func(m *Metadata) { m.Digests["0"].Segments = []string{"0", "3"} }, wantErr: `segment "3"`},

		// hdr_validate_segments: each segment
		{name: "no segments", mutate: func(m *Metadata) {
			m.Segments = map[string]*Segment{}
			m.Digests["0"].Segments = []string{}
		}, wantErr: "no segments"},
		{name: "segment id not a number", mutate: func(m *Metadata) { m.Segments["s"] = m.Segments["0"] }, wantErr: `segment id "s"`},
		{name: "segment id spelled 00", mutate: func(m *Metadata) {
			m.Segments["00"] = m.Segments["0"]
			delete(m.Segments, "0")
			m.Digests["0"].Segments = []string{"00"}
		}, wantErr: "gap"},
		{name: "segment id past the count", mutate: func(m *Metadata) {
			m.Segments["1"] = m.Segments["0"]
			delete(m.Segments, "0")
			m.Digests["0"].Segments = []string{"1"}
		}, wantErr: "gap"},
		{name: "null segment", mutate: func(m *Metadata) { m.Segments["1"] = nil }, wantErr: "is null"},
		{name: "segment without a type", mutate: func(m *Metadata) { m.Segments["0"].Type = "" }, wantErr: "type, an offset and a size"},
		{name: "segment offset not a number", mutate: func(m *Metadata) { m.Segments["0"].Offset = "0x1000000" }, wantErr: "offset"},
		{name: "segment size zero", mutate: func(m *Metadata) { m.Segments["0"].Size = "0" }, wantErr: "size"},
		{name: "segment size not a number", mutate: func(m *Metadata) { m.Segments["0"].Size = "-512" }, wantErr: "size"},
		{name: "segment offset off the 512-byte grid", mutate: func(m *Metadata) { m.Segments["0"].Offset = "16777217" }, wantErr: "multiples of 512"},
		{name: "segment size off the 512-byte grid", mutate: func(m *Metadata) { m.Segments["0"].Size = "1000" }, wantErr: "multiples of 512"},
		{name: "segment flags that are not an array", mutate: func(m *Metadata) { withUnknown(m.Segments["0"], "flags", `"in-reencryption"`) }, wantErr: "flags"},
		{name: "segment flags of strings", mutate: func(m *Metadata) { withUnknown(m.Segments["0"], "flags", `["in-reencryption"]`) }},
		{name: "a linear segment declares no cipher", mutate: func(m *Metadata) {
			s := m.Segments["0"]
			s.Type, s.IVTweak, s.Encryption, s.SectorSize = "linear", "", "", 0
		}},

		// hdr_validate_crypt_segment
		{name: "crypt segment without an iv_tweak", mutate: func(m *Metadata) { m.Segments["0"].IVTweak = "" }, wantErr: "empty iv_tweak"},
		{name: "crypt segment without a cipher", mutate: func(m *Metadata) { m.Segments["0"].Encryption = "" }, wantErr: "empty cipher"},
		{name: "integrity that is not an object", mutate: func(m *Metadata) { withUnknown(m.Segments["0"], "integrity", `"hmac(sha256)"`) }, wantErr: "integrity"},
		{name: "integrity missing a member", mutate: func(m *Metadata) {
			withUnknown(m.Segments["0"], "integrity", `{"type":"hmac(sha256)","journal_encryption":"none"}`)
		}, wantErr: "journal_integrity"},
		{name: "integrity complete", mutate: func(m *Metadata) {
			withUnknown(m.Segments["0"], "integrity", `{"type":"hmac(sha256)","journal_encryption":"none","journal_integrity":"none"}`)
		}},
		// LUKS2 On-Disk Format 1.1.4: integrity.key_size [integer,optional].
		{name: "integrity key_size an integer", mutate: func(m *Metadata) {
			withUnknown(m.Segments["0"], "integrity", `{"type":"hmac(sha256)","journal_encryption":"none","journal_integrity":"none","key_size":32}`)
		}},
		{name: "integrity key_size a string", mutate: func(m *Metadata) {
			withUnknown(m.Segments["0"], "integrity", `{"type":"hmac(sha256)","journal_encryption":"none","journal_integrity":"none","key_size":"32"}`)
		}, wantErr: "integer key_size"},
		{name: "integrity key_size a fraction", mutate: func(m *Metadata) {
			withUnknown(m.Segments["0"], "integrity", `{"type":"hmac(sha256)","journal_encryption":"none","journal_integrity":"none","key_size":32.5}`)
		}, wantErr: "integer key_size"},
		{name: "integrity key_size null", mutate: func(m *Metadata) {
			withUnknown(m.Segments["0"], "integrity", `{"type":"hmac(sha256)","journal_encryption":"none","journal_integrity":"none","key_size":null}`)
		}, wantErr: "integer key_size"},
		{name: "sector size zero", mutate: func(m *Metadata) { m.Segments["0"].SectorSize = 0 }, wantErr: "sector size"},
		{name: "sector size off the 512-byte grid", mutate: func(m *Metadata) { m.Segments["0"].SectorSize = 768 }, wantErr: "sector size"},
		{name: "iv_tweak not a number", mutate: func(m *Metadata) { m.Segments["0"].IVTweak = "0x10" }, wantErr: "iv_tweak"},
		{name: "fixed size a whole number of sectors", mutate: func(m *Metadata) {
			m.Segments["0"].SectorSize, m.Segments["0"].Size = 4096, "8192"
		}},
		{name: "fixed size not a whole number of sectors", mutate: func(m *Metadata) {
			m.Segments["0"].SectorSize, m.Segments["0"].Size = 4096, "1024"
		}, wantErr: "not a multiple of its sector size"},
		{name: "crypt segment no digest attests", mutate: func(m *Metadata) { m.Digests["0"].Segments = []string{} }, wantErr: "not assigned to any digest"},

		// hw-opal segments
		{name: "OPAL segment", build: func() *Metadata { return opalFixture("hw-opal") }, mutate: func(*Metadata) {}},
		{name: "OPAL crypt segment", build: func() *Metadata { return opalFixture("hw-opal-crypt") }, mutate: func(*Metadata) {}},
		{name: "OPAL segment with a dynamic size", build: func() *Metadata { return opalFixture("hw-opal") },
			mutate: func(m *Metadata) { m.Segments["0"].Size = "dynamic" }, wantErr: "dynamic size"},
		{name: "OPAL segment number as a string", build: func() *Metadata { return opalFixture("hw-opal") },
			mutate: func(m *Metadata) { withUnknown(m.Segments["0"], "opal_segment_number", `"1"`) }, wantErr: "opal_segment_number"},
		{name: "OPAL key size missing", build: func() *Metadata { return opalFixture("hw-opal") },
			mutate: func(m *Metadata) { delete(m.Segments["0"].unknown, "opal_key_size") }, wantErr: "opal_key_size"},
		{name: "OPAL range size as a number", build: func() *Metadata { return opalFixture("hw-opal") },
			mutate: func(m *Metadata) { withUnknown(m.Segments["0"], "opal_segment_size", `1048576`) }, wantErr: "opal_segment_size"},
		{name: "OPAL range size zero", build: func() *Metadata { return opalFixture("hw-opal") },
			mutate: func(m *Metadata) { withUnknown(m.Segments["0"], "opal_segment_size", `"0"`) }, wantErr: "opal_segment_size"},
		{name: "OPAL segment larger than its range", build: func() *Metadata { return opalFixture("hw-opal") },
			mutate: func(m *Metadata) { m.Segments["0"].Size = "2097152" }, wantErr: "locking range"},
		{name: "OPAL crypt segment no digest attests", build: func() *Metadata { return opalFixture("hw-opal-crypt") },
			mutate: func(m *Metadata) { m.Digests["0"].Segments = []string{} }, wantErr: "not assigned to any digest"},

		// hdr_validate_segments: the segments together
		{name: "two regular segments that overlap", mutate: func(m *Metadata) {
			first := *m.Segments["0"]
			first.Size = "1048576"
			m.Segments["0"], m.Segments["1"] = &first, m.Segments["0"]
			m.Segments["1"].Offset = "17301504" // inside the first
			m.Digests["0"].Segments = []string{"0", "1"}
		}, wantErr: "overlap"},
		{name: "two regular segments end to end", mutate: func(m *Metadata) {
			first := *m.Segments["0"]
			first.Size = "1048576"
			m.Segments["0"], m.Segments["1"] = &first, m.Segments["0"]
			m.Segments["1"].Offset = "17825792"
			m.Digests["0"].Segments = []string{"0", "1"}
		}},
		{name: "a dynamic segment that is not the last", mutate: func(m *Metadata) {
			second := *m.Segments["0"]
			second.Offset, second.Size = "33554432", "1048576"
			m.Segments["1"] = &second
			m.Digests["0"].Segments = []string{"0", "1"}
		}, wantErr: "only the last regular segment"},
		{name: "a segment whose end overflows", mutate: func(m *Metadata) {
			first := *m.Segments["0"]
			first.Size = "1048576"
			second := *m.Segments["0"]
			second.Offset, second.Size = "18446744073709550592", "1024"
			m.Segments["0"], m.Segments["1"] = &first, &second
			m.Digests["0"].Segments = []string{"0", "1"}
		}, wantErr: "overflows"},
		{name: "only backup segments", mutate: func(m *Metadata) { withUnknown(m.Segments["0"], "flags", `["backup-final"]`) }, wantErr: "no regular segment"},
		{name: "a regular segment after a backup", mutate: func(m *Metadata) {
			backup := *m.Segments["0"]
			backup.unknown = nil
			withUnknown(&backup, "flags", `["backup-final"]`)
			m.Segments["1"] = &backup
			m.Segments["2"] = m.Segments["0"]
			m.Digests["0"].Segments = []string{"0", "1", "2"}
		}, wantErr: "after backup segment"},
		{name: "a gap before the backups", mutate: func(m *Metadata) {
			backup := *m.Segments["0"]
			withUnknown(&backup, "flags", `["backup-final"]`)
			m.Segments["2"] = &backup
			m.Digests["0"].Segments = []string{"0", "2"}
		}, wantErr: "gap"},

		// validate_reencrypt_segments
		{name: "online reencryption with both backups", build: reencryptFixture, mutate: func(*Metadata) {}},
		{name: "online reencryption without backup-previous", build: reencryptFixture, mutate: func(m *Metadata) {
			withUnknown(m.Segments["2"], "flags", `["backup-moved-segment"]`)
		}, wantErr: "backup-previous"},
		{name: "a segment in reencryption that is not the final one", build: reencryptFixture, mutate: func(m *Metadata) {
			withUnknown(m.Segments["0"], "flags", `["in-reencryption"]`)
			m.Segments["1"].SectorSize = 4096
		}, wantErr: "backup-final"},
		{name: "a segment matching neither backup", build: reencryptFixture, mutate: func(m *Metadata) {
			m.Segments["0"].Encryption = "aes-cbc-essiv:sha256"
		}, wantErr: "neither"},
		{name: "a linear segment beside linear backups", build: reencryptFixture, mutate: func(m *Metadata) {
			for _, s := range m.Segments {
				s.Type = "linear"
			}
		}},

		// hdr_validate_keyslots
		{name: "keyslot id not a number", mutate: func(m *Metadata) { m.Keyslots["k"] = m.Keyslots["0"] }, wantErr: `keyslot id "k"`},
		{name: "null keyslot", mutate: func(m *Metadata) { m.Keyslots["1"] = nil }, wantErr: `keyslot "1" is null`},
		{name: "keyslot id with a leading zero", mutate: func(m *Metadata) {
			m.Keyslots["07"] = m.Keyslots["0"]
			m.Digests["0"].Keyslots = []string{"0", "07"}
		}, wantErr: "canonical spelling"},
		{name: "keyslot id past 31", mutate: func(m *Metadata) {
			second := *m.Keyslots["0"]
			area := *second.Area
			area.Offset = "290816"
			second.Area = &area
			m.Keyslots["32"] = &second
			m.Digests["0"].Keyslots = []string{"0", "32"}
		}},
		{name: "keyslot without a type", mutate: func(m *Metadata) { m.Keyslots["0"].Type = "" }, wantErr: "declares no type"},
		// LUKS2_keyslots_validate's structural rules
		{name: "luks2 keyslot named by two digests", mutate: func(m *Metadata) {
			second := *m.Digests["0"]
			second.Segments = []string{}
			m.Digests["1"] = &second
		}, wantErr: "named by 2 digests"},
		{name: "luks2 keyslot named by no digest", mutate: func(m *Metadata) { m.Digests["0"].Keyslots = []string{} }, wantErr: "named by 0 digests"},
		{name: "reencrypt keyslot without a requirement", build: reencryptFixture, mutate: func(m *Metadata) {
			m.Config.Requirements = nil
			delete(m.Segments, "1")
			delete(m.Segments, "2")
			m.Digests["0"].Segments = []string{"0"}
		}, wantErr: "no reencryption requirement"},
		{name: "two reencrypt keyslots", build: reencryptFixture, mutate: func(m *Metadata) {
			m.Keyslots["2"] = &Keyslot{Type: "reencrypt", KeySize: 1, Area: &KeyslotArea{Type: "checksum", Offset: "294912", Size: "4096"}}
		}, wantErr: "2 reencrypt keyslots"},
		{name: "online reencryption without a reencrypt keyslot", build: reencryptFixture, mutate: func(m *Metadata) { delete(m.Keyslots, "1") }, wantErr: "no reencrypt keyslot"},
		{name: "keyslot key_size negative", mutate: func(m *Metadata) { m.Keyslots["0"].KeySize = -1 }, wantErr: "key_size"},

		// hdr_validate_config
		{name: "no config", mutate: func(m *Metadata) { m.Config = nil }, wantErr: "no config"},
		{name: "json_size not a number", mutate: func(m *Metadata) { m.Config.JSONSize = "-1" }, wantErr: "json_size"},
		{name: "keyslots_size not a number", mutate: func(m *Metadata) { m.Config.KeyslotsSize = "0x1000" }, wantErr: "keyslots_size"},
		{name: "json_size of an illegal metadata size", mutate: func(m *Metadata) { m.Config.JSONSize = "8192" }, wantErr: "not a LUKS2 metadata size"},
		{name: "keyslots_size off the 4 KiB grid", mutate: func(m *Metadata) { m.Config.KeyslotsSize = "16744000" }, wantErr: "multiple of 4096"},
		{name: "keyslots_size above 128 MiB", mutate: func(m *Metadata) { m.Config.KeyslotsSize = "134221824" }, wantErr: "multiple of 4096"},
		{name: "keyslots area running into the data", mutate: func(m *Metadata) { m.Config.KeyslotsSize = "16777216" }, wantErr: "does not fit"},
		{name: "data inside the header copies", mutate: func(m *Metadata) {
			m.Segments["0"].Offset = "16384"
			m.Config.KeyslotsSize = "0"
			m.Keyslots = map[string]*Keyslot{}
			m.Digests["0"].Keyslots, m.Tokens["0"].Keyslots = []string{}, []string{}
		}, wantErr: "does not fit"},
		{name: "a detached header's data at offset 0", mutate: func(m *Metadata) { m.Segments["0"].Offset = "0" }},
		{name: "a backup segment is not the data offset", build: reencryptFixture, mutate: func(m *Metadata) { m.Segments["2"].Offset = "0" }},

		// hdr_validate_areas
		{name: "keyslot without an area", mutate: func(m *Metadata) { m.Keyslots["0"].Area = nil }, wantErr: "area with a type"},
		{name: "keyslot area without a type", mutate: func(m *Metadata) { m.Keyslots["0"].Area.Type = "" }, wantErr: "area with a type"},
		{name: "keyslot area offset not a number", mutate: func(m *Metadata) { m.Keyslots["0"].Area.Offset = "-4096" }, wantErr: "decimal byte counts"},
		{name: "keyslot area inside the header copies", mutate: func(m *Metadata) { m.Keyslots["0"].Area.Offset = "16384" }, wantErr: "inside the header copies"},
		{name: "keyslot area empty", mutate: func(m *Metadata) { m.Keyslots["0"].Area.Size = "0" }, wantErr: "is empty"},
		{name: "keyslot area end overflows", mutate: func(m *Metadata) {
			m.Keyslots["0"].Area.Offset, m.Keyslots["0"].Area.Size = "18446744073709551615", "1"
		}, wantErr: "overflows"},
		{name: "keyslot area past the keyslots area", mutate: func(m *Metadata) { m.Keyslots["0"].Area.Offset = "16773120" }, wantErr: "runs past"},
		{name: "two keyslot areas that overlap", mutate: func(m *Metadata) {
			second := *m.Keyslots["0"]
			area := *second.Area
			area.Offset = "40960"
			second.Area = &area
			m.Keyslots["1"] = &second
		}, wantErr: "overlap"},
		{name: "a keyslot area whose neighbor overflows", mutate: func(m *Metadata) {
			second := *m.Keyslots["0"]
			area := *second.Area
			area.Offset, area.Size = "18446744073709551615", "1"
			second.Area = &area
			m.Keyslots["9"] = &second
		}, wantErr: "overflows"},

		// hdr_validate_json_size
		{name: "json_size of another geometry", mutate: func(m *Metadata) {
			m.Config.JSONSize = "28672"
			m.Config.KeyslotsSize = "16711680"
			m.Keyslots["0"].Area.Offset = "65536"
		}, wantErr: "does not match"},
	}
	if strconv.IntSize == 64 {
		tests = append(tests, struct {
			name    string
			build   func() *Metadata
			mutate  func(*Metadata)
			wantErr string
		}{name: "keyslot key_size past 32 bits", mutate: func(m *Metadata) { m.Keyslots["0"].KeySize = int(wide) }, wantErr: "key_size"})
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			build := tc.build
			if build == nil {
				build = structureFixture
			}
			m := build()
			if tc.mutate != nil {
				tc.mutate(m)
			}
			err := ValidateHeaderStructure(hdrSize, m)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("a valid header was refused: %v", err)
				}
				return
			}
			if !errors.Is(err, errs.ErrInvalidHeader) || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want ErrInvalidHeader naming %q", err, tc.wantErr)
			}
		})
	}
}

// TestTheReadPathRefusesOnlyHeaderWideFaults pins the split between the two
// entry points. A damaged keyslot or token does not cost the reader the whole
// volume -- that is the recorded per-entry policy -- while every write refuses
// it, so the damage cannot be written back.
func TestTheReadPathRefusesOnlyHeaderWideFaults(t *testing.T) {
	t.Parallel()

	perEntry := map[string]func(*Metadata){
		"a dangling token":           func(m *Metadata) { m.Tokens["0"].Keyslots = []string{"7"} },
		"a keyslot id not a number":  func(m *Metadata) { m.Keyslots["k"] = m.Keyslots["0"] },
		"a keyslot area out of area": func(m *Metadata) { m.Keyslots["0"].Area.Offset = "16384" },
	}
	for name, mutate := range perEntry {
		m := structureFixture()
		mutate(m)
		if err := ValidateHeaderWideStructure(HeaderMinSize, m); err != nil {
			t.Errorf("%s: the read path refused the header: %v", name, err)
		}
		if err := ValidateHeaderStructure(HeaderMinSize, m); !errors.Is(err, errs.ErrInvalidHeader) {
			t.Errorf("%s: the write path accepted it: %v", name, err)
		}
	}

	m := structureFixture()
	m.Segments["0"].Offset = "16777217"
	if err := ValidateHeaderWideStructure(HeaderMinSize, m); !errors.Is(err, errs.ErrInvalidHeader) {
		t.Errorf("the read path accepted a misaligned segment: %v", err)
	}
}
