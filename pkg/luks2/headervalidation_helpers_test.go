// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

// minimalHeaderJSONTail completes a JSON area after its keyslots member with the
// smallest segments, digests and config cryptsetup accepts: one crypt segment
// at 16 MiB, attested by a digest that names no keyslot, in a default-geometry
// header. A fixture about something else uses it so the header around that
// something is valid.
const minimalHeaderJSONTail = `"tokens":{},` +
	`"segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":512}},` +
	`"digests":{"0":{"type":"pbkdf2","keyslots":[],"segments":["0"],"hash":"sha256","iterations":1000,"salt":"","digest":""}},` +
	`"config":{"json_size":"12288","keyslots_size":"16744448"}}`

// minimalValidMetadata is minimalHeaderJSONTail as typed metadata, with no
// keyslots, for a default-geometry (16 KiB) header.
func minimalValidMetadata() *LUKS2Metadata {
	return &LUKS2Metadata{
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
