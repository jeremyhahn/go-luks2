// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Tests for the on-disk JSON ENCODING itself: the LUKS2 metadata area holds
// compact, unescaped JSON terminated by a single NUL, and every property that
// makes that sentence true is asserted here.
//
// These are deliberately separate from the cryptsetup conformance tests. What
// the encoder does is decidable without a third party -- compactness, escaping
// and the terminator are properties of the bytes -- and a test that needs no
// external binary should not be made to depend on one.

// TestCanonicalJSONIsCompact pins the property the 12288-byte metadata area
// actually depends on.
//
// json.MarshalIndent was producing 1193 bytes for the metadata json-c writes in
// 775. That is not a cosmetic difference: encodeMetadataForHeader REFUSES
// metadata that does not fit and cannot enlarge the area (the keyslots and the
// data segment are already placed), so 54% of the area was being spent on
// whitespace and the refusal fired at a keyslot count well below cryptsetup's.
// TestCanonicalJSONHasNoTrailingNewline covers the one hazard of reaching for
// json.Encoder: Encode appends a newline that json.Marshal does not, and it
// would land between the closing brace and the NUL terminator -- one byte of
// divergence at a position every LUKS2 implementation reads.
// TestCanonicalJSONDoesNotEscapeHTML asserts the divergence that is latent
// today and would be silent tomorrow.
//
// encoding/json escapes <, > and & as \u003c, \u003e and \u0026 by default;
// json-c does not. Nothing this package writes carries one of those characters
// right now -- the label and subsystem label are BINARY header fields, not JSON
// -- so this is asserted through a token, which is where a caller-supplied
// string first reaches the metadata.
// TestCanonicalJSONPreservesLUKS2Typing guards the properties the LUKS2 spec
// fixes and that a re-encoding is the natural place to break: the byte offsets
// and sizes are JSON STRINGS, the key sizes and iteration counts are JSON
// NUMBERS, and neither may drift into the other.
//
// The spec (LUKS2 On-Disk Format, "keyslots object" and "segments object")
// requires string encoding for the 64-bit byte values precisely because JSON
// numbers are doubles; an implementation that emits them bare loses precision
// above 2^53 and produces a header others parse differently.
// TestNoObjectWithACustomMarshalerEscapesHTML covers EVERY object that
// implements MarshalJSON, not just the one that was broken when this was
// written.
//
// The drift this prevents has already happened once. marshalCanonicalJSON turns
// escaping off on the outer encoder, but a type implementing Marshaler is
// encoded by the bytes it RETURNS -- the outer encoder compacts them and, with
// escaping off, neither adds escapes nor removes ones already there. So any of
// these methods that reaches for json.Marshal internally reintroduces exactly
// the escapes this package turned off, and does it on the members most likely to
// carry those characters: a foreign object's strings and the names of members
// this package does not model.
//
// #153 added five such methods and #180 added four more. A test naming one
// object is a test that passes while the next object added is wrong, which is
// what happened: the four from #180 shipped with json.Marshal and nothing
// failed. Enumerate the objects instead.
// TestEveryMarshalerIsCovered keeps the table above honest: a new object with a
// custom MarshalJSON must be added to it rather than silently not being tested.
// TestEncodeMetadataForHeaderEmitsCompactJSON checks the WRITE PATH rather than
// the helper, because encodeMetadataForHeader is what the header write calls
// and a future edit could reintroduce indentation there without touching
// marshalCanonicalJSON.
func TestEncodeMetadataForHeaderEmitsCompactJSON(t *testing.T) {
	hdr, err := CreateBinaryHeader(FormatOptions{})
	if err != nil {
		t.Fatalf("CreateBinaryHeader failed: %v", err)
	}

	jsonData, area, err := encodeMetadataForHeader(hdr, sampleMetadata())
	if err != nil {
		t.Fatalf("encodeMetadataForHeader failed: %v", err)
	}
	if area != LUKS2HeaderMinSize {
		t.Fatalf("area = %d, want %d", area, LUKS2HeaderMinSize)
	}
	if bytes.Contains(jsonData, []byte("\n")) {
		t.Fatalf("the write path is still emitting indented JSON\n%s", jsonData)
	}
	if !json.Valid(jsonData) {
		t.Fatalf("the write path emitted invalid JSON\n%s", jsonData)
	}
}

// TestCompactJSONRaisesTheKeyslotCeiling is the consequence that motivated the
// change, measured rather than asserted from the byte counts.
//
// encodeMetadataForHeader refuses metadata that does not fit the 12288-byte
// area. Under MarshalIndent that refusal fired far below the 32 keyslots LUKS2
// allows; the test walks the keyslot count up until the refusal appears and
// requires that the full complement now fits.
func TestCompactJSONRaisesTheKeyslotCeiling(t *testing.T) {
	hdr, err := CreateBinaryHeader(FormatOptions{})
	if err != nil {
		t.Fatalf("CreateBinaryHeader failed: %v", err)
	}

	accepted := 0
	for n := 1; n <= MaxKeyslots; n++ {
		metadata := sampleMetadata()
		for i := 1; i < n; i++ {
			metadata.Keyslots[fmt.Sprint(i)] = sampleKeyslot(i)
			// Named by the digest, as every luks2 keyslot must be (#248).
			metadata.Digests["0"].Keyslots = append(metadata.Digests["0"].Keyslots, fmt.Sprint(i))
		}
		if _, _, err := encodeMetadataForHeader(hdr, metadata); err != nil {
			break
		}
		accepted = n
	}

	if accepted < MaxKeyslots {
		t.Fatalf("only %d of the %d keyslots LUKS2 permits fit the metadata area", accepted, MaxKeyslots)
	}
}

// TestHeaderJSONAreaIsNULTerminatedAndZeroPadded asserts the bytes that follow
// the JSON on disk, which is where a stray encoder newline would surface.
func TestHeaderJSONAreaIsNULTerminatedAndZeroPadded(t *testing.T) {
	pinCryptoRand(t, 0x21)
	pinUUID(t, "6c9e1a04-3d52-4b8f-8e21-77a0c5b31d9e")

	path := filepath.Join(t.TempDir(), "header.img")
	if err := os.WriteFile(path, make([]byte, LUKS2HeaderMinSize*2), 0600); err != nil {
		t.Fatalf("failed to create the image: %v", err)
	}

	hdr, err := CreateBinaryHeader(FormatOptions{})
	if err != nil {
		t.Fatalf("CreateBinaryHeader failed: %v", err)
	}
	if err := writeHeaderInternal(path, hdr, sampleMetadata()); err != nil {
		t.Fatalf("writeHeaderInternal failed: %v", err)
	}

	image, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to read the image back: %v", err)
	}

	area := image[LUKS2HeaderSize:LUKS2HeaderMinSize]
	end := bytes.IndexByte(area, 0)
	if end < 0 {
		t.Fatal("the JSON area has no NUL terminator")
	}
	if area[0] != '{' {
		t.Fatalf("the JSON area starts with %q, want '{'", area[0])
	}
	if area[end-1] != '}' {
		t.Fatalf("the byte before the NUL terminator is %q, want '}' -- the encoder left something between the JSON and the terminator", area[end-1])
	}
	for i, b := range area[end:] {
		if b != 0 {
			t.Fatalf("the padding at JSON-area offset %d is %q, want zero", end+i, b)
		}
	}
}

// TestHeaderIsReproducibleUnderPinnedInputs is the property the seams exist to
// make testable, and the precondition for any byte-for-byte comparison against
// cryptsetup: with the RNG and the UUID pinned, formatting the same parameters
// twice must produce the same header.
func TestHeaderIsReproducibleUnderPinnedInputs(t *testing.T) {
	write := func(seed byte) []byte {
		pinCryptoRand(t, seed)
		pinUUID(t, "6c9e1a04-3d52-4b8f-8e21-77a0c5b31d9e")

		path := filepath.Join(t.TempDir(), "header.img")
		if err := os.WriteFile(path, make([]byte, LUKS2HeaderMinSize*2), 0600); err != nil {
			t.Fatalf("failed to create the image: %v", err)
		}
		hdr, err := CreateBinaryHeader(FormatOptions{})
		if err != nil {
			t.Fatalf("CreateBinaryHeader failed: %v", err)
		}
		if err := writeHeaderInternal(path, hdr, sampleMetadata()); err != nil {
			t.Fatalf("writeHeaderInternal failed: %v", err)
		}
		image, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir()
		if err != nil {
			t.Fatalf("failed to read the image back: %v", err)
		}
		return image
	}

	if !bytes.Equal(write(0x33), write(0x33)) {
		t.Fatal("two headers written from identical pinned inputs differ; the RNG and UUID seams do not cover every unpredictable byte of the header")
	}
	if bytes.Equal(write(0x33), write(0x44)) {
		t.Fatal("changing the RNG seed did not change the header; the pinned reader is not reaching the salt")
	}
}

// TestMarshalCanonicalJSONReportsAnUnencodableValue covers the error path: the
// helper must surface a marshal failure rather than returning half an object.
// sampleMetadata is the metadata shape Format writes for the default geometry,
// with every value fixed. The numbers are the ones a 64 MiB container carries:
// keyslot 0 at 0x8000 for 258048 bytes, data at 16777216, keyslots area
// 16744448.
func sampleMetadata() *LUKS2Metadata {
	return &LUKS2Metadata{
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
			Encryption: KeyslotAreaEncryption,
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
