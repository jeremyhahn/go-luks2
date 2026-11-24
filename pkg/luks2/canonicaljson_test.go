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

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// On-disk JSON encoding tests: compact, unescaped JSON terminated by a single NUL.

// TestEncodeMetadataForHeaderEmitsCompactJSON checks the header write path emits compact JSON.
func TestEncodeMetadataForHeaderEmitsCompactJSON(t *testing.T) {
	hdr, err := createBinaryHeader(formatOptionsForTest{}, testVolumeSys())
	if err != nil {
		t.Fatalf("CreateBinaryHeader failed: %v", err)
	}

	jsonData, area, err := encodeMetadataForHeader(hdr, sampleMetadata())
	if err != nil {
		t.Fatalf("encodeMetadataForHeader failed: %v", err)
	}
	if area != header.HeaderMinSize {
		t.Fatalf("area = %d, want %d", area, header.HeaderMinSize)
	}
	if bytes.Contains(jsonData, []byte("\n")) {
		t.Fatalf("the write path is still emitting indented JSON\n%s", jsonData)
	}
	if !json.Valid(jsonData) {
		t.Fatalf("the write path emitted invalid JSON\n%s", jsonData)
	}
}

// TestCompactJSONRaisesTheKeyslotCeiling: all 32 keyslots fit the 12288-byte area.
func TestCompactJSONRaisesTheKeyslotCeiling(t *testing.T) {
	hdr, err := createBinaryHeader(formatOptionsForTest{}, testVolumeSys())
	if err != nil {
		t.Fatalf("CreateBinaryHeader failed: %v", err)
	}

	accepted := 0
	for n := 1; n <= MaxKeyslots; n++ {
		metadata := sampleMetadata()
		for i := 1; i < n; i++ {
			metadata.Keyslots[fmt.Sprint(i)] = sampleKeyslot(i)
			// Named by the digest, as every luks2 keyslot must be.
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
	sys := testVolumeSys()
	sys.cryptoRand = pinCryptoRand(0x21)
	sys.newUUID = pinUUID(t, "6c9e1a04-3d52-4b8f-8e21-77a0c5b31d9e")

	path := filepath.Join(t.TempDir(), "header.img")
	if err := os.WriteFile(path, make([]byte, header.HeaderMinSize*2), 0600); err != nil {
		t.Fatalf("failed to create the image: %v", err)
	}

	hdr, err := createBinaryHeader(formatOptionsForTest{}, sys)
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

	area := image[header.HeaderSize:header.HeaderMinSize]
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
		sys := testVolumeSys()
		sys.cryptoRand = pinCryptoRand(seed)
		sys.newUUID = pinUUID(t, "6c9e1a04-3d52-4b8f-8e21-77a0c5b31d9e")

		path := filepath.Join(t.TempDir(), "header.img")
		if err := os.WriteFile(path, make([]byte, header.HeaderMinSize*2), 0600); err != nil {
			t.Fatalf("failed to create the image: %v", err)
		}
		hdr, err := createBinaryHeader(formatOptionsForTest{}, sys)
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

// sampleMetadata is Format's metadata for a 64 MiB container with every value fixed.
func sampleMetadata() *header.Metadata {
	return &header.Metadata{
		Keyslots: map[string]*header.Keyslot{"0": sampleKeyslot(0)},
		Tokens:   map[string]*LegacyToken{},
		Segments: map[string]*header.Segment{
			"0": {
				Type:       "crypt",
				Offset:     "16777216",
				Size:       "dynamic",
				IVTweak:    "0",
				Encryption: "aes-xts-plain64",
				SectorSize: 512,
			},
		},
		Digests: map[string]*header.Digest{
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
		Config: &header.Config{
			JSONSize:     "12288",
			KeyslotsSize: "16744448",
		},
	}
}

// sampleKeyslot returns keyslot i with the geometry Format lays out for it.
func sampleKeyslot(i int) *header.Keyslot {
	iterations := 210000
	return &header.Keyslot{
		Type:    "luks2",
		KeySize: 64,
		Area: &header.KeyslotArea{
			Type:       "raw",
			KeySize:    64,
			Offset:     fmt.Sprint(0x8000 + i*258048),
			Size:       "258048",
			Encryption: keyslotAreaEncryption,
		},
		KDF: &header.KDF{
			Type:       "pbkdf2",
			Hash:       "sha512",
			Salt:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			Iterations: &iterations,
		},
		AF: &header.AntiForensic{
			Type:    "luks1",
			Stripes: 4000,
			Hash:    "sha512",
		},
	}
}
