// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"github.com/google/uuid"
)

// TestHeaderStructSize tests the binary header struct size (pure unit test)
func TestHeaderStructSize(t *testing.T) {
	var hdr LUKS2BinaryHeader
	size := unsafe.Sizeof(hdr)
	t.Logf("LUKS2BinaryHeader size: %d bytes (expected: %d)", size, LUKS2HeaderSize)

	if size != LUKS2HeaderSize {
		t.Errorf("Header size mismatch: got %d, want %d", size, LUKS2HeaderSize)
	}
}

// TestCreateBinaryHeader tests the creation of LUKS2 binary headers
func TestCreateBinaryHeader(t *testing.T) {
	tests := []struct {
		name    string
		opts    FormatOptions
		wantErr bool
	}{
		{
			name: "minimal options",
			opts: FormatOptions{
				Device: "/dev/test",
			},
			wantErr: false,
		},
		{
			name: "with label",
			opts: FormatOptions{
				Device: "/dev/test",
				Label:  "test-volume",
			},
			wantErr: false,
		},
		{
			name: "with subsystem",
			opts: FormatOptions{
				Device:    "/dev/test",
				Subsystem: "test-subsystem",
			},
			wantErr: false,
		},
		{
			name: "with label and subsystem",
			opts: FormatOptions{
				Device:    "/dev/test",
				Label:     "test-volume",
				Subsystem: "test-subsystem",
			},
			wantErr: false,
		},
		{
			name: "with long label",
			opts: FormatOptions{
				Device: "/dev/test",
				Label:  "this-is-a-very-long-label-that-exceeds-normal-length",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr, err := CreateBinaryHeader(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CreateBinaryHeader() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			// Validate magic
			if !bytes.Equal(hdr.Magic[:], []byte(LUKS2Magic)) {
				t.Errorf("Invalid magic: got %v, want %v", hdr.Magic[:], []byte(LUKS2Magic))
			}

			// Validate version
			if hdr.Version != LUKS2Version {
				t.Errorf("Invalid version: got %d, want %d", hdr.Version, LUKS2Version)
			}

			// Validate checksum algorithm
			checksumAlgo := string(bytes.TrimRight(hdr.ChecksumAlgorithm[:], "\x00"))
			if checksumAlgo != "sha256" {
				t.Errorf("Invalid checksum algorithm: got %s, want sha256", checksumAlgo)
			}

			// Validate UUID is set
			uuidStr := string(bytes.TrimRight(hdr.UUID[:], "\x00"))
			if uuidStr == "" {
				t.Error("UUID not set")
			}
			if _, err := uuid.Parse(uuidStr); err != nil {
				t.Errorf("Invalid UUID: %v", err)
			}

			// Validate salt is set (not all zeros)
			allZero := true
			for _, b := range hdr.Salt {
				if b != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				t.Error("Salt not generated (all zeros)")
			}

			// Validate sequence ID
			if hdr.SequenceID != 1 {
				t.Errorf("Invalid sequence ID: got %d, want 1", hdr.SequenceID)
			}

			// Validate label if provided
			if tt.opts.Label != "" {
				label := string(bytes.TrimRight(hdr.Label[:], "\x00"))
				// Label should be truncated to fit in 48 bytes
				expectedLabel := tt.opts.Label
				if len(expectedLabel) > 48 {
					expectedLabel = expectedLabel[:48]
				}
				if label != expectedLabel {
					t.Errorf("Invalid label: got %s, want %s", label, expectedLabel)
				}
			}

			// Validate subsystem if provided
			if tt.opts.Subsystem != "" {
				subsystem := string(bytes.TrimRight(hdr.SubsystemLabel[:], "\x00"))
				expectedSubsystem := tt.opts.Subsystem
				if len(expectedSubsystem) > 48 {
					expectedSubsystem = expectedSubsystem[:48]
				}
				if subsystem != expectedSubsystem {
					t.Errorf("Invalid subsystem: got %s, want %s", subsystem, expectedSubsystem)
				}
			}
		})
	}
}

// TestCalculateHeaderChecksum tests checksum calculation
func TestCalculateHeaderChecksum(t *testing.T) {
	tests := []struct {
		name     string
		hdr      *LUKS2BinaryHeader
		jsonData []byte
		jsonSize int
	}{
		{
			name: "minimal header",
			hdr: &LUKS2BinaryHeader{
				Version:    LUKS2Version,
				SequenceID: 1,
				HeaderSize: uint64(LUKS2HeaderSize + LUKS2DefaultSize),
			},
			jsonData: []byte(`{"keyslots":{},"segments":{},"digests":{},"config":{"json_size":"12288"}}`),
			jsonSize: LUKS2DefaultSize,
		},
		{
			name: "with metadata",
			hdr: &LUKS2BinaryHeader{
				Version:    LUKS2Version,
				SequenceID: 1,
				HeaderSize: uint64(LUKS2HeaderSize + 16384),
			},
			jsonData: []byte(`{"keyslots":{"0":{"type":"luks2"}},"segments":{},"digests":{},"config":{"json_size":"16384"}}`),
			jsonSize: 16384,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set magic and checksum algorithm
			copy(tt.hdr.Magic[:], LUKS2Magic)
			copy(tt.hdr.ChecksumAlgorithm[:], "sha256")

			// Calculate checksum
			err := calculateHeaderChecksum(tt.hdr, tt.jsonData, tt.jsonSize)
			if err != nil {
				t.Fatalf("calculateHeaderChecksum() error = %v", err)
			}

			// Verify checksum is not all zeros
			allZero := true
			for _, b := range tt.hdr.Checksum {
				if b != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				t.Error("Checksum not calculated (all zeros)")
			}

			// Manually verify the checksum
			buf := new(bytes.Buffer)
			tmpHdr := *tt.hdr
			tmpHdr.Checksum = [64]byte{} // Zero out checksum

			if err := binary.Write(buf, binary.BigEndian, &tmpHdr); err != nil {
				t.Fatalf("Failed to write header: %v", err)
			}

			buf.Write(tt.jsonData)
			padding := make([]byte, tt.jsonSize-len(tt.jsonData))
			buf.Write(padding)

			h := sha256.New()
			h.Write(buf.Bytes())
			expected := h.Sum(nil)

			if !bytes.Equal(expected, tt.hdr.Checksum[:len(expected)]) {
				t.Errorf("Checksum mismatch:\ngot:  %x\nwant: %x", tt.hdr.Checksum[:32], expected[:32])
			}
		})
	}
}

// TestCalculateHeaderChecksumDeterministic tests that checksum calculation is deterministic
func TestCalculateHeaderChecksumDeterministic(t *testing.T) {
	hdr := &LUKS2BinaryHeader{
		Version:    LUKS2Version,
		SequenceID: 1,
		HeaderSize: uint64(LUKS2HeaderSize + LUKS2DefaultSize),
	}
	copy(hdr.Magic[:], LUKS2Magic)
	copy(hdr.ChecksumAlgorithm[:], "sha256")

	jsonData := []byte(`{"keyslots":{},"segments":{},"digests":{},"config":{"json_size":"12288"}}`)
	jsonSize := LUKS2DefaultSize

	// Calculate checksum first time
	err := calculateHeaderChecksum(hdr, jsonData, jsonSize)
	if err != nil {
		t.Fatalf("calculateHeaderChecksum() error = %v", err)
	}
	firstChecksum := make([]byte, 64)
	copy(firstChecksum, hdr.Checksum[:])

	// Calculate checksum second time
	err = calculateHeaderChecksum(hdr, jsonData, jsonSize)
	if err != nil {
		t.Fatalf("calculateHeaderChecksum() error = %v", err)
	}

	// Verify they match
	if !bytes.Equal(firstChecksum, hdr.Checksum[:]) {
		t.Error("Checksum calculation is not deterministic")
	}
}

// mockReaderAt implements io.ReaderAt for testing
type mockReaderAt struct {
	data []byte
}

func (m *mockReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n = copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// TestValidateHeaderChecksum tests checksum validation with valid checksums
func TestValidateHeaderChecksum(t *testing.T) {
	tests := []struct {
		name        string
		setupHeader func() (*LUKS2BinaryHeader, []byte)
	}{
		{
			name: "valid checksum",
			setupHeader: func() (*LUKS2BinaryHeader, []byte) {
				hdr := &LUKS2BinaryHeader{
					Version:      LUKS2Version,
					SequenceID:   1,
					HeaderSize:   uint64(LUKS2HeaderSize + LUKS2DefaultSize),
					HeaderOffset: 0,
				}
				copy(hdr.Magic[:], LUKS2Magic)
				copy(hdr.ChecksumAlgorithm[:], "sha256")

				jsonData := []byte(`{"keyslots":{},"segments":{},"digests":{},"config":{"json_size":"12288"}}`)
				jsonSize := LUKS2DefaultSize

				// Calculate correct checksum
				if err := calculateHeaderChecksum(hdr, jsonData, jsonSize); err != nil {
					t.Fatalf("Failed to calculate checksum: %v", err)
				}

				// Create full header data
				buf := new(bytes.Buffer)
				if err := binary.Write(buf, binary.BigEndian, hdr); err != nil {
					t.Fatalf("Failed to write header: %v", err)
				}
				buf.Write(jsonData)
				padding := make([]byte, jsonSize-len(jsonData))
				buf.Write(padding)

				return hdr, buf.Bytes()
			},
		},
		{
			name: "valid checksum with backup offset",
			setupHeader: func() (*LUKS2BinaryHeader, []byte) {
				hdr := &LUKS2BinaryHeader{
					Version:      LUKS2Version,
					SequenceID:   1,
					HeaderSize:   uint64(LUKS2HeaderSize + LUKS2DefaultSize),
					HeaderOffset: 0x4000,
				}
				copy(hdr.Magic[:], LUKS2Magic)
				copy(hdr.ChecksumAlgorithm[:], "sha256")

				jsonData := []byte(`{"keyslots":{},"segments":{},"digests":{},"config":{"json_size":"12288"}}`)
				jsonSize := LUKS2DefaultSize

				// Calculate correct checksum
				if err := calculateHeaderChecksum(hdr, jsonData, jsonSize); err != nil {
					t.Fatalf("Failed to calculate checksum: %v", err)
				}

				// Create full header data with padding before header
				buf := new(bytes.Buffer)
				buf.Write(make([]byte, 0x4000)) // Padding before backup header
				if err := binary.Write(buf, binary.BigEndian, hdr); err != nil {
					t.Fatalf("Failed to write header: %v", err)
				}
				buf.Write(jsonData)
				padding := make([]byte, jsonSize-len(jsonData))
				buf.Write(padding)

				return hdr, buf.Bytes()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr, data := tt.setupHeader()
			reader := &mockReaderAt{data: data}

			err := validateHeaderChecksum(hdr, reader, int64(hdr.HeaderOffset), int(hdr.HeaderSize)) // #nosec G115 -- test fixture offsets are 0 or 0x4000 and sizes are 16384
			if err != nil {
				t.Errorf("validateHeaderChecksum() error = %v, want nil", err)
			}
		})
	}
}

// TestValidateHeaderChecksumInvalid tests checksum validation with invalid checksums
func TestValidateHeaderChecksumInvalid(t *testing.T) {
	tests := []struct {
		name        string
		setupHeader func() (*LUKS2BinaryHeader, []byte)
		wantErr     bool
	}{
		{
			name: "corrupted checksum",
			setupHeader: func() (*LUKS2BinaryHeader, []byte) {
				hdr := &LUKS2BinaryHeader{
					Version:      LUKS2Version,
					SequenceID:   1,
					HeaderSize:   uint64(LUKS2HeaderSize + LUKS2DefaultSize),
					HeaderOffset: 0,
				}
				copy(hdr.Magic[:], LUKS2Magic)
				copy(hdr.ChecksumAlgorithm[:], "sha256")

				jsonData := []byte(`{"keyslots":{},"segments":{},"digests":{},"config":{"json_size":"12288"}}`)
				jsonSize := LUKS2DefaultSize

				// Calculate correct checksum
				if err := calculateHeaderChecksum(hdr, jsonData, jsonSize); err != nil {
					t.Fatalf("Failed to calculate checksum: %v", err)
				}

				// Corrupt the checksum
				hdr.Checksum[0] ^= 0xFF

				// Create full header data
				buf := new(bytes.Buffer)
				if err := binary.Write(buf, binary.BigEndian, hdr); err != nil {
					t.Fatalf("Failed to write header: %v", err)
				}
				buf.Write(jsonData)
				padding := make([]byte, jsonSize-len(jsonData))
				buf.Write(padding)

				return hdr, buf.Bytes()
			},
			wantErr: true,
		},
		{
			name: "corrupted data",
			setupHeader: func() (*LUKS2BinaryHeader, []byte) {
				hdr := &LUKS2BinaryHeader{
					Version:      LUKS2Version,
					SequenceID:   1,
					HeaderSize:   uint64(LUKS2HeaderSize + LUKS2DefaultSize),
					HeaderOffset: 0,
				}
				copy(hdr.Magic[:], LUKS2Magic)
				copy(hdr.ChecksumAlgorithm[:], "sha256")

				jsonData := []byte(`{"keyslots":{},"segments":{},"digests":{},"config":{"json_size":"12288"}}`)
				jsonSize := LUKS2DefaultSize

				// Calculate correct checksum
				if err := calculateHeaderChecksum(hdr, jsonData, jsonSize); err != nil {
					t.Fatalf("Failed to calculate checksum: %v", err)
				}

				// Create full header data
				buf := new(bytes.Buffer)
				if err := binary.Write(buf, binary.BigEndian, hdr); err != nil {
					t.Fatalf("Failed to write header: %v", err)
				}
				buf.Write(jsonData)
				padding := make([]byte, jsonSize-len(jsonData))
				buf.Write(padding)

				// Corrupt data after the header
				data := buf.Bytes()
				data[LUKS2HeaderSize] ^= 0xFF

				return hdr, data
			},
			wantErr: true,
		},
		{
			name: "truncated data",
			setupHeader: func() (*LUKS2BinaryHeader, []byte) {
				hdr := &LUKS2BinaryHeader{
					Version:      LUKS2Version,
					SequenceID:   1,
					HeaderSize:   uint64(LUKS2HeaderSize + LUKS2DefaultSize),
					HeaderOffset: 0,
				}
				copy(hdr.Magic[:], LUKS2Magic)
				copy(hdr.ChecksumAlgorithm[:], "sha256")

				// Create truncated data (not enough for full header)
				data := make([]byte, LUKS2HeaderSize/2)
				return hdr, data
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr, data := tt.setupHeader()
			reader := &mockReaderAt{data: data}

			err := validateHeaderChecksum(hdr, reader, int64(hdr.HeaderOffset), int(hdr.HeaderSize)) // #nosec G115 -- test fixture offsets are 0 or 0x4000 and sizes are 16384
			if (err != nil) != tt.wantErr {
				t.Errorf("validateHeaderChecksum() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestReadJSONMetadata tests JSON metadata parsing
func TestReadJSONMetadata(t *testing.T) {
	tests := []struct {
		name     string
		hdr      *LUKS2BinaryHeader
		jsonData []byte
		wantErr  bool
	}{
		{
			name: "minimal metadata",
			hdr: &LUKS2BinaryHeader{
				HeaderSize:   uint64(LUKS2HeaderSize + LUKS2DefaultSize),
				HeaderOffset: 0,
			},
			jsonData: []byte(`{"keyslots":{},"segments":{},"digests":{},"config":{"json_size":"12288"}}`),
			wantErr:  false,
		},
		{
			// A COMPLETE luks2 keyslot. The fixture used to carry only type
			// and key_size, which is not a keyslot any LUKS2 implementation
			// writes: it has nowhere to live on the device and no KDF to
			// unwrap it. Completing it makes the case test what it is named
			// for against a realistic keyslot; the incomplete form is kept
			// below, because parsing it is the documented behavior.
			name: "with keyslots",
			hdr: &LUKS2BinaryHeader{
				HeaderSize:   uint64(LUKS2HeaderSize + LUKS2DefaultSize),
				HeaderOffset: 0,
			},
			jsonData: []byte(`{"keyslots":{"0":{"type":"luks2","key_size":64,` +
				`"kdf":{"type":"pbkdf2","hash":"sha256","salt":"dGVzdHNhbHQ=","iterations":1000},` +
				`"af":{"type":"luks1","stripes":4000,"hash":"sha256"},` +
				`"area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64}}},` +
				`"segments":{},"digests":{},"config":{"json_size":"12288"}}`),
			wantErr: false,
		},
		{
			// An incomplete keyslot still PARSES. It is refused where it is
			// used, not here: refusing the header would make a container with
			// one damaged keyslot unreadable through its intact ones. See
			// keyslotvalidation.go.
			name: "keyslot missing its kdf, af and area still parses",
			hdr: &LUKS2BinaryHeader{
				HeaderSize:   uint64(LUKS2HeaderSize + LUKS2DefaultSize),
				HeaderOffset: 0,
			},
			jsonData: []byte(`{"keyslots":{"0":{"type":"luks2","key_size":64}},"segments":{},"digests":{},"config":{"json_size":"12288"}}`),
			wantErr:  false,
		},
		{
			name: "with null terminator",
			hdr: &LUKS2BinaryHeader{
				HeaderSize:   uint64(LUKS2HeaderSize + LUKS2DefaultSize),
				HeaderOffset: 0,
			},
			jsonData: append([]byte(`{"keyslots":{},"segments":{},"digests":{},"config":{"json_size":"12288"}}`), 0, 0, 0),
			wantErr:  false,
		},
		{
			name: "invalid JSON",
			hdr: &LUKS2BinaryHeader{
				HeaderSize:   uint64(LUKS2HeaderSize + LUKS2DefaultSize),
				HeaderOffset: 0,
			},
			jsonData: []byte(`{invalid json`),
			wantErr:  true,
		},
		{
			name: "empty JSON",
			hdr: &LUKS2BinaryHeader{
				HeaderSize:   uint64(LUKS2HeaderSize + LUKS2DefaultSize),
				HeaderOffset: 0,
			},
			jsonData: []byte(``),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create data buffer with header + JSON
			buf := new(bytes.Buffer)

			// Add offset padding if needed
			if tt.hdr.HeaderOffset > 0 {
				buf.Write(make([]byte, tt.hdr.HeaderOffset))
			}

			// Write a dummy header (size matters for offset calculation)
			var dummyHdr LUKS2BinaryHeader
			if err := binary.Write(buf, binary.BigEndian, &dummyHdr); err != nil {
				t.Fatalf("Failed to write dummy header: %v", err)
			}

			// Write JSON data with padding
			jsonSize := int(tt.hdr.HeaderSize) - LUKS2HeaderSize
			buf.Write(tt.jsonData)
			if len(tt.jsonData) < jsonSize {
				padding := make([]byte, jsonSize-len(tt.jsonData))
				buf.Write(padding)
			}

			reader := &mockReaderAt{data: buf.Bytes()}
			metadata, err := readJSONMetadata(reader, tt.hdr, int64(tt.hdr.HeaderOffset), int(tt.hdr.HeaderSize)) // #nosec G115 -- test fixture offsets are 0 or 0x4000 and sizes are 16384

			if (err != nil) != tt.wantErr {
				t.Errorf("readJSONMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if metadata == nil {
					t.Error("readJSONMetadata() returned nil metadata")
					return
				}

				// Verify basic structure
				if metadata.Keyslots == nil {
					t.Error("Keyslots map is nil")
				}
				if metadata.Segments == nil {
					t.Error("Segments map is nil")
				}
				if metadata.Digests == nil {
					t.Error("Digests map is nil")
				}
				if metadata.Config == nil {
					t.Error("Config is nil")
				}
			}
		})
	}
}

// TestReadJSONMetadataRoundTrip tests that metadata can be marshaled and unmarshaled
func TestReadJSONMetadataRoundTrip(t *testing.T) {
	original := &LUKS2Metadata{
		Keyslots: map[string]*Keyslot{
			"0": {
				Type:    "luks2",
				KeySize: 64,
				Area: &KeyslotArea{
					Type:       "raw",
					Offset:     "32768",
					Size:       "258048",
					Encryption: "aes-xts-plain64",
					KeySize:    64,
				},
				KDF: &KDF{
					Type: "pbkdf2",
					Hash: "sha256",
					Salt: "dGVzdHNhbHQ=",
				},
				// The af object is mandatory on a luks2 keyslot: it is what
				// says how the volume key is spread across the area above. The
				// fixture omitted it and only parsed because nothing checked.
				AF: &AntiForensic{
					Type:    "luks1",
					Stripes: AFStripes,
					Hash:    "sha256",
				},
			},
		},
		Segments: map[string]*Segment{
			"0": {
				Type:       "crypt",
				Offset:     "8388608",
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
				Hash:       "sha256",
				Iterations: 1000,
				Salt:       "ZGlnZXN0c2FsdA==",
				Digest:     "ZGlnZXN0dmFsdWU=",
			},
		},
		Config: &Config{
			JSONSize:     "12288",
			KeyslotsSize: "8355840",
		},
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal metadata: %v", err)
	}

	// Create header
	hdr := &LUKS2BinaryHeader{
		HeaderSize:   uint64(LUKS2HeaderSize + LUKS2DefaultSize),
		HeaderOffset: 0,
	}

	// Create buffer
	buf := new(bytes.Buffer)
	var dummyHdr LUKS2BinaryHeader
	if err := binary.Write(buf, binary.BigEndian, &dummyHdr); err != nil {
		t.Fatalf("Failed to write dummy header: %v", err)
	}

	jsonSize := int(hdr.HeaderSize) - LUKS2HeaderSize
	buf.Write(jsonData)
	padding := make([]byte, jsonSize-len(jsonData))
	buf.Write(padding)

	// Read back
	reader := &mockReaderAt{data: buf.Bytes()}
	recovered, err := readJSONMetadata(reader, hdr, int64(hdr.HeaderOffset), int(hdr.HeaderSize)) // #nosec G115 -- test fixture offset is 0 and size is 16384
	if err != nil {
		t.Fatalf("readJSONMetadata() error = %v", err)
	}

	// Verify key structures are present
	if len(recovered.Keyslots) != len(original.Keyslots) {
		t.Errorf("Keyslot count mismatch: got %d, want %d", len(recovered.Keyslots), len(original.Keyslots))
	}
	if len(recovered.Segments) != len(original.Segments) {
		t.Errorf("Segment count mismatch: got %d, want %d", len(recovered.Segments), len(original.Segments))
	}
	if len(recovered.Digests) != len(original.Digests) {
		t.Errorf("Digest count mismatch: got %d, want %d", len(recovered.Digests), len(original.Digests))
	}

	// Verify keyslot details
	if ks, ok := recovered.Keyslots["0"]; ok {
		if ks.Type != "luks2" {
			t.Errorf("Keyslot type mismatch: got %s, want luks2", ks.Type)
		}
		if ks.KeySize != 64 {
			t.Errorf("Keyslot key size mismatch: got %d, want 64", ks.KeySize)
		}
	} else {
		t.Error("Keyslot 0 not found")
	}
}

// TestCalculateHeaderChecksumEdgeCases tests edge cases in checksum calculation
func TestCalculateHeaderChecksumEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		hdr      *LUKS2BinaryHeader
		jsonData []byte
		jsonSize int
		wantErr  bool
	}{
		{
			name: "empty JSON",
			hdr: &LUKS2BinaryHeader{
				Version:    LUKS2Version,
				HeaderSize: uint64(LUKS2HeaderSize + LUKS2DefaultSize),
			},
			jsonData: []byte{},
			jsonSize: LUKS2DefaultSize,
			wantErr:  false,
		},
		{
			name: "large JSON",
			hdr: &LUKS2BinaryHeader{
				Version:    LUKS2Version,
				HeaderSize: uint64(LUKS2HeaderSize + 32768),
			},
			jsonData: make([]byte, 20000),
			jsonSize: 32768,
			wantErr:  false,
		},
		{
			name: "exact fit JSON",
			hdr: &LUKS2BinaryHeader{
				Version:    LUKS2Version,
				HeaderSize: uint64(LUKS2HeaderSize + 16384),
			},
			jsonData: make([]byte, 16384),
			jsonSize: 16384,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copy(tt.hdr.Magic[:], LUKS2Magic)
			copy(tt.hdr.ChecksumAlgorithm[:], "sha256")

			err := calculateHeaderChecksum(tt.hdr, tt.jsonData, tt.jsonSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("calculateHeaderChecksum() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateHeaderChecksumRefusesABufferTooShortForTheChecksumField is the
// regression test for #62's actual deliverable: this function's own length
// check is now REACHABLE and load-bearing.
//
// Before the size bound was hoisted into readHeaderCopy, this function derived
// the size itself five lines above the checksum-field write, so a guard on the
// buffer length could not fire -- instrumented with panic("GUARD REACHED") it
// was reached zero times across the whole suite, and a test that believed it was
// exercising the guard was in fact being satisfied by headerAreaSize's rejection
// wrapping the same sentinel.
//
// With the size arriving as a parameter, a short one reaches this function, and
// the assertion is that it comes back as an ERROR rather than as a panic: the
// checksum-field indices are fixed by the on-disk layout, so without the guard
// the slice expression runs off the end of the buffer and the process dies.
//
// The error is attributed to errChecksumBufferTooShort SPECIFICALLY, not to
// ErrInvalidHeader, because that is the whole lesson of #62 -- errors.Is on a
// shared sentinel answers "was it this class", never "was it this check".
func TestValidateHeaderChecksumRefusesABufferTooShortForTheChecksumField(t *testing.T) {
	// A reader long enough to satisfy any ReadAt this test makes, so nothing
	// but the length guard can decide the outcome.
	reader := &mockReaderAt{data: make([]byte, LUKS2HeaderSize*2)}
	hdr := &LUKS2BinaryHeader{Version: LUKS2Version}
	need := checksumFieldOffset + len(hdr.Checksum)

	for _, tc := range []struct {
		name string
		size int
	}{
		{"negative, which make() would panic on", -1},
		{"zero", 0},
		{"one", 1},
		{"far below the checksum field", 100},
		{"one below the checksum field's end", need - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("validateHeaderChecksum panicked on headerSize=%d instead of returning an error: %v", tc.size, r)
				}
			}()

			err := validateHeaderChecksum(hdr, reader, 0, tc.size)
			if err == nil {
				t.Fatalf("validateHeaderChecksum accepted headerSize=%d", tc.size)
			}
			if !errors.Is(err, errChecksumBufferTooShort) {
				t.Errorf("error = %v, want it to be errChecksumBufferTooShort; a different guard decided this", err)
			}
			if !errors.Is(err, ErrInvalidHeader) {
				t.Errorf("error = %v, want it to still classify as ErrInvalidHeader for callers", err)
			}
			if !strings.Contains(err.Error(), fmt.Sprint(tc.size)) {
				t.Errorf("error = %q, want it to name the rejected size %d", err.Error(), tc.size)
			}
		})
	}

	// The boundary in the other direction, so the comparison cannot be
	// off by one: a buffer exactly large enough for the checksum field gets
	// PAST this guard. It then fails on the checksum itself, which is a
	// different error, and that difference is the assertion.
	t.Run("exactly large enough is not refused by this guard", func(t *testing.T) {
		err := validateHeaderChecksum(hdr, reader, 0, need)
		if errors.Is(err, errChecksumBufferTooShort) {
			t.Fatalf("headerSize=%d was refused as too short, but it is exactly the %d bytes the checksum field needs", need, need)
		}
	})
}

// TestReadJSONMetadataRefusesAHeaderSizeWithNoRoomForJSON is the same property
// for the other function the bound was hoisted out of.
//
// jsonSize is headerSize - LUKS2HeaderSize. A size at or below LUKS2HeaderSize
// makes that zero or negative, and make() panics on a negative length, so this
// check is what turns a caller's mistake into an error the caller can see.
func TestReadJSONMetadataRefusesAHeaderSizeWithNoRoomForJSON(t *testing.T) {
	reader := &mockReaderAt{data: make([]byte, LUKS2HeaderSize*2)}
	hdr := &LUKS2BinaryHeader{Version: LUKS2Version}

	for _, size := range []int{-1, 0, 1, LUKS2HeaderSize - 1, LUKS2HeaderSize} {
		t.Run(fmt.Sprintf("size %d", size), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("readJSONMetadata panicked on headerSize=%d instead of returning an error: %v", size, r)
				}
			}()

			_, err := readJSONMetadata(reader, hdr, 0, size)
			if err == nil {
				t.Fatalf("readJSONMetadata accepted headerSize=%d", size)
			}
			if !errors.Is(err, ErrInvalidHeader) {
				t.Errorf("error = %v, want it to wrap ErrInvalidHeader", err)
			}
		})
	}

	// One byte more than the binary header leaves one byte of JSON area, which
	// is not enough to parse but IS enough to get past this guard. The failure
	// must move to the JSON parse.
	t.Run("one byte of JSON area is not refused by this guard", func(t *testing.T) {
		_, err := readJSONMetadata(reader, hdr, 0, LUKS2HeaderSize+1)
		if err == nil {
			t.Fatal("readJSONMetadata accepted a one-byte JSON area")
		}
		if !strings.Contains(err.Error(), "parse JSON") {
			t.Fatalf("error = %v, want the failure to have moved to the JSON parse", err)
		}
	})
}

// TestReadHeaderBoundsTheDeclaredSizeBeforeAnythingElseUsesIt pins WHERE the
// bound now lives, which is the part of #62 a size-rejection test cannot see.
//
// A header carrying BOTH an out-of-range HeaderSize and an illegal HeaderOffset
// has two things wrong with it, and which one is reported says which check ran
// first. Before the hoist the offset check ran first and the size was not
// examined until validateHeaderChecksum re-derived it; after the hoist the size
// is bounded immediately after the magic and version, before anything else
// consults the header at all.
//
// The assertion is on the size, so moving the bound back down turns this test
// red rather than leaving it satisfied by the other guard.
func TestReadHeaderBoundsTheDeclaredSizeBeforeAnythingElseUsesIt(t *testing.T) {
	t.Parallel()

	const craftedSize = uint64(1) << 62
	const craftedOffset = uint64(0x1234) // not 0, not 16 KiB-aligned

	device, _ := headerSizeVolume(t)
	setHeaderSize(t, device, craftedSize)
	setHeaderOffset(t, device, craftedOffset)

	_, _, err := ReadHeader(device)
	if err == nil {
		t.Fatal("ReadHeader accepted a header with both an out-of-range size and an illegal offset")
	}
	if !strings.Contains(err.Error(), fmt.Sprint(craftedSize)) {
		t.Fatalf("error = %q, want the SIZE (%d) to be what was reported: the bound must run before the offset check",
			err.Error(), craftedSize)
	}
	if strings.Contains(err.Error(), fmt.Sprint(craftedOffset)) {
		t.Fatalf("error = %q, want the size bound to have refused this header before the offset was consulted", err.Error())
	}
}

// nullEntryVolume writes a container carrying null keyslot AND null token
// entries alongside healthy ones, through the exported write path.
//
// Both kinds in one fixture on purpose: the report has to say WHICH id space
// each lost entry came from, and a fixture with only one kind cannot tell a
// correct report from one that labels everything "keyslot".
func nullEntryVolume(t *testing.T, name string) string {
	t.Helper()

	path := newImage(t, name)
	formatWithLibrary(t, path)

	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	healthy := cloneKeyslot(metadata.Keyslots["0"])
	metadata.Keyslots = map[string]*Keyslot{
		"0":  nil,
		"1":  healthy,
		"10": nil,
		"2":  nil,
	}
	metadata.Tokens = map[string]*Token{
		"0": {Type: "healthy-token", Keyslots: []string{"1"}},
		"3": nil,
	}
	for _, digest := range metadata.Digests {
		digest.Keyslots = []string{"0", "1", "2", "10"}
	}

	if err := writeHeaderInternal(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the null-entry fixture: %v", err)
	}
	return path
}

// TestReadHeaderReportsTheNullEntriesItDropped is the fix for #27.
//
// ReadHeader removes null keyslot and token entries, which is what makes the
// nil unrepresentable downstream and is deliberate. What was wrong is that no
// caller could learn it happened, so a ReadHeader -> mutate -> WriteHeader
// cycle silently deleted them from the device.
//
// The assertion is on the exact report, ids and kinds and ORDER, not merely
// that something non-empty came back: a report that names the wrong id space,
// or that changes between runs, is the same problem in a new place.
func TestReadHeaderReportsTheNullEntriesItDropped(t *testing.T) {
	t.Parallel()

	path := nullEntryVolume(t, "null-entries.img")

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("a container with null entries no longer reads: %v", err)
	}

	want := []DroppedEntry{
		{Kind: DroppedKindKeyslot, ID: "0"},
		{Kind: DroppedKindKeyslot, ID: "2"},
		{Kind: DroppedKindKeyslot, ID: "10"},
		{Kind: DroppedKindToken, ID: "3"},
	}
	if !slices.Equal(metadata.DroppedNullEntries, want) {
		t.Fatalf("DroppedNullEntries = %v, want %v", metadata.DroppedNullEntries, want)
	}

	// The report describes entries that are actually gone, and only those.
	if len(metadata.Keyslots) != 1 || metadata.Keyslots["1"] == nil {
		t.Fatalf("keyslots = %v, want only the healthy slot 1", metadata.Keyslots)
	}
	if len(metadata.Tokens) != 1 || metadata.Tokens["0"] == nil {
		t.Fatalf("tokens = %v, want only the healthy token 0", metadata.Tokens)
	}

	// Ordering is a property, not an accident of this run. Go randomizes map
	// iteration, so a report built by ranging two maps without sorting differs
	// between reads of an unchanged device -- and a diagnostic an operator
	// compares against last time's is exactly where that is unacceptable.
	for i := 0; i < 20; i++ {
		_, again, err := ReadHeader(path)
		if err != nil {
			t.Fatalf("ReadHeader failed on repeat %d: %v", i, err)
		}
		if !slices.Equal(again.DroppedNullEntries, want) {
			t.Fatalf("read %d reported %v, want the same %v every time",
				i, again.DroppedNullEntries, want)
		}
	}
}

// TestReadHeaderReportsNothingDroppedForAnIntactHeader is the control that
// keeps the report from being noise. A diagnostic that fires on healthy
// containers is one an operator learns to ignore, and then it protects nothing.
func TestReadHeaderReportsNothingDroppedForAnIntactHeader(t *testing.T) {
	t.Parallel()

	path := newImage(t, "intact.img")
	formatWithLibrary(t, path)

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if metadata.DroppedNullEntries != nil {
		t.Fatalf("DroppedNullEntries = %v for an intact header, want nil", metadata.DroppedNullEntries)
	}
}

// TestDroppedNullEntriesNeverReachesTheDisk pins that the diagnostic field
// cannot become a wire field.
//
// It asserts on the TYPE's reflected json tag set rather than on the bytes of
// one marshaled instance. Absence asserted through the serializer is blind to
// a field the serializer declines to emit -- an empty slice with omitempty, or
// a nil map -- so a keySet check on emitted JSON would pass with the tag
// removed and the field merely unset. The field set also fails on an ADDED
// field, so no new member of this struct can reach a LUKS2 header without this
// test acknowledging it, which matters because cryptsetup validates the JSON
// object and rejects members it does not expect.
func TestDroppedNullEntriesNeverReachesTheDisk(t *testing.T) {
	var got []string
	typ := reflect.TypeOf(LUKS2Metadata{})
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if name == "" {
			t.Fatalf("field %s carries no json tag, so it would be marshaled under its Go name",
				typ.Field(i).Name)
		}
		got = append(got, name)
	}

	want := []string{"keyslots", "tokens", "segments", "digests", "config"}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("LUKS2Metadata marshals %v, want exactly %v -- a LUKS2 JSON object carries these five members and nothing else",
			got, want)
	}
}

// TestDroppedNullEntriesDoesNotSurviveAWriteBack is the behavioral half of the
// above: the report describes ONE read, and a caller must not be able to
// mistake a stale report for a fresh one after the repair has been written.
func TestDroppedNullEntriesDoesNotSurviveAWriteBack(t *testing.T) {
	path := nullEntryVolume(t, "null-entries-writeback.img")

	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if len(metadata.DroppedNullEntries) == 0 {
		t.Fatal("the fixture reported no dropped entries, so this test proves nothing")
	}

	// Writing the metadata back is the repair the report warns about.
	if err := writeHeaderInternal(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the repaired header: %v", err)
	}

	_, reread, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed after the write-back: %v", err)
	}
	if reread.DroppedNullEntries != nil {
		t.Fatalf("DroppedNullEntries = %v after the nulls were written out, want nil",
			reread.DroppedNullEntries)
	}
}

// TestDroppedEntryStringNamesBothTheKindAndTheID keeps the rendering an
// application prints from losing the id space. "3" alone does not say whether
// keyslot 3 or token 3 was lost, and they are different things.
func TestDroppedEntryStringNamesBothTheKindAndTheID(t *testing.T) {
	for _, tc := range []struct {
		entry DroppedEntry
		want  string
	}{
		{DroppedEntry{Kind: DroppedKindKeyslot, ID: "3"}, `keyslot "3"`},
		{DroppedEntry{Kind: DroppedKindToken, ID: "3"}, `token "3"`},
		{DroppedEntry{Kind: DroppedKindKeyslot, ID: "01"}, `keyslot "01"`},
	} {
		if got := tc.entry.String(); got != tc.want {
			t.Errorf("DroppedEntry%v.String() = %q, want %q", tc.entry, got, tc.want)
		}
	}
}

// luksPrefixImage writes prefix at the start of a fresh image, for the probes
// that read nothing past the first eight bytes.
func luksPrefixImage(t *testing.T, name string, prefix []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, prefix, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

// luksVersionPrefix is the magic followed by a big-endian version -- all that
// IsLUKS and IsLUKS2 read -- padded to a whole binary header, which is what
// ReadHeader reads before it looks at the version.
func luksVersionPrefix(version uint16) []byte {
	prefix := append([]byte(LUKS2Magic), 0, 0)
	binary.BigEndian.PutUint16(prefix[LUKS2MagicLen:], version)
	return append(prefix, make([]byte, LUKS2HeaderSize-len(prefix))...)
}

// TestIsLUKSAndIsLUKS2TellTheVersionsApart pins the two probes against each
// other: IsLUKS answers "is there a LUKS header at all", IsLUKS2 "is it the
// version this package reads", and a LUKS1 container is where they must
// disagree -- it is the one case that tells a probe that checks the version
// from one that does not.
func TestIsLUKSAndIsLUKS2TellTheVersionsApart(t *testing.T) {
	golden := newImage(t, "luks2.img")
	formatWithLibrary(t, golden)

	for _, tc := range []struct {
		name         string
		device       string
		luks, luksV2 bool
	}{
		{"a container this package formatted", golden, true, true},
		{"a LUKS1 header", luksPrefixImage(t, "luks1.img", luksVersionPrefix(1)), true, false},
		{"the LUKS magic with an unknown version", luksPrefixImage(t, "luks3.img", luksVersionPrefix(3)), true, false},
		{"no LUKS magic", luksPrefixImage(t, "plain.img", make([]byte, 4096)), false, false},
		{"the secondary header's magic at offset 0", luksPrefixImage(t, "skul.img",
			append([]byte(LUKS2SecondaryMagic), 0, 2)), false, false},
		{"fewer bytes than the magic", luksPrefixImage(t, "tiny.img", []byte("LUK")), false, false},
		{"the magic and half a version", luksPrefixImage(t, "seven.img", append([]byte(LUKS2Magic), 0)), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := IsLUKS(tc.device)
			if err != nil || got != tc.luks {
				t.Errorf("IsLUKS = %v, %v; want %v, nil", got, err, tc.luks)
			}
			got, err = IsLUKS2(tc.device)
			if err != nil || got != tc.luksV2 {
				t.Errorf("IsLUKS2 = %v, %v; want %v, nil", got, err, tc.luksV2)
			}
		})
	}
}

// TestIsLUKSRefusesAPathItCannotProbe is the failure half: a path that cannot
// be probed is an error, never a confident "not LUKS" -- a caller deciding
// whether to format would read false as permission.
func TestIsLUKSRefusesAPathItCannotProbe(t *testing.T) {
	for _, tc := range []struct {
		name, device string
		want         error
	}{
		{"an empty path", "", ErrInvalidPath},
		{"a relative path", "relative/volume.img", ErrInvalidPath},
		{"a path that does not exist", filepath.Join(t.TempDir(), "absent.img"), ErrDeviceNotFound},
		{"a directory", t.TempDir(), ErrInvalidPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := IsLUKS(tc.device); !errors.Is(err, tc.want) {
				t.Errorf("IsLUKS = %v, %v; want an error wrapping %v", got, err, tc.want)
			}
			if got, err := IsLUKS2(tc.device); !errors.Is(err, tc.want) {
				t.Errorf("IsLUKS2 = %v, %v; want an error wrapping %v", got, err, tc.want)
			}
		})
	}
}

// TestReadHeaderRefusesALUKS1Container: IsLUKS says yes and this package must
// still not parse it -- a LUKS1 header has a different layout after the
// version field, and reading it as LUKS2 would interpret its key material
// offsets as JSON sizes.
func TestReadHeaderRefusesALUKS1Container(t *testing.T) {
	device := luksPrefixImage(t, "luks1.img", luksVersionPrefix(1))
	if _, _, err := ReadHeader(device); err == nil || !strings.Contains(err.Error(), "unsupported LUKS version: 1") {
		t.Fatalf("ReadHeader = %v, want it to refuse LUKS version 1 by name", err)
	}
}
