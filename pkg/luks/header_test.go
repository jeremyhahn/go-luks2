// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
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

			if err := binary.Write(buf, binary.LittleEndian, &tmpHdr); err != nil {
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
				if err := binary.Write(buf, binary.LittleEndian, hdr); err != nil {
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
				if err := binary.Write(buf, binary.LittleEndian, hdr); err != nil {
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

			err := validateHeaderChecksum(hdr, reader)
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
				if err := binary.Write(buf, binary.LittleEndian, hdr); err != nil {
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
				if err := binary.Write(buf, binary.LittleEndian, hdr); err != nil {
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

			err := validateHeaderChecksum(hdr, reader)
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
			name: "with keyslots",
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
			if err := binary.Write(buf, binary.LittleEndian, &dummyHdr); err != nil {
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
			metadata, err := readJSONMetadata(reader, tt.hdr)

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
	if err := binary.Write(buf, binary.LittleEndian, &dummyHdr); err != nil {
		t.Fatalf("Failed to write dummy header: %v", err)
	}

	jsonSize := int(hdr.HeaderSize) - LUKS2HeaderSize
	buf.Write(jsonData)
	padding := make([]byte, jsonSize-len(jsonData))
	buf.Write(padding)

	// Read back
	reader := &mockReaderAt{data: buf.Bytes()}
	recovered, err := readJSONMetadata(reader, hdr)
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
