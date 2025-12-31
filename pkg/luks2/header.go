// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
)

// ReadHeader reads and validates a LUKS2 header from a device
func ReadHeader(device string) (*LUKS2BinaryHeader, *LUKS2Metadata, error) {
	// Validate device path
	if err := ValidateDevicePath(device); err != nil {
		return nil, nil, err
	}

	f, err := os.Open(device) // #nosec G304 -- device path validated above
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open device: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Read binary header (LUKS2 uses big-endian for integer fields)
	var hdr LUKS2BinaryHeader
	if err := binary.Read(f, binary.BigEndian, &hdr); err != nil {
		return nil, nil, fmt.Errorf("failed to read header: %w", err)
	}

	// Validate magic
	if !bytes.Equal(hdr.Magic[:], []byte(LUKS2Magic)) {
		return nil, nil, fmt.Errorf("invalid LUKS magic: not a LUKS2 device")
	}

	// Validate version
	if hdr.Version != LUKS2Version {
		return nil, nil, fmt.Errorf("unsupported LUKS version: %d", hdr.Version)
	}

	// Validate checksum
	if err := validateHeaderChecksum(&hdr, f); err != nil {
		return nil, nil, err
	}

	// Read JSON metadata
	metadata, err := readJSONMetadata(f, &hdr)
	if err != nil {
		return nil, nil, err
	}

	return &hdr, metadata, nil
}

// IsLUKS checks if a device or file contains a LUKS header (either LUKS1 or LUKS2).
// This is a pure Go implementation that doesn't require the cryptsetup CLI.
// It checks for LUKS magic bytes at offset 0.
func IsLUKS(device string) (bool, error) {
	// Validate device path
	if err := ValidateDevicePath(device); err != nil {
		return false, err
	}

	f, err := os.Open(device) // #nosec G304 -- device path validated above
	if err != nil {
		return false, fmt.Errorf("failed to open device: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Read first 6 bytes (LUKS magic)
	magic := make([]byte, LUKS2MagicLen)
	n, err := f.Read(magic)
	if err != nil {
		return false, fmt.Errorf("failed to read device: %w", err)
	}
	if n < LUKS2MagicLen {
		return false, nil // Too small to be LUKS
	}

	// Check for LUKS magic bytes
	// Both LUKS1 and LUKS2 use the same magic: "LUKS\xba\xbe"
	return bytes.Equal(magic, []byte(LUKS2Magic)), nil
}

// IsLUKS2 checks if a device contains a LUKS2 header specifically.
// Returns true only for LUKS2 (not LUKS1).
func IsLUKS2(device string) (bool, error) {
	// Validate device path
	if err := ValidateDevicePath(device); err != nil {
		return false, err
	}

	f, err := os.Open(device) // #nosec G304 -- device path validated above
	if err != nil {
		return false, fmt.Errorf("failed to open device: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Read first 8 bytes (magic + version)
	header := make([]byte, 8)
	n, err := f.Read(header)
	if err != nil {
		return false, fmt.Errorf("failed to read device: %w", err)
	}
	if n < 8 {
		return false, nil // Too small to be LUKS
	}

	// Check for LUKS magic bytes
	if !bytes.Equal(header[:LUKS2MagicLen], []byte(LUKS2Magic)) {
		return false, nil // Not LUKS at all
	}

	// Check version (bytes 6-7, big-endian)
	// LUKS2 version is 0x0002
	version := binary.BigEndian.Uint16(header[6:8])
	return version == LUKS2Version, nil
}

// WriteHeader writes a LUKS2 header to a device (acquires lock)
func WriteHeader(device string, hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata) error {
	// Validate device path
	if err := ValidateDevicePath(device); err != nil {
		return err
	}

	// Acquire file lock for exclusive access
	lock, err := AcquireFileLock(device)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	return writeHeaderInternal(device, hdr, metadata)
}

// writeHeaderInternal writes a LUKS2 header without acquiring a lock
// Caller must hold the lock
func writeHeaderInternal(device string, hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata) error {
	f, err := os.OpenFile(device, os.O_RDWR, 0600) // #nosec G304 -- device path from trusted internal call
	if err != nil {
		return fmt.Errorf("failed to open device: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Marshal JSON metadata
	jsonData, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Calculate JSON size (must be power of 2, at least 16KB)
	jsonSize := nextPowerOf2(len(jsonData) + 1) // +1 for null terminator
	if jsonSize < LUKS2DefaultSize {
		jsonSize = LUKS2DefaultSize
	}

	// Update header size
	hdr.HeaderSize = uint64(LUKS2HeaderSize + jsonSize) // #nosec G115 - header size is bounded by LUKS2 spec

	// Calculate and set checksum
	if err := calculateHeaderChecksum(hdr, jsonData, jsonSize); err != nil {
		return err
	}

	// Write binary header (LUKS2 uses big-endian for integer fields)
	if err := binary.Write(f, binary.BigEndian, hdr); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write JSON metadata with padding
	if _, err := f.Write(jsonData); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	// Null-terminate and pad to jsonSize
	padding := make([]byte, jsonSize-len(jsonData))
	if _, err := f.Write(padding); err != nil {
		return fmt.Errorf("failed to write padding: %w", err)
	}

	// Write backup header at offset 0x4000
	if _, err := f.Seek(0x4000, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to backup header: %w", err)
	}

	// Update header offset for backup
	backupHdr := *hdr
	backupHdr.HeaderOffset = 0x4000

	// Recalculate checksum for backup header
	if err := calculateHeaderChecksum(&backupHdr, jsonData, jsonSize); err != nil {
		return err
	}

	// Write backup header (LUKS2 uses big-endian for integer fields)
	if err := binary.Write(f, binary.BigEndian, &backupHdr); err != nil {
		return fmt.Errorf("failed to write backup header: %w", err)
	}

	// Write backup JSON metadata
	if _, err := f.Write(jsonData); err != nil {
		return fmt.Errorf("failed to write backup metadata: %w", err)
	}
	if _, err := f.Write(padding); err != nil {
		return fmt.Errorf("failed to write backup padding: %w", err)
	}

	return f.Sync()
}

// CreateBinaryHeader creates a new LUKS2 binary header
func CreateBinaryHeader(opts FormatOptions) (*LUKS2BinaryHeader, error) {
	hdr := &LUKS2BinaryHeader{
		Version: LUKS2Version,
	}

	// Set magic
	copy(hdr.Magic[:], LUKS2Magic)

	// Set checksum algorithm
	copy(hdr.ChecksumAlgorithm[:], "sha256")

	// Generate UUID
	u := uuid.New()
	copy(hdr.UUID[:], u.String())

	// Set label if provided
	if opts.Label != "" {
		copy(hdr.Label[:], opts.Label)
	}

	// Set subsystem if provided
	if opts.Subsystem != "" {
		copy(hdr.SubsystemLabel[:], opts.Subsystem)
	}

	// Generate salt for checksum
	if _, err := rand.Read(hdr.Salt[:]); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Sequence ID starts at 1
	hdr.SequenceID = 1

	return hdr, nil
}

// validateHeaderChecksum validates the header checksum
func validateHeaderChecksum(hdr *LUKS2BinaryHeader, r io.ReaderAt) error {
	// Safe conversion of header offset
	headerOffset, err := SafeUint64ToInt64(hdr.HeaderOffset)
	if err != nil {
		return fmt.Errorf("invalid header offset: %w", err)
	}

	// Read entire header area
	headerData := make([]byte, hdr.HeaderSize)
	if _, err := r.ReadAt(headerData, headerOffset); err != nil {
		return fmt.Errorf("failed to read header for checksum: %w", err)
	}

	// Zero out checksum field
	checksumOffset := 0x1C0 // Offset of Checksum field

	for i := 0; i < 64; i++ {
		headerData[checksumOffset+i] = 0
	}

	// Calculate checksum
	h := sha256.New()
	h.Write(headerData)
	calculated := h.Sum(nil)

	// Compare
	if !bytes.Equal(calculated, hdr.Checksum[:len(calculated)]) {
		return fmt.Errorf("header checksum mismatch\nExpected: %x\nCalculated: %x\nHeaderSize: %d, HeaderOffset: %d",
			hdr.Checksum[:32], calculated[:32], hdr.HeaderSize, hdr.HeaderOffset)
	}

	return nil
}

// calculateHeaderChecksum calculates and sets the header checksum
func calculateHeaderChecksum(hdr *LUKS2BinaryHeader, jsonData []byte, jsonSize int) error {
	// Create buffer for entire header area
	buf := new(bytes.Buffer)

	// Write binary header with zeroed checksum (LUKS2 uses big-endian for integer fields)
	// Create a clean copy to ensure padding bytes are zeroed
	tmpHdr := *hdr
	tmpHdr.Checksum = [64]byte{}

	if err := binary.Write(buf, binary.BigEndian, &tmpHdr); err != nil {
		return fmt.Errorf("failed to write header for checksum: %w", err)
	}

	// Write JSON data with padding
	buf.Write(jsonData)
	padding := make([]byte, jsonSize-len(jsonData))
	buf.Write(padding)

	// Calculate checksum
	h := sha256.New()
	h.Write(buf.Bytes())
	checksum := h.Sum(nil)

	// Set checksum in header
	copy(hdr.Checksum[:], checksum)

	return nil
}

// readJSONMetadata reads the JSON metadata from the header
func readJSONMetadata(r io.ReaderAt, hdr *LUKS2BinaryHeader) (*LUKS2Metadata, error) {
	// Safe conversion of header size
	headerSizeInt, err := SafeUint64ToInt(hdr.HeaderSize)
	if err != nil {
		return nil, fmt.Errorf("invalid header size: %w", err)
	}
	jsonSize := headerSizeInt - LUKS2HeaderSize
	jsonData := make([]byte, jsonSize)

	// Safe conversion of header offset
	headerOffset, err := SafeUint64ToInt64(hdr.HeaderOffset)
	if err != nil {
		return nil, fmt.Errorf("invalid header offset: %w", err)
	}
	offset := headerOffset + LUKS2HeaderSize
	if _, err := r.ReadAt(jsonData, offset); err != nil {
		return nil, fmt.Errorf("failed to read JSON metadata: %w", err)
	}

	// Find null terminator
	nullIdx := bytes.IndexByte(jsonData, 0)
	if nullIdx != -1 {
		jsonData = jsonData[:nullIdx]
	}

	var metadata LUKS2Metadata
	if err := json.Unmarshal(jsonData, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse JSON metadata: %w", err)
	}

	return &metadata, nil
}

// GetVolumeInfo extracts volume information from a LUKS device
func GetVolumeInfo(device string) (*VolumeInfo, error) {
	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		return nil, err
	}

	info := &VolumeInfo{
		UUID:     string(bytes.TrimRight(hdr.UUID[:], "\x00")),
		Label:    string(bytes.TrimRight(hdr.Label[:], "\x00")),
		Version:  int(hdr.Version),
		Metadata: metadata,
	}

	// Extract cipher info from first segment
	for _, seg := range metadata.Segments {
		if seg.Type == "crypt" {
			info.Cipher = seg.Encryption
			info.SectorSize = seg.SectorSize
			break
		}
	}

	// Find active keyslots
	for id := range metadata.Keyslots {
		// Parse keyslot ID
		var slotNum int
		if _, err := fmt.Sscanf(id, "%d", &slotNum); err == nil {
			info.ActiveKeyslots = append(info.ActiveKeyslots, slotNum)
		}
	}

	return info, nil
}
