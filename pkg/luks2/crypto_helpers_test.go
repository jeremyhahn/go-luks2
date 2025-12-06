// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestEncryptDecryptKeyMaterial tests the round-trip encryption/decryption
func TestEncryptDecryptKeyMaterial(t *testing.T) {
	tests := []struct {
		name     string
		dataSize int
		keySize  int
		cipher   string
		wantErr  bool
	}{
		{
			name:     "AES-XTS with 256-bit key (32 bytes)",
			dataSize: 4096,
			keySize:  32,
			cipher:   "aes",
			wantErr:  false,
		},
		{
			name:     "AES-XTS with 512-bit key (64 bytes)",
			dataSize: 8192,
			keySize:  64,
			cipher:   "aes",
			wantErr:  false,
		},
		{
			name:     "Small data with 256-bit key",
			dataSize: 512,
			keySize:  32,
			cipher:   "aes",
			wantErr:  false,
		},
		{
			name:     "Large data with 512-bit key",
			dataSize: 16384,
			keySize:  64,
			cipher:   "aes",
			wantErr:  false,
		},
		{
			name:     "Single sector with 256-bit key",
			dataSize: 512,
			keySize:  32,
			cipher:   "aes",
			wantErr:  false,
		},
		{
			name:     "Multiple sectors with 512-bit key",
			dataSize: 2048,
			keySize:  64,
			cipher:   "aes",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate test data
			originalData := make([]byte, tt.dataSize)
			if _, err := rand.Read(originalData); err != nil {
				t.Fatalf("Failed to generate test data: %v", err)
			}

			// Generate key
			key := make([]byte, tt.keySize)
			if _, err := rand.Read(key); err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			// Encrypt
			encrypted, err := encryptKeyMaterial(originalData, key, tt.cipher)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			if len(encrypted) != len(originalData) {
				t.Fatalf("Encrypted size mismatch: got %d, want %d", len(encrypted), len(originalData))
			}

			// Verify data is actually encrypted (should differ from original)
			if bytes.Equal(originalData, encrypted) {
				t.Fatal("Encrypted data identical to original")
			}

			// Decrypt
			decrypted, err := decryptKeyMaterial(encrypted, key, tt.cipher, 512)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if len(decrypted) != len(originalData) {
				t.Fatalf("Decrypted size mismatch: got %d, want %d", len(decrypted), len(originalData))
			}

			// Verify round-trip produces original data
			if !bytes.Equal(originalData, decrypted) {
				t.Fatal("Decrypted data doesn't match original")
			}
		})
	}
}

// TestEncryptKeyMaterialUnsupportedCipher tests error handling for unsupported ciphers
func TestEncryptKeyMaterialUnsupportedCipher(t *testing.T) {
	data := make([]byte, 512)
	key := make([]byte, 32)

	tests := []struct {
		name   string
		cipher string
	}{
		{"des cipher", "des"},
		{"3des cipher", "3des"},
		{"blowfish cipher", "blowfish"},
		{"empty cipher", ""},
		{"unknown cipher", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encryptKeyMaterial(data, key, tt.cipher)
			if err == nil {
				t.Fatal("Expected error for unsupported cipher, got nil")
			}
		})
	}
}

// TestDecryptKeyMaterialUnsupportedCipher tests error handling for unsupported ciphers
func TestDecryptKeyMaterialUnsupportedCipher(t *testing.T) {
	data := make([]byte, 512)
	key := make([]byte, 32)

	tests := []struct {
		name   string
		cipher string
	}{
		{"des cipher", "des"},
		{"3des cipher", "3des"},
		{"blowfish cipher", "blowfish"},
		{"empty cipher", ""},
		{"unknown cipher", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decryptKeyMaterial(data, key, tt.cipher, 512)
			if err == nil {
				t.Fatal("Expected error for unsupported cipher, got nil")
			}
		})
	}
}

// TestEncryptKeyMaterialInvalidKeySize tests error handling for invalid key sizes
func TestEncryptKeyMaterialInvalidKeySize(t *testing.T) {
	data := make([]byte, 512)

	tests := []struct {
		name    string
		keySize int
	}{
		{"8-bit key", 1},
		{"16-bit key", 2},
		{"128-bit key (16 bytes)", 16},
		{"odd-sized key", 33},
		{"very small key", 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			_, err := encryptKeyMaterial(data, key, "aes")
			if err == nil {
				t.Fatal("Expected error for invalid key size, got nil")
			}
		})
	}
}

// TestDecryptKeyMaterialInvalidKeySize tests error handling for invalid key sizes
func TestDecryptKeyMaterialInvalidKeySize(t *testing.T) {
	data := make([]byte, 512)

	tests := []struct {
		name    string
		keySize int
	}{
		{"8-bit key", 1},
		{"16-bit key", 2},
		{"128-bit key (16 bytes)", 16},
		{"odd-sized key", 33},
		{"very small key", 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			_, err := decryptKeyMaterial(data, key, "aes", 512)
			if err == nil {
				t.Fatal("Expected error for invalid key size, got nil")
			}
		})
	}
}

// TestEncryptKeyMaterialDifferentSectorSizes tests encryption with various data sizes
func TestEncryptKeyMaterialDifferentSectorSizes(t *testing.T) {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	tests := []struct {
		name     string
		dataSize int
	}{
		{"Exactly one sector", 512},
		{"One and a half sectors", 768},
		{"Two sectors", 1024},
		{"Partial sector", 256},
		{"Three sectors plus partial", 1792},
		{"Large multi-sector", 8192},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.dataSize)
			if _, err := rand.Read(data); err != nil {
				t.Fatalf("Failed to generate test data: %v", err)
			}

			encrypted, err := encryptKeyMaterial(data, key, "aes")
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypted, err := decryptKeyMaterial(encrypted, key, "aes", 512)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if !bytes.Equal(data, decrypted) {
				t.Fatal("Round-trip failed for data size")
			}
		})
	}
}

// TestEncryptKeyMaterialDeterministic tests that encryption with same sector number produces same result
func TestEncryptKeyMaterialDeterministic(t *testing.T) {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	data := make([]byte, 512)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	// Encrypt same data multiple times
	encrypted1, err := encryptKeyMaterial(data, key, "aes")
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	encrypted2, err := encryptKeyMaterial(data, key, "aes")
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Same input should produce same output with XTS (deterministic with same IV)
	if !bytes.Equal(encrypted1, encrypted2) {
		t.Fatal("Encryption not deterministic for same input")
	}
}

// TestDecryptKeyMaterialCorruptedData tests decryption behavior with corrupted ciphertext
func TestDecryptKeyMaterialCorruptedData(t *testing.T) {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	originalData := make([]byte, 1024)
	if _, err := rand.Read(originalData); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	// Encrypt
	encrypted, err := encryptKeyMaterial(originalData, key, "aes")
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Corrupt the ciphertext
	corrupted := make([]byte, len(encrypted))
	copy(corrupted, encrypted)
	corrupted[100] ^= 0xFF // Flip bits

	// Decrypt corrupted data (XTS doesn't have authentication, so no error expected)
	decrypted, err := decryptKeyMaterial(corrupted, key, "aes", 512)
	if err != nil {
		t.Fatalf("Decryption of corrupted data failed: %v", err)
	}

	// Decrypted data should differ from original (corruption detected by comparison)
	if bytes.Equal(originalData, decrypted) {
		t.Fatal("Corrupted data decrypted to original (unexpected)")
	}
}

// TestDecryptKeyMaterialWrongKey tests decryption with incorrect key
func TestDecryptKeyMaterialWrongKey(t *testing.T) {
	correctKey := make([]byte, 64)
	if _, err := rand.Read(correctKey); err != nil {
		t.Fatalf("Failed to generate correct key: %v", err)
	}

	wrongKey := make([]byte, 64)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatalf("Failed to generate wrong key: %v", err)
	}

	originalData := make([]byte, 1024)
	if _, err := rand.Read(originalData); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	// Encrypt with correct key
	encrypted, err := encryptKeyMaterial(originalData, correctKey, "aes")
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt with wrong key (no error expected, but data will be garbage)
	decrypted, err := decryptKeyMaterial(encrypted, wrongKey, "aes", 512)
	if err != nil {
		t.Fatalf("Decryption with wrong key failed: %v", err)
	}

	// Data should differ (wrong key produces garbage)
	if bytes.Equal(originalData, decrypted) {
		t.Fatal("Wrong key produced correct plaintext (unexpected)")
	}
}

// TestCreateDigest tests digest creation
func TestCreateDigest(t *testing.T) {
	tests := []struct {
		name      string
		masterKey []byte
		hashAlgo  string
		wantErr   bool
	}{
		{
			name:      "SHA256 digest",
			masterKey: make([]byte, 32),
			hashAlgo:  "sha256",
			wantErr:   false,
		},
		{
			name:      "SHA512 digest",
			masterKey: make([]byte, 64),
			hashAlgo:  "sha512",
			wantErr:   false,
		},
		{
			name:      "Small key with SHA256",
			masterKey: make([]byte, 16),
			hashAlgo:  "sha256",
			wantErr:   false,
		},
		{
			name:      "Large key with SHA512",
			masterKey: make([]byte, 128),
			hashAlgo:  "sha512",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate random master key
			if _, err := rand.Read(tt.masterKey); err != nil {
				t.Fatalf("Failed to generate master key: %v", err)
			}

			kdf, digestValue, err := createDigest(tt.masterKey, tt.hashAlgo)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("createDigest failed: %v", err)
			}

			// Verify KDF structure
			if kdf == nil {
				t.Fatal("KDF is nil")
			}
			if kdf.Type != "pbkdf2" {
				t.Fatalf("Expected KDF type 'pbkdf2', got %s", kdf.Type)
			}
			if kdf.Hash != tt.hashAlgo {
				t.Fatalf("Expected hash %s, got %s", tt.hashAlgo, kdf.Hash)
			}
			if kdf.Salt == "" {
				t.Fatal("Salt is empty")
			}
			if kdf.Iterations == nil {
				t.Fatal("Iterations is nil")
			}
			if *kdf.Iterations != DigestIterations {
				t.Fatalf("Expected %d iterations, got %d", DigestIterations, *kdf.Iterations)
			}

			// Verify digest value
			if digestValue == "" {
				t.Fatal("Digest value is empty")
			}

			// Verify salt is valid base64
			_, err = decodeBase64(kdf.Salt)
			if err != nil {
				t.Fatalf("Salt is not valid base64: %v", err)
			}

			// Verify digest is valid base64
			digestBytes, err := decodeBase64(digestValue)
			if err != nil {
				t.Fatalf("Digest is not valid base64: %v", err)
			}

			// Verify digest is 32 bytes (as specified in createDigest)
			if len(digestBytes) != 32 {
				t.Fatalf("Expected digest size 32 bytes, got %d", len(digestBytes))
			}
		})
	}
}

// TestCreateDigestDeterministic tests that same input produces different digests due to random salt
func TestCreateDigestDeterministic(t *testing.T) {
	masterKey := make([]byte, 64)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	kdf1, digest1, err := createDigest(masterKey, "sha256")
	if err != nil {
		t.Fatalf("First createDigest failed: %v", err)
	}

	kdf2, digest2, err := createDigest(masterKey, "sha256")
	if err != nil {
		t.Fatalf("Second createDigest failed: %v", err)
	}

	// Salts should differ (random generation)
	if kdf1.Salt == kdf2.Salt {
		t.Fatal("Salts are identical (should be random)")
	}

	// Digests should differ (different salts)
	if digest1 == digest2 {
		t.Fatal("Digests are identical (should differ due to different salts)")
	}
}

// TestCreateDigestVerification tests that the digest can be used to verify the master key
func TestCreateDigestVerification(t *testing.T) {
	masterKey := make([]byte, 64)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	kdf, expectedDigest, err := createDigest(masterKey, "sha256")
	if err != nil {
		t.Fatalf("createDigest failed: %v", err)
	}

	// Re-derive the digest using the same KDF
	actualDigest, err := DeriveKey(masterKey, kdf, 32)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	// Encode and compare
	actualDigestB64 := encodeBase64(actualDigest)
	if actualDigestB64 != expectedDigest {
		t.Fatal("Digest verification failed: re-derived digest doesn't match")
	}
}

// TestCreateDigestInvalidHashAlgo tests error handling for unsupported hash algorithms
func TestCreateDigestInvalidHashAlgo(t *testing.T) {
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	tests := []struct {
		name     string
		hashAlgo string
	}{
		{"MD5", "md5"},
		{"SHA1", "sha1"},
		{"Unknown", "unknown"},
		{"Empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := createDigest(masterKey, tt.hashAlgo)
			if err == nil {
				t.Fatal("Expected error for unsupported hash algorithm, got nil")
			}
		})
	}
}

// TestCreateMetadata tests metadata structure creation
func TestCreateMetadata(t *testing.T) {
	// Create test KDFs
	iterations := 100000

	kdf := &KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       "dGVzdHNhbHQ=",
		Iterations: &iterations,
	}

	digestKDF := &KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       "ZGlnZXN0c2FsdA==",
		Iterations: &iterations,
	}

	digestValue := "dGVzdGRpZ2VzdA=="

	opts := FormatOptions{
		Device:     "/dev/test",
		Cipher:     "aes",
		CipherMode: "xts-plain64",
		HashAlgo:   "sha256",
		SectorSize: 512,
	}

	masterKeySize := 64
	keyslotOffset := 0x8000
	keyslotSize := 4096
	dataOffset := keyslotOffset + keyslotSize

	metadata := createMetadata(kdf, digestKDF, digestValue, opts, masterKeySize,
		keyslotOffset, keyslotSize, dataOffset)

	// Verify keyslots
	if metadata.Keyslots == nil {
		t.Fatal("Keyslots is nil")
	}
	if len(metadata.Keyslots) != 1 {
		t.Fatalf("Expected 1 keyslot, got %d", len(metadata.Keyslots))
	}

	keyslot, ok := metadata.Keyslots["0"]
	if !ok {
		t.Fatal("Keyslot 0 not found")
	}
	if keyslot.Type != "luks2" {
		t.Fatalf("Expected keyslot type 'luks2', got %s", keyslot.Type)
	}
	if keyslot.KeySize != masterKeySize {
		t.Fatalf("Expected keyslot key size %d, got %d", masterKeySize, keyslot.KeySize)
	}
	if keyslot.Priority == nil || *keyslot.Priority != 1 {
		t.Fatal("Expected priority 1")
	}

	// Verify keyslot area
	if keyslot.Area == nil {
		t.Fatal("Keyslot area is nil")
	}
	if keyslot.Area.Type != "raw" {
		t.Fatalf("Expected area type 'raw', got %s", keyslot.Area.Type)
	}
	if keyslot.Area.KeySize != masterKeySize {
		t.Fatalf("Expected area key size %d, got %d", masterKeySize, keyslot.Area.KeySize)
	}
	if keyslot.Area.Offset != formatSize(int64(keyslotOffset)) {
		t.Fatalf("Expected offset %s, got %s", formatSize(int64(keyslotOffset)), keyslot.Area.Offset)
	}
	if keyslot.Area.Size != formatSize(int64(keyslotSize)) {
		t.Fatalf("Expected size %s, got %s", formatSize(int64(keyslotSize)), keyslot.Area.Size)
	}
	if keyslot.Area.Encryption != "aes-xts-plain64" {
		t.Fatalf("Expected encryption 'aes-xts-plain64', got %s", keyslot.Area.Encryption)
	}

	// Verify KDF
	if keyslot.KDF == nil {
		t.Fatal("Keyslot KDF is nil")
	}
	if keyslot.KDF.Type != kdf.Type {
		t.Fatalf("Expected KDF type %s, got %s", kdf.Type, keyslot.KDF.Type)
	}

	// Verify AF
	if keyslot.AF == nil {
		t.Fatal("Anti-forensic is nil")
	}
	if keyslot.AF.Type != "luks1" {
		t.Fatalf("Expected AF type 'luks1', got %s", keyslot.AF.Type)
	}
	if keyslot.AF.Stripes != AFStripes {
		t.Fatalf("Expected AF stripes %d, got %d", AFStripes, keyslot.AF.Stripes)
	}
	if keyslot.AF.Hash != opts.HashAlgo {
		t.Fatalf("Expected AF hash %s, got %s", opts.HashAlgo, keyslot.AF.Hash)
	}

	// Verify segments
	if metadata.Segments == nil {
		t.Fatal("Segments is nil")
	}
	if len(metadata.Segments) != 1 {
		t.Fatalf("Expected 1 segment, got %d", len(metadata.Segments))
	}

	segment, ok := metadata.Segments["0"]
	if !ok {
		t.Fatal("Segment 0 not found")
	}
	if segment.Type != "crypt" {
		t.Fatalf("Expected segment type 'crypt', got %s", segment.Type)
	}
	if segment.Offset != formatSize(int64(dataOffset)) {
		t.Fatalf("Expected offset %s, got %s", formatSize(int64(dataOffset)), segment.Offset)
	}
	if segment.Size != "dynamic" {
		t.Fatalf("Expected size 'dynamic', got %s", segment.Size)
	}
	if segment.IVTweak != "0" {
		t.Fatalf("Expected IV tweak '0', got %s", segment.IVTweak)
	}
	if segment.Encryption != "aes-xts-plain64" {
		t.Fatalf("Expected encryption 'aes-xts-plain64', got %s", segment.Encryption)
	}
	if segment.SectorSize != opts.SectorSize {
		t.Fatalf("Expected sector size %d, got %d", opts.SectorSize, segment.SectorSize)
	}

	// Verify digests
	if metadata.Digests == nil {
		t.Fatal("Digests is nil")
	}
	if len(metadata.Digests) != 1 {
		t.Fatalf("Expected 1 digest, got %d", len(metadata.Digests))
	}

	digest, ok := metadata.Digests["0"]
	if !ok {
		t.Fatal("Digest 0 not found")
	}
	if digest.Type != "pbkdf2" {
		t.Fatalf("Expected digest type 'pbkdf2', got %s", digest.Type)
	}
	if len(digest.Keyslots) != 1 || digest.Keyslots[0] != "0" {
		t.Fatal("Expected digest to reference keyslot 0")
	}
	if len(digest.Segments) != 1 || digest.Segments[0] != "0" {
		t.Fatal("Expected digest to reference segment 0")
	}
	if digest.Hash != digestKDF.Hash {
		t.Fatalf("Expected digest hash %s, got %s", digestKDF.Hash, digest.Hash)
	}
	if digest.Iterations != *digestKDF.Iterations {
		t.Fatalf("Expected digest iterations %d, got %d", *digestKDF.Iterations, digest.Iterations)
	}
	if digest.Salt != digestKDF.Salt {
		t.Fatalf("Expected digest salt %s, got %s", digestKDF.Salt, digest.Salt)
	}
	if digest.Digest != digestValue {
		t.Fatalf("Expected digest value %s, got %s", digestValue, digest.Digest)
	}

	// Verify config
	if metadata.Config == nil {
		t.Fatal("Config is nil")
	}
	expectedJSONSize := formatSize(int64(LUKS2DefaultSize))
	if metadata.Config.JSONSize != expectedJSONSize {
		t.Fatalf("Expected JSON size %s, got %s", expectedJSONSize, metadata.Config.JSONSize)
	}
	expectedKeyslotsSize := formatSize(int64(keyslotOffset + keyslotSize))
	if metadata.Config.KeyslotsSize != expectedKeyslotsSize {
		t.Fatalf("Expected keyslots size %s, got %s", expectedKeyslotsSize, metadata.Config.KeyslotsSize)
	}
}

// TestCreateMetadataWithArgon2 tests metadata creation with Argon2 KDF
func TestCreateMetadataWithArgon2(t *testing.T) {
	argonTime := 4
	argonMemory := 1048576
	argonCPUs := 4

	kdf := &KDF{
		Type:   "argon2id",
		Salt:   "dGVzdHNhbHQ=",
		Time:   &argonTime,
		Memory: &argonMemory,
		CPUs:   &argonCPUs,
	}

	digestIterations := 100000
	digestKDF := &KDF{
		Type:       "pbkdf2",
		Hash:       "sha512",
		Salt:       "ZGlnZXN0c2FsdA==",
		Iterations: &digestIterations,
	}

	digestValue := "dGVzdGRpZ2VzdA=="

	opts := FormatOptions{
		Device:     "/dev/test",
		Cipher:     "aes",
		CipherMode: "xts-plain64",
		HashAlgo:   "sha512",
		SectorSize: 4096,
	}

	masterKeySize := 32
	keyslotOffset := 0x8000
	keyslotSize := 8192
	dataOffset := keyslotOffset + keyslotSize

	metadata := createMetadata(kdf, digestKDF, digestValue, opts, masterKeySize,
		keyslotOffset, keyslotSize, dataOffset)

	if metadata == nil {
		t.Fatal("Metadata is nil")
	}

	// Verify Argon2 KDF is properly set
	keyslot := metadata.Keyslots["0"]
	if keyslot.KDF.Type != "argon2id" {
		t.Fatalf("Expected KDF type 'argon2id', got %s", keyslot.KDF.Type)
	}
	if keyslot.KDF.Time == nil || *keyslot.KDF.Time != argonTime {
		t.Fatalf("Expected time %d, got %v", argonTime, keyslot.KDF.Time)
	}
	if keyslot.KDF.Memory == nil || *keyslot.KDF.Memory != argonMemory {
		t.Fatalf("Expected memory %d, got %v", argonMemory, keyslot.KDF.Memory)
	}
	if keyslot.KDF.CPUs == nil || *keyslot.KDF.CPUs != argonCPUs {
		t.Fatalf("Expected CPUs %d, got %v", argonCPUs, keyslot.KDF.CPUs)
	}

	// Verify SHA512 is used
	segment := metadata.Segments["0"]
	if segment.SectorSize != 4096 {
		t.Fatalf("Expected sector size 4096, got %d", segment.SectorSize)
	}
}

// TestCreateMetadataVariousOffsets tests metadata creation with different offset configurations
func TestCreateMetadataVariousOffsets(t *testing.T) {
	iterations := 100000
	kdf := &KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       "dGVzdHNhbHQ=",
		Iterations: &iterations,
	}

	digestKDF := &KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       "ZGlnZXN0c2FsdA==",
		Iterations: &iterations,
	}

	digestValue := "dGVzdGRpZ2VzdA=="

	opts := FormatOptions{
		Device:     "/dev/test",
		Cipher:     "aes",
		CipherMode: "xts-plain64",
		HashAlgo:   "sha256",
		SectorSize: 512,
	}

	tests := []struct {
		name          string
		masterKeySize int
		keyslotOffset int
		keyslotSize   int
	}{
		{"Standard configuration", 64, 0x8000, 4096},
		{"Large keyslot", 64, 0x8000, 16384},
		{"Small keyslot", 32, 0x8000, 2048},
		{"Different offset", 64, 0x10000, 8192},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataOffset := tt.keyslotOffset + tt.keyslotSize

			metadata := createMetadata(kdf, digestKDF, digestValue, opts, tt.masterKeySize,
				tt.keyslotOffset, tt.keyslotSize, dataOffset)

			if metadata == nil {
				t.Fatal("Metadata is nil")
			}

			keyslot := metadata.Keyslots["0"]
			if keyslot.Area.Offset != formatSize(int64(tt.keyslotOffset)) {
				t.Fatalf("Expected offset %s, got %s",
					formatSize(int64(tt.keyslotOffset)), keyslot.Area.Offset)
			}
			if keyslot.Area.Size != formatSize(int64(tt.keyslotSize)) {
				t.Fatalf("Expected size %s, got %s",
					formatSize(int64(tt.keyslotSize)), keyslot.Area.Size)
			}

			segment := metadata.Segments["0"]
			if segment.Offset != formatSize(int64(dataOffset)) {
				t.Fatalf("Expected data offset %s, got %s",
					formatSize(int64(dataOffset)), segment.Offset)
			}
		})
	}
}
