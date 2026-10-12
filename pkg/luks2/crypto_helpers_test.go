// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"crypto/rand"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

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
			// The digest cost is CALIBRATED, and a calibration is a wall-clock
			// measurement, so it is pinned here rather than measured a second
			// time. See the iteration assertion below for why (#204).
			const pinnedIterations = 123_457
			askedFor, digestIterationsFor := recordDigestCalibration(t, pinnedIterations)
			sys := testVolumeSys()
			sys.digestIterationsFor = digestIterationsFor

			// Generate random master key
			if _, err := rand.Read(tt.masterKey); err != nil {
				t.Fatalf("Failed to generate master key: %v", err)
			}

			kdf, digestValue, err := createDigest(enclaveFrom(t, tt.masterKey), tt.hashAlgo, sys)
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
			// CALIBRATED, so there is no constant to compare against. This
			// used to compare the recorded count against a SECOND, fresh
			// calibration and accept anything within 2x -- which compares two
			// wall-clock measurements taken moments apart. That is a property
			// of how busy the host is, not of this code: under load the two
			// measurements land five-fold apart and the test fails on a tree
			// that is correct (#204).
			//
			// The property that actually belongs to createDigest is pinned
			// instead: it records EXACTLY the count the calibration returned,
			// for the hash the digest declares -- no rounding, no substituted
			// default, no second call whose answer could differ from the one
			// the digest was derived with. That the REAL calibration tracks
			// its time target and clears the LUKS2 iteration floor is a
			// property of the calibration, and is checked where it lives, in
			// TestDigestCalibrationTargetsItsBudget.
			if *kdf.Iterations != pinnedIterations {
				t.Fatalf("digest records %d iterations; the calibration returned %d",
					*kdf.Iterations, pinnedIterations)
			}
			if len(*askedFor) != 1 || (*askedFor)[0] != tt.hashAlgo {
				t.Fatalf("calibration was asked for %v; want exactly one call, for %q",
					*askedFor, tt.hashAlgo)
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

			// The digest must be as long as the OUTPUT OF THE HASH IT DECLARES
			// -- 64 bytes for sha512, 32 for sha256 -- because that is what a
			// LUKS2 digest is. This assertion used to demand a flat 32 bytes,
			// which is the write half of #73: it locked in a digest that no
			// other LUKS2 implementation derives the same way, so cryptsetup
			// returned "incorrect passphrase" for the correct passphrase.
			wantLen, err := hashOutputLen(tt.hashAlgo)
			if err != nil {
				t.Fatalf("hashOutputLen(%q) failed: %v", tt.hashAlgo, err)
			}
			if len(digestBytes) != wantLen {
				t.Fatalf("Expected digest size %d bytes for %s, got %d", wantLen, tt.hashAlgo, len(digestBytes))
			}
		})
	}
}

// TestCreateDigestDeterministic tests that same input produces different digests due to random salt
func TestCreateDigestDeterministic(t *testing.T) {
	defer parallel(t)()

	masterKey := make([]byte, 64)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	kdf1, digest1, err := createDigest(enclaveFrom(t, masterKey), "sha256", testVolumeSys())
	if err != nil {
		t.Fatalf("First createDigest failed: %v", err)
	}

	kdf2, digest2, err := createDigest(enclaveFrom(t, masterKey), "sha256", testVolumeSys())
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
	defer parallel(t)()

	masterKey := make([]byte, 64)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	kdf, expectedDigest, err := createDigest(enclaveFrom(t, masterKey), "sha256", testVolumeSys())
	if err != nil {
		t.Fatalf("createDigest failed: %v", err)
	}

	// Re-derive the digest using the same KDF, to the length the digest is
	// actually stored at rather than to a constant -- deriving to a hardcoded
	// 32 here would keep passing for sha256 and quietly stop testing anything
	// for any other hash.
	expectedBytes, err := decodeBase64(expectedDigest)
	if err != nil {
		t.Fatalf("Digest is not valid base64: %v", err)
	}
	actualDigest, err := deriveKeyPlain(masterKey, kdf, len(expectedBytes))
	if err != nil {
		t.Fatalf("deriveKeyPlain failed: %v", err)
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
		// Note: SHA-1 is accepted outside FIPS mode for legacy LUKS headers, so
		// it is not listed here as an unsupported algorithm (docs/fips/architecture.md, "SHA-1").
		{"Unknown", "unknown"},
		{"Empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := createDigest(enclaveFrom(t, masterKey), tt.hashAlgo, testVolumeSys())
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

	kdf := &header.KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       "dGVzdHNhbHQ=",
		Iterations: &iterations,
	}

	digestKDF := &header.KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       "ZGlnZXN0c2FsdA==",
		Iterations: &iterations,
	}

	digestValue := "dGVzdGRpZ2VzdA=="

	opts := formatOptionsForTest{
		Device:     "/dev/test",
		Cipher:     "aes",
		CipherMode: "xts-plain64",
		HashAlgo:   "sha256",
		SectorSize: 512,
	}

	masterKeySize := 64
	keyslotOffset := 0x8000
	keyslotSize := 4096
	keyslotsAreaSize := keyslotSize // For test, use same size
	dataOffset := keyslotOffset + keyslotsAreaSize

	metadata := createMetadata(kdf, digestKDF, digestValue, opts, masterKeySize,
		keyslotOffset, keyslotSize, keyslotsAreaSize, dataOffset)

	// Verify keyslots
	if metadata.Keyslots == nil {
		t.Fatal("Keyslots is nil")
	}
	if len(metadata.Keyslots) != 1 {
		t.Fatalf("Expected 1 keyslot, got %d", len(metadata.Keyslots))
	}

	keyslot, ok := metadata.Keyslots["0"]
	if !ok {
		t.Fatal("header.Keyslot 0 not found")
	}
	if keyslot.Type != "luks2" {
		t.Fatalf("Expected keyslot type 'luks2', got %s", keyslot.Type)
	}
	if keyslot.KeySize != masterKeySize {
		t.Fatalf("Expected keyslot key size %d, got %d", masterKeySize, keyslot.KeySize)
	}
	// NO priority member, which is how "normal" is spelled in LUKS2: the field
	// is optional and its default IS normal, so writing 1 states what every
	// reader already assumes and diverges from what cryptsetup writes. See
	// createMetadata.
	if keyslot.Priority != nil {
		t.Fatalf("createMetadata set priority %d; a normal keyslot carries no priority member", *keyslot.Priority)
	}

	// Verify keyslot area
	if keyslot.Area == nil {
		t.Fatal("header.Keyslot area is nil")
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
		t.Fatal("header.Keyslot KDF is nil")
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
	if keyslot.AF.Stripes != header.AFStripes {
		t.Fatalf("Expected AF stripes %d, got %d", header.AFStripes, keyslot.AF.Stripes)
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

	// Verify tokens: mandatory LUKS2 object, empty but NOT nil, so it marshals
	// as {} rather than being omitted or written as null (#28).
	if metadata.Tokens == nil {
		t.Fatal("Tokens is nil: LUKS2 requires the object to be present, empty when there are none")
	}
	if len(metadata.Tokens) != 0 {
		t.Fatalf("Expected 0 tokens, got %d", len(metadata.Tokens))
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
	expectedJSONSize := formatSize(int64(header.DefaultSize))
	if metadata.Config.JSONSize != expectedJSONSize {
		t.Fatalf("Expected JSON size %s, got %s", expectedJSONSize, metadata.Config.JSONSize)
	}
	// config.keyslots_size is the SIZE of the keyslots area, not the offset at
	// which it ends. This assertion used to demand keyslotOffset +
	// keyslotsAreaSize, which is the defect from #28 written down as a test:
	// cryptsetup reads the field as a size and rejected the container with
	// "keyslots_size is too large 16777216 (bytes)".
	expectedKeyslotsSize := formatSize(int64(keyslotsAreaSize))
	if metadata.Config.KeyslotsSize != expectedKeyslotsSize {
		t.Fatalf("Expected keyslots size %s, got %s", expectedKeyslotsSize, metadata.Config.KeyslotsSize)
	}
}

// TestCreateMetadataWithArgon2 tests metadata creation with Argon2 KDF
func TestCreateMetadataWithArgon2(t *testing.T) {
	argonTime := 4
	argonMemory := 1048576
	argonCPUs := 4

	kdf := &header.KDF{
		Type:   "argon2id",
		Salt:   "dGVzdHNhbHQ=",
		Time:   &argonTime,
		Memory: &argonMemory,
		CPUs:   &argonCPUs,
	}

	digestIterations := 100000
	digestKDF := &header.KDF{
		Type:       "pbkdf2",
		Hash:       "sha512",
		Salt:       "ZGlnZXN0c2FsdA==",
		Iterations: &digestIterations,
	}

	digestValue := "dGVzdGRpZ2VzdA=="

	opts := formatOptionsForTest{
		Device:     "/dev/test",
		Cipher:     "aes",
		CipherMode: "xts-plain64",
		HashAlgo:   "sha512",
		SectorSize: 4096,
	}

	masterKeySize := 32
	keyslotOffset := 0x8000
	keyslotSize := 8192
	keyslotsAreaSize := keyslotSize // For test, use same size
	dataOffset := keyslotOffset + keyslotsAreaSize

	metadata := createMetadata(kdf, digestKDF, digestValue, opts, masterKeySize,
		keyslotOffset, keyslotSize, keyslotsAreaSize, dataOffset)

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
	kdf := &header.KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       "dGVzdHNhbHQ=",
		Iterations: &iterations,
	}

	digestKDF := &header.KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       "ZGlnZXN0c2FsdA==",
		Iterations: &iterations,
	}

	digestValue := "dGVzdGRpZ2VzdA=="

	opts := formatOptionsForTest{
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
			keyslotsAreaSize := tt.keyslotSize // For test, use same size
			dataOffset := tt.keyslotOffset + keyslotsAreaSize

			metadata := createMetadata(kdf, digestKDF, digestValue, opts, tt.masterKeySize,
				tt.keyslotOffset, tt.keyslotSize, keyslotsAreaSize, dataOffset)

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
