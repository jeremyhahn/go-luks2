// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"crypto/aes"
	"fmt"
	"os"

	"golang.org/x/crypto/xts"
)

// Format creates a new LUKS2 volume
func Format(opts FormatOptions) error {
	// Validate options
	if err := ValidateFormatOptions(opts); err != nil {
		return err
	}

	// Acquire file lock for exclusive access
	lock, err := AcquireFileLock(opts.Device)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	// Set defaults
	if opts.Cipher == "" {
		opts.Cipher = DefaultCipher
	}
	if opts.CipherMode == "" {
		opts.CipherMode = DefaultCipherMode
	}
	if opts.KeySize == 0 {
		opts.KeySize = DefaultKeySize
	}
	if opts.HashAlgo == "" {
		opts.HashAlgo = DefaultHashAlgo
	}
	if opts.SectorSize == 0 {
		opts.SectorSize = DefaultSectorSize
	}

	// Open device
	f, err := os.OpenFile(opts.Device, os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open device: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Generate master key
	masterKeySize := opts.KeySize / 8 // Convert bits to bytes
	masterKey, err := randomBytes(masterKeySize)
	if err != nil {
		return fmt.Errorf("failed to generate master key: %w", err)
	}
	defer clearBytes(masterKey)

	// Create binary header
	hdr, err := CreateBinaryHeader(opts)
	if err != nil {
		return err
	}

	// Create KDF for keyslot 0
	kdf, err := CreateKDF(opts, masterKeySize)
	if err != nil {
		return err
	}

	// Derive key from passphrase
	passphraseKey, err := DeriveKey(opts.Passphrase, kdf, masterKeySize)
	if err != nil {
		return err
	}
	defer clearBytes(passphraseKey)

	// Create digest KDF and digest
	digestKDF, digestValue, err := createDigest(masterKey, opts.HashAlgo)
	if err != nil {
		return err
	}

	// Apply anti-forensic split to master key
	afData, err := AFSplit(masterKey, AFStripes, opts.HashAlgo)
	if err != nil {
		return err
	}
	defer clearBytes(afData)

	// Encrypt AF-split key material with passphrase-derived key
	encryptedKeyMaterial, err := encryptKeyMaterial(afData, passphraseKey, opts.Cipher)
	if err != nil {
		return err
	}
	defer clearBytes(encryptedKeyMaterial)

	// Calculate offsets and sizes
	const keyslotAreaStart = 0x8000 // 32KB (after both headers)
	keyMaterialSize := len(encryptedKeyMaterial)
	alignedKeyMaterialSize := alignTo(int64(keyMaterialSize), 4096)

	dataOffset := keyslotAreaStart + alignedKeyMaterialSize

	// Create metadata structure
	metadata := createMetadata(kdf, digestKDF, digestValue, opts, masterKeySize,
		keyslotAreaStart, int(alignedKeyMaterialSize), int(dataOffset))

	// Write headers
	if err := writeHeaderInternal(opts.Device, hdr, metadata); err != nil {
		return err
	}

	// Write encrypted key material
	if _, err := f.Seek(int64(keyslotAreaStart), 0); err != nil {
		return fmt.Errorf("failed to seek to keyslot area: %w", err)
	}
	if _, err := f.Write(encryptedKeyMaterial); err != nil {
		return fmt.Errorf("failed to write key material: %w", err)
	}

	// Pad to aligned size
	padding := make([]byte, alignedKeyMaterialSize-int64(keyMaterialSize))
	if _, err := f.Write(padding); err != nil {
		return fmt.Errorf("failed to write padding: %w", err)
	}

	return f.Sync()
}

// createMetadata creates the JSON metadata structure
func createMetadata(kdf, digestKDF *KDF, digestValue string, opts FormatOptions,
	masterKeySize, keyslotOffset, keyslotSize, dataOffset int) *LUKS2Metadata {

	// Create keyslot
	keyslots := make(map[string]*Keyslot)
	priority := 1
	keyslots["0"] = &Keyslot{
		Type:     "luks2",
		KeySize:  masterKeySize,
		Priority: &priority,
		Area: &KeyslotArea{
			Type:       "raw",
			KeySize:    masterKeySize,
			Offset:     formatSize(int64(keyslotOffset)),
			Size:       formatSize(int64(keyslotSize)),
			Encryption: opts.Cipher + "-" + opts.CipherMode,
		},
		KDF: kdf,
		AF: &AntiForensic{
			Type:    "luks1",
			Stripes: AFStripes,
			Hash:    opts.HashAlgo,
		},
	}

	// Create segments
	segments := make(map[string]*Segment)
	segments["0"] = &Segment{
		Type:       "crypt",
		Offset:     formatSize(int64(dataOffset)),
		Size:       "dynamic",
		IVTweak:    "0",
		Encryption: opts.Cipher + "-" + opts.CipherMode,
		SectorSize: opts.SectorSize,
	}

	// Create digests
	digests := make(map[string]*Digest)
	digests["0"] = &Digest{
		Type:       "pbkdf2",
		Keyslots:   []string{"0"},
		Segments:   []string{"0"},
		Hash:       digestKDF.Hash,
		Iterations: *digestKDF.Iterations,
		Salt:       digestKDF.Salt,
		Digest:     digestValue,
	}

	// Create config
	jsonSize := LUKS2DefaultSize
	config := &Config{
		JSONSize:     formatSize(int64(jsonSize)),
		KeyslotsSize: formatSize(int64(keyslotOffset + keyslotSize)),
	}

	return &LUKS2Metadata{
		Keyslots: keyslots,
		Segments: segments,
		Digests:  digests,
		Config:   config,
	}
}

// createDigest creates a digest for master key verification
func createDigest(masterKey []byte, hashAlgo string) (*KDF, string, error) {
	// Use PBKDF2 for digest with 600000 iterations (NIST recommendation)
	digestIterations := 600000

	salt, err := randomBytes(32)
	if err != nil {
		return nil, "", err
	}

	kdf := &KDF{
		Type:       "pbkdf2",
		Hash:       hashAlgo,
		Salt:       encodeBase64(salt),
		Iterations: &digestIterations,
	}

	digest, err := DeriveKey(masterKey, kdf, 32) // 32 bytes digest
	if err != nil {
		return nil, "", err
	}
	defer clearBytes(digest)

	return kdf, encodeBase64(digest), nil
}

// encryptKeyMaterial encrypts the key material using AES-XTS
func encryptKeyMaterial(data, key []byte, cipherAlgo string) ([]byte, error) {
	if cipherAlgo != "aes" {
		return nil, fmt.Errorf("unsupported cipher: %s", cipherAlgo)
	}

	// XTS requires key length to be 32, 64 bytes (for AES-128-XTS, AES-256-XTS)
	// The key is already the correct size (64 bytes for 512-bit keys)
	// XTS will internally split it: first half for cipher, second half for tweak
	xtsCipher, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create XTS cipher: %w", err)
	}

	// Encrypt in 512-byte sectors
	encrypted := make([]byte, len(data))
	sectorSize := 512
	numSectors := (len(data) + sectorSize - 1) / sectorSize

	for i := 0; i < numSectors; i++ {
		start := i * sectorSize
		end := start + sectorSize
		if end > len(data) {
			end = len(data)
		}

		sector := make([]byte, sectorSize)
		copy(sector, data[start:end])

		encSector := make([]byte, sectorSize)
		xtsCipher.Encrypt(encSector, sector, uint64(i)) // #nosec G115 - loop counter bounded by data length

		copy(encrypted[start:end], encSector[:end-start])

		// Clear temporary buffers
		clearBytes(sector)
		clearBytes(encSector)
	}

	return encrypted, nil
}

// decryptKeyMaterial decrypts the key material using AES-XTS
func decryptKeyMaterial(data, key []byte, cipherAlgo string, sectorSize int) ([]byte, error) {
	if cipherAlgo != "aes" {
		return nil, fmt.Errorf("unsupported cipher: %s", cipherAlgo)
	}

	// XTS requires key length to be 32, 64 bytes (for AES-128-XTS, AES-256-XTS)
	// The key is already the correct size (64 bytes for 512-bit keys)
	// XTS will internally split it: first half for cipher, second half for tweak
	xtsCipher, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create XTS cipher: %w", err)
	}

	// Decrypt in sectors
	decrypted := make([]byte, len(data))
	numSectors := (len(data) + sectorSize - 1) / sectorSize

	for i := 0; i < numSectors; i++ {
		start := i * sectorSize
		end := start + sectorSize
		if end > len(data) {
			end = len(data)
		}

		sector := make([]byte, sectorSize)
		copy(sector, data[start:end])

		decSector := make([]byte, sectorSize)
		xtsCipher.Decrypt(decSector, sector, uint64(i)) // #nosec G115 - loop counter bounded by data length

		copy(decrypted[start:end], decSector[:end-start])

		// Clear temporary buffers
		clearBytes(sector)
		clearBytes(decSector)
	}

	return decrypted, nil
}
