// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"encoding/json"
)

// LUKS2 on-disk format constants
const (
	LUKS2Magic       = "LUKS\xba\xbe"
	LUKS2MagicLen    = 6
	LUKS2Version     = 2
	LUKS2SectorSize  = 512
	LUKS2HeaderSize  = 4096
	LUKS2DefaultSize = 12288 // 12KB JSON size (4096 + 12288 = 16KB total per header)

	// Anti-forensic stripes (LUKS standard)
	AFStripes = 4000

	// Default encryption parameters
	DefaultCipher     = "aes"
	DefaultCipherMode = "xts-plain64"
	DefaultHashAlgo   = "sha256"
	DefaultKeySize    = 512 // bits (64 bytes)
	DefaultSectorSize = 512
)

// LUKS2BinaryHeader represents the binary header structure (4096 bytes)
type LUKS2BinaryHeader struct {
	Magic             [6]byte   // "LUKS\xba\xbe"
	Version           uint16    // 2
	HeaderSize        uint64    // Size of binary + JSON area
	SequenceID        uint64    // Incremented on updates
	Label             [48]byte  // Volume label
	ChecksumAlgorithm [32]byte  // "sha256"
	Salt              [64]byte  // Salt for checksum
	UUID              [40]byte  // Volume UUID
	SubsystemLabel    [48]byte  // Subsystem label (optional)
	HeaderOffset      uint64    // Offset of this header (0 or 0x4000)
	_                 [184]byte // Reserved
	Checksum          [64]byte  // Header checksum
	// Padding to 4096 bytes total (LUKS2HeaderSize)
	// 4096 - (6+2+8+8+48+32+64+40+48+8+184+64) = 4096 - 512 = 3584
	_ [3584]byte
}

// LUKS2Metadata represents the JSON metadata structure
type LUKS2Metadata struct {
	Keyslots map[string]*Keyslot `json:"keyslots"`
	Tokens   map[string]*Token   `json:"tokens,omitempty"`
	Segments map[string]*Segment `json:"segments"`
	Digests  map[string]*Digest  `json:"digests"`
	Config   *Config             `json:"config"`
}

// Keyslot represents a key slot in LUKS2
type Keyslot struct {
	Type     string                 `json:"type"`     // "luks2"
	KeySize  int                    `json:"key_size"` // Key size in bytes
	Priority *int                   `json:"priority,omitempty"`
	Area     *KeyslotArea           `json:"area"`
	KDF      *KDF                   `json:"kdf"`
	AF       *AntiForensic          `json:"af,omitempty"`
	Custom   map[string]interface{} `json:"-"` // For unknown fields
}

// KeyslotArea defines the encrypted key material storage area
type KeyslotArea struct {
	Type       string `json:"type"`       // "raw"
	KeySize    int    `json:"key_size"`   // Size of encrypted key
	Offset     string `json:"offset"`     // Offset in bytes (as string)
	Size       string `json:"size"`       // Size in bytes (as string)
	Encryption string `json:"encryption"` // e.g., "aes-xts-plain64"
}

// KDF represents key derivation function parameters
type KDF struct {
	Type       string `json:"type"`                 // "pbkdf2" or "argon2i" or "argon2id"
	Hash       string `json:"hash,omitempty"`       // For pbkdf2: "sha256", "sha512"
	Salt       string `json:"salt"`                 // Base64-encoded salt
	Iterations *int   `json:"iterations,omitempty"` // For pbkdf2
	Time       *int   `json:"time,omitempty"`       // For argon2
	Memory     *int   `json:"memory,omitempty"`     // For argon2 (KB)
	CPUs       *int   `json:"cpus,omitempty"`       // For argon2
}

// AntiForensic represents anti-forensic information splitting parameters
type AntiForensic struct {
	Type    string `json:"type"`    // "luks1"
	Stripes int    `json:"stripes"` // Always 4000 for compatibility
	Hash    string `json:"hash"`    // Hash algorithm
}

// Token represents optional token metadata (TPM, FIDO2, etc.)
type Token struct {
	Type     string   `json:"type"`
	Keyslots []string `json:"keyslots"`

	// FIDO2-specific fields (for type "fido2-manual")
	FIDO2Credential string `json:"fido2-credential,omitempty"`
	FIDO2Salt       string `json:"fido2-salt,omitempty"`
	FIDO2RP         string `json:"fido2-rp,omitempty"`
	FIDO2UPRequired bool   `json:"fido2-up-required,omitempty"`

	// TPM-specific fields (for type "systemd-tpm2")
	TPM2Hash       string `json:"tpm2-hash,omitempty"`
	TPM2PolicyHash string `json:"tpm2-policy-hash,omitempty"`
	TPM2PCRBank    string `json:"tpm2-pcr-bank,omitempty"`
	TPM2PCRs       []int  `json:"tpm2-pcrs,omitempty"`
	TPM2Blob       string `json:"tpm2-blob,omitempty"`
	TPM2PublicKey  string `json:"tpm2-pubkey,omitempty"`
	TPM2SRKNV      string `json:"tpm2-srk-nv,omitempty"`
	TPM2KeyHandle  uint64 `json:"tpm2-key-handle,omitempty"`
}

// Segment represents a data segment on the device
type Segment struct {
	Type       string `json:"type"`       // "crypt"
	Offset     string `json:"offset"`     // Offset in bytes (as string)
	Size       string `json:"size"`       // Size in bytes or "dynamic"
	IVTweak    string `json:"iv_tweak"`   // IV tweak value
	Encryption string `json:"encryption"` // e.g., "aes-xts-plain64"
	SectorSize int    `json:"sector_size"`
}

// Digest represents a key digest for verification
type Digest struct {
	Type       string   `json:"type"`     // "pbkdf2"
	Keyslots   []string `json:"keyslots"` // Which keyslots this digest applies to
	Segments   []string `json:"segments"` // Which segments use this key
	Hash       string   `json:"hash"`     // Hash algorithm
	Iterations int      `json:"iterations"`
	Salt       string   `json:"salt"`   // Base64-encoded
	Digest     string   `json:"digest"` // Base64-encoded digest value
}

// Config represents global configuration
type Config struct {
	JSONSize     string   `json:"json_size"`     // JSON area size (as string)
	KeyslotsSize string   `json:"keyslots_size"` // Keyslot area size (as string)
	Flags        []string `json:"flags,omitempty"`
	Requirements []string `json:"requirements,omitempty"`
}

// FormatOptions contains options for formatting a LUKS2 volume
type FormatOptions struct {
	Device         string // Path to device/file
	Passphrase     []byte // Initial passphrase
	Label          string // Volume label (optional)
	Subsystem      string // Subsystem label (optional)
	Cipher         string // Cipher algorithm (default: "aes")
	CipherMode     string // Cipher mode (default: "xts-plain64")
	KeySize        int    // Key size in bits (default: 512)
	HashAlgo       string // Hash algorithm (default: "sha256")
	SectorSize     int    // Sector size (default: 512)
	KDFType        string // KDF type: "pbkdf2", "argon2i", "argon2id" (default: "argon2id")
	PBKDFIterTime  int    // Target ms for PBKDF2 (default: 2000)
	Argon2Time     int    // Argon2 time cost (default: 4)
	Argon2Memory   int    // Argon2 memory cost in KB (default: 1048576 = 1GB)
	Argon2Parallel int    // Argon2 parallelism (default: 4)
}

// VolumeInfo contains information about a LUKS volume
type VolumeInfo struct {
	UUID           string
	Label          string
	Version        int
	Cipher         string
	KeySize        int
	SectorSize     int
	ActiveKeyslots []int
	Metadata       *LUKS2Metadata
}

// UnmarshalJSON custom unmarshaler to handle unknown fields in keyslots
func (k *Keyslot) UnmarshalJSON(data []byte) error {
	type Alias Keyslot
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(k),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Store in map for later if needed
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	k.Custom = raw

	return nil
}
