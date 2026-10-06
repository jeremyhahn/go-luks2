// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// LUKS2 on-disk format constants and types now live in internal/header; see
// docs/design/DECISIONS.md's H5 entry. These are transitional aliases, kept
// under their original names so that every existing caller and test in this
// package keeps compiling unchanged. They are removed, along with every
// other alias in this file, at H13.
const (
	LUKS2Magic          = header.Magic
	LUKS2SecondaryMagic = header.SecondaryMagic
	LUKS2MagicLen       = header.MagicLen
	LUKS2Version        = header.Version
	LUKS2SectorSize     = header.SectorSize
	LUKS2HeaderSize     = header.HeaderSize
	LUKS2DefaultSize    = header.DefaultSize

	// AFStripes is the anti-forensic stripe count (LUKS standard).
	AFStripes = header.AFStripes

	// Default encryption parameters. These are pkg/luks2's own public policy
	// defaults, not part of the on-disk model, so they stay here rather than
	// moving to internal/header.
	DefaultCipher     = "aes"
	DefaultCipherMode = "xts-plain64"
	DefaultHashAlgo   = "sha256"
	DefaultKeySize    = 512 // bits (64 bytes)
	DefaultSectorSize = 512

	// LUKS2 header size limits (matching cryptsetup).
	LUKS2HeaderMinSize     = header.HeaderMinSize
	LUKS2HeaderDefaultSize = header.HeaderDefaultSize
	LUKS2HeaderMaxOffset   = header.HeaderMaxOffset
	LUKS2MaxKeyslotsSize   = header.MaxKeyslotsSize
	LUKS2MaxKeyslots       = header.MaxKeyslots

	// LUKS2DefaultKeyslotsSize is the default keyslots area size (matching
	// cryptsetup).
	LUKS2DefaultKeyslotsSize = header.DefaultKeyslotsSize

	DroppedKindKeyslot = header.DroppedKindKeyslot
	DroppedKindToken   = header.DroppedKindToken

	// The token types systemd defines and dispatches on.
	TokenTypeSystemdFIDO2    = header.TokenTypeSystemdFIDO2
	TokenTypeSystemdRecovery = header.TokenTypeSystemdRecovery
)

// The LUKS2 on-disk model: the binary header, the JSON metadata objects, the
// requirements object and its error, and the JSON passthrough error. All are
// type aliases of internal/header's types, so every field, method and tag
// this package's code already depends on is unchanged.
type (
	LUKS2BinaryHeader           = header.BinaryHeader
	LUKS2Metadata               = header.Metadata
	DroppedEntry                = header.DroppedEntry
	Keyslot                     = header.Keyslot
	KeyslotArea                 = header.KeyslotArea
	KDF                         = header.KDF
	AntiForensic                = header.AntiForensic
	Token                       = header.Token
	Segment                     = header.Segment
	Digest                      = header.Digest
	Config                      = header.Config
	Requirements                = header.Requirements
	UnsupportedRequirementError = header.UnsupportedRequirementError
	MetadataJSONError           = header.MetadataJSONError
)

// FormatOptions contains options for formatting a LUKS2 volume
type FormatOptions struct {
	Device string // Path to device/file
	// Passphrase is the initial passphrase. It is the CALLER'S memory and
	// stays that way: this package borrows it for the key derivation and
	// neither locks nor wipes a buffer it does not own. Everything derived
	// from it is held in protected memory -- see internal/secret.
	Passphrase      []byte
	Label           string // Volume label (optional)
	Subsystem       string // Subsystem label (optional)
	Cipher          string // Cipher algorithm (default: "aes")
	CipherMode      string // Cipher mode (default: "xts-plain64")
	KeySize         int    // Key size in bits (default: 512)
	HashAlgo        string // Hash algorithm (default: "sha256")
	SectorSize      int    // Sector size (default: 512)
	KDFType         string // KDF type: "pbkdf2[-sha*]", "argon2i", "argon2id" (default: DefaultKDFType -- "pbkdf2-sha512" in FIPS mode, else "argon2id")
	PBKDFIterTime   int    // Target ms for PBKDF2, 1..600000 (default: 2000); calibrated, never assumed
	PBKDFIterations int    // Exact PBKDF2 iterations; skips calibration when non-zero. Bounded -- see forcedPBKDF2Iterations
	Argon2Time      int    // Argon2 time cost (default: 4)
	Argon2Memory    int    // Argon2 memory cost in KB (default: 1048576 = 1GB)
	Argon2Parallel  int    // Argon2 parallelism (default: 4)

	// MetadataSize is the size of ONE header copy -- the 4096-byte binary
	// header plus its JSON area -- in bytes, the equivalent of cryptsetup's
	// --luks2-metadata-size. Zero selects the default, 16 KiB, which leaves
	// 12288 bytes for JSON. Otherwise it must be a power of two from 16 KiB to
	// 4 MiB; anything else is refused with ErrInvalidMetadataSize.
	//
	// The size is fixed for the life of the container: the second header copy
	// starts at MetadataSize, the keyslots area at 2 x MetadataSize, and the
	// keyslots area is sized so the data segment still starts at 16 MiB, as
	// cryptsetup lays it out. Choose a larger size up front when the container
	// will carry large tokens; metadata that does not fit is refused with
	// ErrMetadataTooLarge rather than grown into.
	MetadataSize int
}

// VolumeInfo contains information about a LUKS volume
type VolumeInfo struct {
	UUID    string
	Label   string
	Version int
	Cipher  string
	// KeySize is the volume key size in BITS, as FormatOptions.KeySize states
	// it: the key_size of a keyslot attested for the crypt segment, times 8.
	// It is 0 when no keyslot is attested for that segment.
	KeySize        int
	SectorSize     int
	ActiveKeyslots []int
	Metadata       *LUKS2Metadata
}
