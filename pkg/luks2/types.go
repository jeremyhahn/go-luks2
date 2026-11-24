// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// LUKS2 on-disk format constants and types live in internal/header; this
// file keeps only this package's policy defaults and the header types it
// re-exports as aliases.
const (
	// Default encryption parameters. These are pkg/luks2's own public policy
	// defaults, not part of the on-disk model, so they stay here rather than
	// moving to internal/header.
	defaultCipherAlgo = "aes"
	defaultCipherMode = "xts-plain64"
	defaultHashAlgo   = "sha256"
	DefaultKeySize    = 512 // bits (64 bytes)
	DefaultSectorSize = 512
)

type (
	// DroppedEntry is KEEP in B.6, reached through (*Header).Dropped()
	// rather than a raw metadata field, so it stays a public alias.
	DroppedEntry = header.DroppedEntry

	// LegacyToken is the on-disk token shape (systemd's FIDO2 fields and all)
	// that Token aliased before the generic, value-returning
	// Token{Type, Keyslots, Members} took the name. The pre-existing free functions in token.go (GetToken,
	// ListTokens, ImportToken, ImportTokenJSON) and this package's own old
	// enrollment path (keyprovider.go, recovery.go) still read and write this
	// shape directly; Token.toLegacyToken/tokenFromLegacy convert between the
	// two at the one boundary that needs both.
	LegacyToken = header.Token
)

// formatOptionsForTest contains options for formatting a LUKS2 volume
type formatOptionsForTest struct {
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
	KDFType         string // KDF type: "pbkdf2[-sha*]", "argon2i", "argon2id" (default: DefaultKDFSpec -- "pbkdf2-sha512" in FIPS mode, else "argon2id")
	PBKDFIterTime   int    // Target ms for PBKDF2, 1..600000 (default: 2000); calibrated, never assumed
	PBKDFIterations int    // Exact PBKDF2 iterations; skips calibration when non-zero. Bounded -- see forcedPBKDF2Iterations
	Argon2Time      int    // Argon2 time cost (default: 4)
	Argon2Memory    int    // Argon2 memory cost in KB (default: 1048576 = 1GB)
	Argon2Parallel  int    // Argon2 parallelism (default: 4)

	// MetadataSize is the size of ONE header copy -- the 4096-byte binary
	// header plus its JSON area -- in bytes, the equivalent of cryptsetup's
	// --luks2-metadata-size. Zero selects the default, 16 KiB, which leaves
	// 12288 bytes for JSON. Otherwise it must be a power of two from 16 KiB to
	// 4 MiB; anything else is refused with ErrInvalidArgument.
	//
	// The size is fixed for the life of the container: the second header copy
	// starts at MetadataSize, the keyslots area at 2 x MetadataSize, and the
	// keyslots area is sized so the data segment still starts at 16 MiB, as
	// cryptsetup lays it out. Choose a larger size up front when the container
	// will carry large tokens; metadata that does not fit is refused with
	// ErrNoSpace rather than grown into.
	MetadataSize int
}

// volumeInfoForTest contains information about a LUKS volume
type volumeInfoForTest struct {
	UUID    string
	Label   string
	Version int
	Cipher  string
	// KeySize is the volume key size in BITS, as formatOptionsForTest.KeySize states
	// it: the key_size of a keyslot attested for the crypt segment, times 8.
	// It is 0 when no keyslot is attested for that segment.
	KeySize        int
	SectorSize     int
	ActiveKeyslots []int
	Metadata       *header.Metadata
}
