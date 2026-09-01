// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"encoding/json"
	"fmt"
)

// LUKS2 on-disk format constants
// These match cryptsetup's lib/luks2/luks2.h for maximum compatibility
const (
	LUKS2Magic = "LUKS\xba\xbe"

	// LUKS2SecondaryMagic is the magic of the SECOND header copy, and it is not
	// the primary magic. LUKS2 spells the second copy "SKUL\xba\xbe" -- the
	// first four bytes reversed -- precisely so that a tool scanning a device
	// cannot mistake a backup header for the start of a container. cryptsetup
	// enforces this: a second copy carrying the primary magic is not read as a
	// header at all, so the backup written for the case of a damaged primary is
	// unusable for exactly the repair it exists to perform (#64).
	LUKS2SecondaryMagic = "SKUL\xba\xbe"

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

	// LUKS2 header size limits (matching cryptsetup)
	// Reference: cryptsetup/lib/luks2/luks2.h
	LUKS2HeaderMinSize     = 0x4000    // 16 KiB - minimum header size per copy
	LUKS2HeaderDefaultSize = 0x1000000 // 16 MiB - default total metadata area size
	LUKS2HeaderMaxOffset   = 0x400000  // 4 MiB - maximum offset for secondary header
	LUKS2MaxKeyslotsSize   = 0x8000000 // 128 MiB - maximum keyslots area size
	LUKS2MaxKeyslots       = 32        // Maximum number of keyslots

	// Default keyslots area size (matching cryptsetup)
	// Formula: LUKS2_DEFAULT_HDR_SIZE - 2 * metadata_size
	// With 16 KiB metadata: 16 MiB - 32 KiB ≈ 16 MiB
	LUKS2DefaultKeyslotsSize = LUKS2HeaderDefaultSize - 2*LUKS2HeaderMinSize
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

// LUKS2Metadata represents the JSON metadata structure.
//
// keyslots, tokens, segments, digests and config are all MANDATORY LUKS2 JSON
// objects. cryptsetup's hdr_validate_json checks for the presence of each by
// name and fails the whole header when one is absent -- "JSON area \"\" is
// missing \"tokens\" (object) specification" -> "LUKS2 validation failed" ->
// the device is not a valid LUKS device. Absent is not the same as empty: a
// container with no tokens carries `"tokens": {}`.
//
// So none of these fields may carry `omitempty`, and none may be marshaled
// while nil -- a nil Go map encodes as `null`, which is a JSON value of the
// wrong type rather than an empty object and is rejected the same way.
// ensureRequiredObjects enforces the non-nil half immediately before every
// write; the struct tags enforce the emitted-at-all half here.
type LUKS2Metadata struct {
	Keyslots map[string]*Keyslot `json:"keyslots"`
	Tokens   map[string]*Token   `json:"tokens"`
	Segments map[string]*Segment `json:"segments"`
	Digests  map[string]*Digest  `json:"digests"`
	Config   *Config             `json:"config"`

	// DroppedNullEntries names the keyslot and token entries this read
	// REMOVED because the header spelled them as JSON null. It is nil for
	// every intact header.
	//
	// It is diagnostic state on a type that otherwise models on-disk
	// structure, and that is a deliberate trade rather than an oversight
	// (#27). The alternatives were worse: a logger in a Layer-0 primitive
	// imposes a logging decision on every embedding application, a variadic
	// option on ReadHeader permanently widens the package's simplest entry
	// point to serve a rare diagnostic, and a second sibling read invites
	// the two readers to drift -- which is the failure mode this package has
	// hit repeatedly. A json:"-" field costs nothing at any call site and
	// adds no second way to read a header.
	//
	// It describes THIS read and nothing else. It is never marshaled, so it
	// cannot reach the disk; it is not maintained as a caller mutates the
	// metadata; and it says nothing about what a subsequent write will
	// contain. What it is for is the one thing a caller could not previously
	// learn: that a ReadHeader -> mutate -> WriteHeader cycle is about to
	// drop these entries from the on-disk header, which is a repair an
	// operator should be able to find out about afterwards.
	DroppedNullEntries []DroppedEntry `json:"-"`
}

// DroppedEntry identifies one metadata entry removed by ReadHeader because the
// header spelled it as JSON null.
//
// Kind is what the id names -- "keyslot" or "token" -- and it is carried
// rather than left to the caller to infer, because the two id spaces are
// independent: keyslot 0 and token 0 are different things, and a bare list of
// ids cannot say which was lost.
type DroppedEntry struct {
	Kind string
	ID   string
}

// String renders an entry as `keyslot "3"`, so a caller that only wants to put
// it in front of an operator does not have to decide on a spelling.
func (d DroppedEntry) String() string {
	return fmt.Sprintf("%s %q", d.Kind, d.ID)
}

// The kinds DroppedEntry carries. They are constants rather than literals at
// the two sites that produce them so a consumer switching on Kind cannot be
// broken by a typo on either side.
const (
	DroppedKindKeyslot = "keyslot"
	DroppedKindToken   = "token"
)

// ensureRequiredObjects initializes the mandatory LUKS2 JSON objects that are
// nil, so they marshal as `{}` rather than `null`.
//
// It is called on the single path that serializes metadata to disk rather than
// at each construction site: metadata reaches that path both from Format (which
// builds it) and from ReadHeader (which parses it, and yields nil maps for any
// object a foreign writer omitted), and only one of those is under this
// package's control.
//
// Config is deliberately NOT invented here. An empty config object would pass
// the presence check and then fail on its mandatory json_size/keyslots_size
// members, turning a missing-config bug into a harder-to-read one.
func (m *LUKS2Metadata) ensureRequiredObjects() {
	if m.Keyslots == nil {
		m.Keyslots = make(map[string]*Keyslot)
	}
	if m.Tokens == nil {
		m.Tokens = make(map[string]*Token)
	}
	if m.Segments == nil {
		m.Segments = make(map[string]*Segment)
	}
	if m.Digests == nil {
		m.Digests = make(map[string]*Digest)
	}
}

// Keyslot represents a key slot in LUKS2
type Keyslot struct {
	Type     string       `json:"type"`     // "luks2"
	KeySize  int          `json:"key_size"` // Key size in bytes
	Priority *int         `json:"priority,omitempty"`
	Area     *KeyslotArea `json:"area"`
	KDF      *KDF         `json:"kdf"`
	// AF is mandatory for a keyslot of type "luks2" -- cryptsetup's luks2
	// keyslot validator requires the object -- so it carries no omitempty.
	// A nil AF here is a bug in the caller either way; emitting `"af": null`
	// makes it visible instead of producing a keyslot that merely looks
	// well-formed.
	AF     *AntiForensic          `json:"af"`
	Custom map[string]interface{} `json:"-"` // For unknown fields
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
	Type string `json:"type"` // "pbkdf2"

	// Keyslots names the keyslots this digest authenticates. It is
	// LOAD-BEARING, in this library and in cryptsetup, and it has two readers
	// rather than one.
	//
	// The internal reader is verifyMasterKey, which consults it BEFORE any
	// derivation and skips every digest that does not name the keyslot being
	// opened. Trying every digest against a key recovered from ONE keyslot
	// accepts that key on the strength of an attestation made about a
	// different keyslot -- and a container legitimately holds more than one
	// volume key, which is the ordinary state mid-reencryption. A keyslot no
	// digest names cannot be authenticated at all and is reported as
	// ErrInvalidHeader: a header defect, not a credential verdict. See
	// verifyMasterKey in unlock.go for the full reasoning and
	// TestADigestCannotAuthenticateAKeyslotItDoesNotName for the pin.
	//
	// The external reader is cryptsetup, which uses the same coverage to
	// decide which digest validates which keyslot. That reader is why the
	// field could never have been deleted as unused even while nothing here
	// read it -- #32 exists because "never read internally" is not "unused",
	// and it recorded the external reader by name so nobody reached for the
	// delete key. The internal reader has since landed, so the two now agree:
	// a header's coverage means the same thing to this library and to
	// cryptsetup, rather than being enforced by one and ignored by the other.
	//
	// AddKey appends to it, KillKeyslot and the null-normalization sweep strip
	// from it. Those are maintenance, not consumption; the two readers above
	// are what the maintenance is for.
	Keyslots []string `json:"keyslots"`

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
	Device string // Path to device/file
	// Passphrase is the initial passphrase. It is the CALLER'S memory and
	// stays that way: this package borrows it for the key derivation and
	// neither locks nor wipes a buffer it does not own. Everything derived
	// from it is held in protected memory -- see pkg/luks2/enclave.go.
	Passphrase     []byte
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
