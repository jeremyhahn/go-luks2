// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// LUKS2 on-disk format constants.
// These match cryptsetup's lib/luks2/luks2.h for maximum compatibility.
const (
	Magic = "LUKS\xba\xbe"

	// SecondaryMagic is the second header copy's magic, "SKUL\xba\xbe", which cryptsetup requires.
	SecondaryMagic = "SKUL\xba\xbe"

	MagicLen    = 6
	Version     = 2
	SectorSize  = 512
	HeaderSize  = 4096
	DefaultSize = 12288 // 12KB JSON size (4096 + 12288 = 16KB total per header)

	// AFStripes is the anti-forensic stripe count (LUKS standard).
	AFStripes = 4000

	// LUKS2 header size limits (matching cryptsetup).
	// Reference: cryptsetup/lib/luks2/luks2.h
	HeaderMinSize     = 0x4000    // 16 KiB - minimum header size per copy
	HeaderDefaultSize = 0x1000000 // 16 MiB - default total metadata area size
	HeaderMaxOffset   = 0x400000  // 4 MiB - maximum offset for secondary header
	MaxKeyslotsSize   = 0x8000000 // 128 MiB - maximum keyslots area size
	MaxKeyslots       = 32        // Maximum number of keyslots

	// DefaultKeyslotsSize is the default keyslots area size, matching cryptsetup.
	DefaultKeyslotsSize = HeaderDefaultSize - 2*HeaderMinSize

	// PrimaryHeaderOffset is where the first header copy starts.
	PrimaryHeaderOffset int64 = 0

	// SecondaryHeaderOffset is where the second header copy starts for the default 16 KiB metadata size.
	SecondaryHeaderOffset int64 = 0x4000

	// HeaderMaxSize bounds the header size accepted from disk: LUKS2 allows up to 4 MiB of metadata per copy.
	HeaderMaxSize = 0x400000 // 4 MiB
)

// ChecksumFieldOffset is where the 64-byte checksum field sits inside the 4096-byte binary header.
const ChecksumFieldOffset = 0x1C0

// BinaryHeader represents the binary header structure (4096 bytes).
type BinaryHeader struct {
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
	// Padding to 4096 bytes total (HeaderSize)
	// 4096 - (6+2+8+8+48+32+64+40+48+8+184+64) = 4096 - 512 = 3584
	_ [3584]byte
}

// Metadata represents the JSON metadata; keyslots, tokens, segments, digests and config are mandatory objects, so none is omitempty or nil when written.
type Metadata struct {
	Keyslots map[string]*Keyslot `json:"keyslots"`
	Tokens   map[string]*Token   `json:"tokens"`
	Segments map[string]*Segment `json:"segments"`
	Digests  map[string]*Digest  `json:"digests"`
	Config   *Config             `json:"config"`

	// DroppedNullEntries names the keyslot and token entries this read removed because they were JSON null; never marshaled, nil for an intact header.
	DroppedNullEntries []DroppedEntry `json:"-"`
}

// DroppedEntry identifies one keyslot or token entry ReadHeader removed because the header spelled it as JSON null.
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

// ensureRequiredObjects initializes nil mandatory objects so they marshal as {} rather than null; Config is never invented.
func (m *Metadata) ensureRequiredObjects() {
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

// Keyslot represents a LUKS2 keyslot; field order is cryptsetup's member order, and unmodeled members round-trip (unknownfields.go).
type Keyslot struct {
	Type    string `json:"type"`     // "luks2"
	KeySize int    `json:"key_size"` // Key size in bytes

	// AF and KDF are omitempty because a reencrypt keyslot has neither; validateKeyslot requires them on a luks2 keyslot.
	AF   *AntiForensic `json:"af,omitempty"`
	Area *KeyslotArea  `json:"area"`
	KDF  *KDF          `json:"kdf,omitempty"`

	// Priority is 0 (ignore), 1 (normal) or 2 (prefer); nil means normal, and it is declared last, where cryptsetup emits it.
	Priority *int `json:"priority,omitempty"`

	unknown unknownFields
}

// KeyslotArea defines a keyslot's storage area, in cryptsetup's member order; encryption and key_size are omitempty because a reencrypt area has neither.
type KeyslotArea struct {
	Type       string `json:"type"`                 // "raw"
	Offset     string `json:"offset"`               // Offset in bytes (as string)
	Size       string `json:"size"`                 // Size in bytes (as string)
	Encryption string `json:"encryption,omitempty"` // e.g., "aes-xts-plain64"
	KeySize    int    `json:"key_size,omitempty"`   // Size of encrypted key

	unknown unknownFields
}

// KDF represents key derivation parameters; member order fits both pbkdf2 and argon2 shapes, salt last.
type KDF struct {
	Type       string `json:"type"`                 // "pbkdf2" or "argon2i" or "argon2id"
	Hash       string `json:"hash,omitempty"`       // For pbkdf2: "sha256", "sha512"
	Iterations *int   `json:"iterations,omitempty"` // For pbkdf2
	Time       *int   `json:"time,omitempty"`       // For argon2
	Memory     *int   `json:"memory,omitempty"`     // For argon2 (KB)
	CPUs       *int   `json:"cpus,omitempty"`       // For argon2
	Salt       string `json:"salt"`                 // Base64-encoded salt

	unknown unknownFields
}

// AntiForensic represents anti-forensic information splitting parameters.
type AntiForensic struct {
	Type    string `json:"type"`    // "luks1"
	Stripes int    `json:"stripes"` // Always 4000 for compatibility
	Hash    string `json:"hash"`    // Hash algorithm

	unknown unknownFields
}

// The token types systemd-cryptsetup dispatches on, as spelled in systemd 255.
const (
	// TokenTypeSystemdFIDO2 is the token systemd-cryptenroll --fido2-device
	// writes.
	TokenTypeSystemdFIDO2 = "systemd-fido2"

	// TokenTypeSystemdRecovery is the token systemd-cryptenroll
	// --recovery-key writes. It carries nothing but its type and keyslots:
	// the recovery key IS the passphrase, so there is no material to record.
	TokenTypeSystemdRecovery = "systemd-recovery"
)

// Token represents optional token metadata (TPM, FIDO2, etc.); unmodeled members round-trip verbatim.
type Token struct {
	Type     string   `json:"type"`
	Keyslots []string `json:"keyslots"`

	// FIDO2 fields for TokenTypeSystemdFIDO2, in systemd's names, spelling and order.
	FIDO2Credential string `json:"fido2-credential,omitempty"`
	FIDO2Salt       string `json:"fido2-salt,omitempty"`
	FIDO2RP         string `json:"fido2-rp,omitempty"`

	// Pointers because systemd writes false on purpose.
	FIDO2ClientPinRequired *bool `json:"fido2-clientPin-required,omitempty"`
	FIDO2UPRequired        *bool `json:"fido2-up-required,omitempty"`
	FIDO2UVRequired        *bool `json:"fido2-uv-required,omitempty"`

	// No TPM2 fields: a systemd-tpm2 token round-trips through the unmodeled-member passthrough.

	unknown unknownFields
}

// Segment represents a data segment on the device.
type Segment struct {
	Type       string `json:"type"`       // "crypt"
	Offset     string `json:"offset"`     // Offset in bytes (as string)
	Size       string `json:"size"`       // Size in bytes or "dynamic"
	IVTweak    string `json:"iv_tweak"`   // IV tweak value
	Encryption string `json:"encryption"` // e.g., "aes-xts-plain64"
	SectorSize int    `json:"sector_size"`

	unknown unknownFields
}

// HasIntegrity reports whether the segment carries an "integrity" member this
// package does not model -- a segment on dm-integrity, which this package
// does not implement.
func (x *Segment) HasIntegrity() bool {
	_, ok := x.unknown["integrity"]
	return ok
}

// IntegrityKeySize reports integrity.key_size in bytes; present is false when the segment declares none.
func (x *Segment) IntegrityKeySize() (size int64, present bool) {
	var integrity struct {
		KeySize *json.RawMessage `json:"key_size"`
	}
	raw, ok := x.unknown["integrity"]
	if !ok || json.Unmarshal(raw, &integrity) != nil || integrity.KeySize == nil {
		return 0, false
	}
	size, err := strconv.ParseInt(string(*integrity.KeySize), 10, 64)
	if err != nil {
		return 0, false
	}
	return size, true
}

// SetUnknownMember sets a member this package does not model, as though the
// decoder had carried it in. It exists for callers -- chiefly tests -- that
// build a Segment synthetically rather than through ParseJSONMetadata.
func (x *Segment) SetUnknownMember(name string, raw json.RawMessage) {
	if x.unknown == nil {
		x.unknown = unknownFields{}
	}
	x.unknown[name] = raw
}

// ClearUnknownMembers removes every member this package does not model from
// the segment. See SetUnknownMember.
func (x *Segment) ClearUnknownMembers() {
	x.unknown = nil
}

// Digest represents a key digest for verification.
type Digest struct {
	Type string `json:"type"` // "pbkdf2"

	// Keyslots names the keyslots this digest authenticates; verifyMasterKey and cryptsetup both rely on it.
	Keyslots []string `json:"keyslots"`

	Segments   []string `json:"segments"` // Which segments use this key
	Hash       string   `json:"hash"`     // Hash algorithm
	Iterations int      `json:"iterations"`

	// Time, Memory and CPUs are an Argon2 digest's cost, omitted when nil; modeled so a foreign header can be migrated to PBKDF2 for FIPS.
	Time   *int `json:"time,omitempty"`
	Memory *int `json:"memory,omitempty"`
	CPUs   *int `json:"cpus,omitempty"`

	Salt   string `json:"salt"`   // Base64-encoded
	Digest string `json:"digest"` // Base64-encoded digest value

	unknown unknownFields
}

// Config represents global configuration.
type Config struct {
	JSONSize     string   `json:"json_size"`     // JSON area size (as string)
	KeyslotsSize string   `json:"keyslots_size"` // Keyslot area size (as string)
	Flags        []string `json:"flags,omitempty"`

	// Requirements is the LUKS2 requirements object, nil when the container declares none.
	Requirements *Requirements `json:"requirements,omitempty"`

	unknown unknownFields
}

// Requirements is config.requirements: an unimplemented mandatory requirement does not stop a read but refuses every write.
type Requirements struct {
	// Mandatory names requirements an implementation MUST understand to modify
	// the container. LUKS2 defines no optional counterpart today; an
	// implementation that meets an unknown entry here is required to refuse.
	Mandatory []string `json:"mandatory,omitempty"`

	unknown unknownFields
}

// UnsupportedRequirementError names the requirement that makes a container unwritable, with the whole mandatory list.
type UnsupportedRequirementError struct {
	// Requirement is the first mandatory entry this package does not implement.
	Requirement string

	// Mandatory is every mandatory requirement the container declares.
	Mandatory []string
}

func (e *UnsupportedRequirementError) Error() string {
	return fmt.Sprintf("refusing to modify the container: it requires %q, which this package does not implement (mandatory: %s)",
		e.Requirement, strings.Join(e.Mandatory, ", "))
}

func (e *UnsupportedRequirementError) Unwrap() error { return ErrUnsupportedRequirement }

// implementedRequirements is every LUKS2 mandatory requirement this package can honor on a write; currently none.
var implementedRequirements = map[string]bool{}

// CheckRequirementsImplemented refuses a container with an unimplemented mandatory requirement, reporting the first in declaration order.
func (m *Metadata) CheckRequirementsImplemented() error {
	if m == nil || m.Config == nil || m.Config.Requirements == nil {
		return nil
	}
	mandatory := m.Config.Requirements.Mandatory
	for _, requirement := range mandatory {
		if !implementedRequirements[requirement] {
			return &UnsupportedRequirementError{Requirement: requirement, Mandatory: mandatory}
		}
	}
	return nil
}
