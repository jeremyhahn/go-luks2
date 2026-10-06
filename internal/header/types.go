// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"encoding/json"
	"fmt"
	"strings"
)

// LUKS2 on-disk format constants.
// These match cryptsetup's lib/luks2/luks2.h for maximum compatibility.
const (
	Magic = "LUKS\xba\xbe"

	// SecondaryMagic is the magic of the SECOND header copy, and it is not
	// the primary magic. LUKS2 spells the second copy "SKUL\xba\xbe" -- the
	// first four bytes reversed -- precisely so that a tool scanning a device
	// cannot mistake a backup header for the start of a container. cryptsetup
	// enforces this: a second copy carrying the primary magic is not read as a
	// header at all, so the backup written for the case of a damaged primary is
	// unusable for exactly the repair it exists to perform (#64).
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

	// DefaultKeyslotsSize is the default keyslots area size (matching
	// cryptsetup).
	// Formula: HeaderDefaultSize - 2 * metadata_size
	// With 16 KiB metadata: 16 MiB - 32 KiB ~= 16 MiB
	DefaultKeyslotsSize = HeaderDefaultSize - 2*HeaderMinSize

	// PrimaryHeaderOffset is where the first header copy starts.
	PrimaryHeaderOffset int64 = 0

	// SecondaryHeaderOffset is where the second header copy starts for the
	// DEFAULT 16 KiB metadata size. It is the primary copy's total area size,
	// not a free-standing constant: a container written with a larger
	// metadata area puts its second copy correspondingly further out.
	SecondaryHeaderOffset int64 = 0x4000

	// HeaderMaxSize bounds the header size accepted from disk. The LUKS2
	// on-disk format allows a metadata area up to 4 MiB per copy; anything
	// beyond that is a malformed or hostile header rather than a volume this
	// library wrote.
	HeaderMaxSize = 0x400000 // 4 MiB
)

// ChecksumFieldOffset is where the 64-byte checksum field sits inside the
// 4096-byte binary header. It is a property of the on-disk layout, so it is
// stated once here rather than spelled as a literal at each site that has to
// blank the field before hashing over it.
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

// Metadata represents the JSON metadata structure.
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
type Metadata struct {
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

// Keyslot represents a key slot in LUKS2.
//
// FIELD ORDER IS THE ON-DISK MEMBER ORDER. encoding/json marshals a struct's
// fields in declaration order, and this order is cryptsetup 2.7.0's, measured
// with `cryptsetup luksDump --dump-json-metadata`: type, key_size, af, area,
// kdf, and priority last on the keyslots that carry one. Nothing in LUKS2
// requires a member order, so this
// buys no compatibility -- what it buys is that a header this package wrote
// and one cryptsetup wrote can be diffed, which is how the members that were
// being dropped entirely were found.
//
// Members this package does not model are carried across a read-modify-write
// cycle rather than deleted; see unknownfields.go.
type Keyslot struct {
	Type    string `json:"type"`     // "luks2"
	KeySize int    `json:"key_size"` // Key size in bytes

	// AF and KDF are mandatory for a keyslot of type "luks2" and absent from
	// one of type "reencrypt", so they carry omitempty: a keyslot legitimately
	// has neither, and LUKS2 has more than one keyslot type.
	//
	// They carried none from before this package's first release until #143 --
	// so every version shipped so far writes the nulls described below, and
	// this is a fix to existing behavior rather than to anything #143
	// introduced. The reasoning was that a nil AF is a caller bug and
	// `"af": null` makes it visible. The goal was right and the place was
	// wrong. Serialization describes what IS there; asserting what OUGHT
	// to be there is validateKeyslot's job, and it already does exactly this
	// -- it refuses a luks2 keyslot with no kdf or no af as ErrInvalidKeyslot,
	// while deliberately exempting other types (keyslotvalidation.go). That
	// check is louder than a null member and reaches every path that acts on a
	// keyslot.
	//
	// What the missing omitempty cost was the other direction. cryptsetup
	// leaves a reencrypt keyslot in the header during an online reencryption;
	// this package would read it, and the next unrelated header write would
	// hand it back to disk carrying `"af": null` and `"kdf": null` that it
	// never had. That is the read-modify-write corruption of a foreign object
	// that unknownfields.go exists to prevent, one layer down in the typed
	// half.
	//
	// Whether cryptsetup 2.7.0 REFUSES that shape is untested, and the
	// omitempty is not justified by a claim that it does. Measured: a
	// container carrying a reencrypt keyslot is refused earlier, for
	// "Missing reencryption requirement flag", with and without the null
	// members alike -- so the af/kdf check is never reached. This package
	// cannot currently produce -- or even read -- a container that gets past
	// that point: LUKS2 spells config.requirements as an object with a
	// mandatory array and Config models it as []string, which is #152. The
	// justification is fidelity: an object this package did not create goes
	// back the way it came.
	AF   *AntiForensic `json:"af,omitempty"`
	Area *KeyslotArea  `json:"area"`
	KDF  *KDF          `json:"kdf,omitempty"`

	// Priority is 0 (ignore), 1 (normal) or 2 (prefer). It is a pointer
	// because absent is meaningful: LUKS2 reads an absent priority as normal,
	// and cryptsetup writes no member at all for a normal keyslot.
	//
	// It is declared LAST because that is where cryptsetup emits it when it
	// emits it at all -- after kdf, not among the mandatory members.
	Priority *int `json:"priority,omitempty"`

	unknown unknownFields
}

// KeyslotArea defines the encrypted key material storage area.
//
// Member order is cryptsetup's: type, offset, size, encryption, key_size.
//
// Every keyslot type has an area, but they do not have the same one. A "raw"
// area holds key material and declares the encryption and key size it holds
// it under; a reencrypt keyslot's area is a checksum, journal or datashift
// region with neither, and with members -- hash, sector_size, shift_size --
// this package does not model and carries through instead. So encryption and
// key_size carry omitempty, for the same reason af and kdf do on the keyslot
// above: emitting `"encryption": ""` and `"key_size": 0` into an area that
// legitimately has neither is inventing members on an object this package did
// not create.
type KeyslotArea struct {
	Type       string `json:"type"`                 // "raw"
	Offset     string `json:"offset"`               // Offset in bytes (as string)
	Size       string `json:"size"`                 // Size in bytes (as string)
	Encryption string `json:"encryption,omitempty"` // e.g., "aes-xts-plain64"
	KeySize    int    `json:"key_size,omitempty"`   // Size of encrypted key

	unknown unknownFields
}

// KDF represents key derivation function parameters.
//
// Member order serves BOTH shapes cryptsetup emits, because salt is last in
// each: pbkdf2 is type, hash, iterations, salt, and argon2 is type, time,
// memory, cpus, salt. The members the other shape does not use carry
// omitempty and drop out.
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

// The token types systemd defines and dispatches on.
//
// The type string is not documentation: systemd-cryptsetup switches on it to
// decide which unlock plugin gets the token, so a token spelled anything else
// is one systemd will not look at. These are the literals in the systemd 255
// binary.
const (
	// TokenTypeSystemdFIDO2 is the token systemd-cryptenroll --fido2-device
	// writes.
	TokenTypeSystemdFIDO2 = "systemd-fido2"

	// TokenTypeSystemdRecovery is the token systemd-cryptenroll
	// --recovery-key writes. It carries nothing but its type and keyslots:
	// the recovery key IS the passphrase, so there is no material to record.
	TokenTypeSystemdRecovery = "systemd-recovery"
)

// Token represents optional token metadata (TPM, FIDO2, etc.).
//
// A token this package does not fully model still round-trips: members with no
// field here are carried verbatim rather than dropped. See unknownfields.go
// for why that matters -- a token is written once by whatever enrolled it, and
// every later header write by this package used to rewrite it from these
// fields alone.
type Token struct {
	Type     string   `json:"type"`
	Keyslots []string `json:"keyslots"`

	// FIDO2 fields, for TokenTypeSystemdFIDO2. Name, spelling and order are
	// systemd's -- including the camelCase in fido2-clientPin-required, which
	// is not a typo here and would be a token systemd cannot read if it were
	// normalized.
	FIDO2Credential string `json:"fido2-credential,omitempty"`
	FIDO2Salt       string `json:"fido2-salt,omitempty"`
	FIDO2RP         string `json:"fido2-rp,omitempty"`

	// The three FIDO2 requirement flags are POINTERS because false is a
	// value systemd writes on purpose -- it is what
	// --fido2-with-user-presence=no records -- and `omitempty` on a plain
	// bool cannot express it: the zero value and "not set" are the same
	// value, so the member would vanish from a token that had it.
	FIDO2ClientPinRequired *bool `json:"fido2-clientPin-required,omitempty"`
	FIDO2UPRequired        *bool `json:"fido2-up-required,omitempty"`
	FIDO2UVRequired        *bool `json:"fido2-uv-required,omitempty"`

	// NO TPM2 FIELDS, deliberately (#189). go-xkms owns all hardware and
	// cloud crypto -- TPM2, PKCS#11, the KMS backends -- and this is a
	// Layer 0 library that carries none of it. A systemd-tpm2 token is not
	// lost by that: every member this package does not model is carried
	// through a read-modify-write by the passthrough below, byte for byte,
	// so the token survives a header rewrite exactly as systemd wrote it.

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
	// ErrInvalidHeader: a header defect, not a credential verdict.
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

	// Time, Memory and CPUs are the cost of a digest whose KDF is Argon2,
	// named as an Argon2 keyslot KDF names them. LUKS2 defines digests over
	// PBKDF2 only, so no conformant writer -- this package included -- emits
	// them, and they are omitted when nil. They are modeled rather than left
	// in the unknown-member passthrough because a foreign header that DOES
	// carry one has to be evaluated, and then migrated to PBKDF2, before a
	// FIPS 140-3 process can open it (#84; see MigrateToFIPS).
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

	// Requirements is the LUKS2 requirements object, nil when the container
	// declares none.
	//
	// It is a POINTER TO A STRUCT and not a []string, which is what it was
	// until #152. LUKS2 spells this member as an OBJECT carrying a mandatory
	// array -- both `mandatory` and `online-reencrypt-v3` are literals in
	// libcryptsetup -- so the flat slice did not merely lose detail: the decode
	// failed outright with "cannot unmarshal object into Go struct field
	// Config.config.requirements of type []string", and THIS PACKAGE COULD NOT
	// READ ANY CONTAINER MID-REENCRYPTION AT ALL.
	//
	// That inverted the mechanism. requirements exists so an implementation
	// that does not understand a feature refuses the container instead of
	// damaging it; failing to parse the member that carries the warning meant
	// not being able to read the flag that says "do not touch this".
	Requirements *Requirements `json:"requirements,omitempty"`

	unknown unknownFields
}

// Requirements is config.requirements: how a container tells an implementation
// that does not understand a feature to leave it alone.
//
// WHAT THIS PACKAGE DOES WITH IT. A mandatory requirement it does not implement
// does NOT stop a read -- ReadHeader parses the container and exposes the
// requirement, because a flag whose purpose is to warn is useless if reading it
// is what fails, and an operator diagnosing an interrupted reencryption needs to
// see it. It stops every WRITE: encodeMetadataForHeader refuses with an
// UnsupportedRequirementError before anything touches the device, and that is
// the one chokepoint every mutation in this package passes through. Corruption
// happens on write, so that is where the refusal belongs (owner ruling,
// 2026-09-13).
type Requirements struct {
	// Mandatory names requirements an implementation MUST understand to modify
	// the container. LUKS2 defines no optional counterpart today; an
	// implementation that meets an unknown entry here is required to refuse.
	Mandatory []string `json:"mandatory,omitempty"`

	unknown unknownFields
}

// UnsupportedRequirementError names the requirement that makes a container
// unwritable by this package.
//
// It carries the whole mandatory list and not just the offending entry,
// because an operator deciding what tool to reach for next needs to see
// everything the container is asking of an implementation, not the first
// thing this one happened to trip over.
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

// implementedRequirements is every LUKS2 mandatory requirement this package
// can honor on a WRITE.
//
// It is EMPTY, and that is the honest state rather than an oversight: this
// package implements none of the features LUKS2 currently gates this way --
// online reencryption above all -- so every mandatory requirement it meets is
// one it must refuse to write over. The set exists as a named, searchable place
// to add a requirement the moment support for it lands, so the guard and the
// feature cannot drift apart.
var implementedRequirements = map[string]bool{}

// CheckRequirementsImplemented refuses a container whose mandatory
// requirements this package does not implement.
//
// It reports the FIRST unimplemented entry in declaration order, deterministic
// so the same container always produces the same diagnosis, and carries the
// whole list so an operator sees everything being asked.
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
