// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"bytes"
	cmppkg "cmp"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"strconv"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// NewHeaderParams is what CreateBinaryHeader needs from a caller's format
// options: the fields that land in the binary header, narrowed to this
// package's on-disk concerns. MetadataSize must already be validated -- zero
// for the default, or a legal header area size -- because the bound it is
// checked against (ErrInvalidMetadataSize) is a public pkg/luks2 sentinel
// this package cannot return.
type NewHeaderParams struct {
	Label, Subsystem string
	MetadataSize     int
}

// CreateBinaryHeader creates a new LUKS2 binary header.
//
// rng is the entropy source for the checksum salt, and newUUID produces the
// container's UUID; both are parameters rather than package seams, because
// this package defines no package-level mutable state and the caller already
// has a seam of its own to substitute in tests (determinism_test.go).
func CreateBinaryHeader(rng io.Reader, newUUID func() uuid.UUID, p NewHeaderParams) (*BinaryHeader, error) {
	hdr := &BinaryHeader{
		Version: Version,
	}

	copy(hdr.Magic[:], Magic)
	copy(hdr.ChecksumAlgorithm[:], HeaderChecksumAlgorithm)

	u := newUUID()
	copy(hdr.UUID[:], u.String())

	if p.Label != "" {
		copy(hdr.Label[:], p.Label)
	}
	if p.Subsystem != "" {
		copy(hdr.SubsystemLabel[:], p.Subsystem)
	}

	// Generate salt for checksum.
	if _, err := io.ReadFull(rng, hdr.Salt[:]); err != nil {
		return nil, &errs.Error{Kind: errs.ErrIO, Detail: "generate header salt", Err: err}
	}

	// Sequence ID starts at 1.
	hdr.SequenceID = 1

	hdr.HeaderSize = uint64(p.MetadataSize) // #nosec G115 -- the caller validates MetadataSize before calling

	return hdr, nil
}

// ReadHeaderCopyFrom reads and validates one header copy at offset, over any
// reader: every check the header reader makes, applied to bytes that need not
// have come through the page cache.
func ReadHeaderCopyFrom(f io.ReaderAt, offset int64) (*BinaryHeader, *Metadata, error) {
	// Read binary header (LUKS2 uses big-endian for integer fields).
	raw := make([]byte, HeaderSize)
	if _, err := f.ReadAt(raw, offset); err != nil {
		return nil, nil, &errs.Error{Kind: errs.ErrIO, Detail: "failed to read header", Err: err}
	}
	var hdr BinaryHeader
	if err := binary.Read(bytes.NewReader(raw), binary.BigEndian, &hdr); err != nil {
		return nil, nil, &errs.Error{Kind: errs.ErrIO, Detail: "failed to read header", Err: err}
	}

	// Validate magic -- which copy this is decides which magic is correct.
	if !bytes.Equal(hdr.Magic[:], []byte(ExpectedMagic(offset))) {
		return nil, nil, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: fmt.Sprintf(
			"invalid LUKS magic at offset %d: not a LUKS2 device", offset)}
	}

	// Validate version.
	if hdr.Version != Version {
		return nil, nil, &errs.Error{Kind: ErrUnsupportedLUKSVersion, Detail: strconv.Itoa(int(hdr.Version))}
	}

	// BOUND THE DECLARED HEADER AREA SIZE HERE, ONCE, before anything allocates
	// against it (#62).
	area, err := HeaderAreaSize(&hdr)
	if err != nil {
		return nil, nil, err
	}

	// The hdr_offset field must agree with where this copy was actually found.
	recorded, err := HeaderAreaOffset(&hdr)
	if err != nil {
		return nil, nil, err
	}
	if recorded != offset {
		return nil, nil, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: fmt.Sprintf(
			"header copy at offset %d records hdr_offset %d", offset, recorded)}
	}

	// A secondary copy begins where the primary ends, so its offset and the
	// header area size are the same number.
	if offset != PrimaryHeaderOffset && int64(area) != offset {
		return nil, nil, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: fmt.Sprintf(
			"secondary header at offset %d records header size %d, want %d", offset, area, offset)}
	}

	// THE WHOLE AREA IS READ ONCE, and the checksum, the binary header and the
	// JSON all come from that one buffer (#248).
	buf := make([]byte, area)
	if _, err := f.ReadAt(buf, offset); err != nil {
		return nil, nil, &errs.Error{Kind: errs.ErrIO, Detail: "failed to read header area", Err: err}
	}
	if !bytes.Equal(buf[:HeaderSize], raw) {
		return nil, nil, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: fmt.Sprintf(
			"the header copy at offset %d changed while it was being read; retry once the writer is done", offset)}
	}

	// The checksum is verified with the algorithm the header names, and that
	// can only be sha256 here; see checkHeaderChecksumAlgorithm.
	if err := checkHeaderChecksumAlgorithm(&hdr); err != nil {
		return nil, nil, err
	}

	if err := ValidateAreaChecksum(&hdr, buf); err != nil {
		return nil, nil, err
	}

	metadata, err := ParseJSONMetadata(buf[HeaderSize:], area)
	if err != nil {
		return nil, nil, err
	}

	return &hdr, metadata, nil
}

// ReadSecondaryHeaderFrom finds and reads the secondary header copy in
// device.
//
// The primary, when it is readable, states the area size outright. When it
// is NOT readable, the finite set of legal area sizes is probed instead, and
// a candidate is accepted only when the copy found there passes EVERY check
// ReadHeaderCopyFrom makes.
func ReadSecondaryHeaderFrom(device io.ReaderAt) (*BinaryHeader, *Metadata, error) {
	if hdr, _, err := ReadHeaderCopyFrom(device, PrimaryHeaderOffset); err == nil {
		if area, err := HeaderAreaSize(hdr); err == nil {
			return ReadHeaderCopyFrom(device, int64(area))
		}
	}

	hdr, metadata, _, firstErr := probeSecondaryHeader(device)
	if firstErr == nil {
		return hdr, metadata, nil
	}

	return nil, nil, &errs.Error{
		Kind: errs.ErrInvalidHeader,
		Detail: fmt.Sprintf("no valid secondary header at any legal offset (%d..%d): %v",
			HeaderMinSize, HeaderMaxSize, firstErr),
	}
}

// ExpectedMagic returns the magic a header copy at the given offset must
// carry.
func ExpectedMagic(offset int64) string {
	if offset == PrimaryHeaderOffset {
		return Magic
	}
	return SecondaryMagic
}

// EncodeMetadataForHeader produces exactly the JSON WriteHeaderTo would
// write, and refuses metadata that does not fit the container's header area
// -- without touching the device.
//
// It MUTATES metadata.Config.JSONSize, as the write path always has: json_size
// must equal the JSON area actually written and is a property of the
// container, not of the caller.
func EncodeMetadataForHeader(hdr *BinaryHeader, metadata *Metadata) ([]byte, int, error) {
	jsonData, area, err := EncodeMetadata(hdr, metadata)
	if err != nil {
		return nil, 0, err
	}

	// NOTHING IS WRITTEN THAT CRYPTSETUP WOULD REFUSE TO READ (#248).
	if err := ValidateHeaderStructure(area, metadata); err != nil {
		return nil, 0, err
	}
	return jsonData, area, nil
}

// EncodeMetadata is EncodeMetadataForHeader without the structural
// validation: the requirements guard, the area size, the canonical encoding
// and the fit.
func EncodeMetadata(hdr *BinaryHeader, metadata *Metadata) ([]byte, int, error) {
	// REFUSE BEFORE ANYTHING ELSE. A container that declares a mandatory
	// requirement this package does not implement must not be modified by it.
	if err := metadata.CheckRequirementsImplemented(); err != nil {
		return nil, 0, err
	}
	return EncodeMetadataIgnoringRequirements(hdr, metadata)
}

// EncodeMetadataIgnoringRequirements is EncodeMetadata without the
// requirements guard.
//
// It exists for fixtures that model a header this package's own writer would
// refuse to produce: an online reencryption, or any other container
// declaring a requirement nothing here implements yet. Those are exactly the
// headers the reader has to cope with, and since #248 the normal write path
// can no longer produce them -- so a test that needs one has to go around
// the guard rather than mutate a shared table to defeat it.
func EncodeMetadataIgnoringRequirements(hdr *BinaryHeader, metadata *Metadata) ([]byte, int, error) {
	// The header area size is FIXED by the container; it is never recomputed
	// from how much metadata happens to need writing. See HeaderAreaSizeForWrite.
	area, err := HeaderAreaSizeForWrite(hdr)
	if err != nil {
		return nil, 0, err
	}
	jsonSize := area - HeaderSize

	// Guarantee the mandatory LUKS2 JSON objects exist before they are encoded.
	metadata.ensureRequiredObjects()

	// config.json_size must equal the JSON area actually written.
	if metadata.Config != nil {
		metadata.Config.JSONSize = formatSize(int64(jsonSize))
	}

	// Marshal JSON metadata.
	jsonData, err := MarshalCanonicalJSON(metadata)
	if err != nil {
		return nil, 0, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "failed to marshal metadata", Err: err}
	}

	// Refuse metadata that does not fit rather than enlarging the area to hold
	// it.
	if len(jsonData)+1 > jsonSize {
		return nil, 0, &errs.Error{
			Kind: ErrMetadataTooLarge,
			Detail: fmt.Sprintf("%d bytes of JSON metadata plus its terminator do not fit the %d-byte JSON area of this container's %d-byte header (remove keyslots or tokens, or reformat with a larger metadata area)",
				len(jsonData), jsonSize, area),
		}
	}

	return jsonData, area, nil
}

// marshalCanonicalJSON encodes the LUKS2 metadata exactly as it goes on disk:
// COMPACT, with no HTML escaping and no trailing newline. See unknownfields.go
// for why each of those three is a correctness property.
func MarshalCanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer

	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}

	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

// CheckHeaderWritable reports whether WriteHeaderTo would accept this header
// and metadata, without writing anything or touching the device.
func CheckHeaderWritable(hdr *BinaryHeader, metadata *Metadata) error {
	_, _, err := EncodeMetadataForHeader(hdr, metadata)
	return err
}

// WriteHeaderTo writes both header copies through a descriptor the caller
// already holds, so the path is not resolved again. It writes from offset
// zero whatever the descriptor's position (WriteEncodedHeader seeks).
//
// sync is called once after the primary copy lands and once after the
// secondary; it is a parameter rather than a package seam so the caller's own
// test substitution (fipsmigrate_crash_test.go) keeps working unchanged.
func WriteHeaderTo(f *os.File, hdr *BinaryHeader, metadata *Metadata, sync func(*os.File) error) error {
	jsonData, area, err := EncodeMetadataForHeader(hdr, metadata)
	if err != nil {
		return err
	}
	return WriteEncodedHeader(f, hdr, jsonData, area, sync)
}

// WriteEncodedHeader writes both copies of hdr carrying jsonData, already
// encoded for a header area of area bytes, primary first.
func WriteEncodedHeader(f *os.File, hdr *BinaryHeader, jsonData []byte, area int, sync func(*os.File) error) error {
	if _, err := f.Seek(PrimaryHeaderOffset, io.SeekStart); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "failed to seek to the primary header", Err: err}
	}
	jsonSize := area - HeaderSize
	secondaryOffset := int64(area)

	// Update header size.
	hdr.HeaderSize = uint64(area) // #nosec G115 -- HeaderAreaSizeForWrite bounds this to HeaderMaxSize

	// THE WRITER OWNS EACH COPY'S IDENTITY.
	hdr.HeaderOffset = uint64(PrimaryHeaderOffset) // #nosec G115 -- zero
	copy(hdr.Magic[:], Magic)

	// Calculate and set checksum.
	if err := CalculateHeaderChecksum(hdr, jsonData, jsonSize); err != nil {
		return err
	}

	// Write binary header (LUKS2 uses big-endian for integer fields).
	if err := binary.Write(f, binary.BigEndian, hdr); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "failed to write header", Err: err}
	}

	// Write JSON metadata with padding.
	if _, err := f.Write(jsonData); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "failed to write metadata", Err: err}
	}

	padding := make([]byte, jsonSize-len(jsonData))
	if _, err := f.Write(padding); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "failed to write padding", Err: err}
	}

	// THE PRIMARY IS DURABLE BEFORE THE SECONDARY IS TOUCHED.
	if err := sync(f); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "failed to sync the primary header before writing the secondary", Err: err}
	}

	if err := WriteSecondaryCopy(f, hdr, jsonData, jsonSize, secondaryOffset); err != nil {
		return err
	}

	return sync(f)
}

// WriteSecondaryCopy writes the SECOND header copy of hdr, whose fields
// describe the primary, with jsonData padded to jsonSize, at secondaryOffset.
func WriteSecondaryCopy(f *os.File, hdr *BinaryHeader, jsonData []byte, jsonSize int, secondaryOffset int64) error {
	if _, err := f.Seek(secondaryOffset, io.SeekStart); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "failed to seek to backup header", Err: err}
	}

	// Update header offset and MAGIC for the backup copy.
	backupHdr := *hdr
	backupHdr.HeaderOffset = uint64(secondaryOffset) // #nosec G115 -- bounded by HeaderAreaSizeForWrite
	copy(backupHdr.Magic[:], SecondaryMagic)

	// Recalculate checksum for backup header.
	if err := CalculateHeaderChecksum(&backupHdr, jsonData, jsonSize); err != nil {
		return err
	}

	// Write backup header (LUKS2 uses big-endian for integer fields).
	if err := binary.Write(f, binary.BigEndian, &backupHdr); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "failed to write backup header", Err: err}
	}

	// Write backup JSON metadata.
	if _, err := f.Write(jsonData); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "failed to write backup metadata", Err: err}
	}
	if _, err := f.Write(make([]byte, jsonSize-len(jsonData))); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "failed to write backup padding", Err: err}
	}
	return nil
}

// HeaderCopiesAgree reports whether device's two header copies are both
// readable and carry the same sequence id and the same metadata, as every
// completed WriteHeaderTo leaves them.
func HeaderCopiesAgree(r io.ReaderAt) error {
	hdr, metadata, err := ReadHeaderCopyFrom(r, PrimaryHeaderOffset)
	if err != nil {
		return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "the primary header copy is not readable", Err: err}
	}
	// The secondary is read where the primary says it is, and nowhere else.
	area, err := HeaderAreaSize(hdr)
	if err != nil {
		return err
	}
	shdr, smetadata, err := ReadHeaderCopyFrom(r, int64(area))
	if err != nil {
		return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "the secondary header copy is not readable", Err: err}
	}
	if shdr.SequenceID != hdr.SequenceID {
		return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: fmt.Sprintf(
			"the header copies are at sequence ids %d (primary) and %d (secondary)", hdr.SequenceID, shdr.SequenceID)}
	}
	// A comparison, not a write: the two copies are encoded the way a write
	// would encode them, without the write-time structural validation.
	primary, _, err := EncodeMetadata(hdr, metadata)
	if err != nil {
		return err
	}
	secondary, _, err := EncodeMetadata(shdr, smetadata)
	if err != nil {
		return err
	}
	if !bytes.Equal(primary, secondary) {
		return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: fmt.Sprintf(
			"the header copies carry different metadata at the same sequence id %d", hdr.SequenceID)}
	}
	return nil
}

// HeaderAreaSizeForWrite returns the header area size a write must use. The
// area is a property of the CONTAINER, fixed when it was formatted, not a
// function of how much metadata a particular write happens to produce.
func HeaderAreaSizeForWrite(hdr *BinaryHeader) (int, error) {
	area := HeaderMinSize
	if hdr.HeaderSize != 0 {
		size, err := SafeUint64ToInt(hdr.HeaderSize)
		if err != nil {
			return 0, &errs.Error{
				Kind:   errs.ErrInvalidHeader,
				Detail: fmt.Sprintf("header size %d: %v", hdr.HeaderSize, err),
			}
		}
		area = size
	}

	if area < HeaderMinSize || area > HeaderMaxSize || !isPowerOf2(area) {
		return 0, &errs.Error{
			Kind: errs.ErrInvalidHeader,
			Detail: fmt.Sprintf("header area size %d is not a power of two in %d..%d",
				area, HeaderMinSize, HeaderMaxSize),
		}
	}

	return area, nil
}

// HeaderAreaSize returns the on-disk header size, bounded. hdr.HeaderSize is a
// uint64 read straight off the device before anything has been
// authenticated, so it is bounded here before it sizes any allocation or read
// (#62).
func HeaderAreaSize(hdr *BinaryHeader) (int, error) {
	size, err := SafeUint64ToInt(hdr.HeaderSize)
	if err != nil {
		return 0, &errs.Error{
			Kind:   errs.ErrInvalidHeader,
			Detail: fmt.Sprintf("header size %d: %v", hdr.HeaderSize, err),
		}
	}

	if size <= HeaderSize || size > HeaderMaxSize {
		return 0, &errs.Error{
			Kind: errs.ErrInvalidHeader,
			Detail: fmt.Sprintf("header size %d is outside the %d..%d byte range",
				size, HeaderSize+1, HeaderMaxSize),
		}
	}

	return size, nil
}

// HeaderAreaOffset returns the on-disk offset of this header copy, bounded.
func HeaderAreaOffset(hdr *BinaryHeader) (int64, error) {
	offset, err := SafeUint64ToInt64(hdr.HeaderOffset)
	if err != nil {
		return 0, &errs.Error{
			Kind:   errs.ErrInvalidHeader,
			Detail: fmt.Sprintf("header offset %d: %v", hdr.HeaderOffset, err),
		}
	}

	if offset == PrimaryHeaderOffset {
		return offset, nil
	}

	if offset < HeaderMinSize || offset > HeaderMaxOffset || offset%HeaderMinSize != 0 {
		return 0, &errs.Error{
			Kind: errs.ErrInvalidHeader,
			Detail: fmt.Sprintf("header offset %d is not 0 and not a %d-aligned offset in %d..%d",
				offset, HeaderMinSize, HeaderMinSize, HeaderMaxOffset),
		}
	}

	return offset, nil
}

// errChecksumBufferTooShort reports a header buffer too short to contain the
// checksum field. It is a DISTINCT value rather than another bare
// ErrInvalidHeader because a declared area size outside the legal range and a
// buffer too short to hold the checksum field are different faults (#62). It
// wraps ErrInvalidHeader, so callers classify it exactly as before.
var errChecksumBufferTooShort = &errs.Error{
	Kind:   errs.ErrInvalidHeader,
	Detail: "header buffer is too short to hold the checksum field",
}

// ValidateHeaderChecksum validates the checksum of the header copy at
// headerOffset. The offset and headerSize are parameters rather than
// re-derived from the header's own attacker-controlled fields: the caller
// bounds them once, at the earliest point it can, and threads them down
// (#62).
func ValidateHeaderChecksum(hdr *BinaryHeader, r io.ReaderAt, headerOffset int64, headerSize int) error {
	if headerSize < ChecksumFieldOffset+len(hdr.Checksum) {
		return &errs.Error{Kind: errChecksumBufferTooShort, Detail: fmt.Sprintf("%d bytes, need at least %d",
			headerSize, ChecksumFieldOffset+len(hdr.Checksum))}
	}

	headerData := make([]byte, headerSize)
	if _, err := r.ReadAt(headerData, headerOffset); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "failed to read header for checksum", Err: err}
	}
	return ValidateAreaChecksum(hdr, headerData)
}

// ValidateAreaChecksum checks hdr's checksum against headerData, the whole
// header area it was read from. headerData is modified: its checksum field is
// zeroed, which is the form the checksum is computed over.
func ValidateAreaChecksum(hdr *BinaryHeader, headerData []byte) error {
	if len(headerData) < ChecksumFieldOffset+len(hdr.Checksum) {
		return &errs.Error{Kind: errChecksumBufferTooShort, Detail: fmt.Sprintf("%d bytes, need at least %d",
			len(headerData), ChecksumFieldOffset+len(hdr.Checksum))}
	}

	// Zero out the checksum field, which is not part of what it covers.
	clear(headerData[ChecksumFieldOffset : ChecksumFieldOffset+len(hdr.Checksum)])

	h := sha256.New()
	h.Write(headerData)
	calculated := h.Sum(nil)

	if !bytes.Equal(calculated, hdr.Checksum[:len(calculated)]) {
		return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: fmt.Sprintf(
			"header checksum mismatch\nExpected: %x\nCalculated: %x\nHeaderSize: %d, HeaderOffset: %d",
			hdr.Checksum[:32], calculated[:32], hdr.HeaderSize, hdr.HeaderOffset)}
	}

	return nil
}

// CalculateHeaderChecksum calculates and sets the header checksum.
func CalculateHeaderChecksum(hdr *BinaryHeader, jsonData []byte, jsonSize int) error {
	buf := new(bytes.Buffer)

	// Write binary header with zeroed checksum (LUKS2 uses big-endian for
	// integer fields). A clean copy ensures padding bytes are zeroed.
	tmpHdr := *hdr
	tmpHdr.Checksum = [64]byte{}

	if err := binary.Write(buf, binary.BigEndian, &tmpHdr); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "failed to write header for checksum", Err: err}
	}

	buf.Write(jsonData)
	padding := make([]byte, jsonSize-len(jsonData))
	buf.Write(padding)

	h := sha256.New()
	h.Write(buf.Bytes())
	checksum := h.Sum(nil)

	copy(hdr.Checksum[:], checksum)

	return nil
}

// ReadJSONMetadata reads the JSON metadata that follows the header copy at
// headerOffset. As with ValidateHeaderChecksum, the offset and header area
// size are passed in rather than re-derived from the attacker-controlled
// header fields.
func ReadJSONMetadata(r io.ReaderAt, hdr *BinaryHeader, headerOffset int64, headerSize int) (*Metadata, error) {
	if headerSize <= HeaderSize {
		return nil, &errs.Error{
			Kind:   errs.ErrInvalidHeader,
			Detail: fmt.Sprintf("header size %d leaves no room for JSON metadata", headerSize),
		}
	}
	jsonSize := headerSize - HeaderSize
	jsonData := make([]byte, jsonSize)

	offset := headerOffset + HeaderSize
	if _, err := r.ReadAt(jsonData, offset); err != nil {
		return nil, &errs.Error{Kind: errs.ErrIO, Detail: "failed to read JSON metadata", Err: err}
	}
	return ParseJSONMetadata(jsonData, headerSize)
}

// ParseJSONMetadata parses and validates jsonArea, the JSON area of a header
// whose whole area is headerSize bytes.
func ParseJSONMetadata(jsonArea []byte, headerSize int) (*Metadata, error) {
	jsonData := jsonArea

	nullIdx := bytes.IndexByte(jsonData, 0)
	if nullIdx != -1 {
		jsonData = jsonData[:nullIdx]
	}

	// The top-level object and the four id-keyed objects are checked for
	// duplicate and case-variant members here; every modeled object below them
	// checks its own in its UnmarshalJSON. See ErrAmbiguousJSONMember.
	if err := checkTopLevelMembers(jsonData); err != nil {
		return nil, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "failed to parse JSON metadata", Err: err}
	}

	var metadata Metadata
	if err := json.Unmarshal(jsonData, &metadata); err != nil {
		return nil, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "failed to parse JSON metadata", Err: err}
	}

	// A JSON null is normalized away HERE, at the one point metadata is parsed.
	if err := normalizeMetadataNulls(&metadata); err != nil {
		return nil, err
	}

	// The header as a whole is held to the structural rules cryptsetup applies
	// on every read, after the nulls are gone so the metadata checked is the
	// metadata returned.
	if err := ValidateHeaderWideStructure(headerSize, &metadata); err != nil {
		return nil, err
	}

	// Segment geometry IS validated here.
	if err := validateMetadataSegments(&metadata); err != nil {
		return nil, err
	}

	// Keyslot CONTENTS are deliberately not validated here; see ValidateKeyslot
	// (keyslot.go).

	return &metadata, nil
}

// checkTopLevelMembers refuses a JSON area whose top-level object, or whose
// keyslots, tokens, segments or digests object, names a member twice or names
// a top-level member in a case LUKS2 does not spell it.
func checkTopLevelMembers(jsonData []byte) error {
	top, err := decodeMembers(metadataObjectHeader, jsonData, metadataKnownMembers)
	if err != nil {
		return err
	}
	if top == nil {
		return nil // not an object: the typed decode reports it
	}
	for _, name := range []string{"keyslots", "tokens", "segments", "digests", "config"} {
		raw, present := top[name]
		if trimmed := bytes.TrimLeft(raw, " \t\r\n"); !present || len(trimmed) == 0 || trimmed[0] != '{' {
			return headerStructureError("the JSON area has no %q object; LUKS2 requires one, empty if there is nothing in it", name)
		}
		if name == "config" {
			continue // Config.UnmarshalJSON checks its own members
		}
		if _, err := decodeMembers(name, raw, nil); err != nil {
			return err
		}
	}
	return nil
}

// normalizeMetadataNulls makes a JSON null unrepresentable downstream. See
// the historical note in types.go's Metadata doc for the full reasoning.
func normalizeMetadataNulls(metadata *Metadata) error {
	for id, segment := range metadata.Segments {
		if segment == nil {
			return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: fmt.Sprintf("segment %q is null", id)}
		}
	}

	for id, digest := range metadata.Digests {
		if digest == nil {
			return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: fmt.Sprintf("digest %q is null", id)}
		}
	}

	if metadata.Config == nil {
		return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "config is null"}
	}

	// TWO PHASES: phase one removes every null, phase two repairs the
	// references that pointed at what was removed.
	dropped := make([]string, 0, len(metadata.Keyslots))
	for id, keyslot := range metadata.Keyslots {
		if keyslot == nil {
			delete(metadata.Keyslots, id)
			dropped = append(dropped, id)
			metadata.DroppedNullEntries = append(metadata.DroppedNullEntries,
				DroppedEntry{Kind: DroppedKindKeyslot, ID: id})
		}
	}
	for id, token := range metadata.Tokens {
		if token == nil {
			delete(metadata.Tokens, id)
			metadata.DroppedNullEntries = append(metadata.DroppedNullEntries,
				DroppedEntry{Kind: DroppedKindToken, ID: id})
		}
	}

	// The report is ORDERED: built by ranging two maps, so leaving it as-is
	// would hand a caller a list that changes between runs for an unchanged
	// device.
	sortDroppedEntries(metadata.DroppedNullEntries)

	// Phase two: a dropped keyslot must stop being referenced by digests and
	// tokens.
	for _, id := range dropped {
		ForgetKeyslotID(metadata, id)
	}

	return nil
}

// sortDroppedEntries puts the report in a stable, human order: keyslots before
// tokens, and within a kind ascending by numeric id, with ids that do not parse
// as a number after those in lexical order.
func sortDroppedEntries(entries []DroppedEntry) {
	slices.SortFunc(entries, func(a, b DroppedEntry) int {
		if c := cmppkg.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		na, errA := strconv.Atoi(a.ID)
		nb, errB := strconv.Atoi(b.ID)
		switch {
		case errA == nil && errB == nil:
			if c := cmppkg.Compare(na, nb); c != 0 {
				return c
			}
		case errA == nil:
			return -1
		case errB == nil:
			return 1
		}
		return cmppkg.Compare(a.ID, b.ID)
	})
}

// ForgetKeyslotID removes every reference to a keyslot id from the digests
// and tokens that name it.
func ForgetKeyslotID(metadata *Metadata, id string) {
	for _, digest := range metadata.Digests {
		digest.Keyslots = WithoutID(digest.Keyslots, id)
	}
	for _, token := range metadata.Tokens {
		token.Keyslots = WithoutID(token.Keyslots, id)
	}
}

// WithoutID returns ids with every occurrence of id removed. It allocates a
// new slice rather than filtering in place, because the input may be shared
// with a caller that parsed it.
func WithoutID(ids []string, id string) []string {
	out := make([]string, 0, len(ids))
	for _, candidate := range ids {
		if candidate != id {
			out = append(out, candidate)
		}
	}
	return out
}

// VolumeKeyBits returns the size, in bits, of the key the data in segmentID is
// encrypted with: the key size of a keyslot that a digest attests for that
// segment. It is 0 when no keyslot is attested for it.
func VolumeKeyBits(metadata *Metadata, segmentID string) int {
	for _, digestID := range SortedIDs(metadata.Digests) {
		digest := metadata.Digests[digestID]
		if !slices.Contains(digest.Segments, segmentID) {
			continue
		}
		keyslots := slices.Clone(digest.Keyslots)
		slices.Sort(keyslots)
		for _, id := range keyslots {
			if keyslot := metadata.Keyslots[id]; keyslot != nil && keyslot.Type == "luks2" && keyslot.KeySize > 0 {
				return keyslot.KeySize * 8
			}
		}
	}
	return 0
}

// formatSize formats an int64 size as a string. Private copy of pkg/luks2's
// helper of the same name; see ToKDFParams's sibling comment in keyslot.go.
func formatSize(size int64) string {
	return strconv.FormatInt(size, 10)
}

// isPowerOf2 checks if a number is a power of 2. Private copy of pkg/luks2's
// helper of the same name.
func isPowerOf2(n int) bool {
	return n > 0 && (n&(n-1)) == 0
}

// SafeUint64ToInt64 converts uint64 to int64 safely, returning an error on
// overflow. Private copy of pkg/luks2/security.go's helper of the same name:
// both packages need it and header must not import luks2 to reach the one
// luks2 already has.
func SafeUint64ToInt64(v uint64) (int64, error) {
	if v > math.MaxInt64 {
		return 0, errOverflow
	}
	return int64(v), nil
}

// SafeUint64ToInt converts uint64 to int safely, returning an error on
// overflow. See SafeUint64ToInt64.
func SafeUint64ToInt(v uint64) (int, error) {
	if v > uint64(math.MaxInt) {
		return 0, errOverflow
	}
	return int(v), nil
}
