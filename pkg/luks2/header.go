// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"strconv"

	"github.com/google/uuid"
)

// LUKS2 header copy locations. LUKS2 stores the header twice so a torn or
// damaged primary can be recovered from the secondary; the two copies differ in
// their magic (see LUKS2SecondaryMagic) and in the hdr_offset they record.
const (
	// LUKS2PrimaryHeaderOffset is where the first header copy starts.
	LUKS2PrimaryHeaderOffset int64 = 0

	// LUKS2SecondaryHeaderOffset is where the second header copy starts for the
	// DEFAULT 16 KiB metadata size. It is the primary copy's total
	// area size, not a free-standing constant: a container written with a larger
	// metadata area puts its second copy correspondingly further out.
	LUKS2SecondaryHeaderOffset int64 = 0x4000
)

// ReadHeader reads and validates the PRIMARY LUKS2 header from a device.
// For the second copy -- which carries a different magic -- see
// ReadSecondaryHeader.
//
// A keyslot or token the header spells as JSON null is REMOVED from the
// returned metadata rather than handed back as a nil map entry -- see
// normalizeMetadataNulls for why, and for why segments, digests and config are
// refused instead. The removed entries are reported on
// LUKS2Metadata.DroppedNullEntries, so a caller can tell that a
// ReadHeader -> mutate -> WriteHeader cycle is about to drop them from the
// header on disk.
func ReadHeader(device string) (*LUKS2BinaryHeader, *LUKS2Metadata, error) {
	return readHeaderCopy(device, LUKS2PrimaryHeaderOffset)
}

// ReadSecondaryHeader reads and validates the SECOND LUKS2 header copy, the one
// carrying the SKUL magic.
//
// It exists because writing a spec-correct backup header is only half of a
// recovery path: without a reader that knows the secondary magic, this library
// would produce a copy it could not itself open, which is the state #64
// describes.
//
// The header it returns is a SECONDARY header: its magic is LUKS2SecondaryMagic
// and its hdr_offset is the copy's own offset, because that is what is on disk.
// Callers repairing a damaged primary should use RestorePrimaryHeader rather
// than assembling the sequence themselves; writing this header back is safe --
// writeHeaderTo stamps each copy's identity -- but the named operation
// takes the lock for the whole read-and-write.
//
// # WHERE THE COPY IS
//
// The second copy begins where the first one ends, so its offset is the
// container's header area size. When the primary header is readable it simply
// says so, and that is the first thing tried.
//
// When it is NOT readable -- which is the only situation this function exists
// for -- the size cannot be assumed. Defaulting to LUKS2SecondaryHeaderOffset
// would be right for every container this library formats and wrong for a legal
// container formatted with a larger metadata area, and wrong in the worst
// possible place: recovery would be impossible for exactly the containers whose
// geometry this branch newly taught the reader to accept.
//
// So the finite set of legal area sizes is probed instead. There are nine of
// them (16 KiB through 4 MiB, powers of two), and a candidate is accepted only
// when the copy found there passes EVERY check readHeaderCopy makes -- secondary
// magic, version, hdr_offset equal to the probed offset, header size equal to
// it as well, checksum over the whole area, and a parseable JSON body. Guessing
// an offset is therefore not a way to be handed someone else's bytes; a wrong
// guess is rejected, not tolerated.
func ReadSecondaryHeader(device string) (*LUKS2BinaryHeader, *LUKS2Metadata, error) {
	if err := ValidateDevicePath(device); err != nil {
		return nil, nil, err
	}
	f, err := openDevice("read the LUKS2 header", device, os.O_RDONLY)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	return readSecondaryHeaderFrom(f)
}

// ErrPrimaryHeaderCurrent indicates RestorePrimaryHeader was refused because
// the primary header copy is intact and at least as new as the secondary, so
// restoring would roll the volume back rather than repair it.
var ErrPrimaryHeaderCurrent = errors.New("the primary header is intact and not older than the secondary; restoring would roll the volume back")

// RestoreHeaderOptions controls RestorePrimaryHeaderWithOptions.
type RestoreHeaderOptions struct {
	// Force restores the secondary copy even over an intact primary that is
	// as new as it or newer. That ROLLS THE VOLUME BACK to the secondary's
	// state: a keyslot removed since -- a revoked passphrase -- opens the
	// volume again if its key material has not yet been overwritten.
	Force bool
}

// RestorePrimaryHeader rebuilds a damaged primary header from the secondary
// copy, and is the operation ReadSecondaryHeader's documentation describes.
//
// It exists because "read the secondary and write it back" is a sequence a
// caller should not have to get right. The header returned by
// ReadSecondaryHeader is a SECONDARY header -- that is what it was asked for --
// and what makes writing it back safe is that writeHeaderTo stamps each
// copy's identity itself. Naming the operation puts that guarantee behind an
// API instead of behind a comment, and makes it one locked step rather than a
// read and a write with a window between them.
//
// The secondary copy is validated in full before anything is written: magic,
// version, recorded offset, header size, checksum and JSON body. A container
// whose second copy is also damaged is left exactly as it was.
//
// # It repairs; it does not roll back
//
// It refuses with ErrPrimaryHeaderCurrent when the primary is intact and its
// sequence id is not lower than the secondary's (#248). Header writes put the
// primary on the medium first, so an interrupted ChangeKey or RemoveKey can
// leave a NEWER primary -- the passphrase already revoked -- over an OLDER
// secondary that still lists it. Restoring that secondary would bring the
// revoked passphrase back. cryptsetup resolves the same state the other way,
// keeping the higher sequence id. Use RestorePrimaryHeaderWithOptions with
// Force to restore anyway.
//
// The restored header is written at a sequence id one above both copies', so
// no reader can mistake the restored state for either earlier one.
func RestorePrimaryHeader(device string) error {
	return RestorePrimaryHeaderWithOptions(device, RestoreHeaderOptions{})
}

// RestorePrimaryHeaderWithOptions is RestorePrimaryHeader with options; see
// RestoreHeaderOptions.
func RestorePrimaryHeaderWithOptions(device string, opts RestoreHeaderOptions) error {
	if err := ValidateDevicePath(device); err != nil {
		return err
	}

	lock, err := AcquireFileLock(device)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	// EVERY READ AND THE WRITE GO THROUGH THE LOCKED DESCRIPTOR, so the
	// copies compared, the copy restored and the device written are the one
	// the lock is held on: the path is not resolved again (#248, as #249 does
	// for the keyslot operations).
	f := lock.file
	if err := requireLockableDevice(f, device); err != nil {
		return err
	}

	hdr, metadata, err := readSecondaryHeaderFrom(f)
	if err != nil {
		return fmt.Errorf("cannot restore the primary header: %w", err)
	}

	sequence := hdr.SequenceID
	if primary, _, err := readHeaderCopyFrom(f, LUKS2PrimaryHeaderOffset); err == nil {
		if primary.SequenceID >= hdr.SequenceID && !opts.Force {
			return &detailError{Kind: ErrPrimaryHeaderCurrent, Detail: fmt.Sprintf(
				"%s: primary sequence id %d, secondary %d; the secondary copy is repaired by the next header write",
				device, primary.SequenceID, hdr.SequenceID)}
		}
		sequence = max(sequence, primary.SequenceID)
	}
	if sequence == math.MaxUint64 {
		return &detailError{Kind: ErrInvalidHeader, Detail: "the header sequence id is at its maximum and cannot be advanced past both copies"}
	}
	hdr.SequenceID = sequence + 1

	// The restore REPRODUCES a copy already on the medium; it authors nothing.
	// So it is held to the header-wide rules the secondary already passed when
	// it was read, not to the per-entry ones every other write applies. A
	// damaged keyslot or token in the secondary is the state the volume was in
	// before the primary tore, and refusing to restore it would leave the
	// volume with no readable primary at all -- the loss the per-entry policy
	// exists to prevent (headervalidation.go). Remove the damaged entry once
	// the primary is back.
	jsonData, area, err := encodeMetadata(hdr, metadata)
	if err != nil {
		return err
	}
	if err := validateHeaderWideStructure(area, metadata); err != nil {
		return err
	}
	return writeEncodedHeader(f, hdr, jsonData, area)
}

// readSecondaryHeaderFrom finds and reads the secondary header copy in device,
// which RestorePrimaryHeader passes as its locked descriptor.
func readSecondaryHeaderFrom(device io.ReaderAt) (*LUKS2BinaryHeader, *LUKS2Metadata, error) {
	// The primary, when it is readable, states the area size outright.
	if hdr, _, err := readHeaderCopyFrom(device, LUKS2PrimaryHeaderOffset); err == nil {
		if area, err := headerAreaSize(hdr); err == nil {
			return readHeaderCopyFrom(device, int64(area))
		}
	}

	// The primary is damaged. Probe every legal offset; smallest first, which is
	// the overwhelmingly common geometry.
	var firstErr error
	for _, offset := range legalHeaderAreaSizes() {
		hdr, metadata, err := readHeaderCopyFrom(device, offset)
		if err == nil {
			return hdr, metadata, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}

	return nil, nil, fmt.Errorf("%w: no valid secondary header at any legal offset (%d..%d): %v",
		ErrInvalidHeader, LUKS2HeaderMinSize, LUKS2HeaderMaxSize, firstErr)
}

// legalHeaderAreaSizes returns the header area sizes LUKS2 admits, ascending:
// the powers of two from LUKS2HeaderMinSize to LUKS2HeaderMaxSize.
//
// The list doubles as the list of legal secondary header offsets, because the
// second copy starts where the first one ends. It is generated rather than
// written out so that the two constants remain the only place the range is
// stated.
func legalHeaderAreaSizes() []int64 {
	var sizes []int64
	for size := int64(LUKS2HeaderMinSize); size <= LUKS2HeaderMaxSize; size *= 2 {
		sizes = append(sizes, size)
	}
	return sizes
}

// expectedMagic returns the magic a header copy at the given offset must carry.
func expectedMagic(offset int64) string {
	if offset == LUKS2PrimaryHeaderOffset {
		return LUKS2Magic
	}
	return LUKS2SecondaryMagic
}

// readHeaderCopy reads and validates one header copy at a known offset.
func readHeaderCopy(device string, offset int64) (*LUKS2BinaryHeader, *LUKS2Metadata, error) {
	// Validate device path
	if err := ValidateDevicePath(device); err != nil {
		return nil, nil, err
	}

	f, err := openDevice("read the LUKS2 header", device, os.O_RDONLY)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()

	return readHeaderCopyFrom(f, offset)
}

// readHeaderCopyFrom is readHeaderCopy over any reader: every check the header
// reader makes, applied to bytes that need not have come through the page
// cache -- MigrateToFIPS classifies a failed write from bytes read past it.
func readHeaderCopyFrom(f io.ReaderAt, offset int64) (*LUKS2BinaryHeader, *LUKS2Metadata, error) {
	// Read binary header (LUKS2 uses big-endian for integer fields)
	raw := make([]byte, LUKS2HeaderSize)
	if _, err := f.ReadAt(raw, offset); err != nil {
		return nil, nil, &detailError{Detail: "failed to read header", Err: err}
	}
	var hdr LUKS2BinaryHeader
	if err := binary.Read(bytes.NewReader(raw), binary.BigEndian, &hdr); err != nil {
		return nil, nil, &detailError{Detail: "failed to read header", Err: err}
	}

	// Validate magic -- which copy this is decides which magic is correct
	if !bytes.Equal(hdr.Magic[:], []byte(expectedMagic(offset))) {
		return nil, nil, &detailError{Kind: ErrInvalidHeader, Detail: fmt.Sprintf(
			"invalid LUKS magic at offset %d: not a LUKS2 device", offset)}
	}

	// Validate version
	if hdr.Version != LUKS2Version {
		return nil, nil, &detailError{Kind: ErrUnsupportedLUKSVersion, Detail: strconv.Itoa(int(hdr.Version))}
	}

	// BOUND THE DECLARED HEADER AREA SIZE HERE, ONCE, before anything allocates
	// against it.
	//
	// hdr.HeaderSize is eight bytes read straight off an attacker-controlled
	// device with only the magic and the version in front of them, and it then
	// sizes two allocations and two reads. It used to be bounded independently
	// inside validateHeaderChecksum and inside readJSONMetadata, which is twice
	// in two functions that must not disagree, and it left each of those
	// functions unable to have a local check of its own: any guard they added
	// was shadowed by the bound five lines above it and could not fire (#62 --
	// a guard instrumented with panic("GUARD REACHED") was reached zero times
	// across the whole suite).
	//
	// Enforced at the earliest point it can be, and threaded down as a
	// parameter, the size arrives at those functions already validated, so the
	// checks they DO make are about their own arguments and are reachable when
	// they are called with something short.
	area, err := headerAreaSize(&hdr)
	if err != nil {
		return nil, nil, err
	}

	// The hdr_offset field must agree with where this copy was actually found.
	//
	// The caller already knows the offset; the field is attacker-controlled.
	// Letting the downstream reads re-derive the offset from the field instead
	// of using the one they were given is what allowed a header read at 0x4000
	// to be paired with the JSON at 0, and it makes headerAreaOffset the source
	// of truth for a question the caller had already answered -- the exact
	// confusion #63 and #64 exist to end. headerAreaOffset is kept as the
	// validator that bounds the field and names a bad value; from here on, the
	// `offset` parameter is what addresses the device.
	recorded, err := headerAreaOffset(&hdr)
	if err != nil {
		return nil, nil, err
	}
	if recorded != offset {
		return nil, nil, &detailError{Kind: ErrInvalidHeader, Detail: fmt.Sprintf(
			"header copy at offset %d records hdr_offset %d", offset, recorded)}
	}

	// A secondary copy begins where the primary ends, so its offset and the
	// header area size are the same number. Checking it here is what lets
	// ReadSecondaryHeader probe candidate offsets safely: a copy that merely
	// happens to carry the SKUL magic at some offset is still rejected unless
	// the container's own geometry agrees that the copy belongs there.
	if offset != LUKS2PrimaryHeaderOffset && int64(area) != offset {
		return nil, nil, &detailError{Kind: ErrInvalidHeader, Detail: fmt.Sprintf(
			"secondary header at offset %d records header size %d, want %d", offset, area, offset)}
	}

	// THE WHOLE AREA IS READ ONCE, and the checksum, the binary header and the
	// JSON all come from that one buffer (#248).
	//
	// They used to be three reads -- the binary header, then the area again for
	// the checksum, then the JSON area a third time -- and ReadHeader takes no
	// lock, so a header rewritten between them could be checksummed in one
	// state and parsed in another: metadata no checksum ever covered. The
	// first read above only sizes this one; its bytes must be the ones this
	// read returns, or the header changed underneath us.
	buf := make([]byte, area)
	if _, err := f.ReadAt(buf, offset); err != nil {
		return nil, nil, &detailError{Detail: "failed to read header area", Err: err}
	}
	if !bytes.Equal(buf[:LUKS2HeaderSize], raw) {
		return nil, nil, &detailError{Kind: ErrInvalidHeader, Detail: fmt.Sprintf(
			"the header copy at offset %d changed while it was being read; retry once the writer is done", offset)}
	}

	// The checksum is verified with the algorithm the header names, and that
	// can only be sha256 here; see checkHeaderChecksumAlgorithm.
	if err := checkHeaderChecksumAlgorithm(&hdr); err != nil {
		return nil, nil, err
	}

	if err := validateAreaChecksum(&hdr, buf); err != nil {
		return nil, nil, err
	}

	metadata, err := parseJSONMetadata(buf[LUKS2HeaderSize:], area)
	if err != nil {
		return nil, nil, err
	}

	return &hdr, metadata, nil
}

// IsLUKS checks if a device or file contains a LUKS header (either LUKS1 or LUKS2).
// This is a pure Go implementation that doesn't require the cryptsetup CLI.
// It checks for LUKS magic bytes at offset 0.
func IsLUKS(device string) (bool, error) {
	// Validate device path
	if err := ValidateDevicePath(device); err != nil {
		return false, err
	}

	f, err := openDevice("read the LUKS magic", device, os.O_RDONLY)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	// Read first 6 bytes (LUKS magic)
	magic := make([]byte, LUKS2MagicLen)
	n, err := f.Read(magic)
	if err != nil {
		return false, fmt.Errorf("failed to read device: %w", err)
	}
	if n < LUKS2MagicLen {
		return false, nil // Too small to be LUKS
	}

	// Check for LUKS magic bytes
	// Both LUKS1 and LUKS2 use the same magic: "LUKS\xba\xbe"
	return bytes.Equal(magic, []byte(LUKS2Magic)), nil
}

// IsLUKS2 checks if a device contains a LUKS2 header specifically.
// Returns true only for LUKS2 (not LUKS1).
func IsLUKS2(device string) (bool, error) {
	// Validate device path
	if err := ValidateDevicePath(device); err != nil {
		return false, err
	}

	f, err := openDevice("read the LUKS magic and version", device, os.O_RDONLY)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	// Read first 8 bytes (magic + version)
	header := make([]byte, 8)
	n, err := f.Read(header)
	if err != nil {
		return false, fmt.Errorf("failed to read device: %w", err)
	}
	if n < 8 {
		return false, nil // Too small to be LUKS
	}

	// Check for LUKS magic bytes
	if !bytes.Equal(header[:LUKS2MagicLen], []byte(LUKS2Magic)) {
		return false, nil // Not LUKS at all
	}

	// Check version (bytes 6-7, big-endian)
	// LUKS2 version is 0x0002
	version := binary.BigEndian.Uint16(header[6:8])
	return version == LUKS2Version, nil
}

// WriteHeader writes a LUKS2 header to a device (acquires lock)
func WriteHeader(device string, hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata) error {
	// Validate device path
	if err := ValidateDevicePath(device); err != nil {
		return err
	}

	// Written through the descriptor the lock is held on, not a second open
	// of the path, which a re-pointed symlink could send elsewhere.
	lock, dev, err := lockKeyslotDevice(device)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()

	return dev.writeHeader(hdr, metadata)
}

// encodeMetadataForHeader produces exactly the JSON writeHeaderTo would
// write, and refuses metadata that does not fit the container's header area --
// without touching the device.
//
// It is a separate function so a caller can ask "would this header write?"
// BEFORE doing something irreversible. Every keyslot removal destroys key
// material and only then writes the header, so a header that does not fit is
// discovered after the material it was meant to protect is already gone: a
// failure that could have been a clean refusal instead costs a keyslot (#50).
// The removal paths call checkHeaderWritable on the prospective metadata first.
//
// The pre-flight has to be this function rather than a copy of its rules. A
// second implementation of "does it fit" is the parallel-predicate failure this
// package has now paid for repeatedly (#45): it would agree today and drift the
// first time the encoding changes -- and the direction it would drift in is a
// pre-flight that passes while the real write refuses, which is precisely the
// case the pre-flight exists to prevent.
//
// It MUTATES metadata.Config.JSONSize, as the write path always has: json_size
// must equal the JSON area actually written and is a property of the container,
// not of the caller. Calling this and then not writing leaves that field
// correct for the container it was computed against, so a pre-flight followed by
// a real write is indistinguishable from the write alone.
func encodeMetadataForHeader(hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata) ([]byte, int, error) {
	jsonData, area, err := encodeMetadata(hdr, metadata)
	if err != nil {
		return nil, 0, err
	}

	// NOTHING IS WRITTEN THAT CRYPTSETUP WOULD REFUSE TO READ (#248). The same
	// structural validator the read path applies runs here, in full, on the
	// metadata exactly as it was just encoded, so no write -- an imported token
	// naming a keyslot that does not exist, a caller's WriteHeader, a bug in
	// one of this package's own mutations -- can leave a header that
	// cryptsetup, systemd-cryptsetup and this package's own reader reject.
	// Like the requirements guard, it reaches every writer through this one
	// function, and checkHeaderWritable reaches it without the device.
	if err := validateHeaderStructure(area, metadata); err != nil {
		return nil, 0, err
	}
	return jsonData, area, nil
}

// encodeMetadata is encodeMetadataForHeader without the structural validation:
// the requirements guard, the area size, the canonical encoding and the fit.
// Only encodeMetadataForHeader calls it outside of tests, which use it to
// stand up headers another writer could have produced.
func encodeMetadata(hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata) ([]byte, int, error) {
	// REFUSE BEFORE ANYTHING ELSE. A container that declares a mandatory
	// requirement this package does not implement must not be modified by it --
	// that is what the requirements mechanism is FOR, and the refusal is worth
	// nothing if it arrives after the header has been rewritten.
	//
	// This is the chokepoint every mutation passes through: Format, AddKey,
	// ChangeKey, KillKeyslot, the token writes and WriteHeader all reach the
	// device through writeHeaderTo, which encodes here first, and
	// checkHeaderWritable reaches it without touching the device at all. One
	// guard here covers all of them, and a caller can ask in advance.
	//
	// Reads are deliberately NOT gated; see Requirements (types.go).
	if err := metadata.checkRequirementsImplemented(); err != nil {
		return nil, 0, err
	}

	// The header area size is FIXED by the container; it is never recomputed
	// from how much metadata happens to need writing. See headerAreaSizeForWrite.
	area, err := headerAreaSizeForWrite(hdr)
	if err != nil {
		return nil, 0, err
	}
	jsonSize := area - LUKS2HeaderSize

	// Guarantee the mandatory LUKS2 JSON objects exist before they are encoded.
	// A nil map here becomes `null` on disk and cryptsetup rejects the whole
	// header; see LUKS2Metadata.ensureRequiredObjects.
	metadata.ensureRequiredObjects()

	// config.json_size must equal the JSON area actually written -- cryptsetup
	// checks it against hdr_size - 4096. It is set from `area` here, before the
	// marshal, rather than trusted from the caller: createMetadata hardcoded
	// LUKS2DefaultSize, which was right only for the default geometry and only
	// by coincidence.
	if metadata.Config != nil {
		metadata.Config.JSONSize = formatSize(int64(jsonSize))
	}

	// Marshal JSON metadata
	jsonData, err := marshalCanonicalJSON(metadata)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Refuse metadata that does not fit rather than enlarging the area to hold
	// it. Growing is not an option: the keyslots offset (2 x area) and the data
	// offset are already fixed on this device, so a larger area would move the
	// second header copy on top of whatever now follows it -- for the geometry
	// this library writes, that is the keyslot key material at 0x8000, which
	// would destroy every key on the device.
	//
	// The previous code did grow, via nextPowerOf2(len(jsonData)+1) floored at
	// LUKS2DefaultSize. MEASURED: at 15 keyslots the JSON reaches 8390 bytes,
	// nextPowerOf2 jumps to 16384, HeaderSize becomes 20480, and the backup
	// header written at 16384 lands INSIDE the primary area and overwrites its
	// own JSON tail. 4096+16384 = 20480 is also not a power of two, so the size
	// was not a legal LUKS2 metadata size either.
	if len(jsonData)+1 > jsonSize {
		return nil, 0, fmt.Errorf("%w: %d bytes of JSON metadata plus its terminator do not fit the %d-byte JSON area of this container's %d-byte header (remove keyslots or tokens, or reformat with a larger metadata area)",
			ErrMetadataTooLarge, len(jsonData), jsonSize, area)
	}

	return jsonData, area, nil
}

// marshalCanonicalJSON encodes the LUKS2 metadata exactly as it goes on disk:
// COMPACT, with no HTML escaping and no trailing newline.
//
// Each of those three is a correctness property, not a formatting preference.
//
//   - COMPACT. json.MarshalIndent produced 1193 bytes where cryptsetup's json-c
//     emits 775 for the identical metadata -- 54% overhead of indentation, in a
//     fixed 12288-byte area. encodeMetadataForHeader REFUSES metadata that does
//     not fit rather than growing the area (it cannot grow; the keyslots and the
//     data segment are already placed), so the padding was not free. MEASURED
//     on a real container: 22 of the 32 keyslots LUKS2 defines fit indented,
//     all 32 fit compact in 10676 bytes, and cryptsetup has never had the
//     lower limit.
//
//   - NO HTML ESCAPING. encoding/json escapes <, > and & as \u003c, \u003e and
//     \u0026 by default, which json-c does not. No field this package writes
//     today contains one -- labels and subsystem labels live in the BINARY
//     header, not the JSON -- so this is a latent divergence rather than a live
//     defect, and it is closed here because the field that first carries such a
//     character (a token, a user-supplied string in some future object) would
//     otherwise produce a header no other implementation encodes the same way.
//
//   - NO TRAILING NEWLINE. json.Encoder.Encode appends one; cryptsetup's area
//     holds the JSON, a single NUL terminator and then zero padding to the end
//     of the area. A newline between the closing brace and the NUL would be one
//     byte of divergence at a position every implementation reads.
//
// json.Encoder is used rather than json.Marshal because SetEscapeHTML is only
// reachable through the encoder.
//
// # WHERE BYTE-IDENTITY WITH json-c STOPS
//
// Two residual differences remain, both measured, both properties of
// encoding/json that no option reaches. Neither is a conformance failure --
// JSON objects are unordered and both encodings parse identically -- but a
// reader comparing bytes needs to know the boundary rather than discover it.
//
//   - OBJECT KEY ORDER PAST TEN ENTRIES. encoding/json sorts map keys as
//     strings; json-c preserves insertion order. cryptsetup inserts keyslots in
//     ascending numeric order, so with 11 keyslots it writes 0,1,...,9,10 and
//     this package writes 0,1,10,2,...,9. Identical up to ten entries in any of
//     keyslots, tokens, segments or digests, and divergent above that.
//
//   - U+2028 AND U+2029. encoding/json escapes the two Unicode line separators
//     as the escapes \u2028 and \u2029 REGARDLESS of SetEscapeHTML; json-c
//     emits them as UTF-8. Unreachable today -- no field this package writes
//     carries them -- and it stays unreachable until a token string does.
func marshalCanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer

	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}

	// Encode always terminates with exactly one newline. Trimming is safe
	// rather than merely convenient: the value being encoded is a struct, so
	// the last byte before it is the closing brace of an object.
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

// checkHeaderWritable reports whether writeHeaderTo would accept this
// header and metadata, without writing anything or touching the device.
//
// A guard on a write path is validation that runs AFTER everything destructive
// has already happened. The value of a refusal is that nothing was lost; a
// refusal issued after the wipe keeps the error and discards the benefit. See
// encodeMetadataForHeader and #50.
func checkHeaderWritable(hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata) error {
	_, _, err := encodeMetadataForHeader(hdr, metadata)
	return err
}

// writeHeaderTo writes both header copies through a descriptor the caller
// already holds, so the path is not resolved again: the locked one for a keyslot
// operation that must not reopen the device between reading the header and
// writing it (#249, A10), and Format's exclusive one (#248). It writes from
// offset zero whatever the descriptor's position (writeEncodedHeader seeks).
func writeHeaderTo(f *os.File, hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata) error {
	jsonData, area, err := encodeMetadataForHeader(hdr, metadata)
	if err != nil {
		return err
	}
	return writeEncodedHeader(f, hdr, jsonData, area)
}

// writeEncodedHeader writes both copies of hdr carrying jsonData, already
// encoded for a header area of area bytes, primary first.
func writeEncodedHeader(f *os.File, hdr *LUKS2BinaryHeader, jsonData []byte, area int) error {
	if _, err := f.Seek(LUKS2PrimaryHeaderOffset, io.SeekStart); err != nil {
		return &detailError{Detail: "failed to seek to the primary header", Err: err}
	}
	jsonSize := area - LUKS2HeaderSize
	secondaryOffset := int64(area)

	// Update header size
	hdr.HeaderSize = uint64(area) // #nosec G115 -- headerAreaSizeForWrite bounds this to LUKS2HeaderMaxSize

	// THE WRITER OWNS EACH COPY'S IDENTITY. What distinguishes the two copies --
	// the magic and the recorded hdr_offset -- is a function of WHERE each one
	// is written, so it is stamped here rather than taken from the caller.
	//
	// The backup copy was already handled this way. The primary was not: it was
	// written with whatever identity the caller's header happened to carry,
	// because the only place that ever set LUKS2Magic was CreateBinaryHeader on
	// the format path. That asymmetry is what broke recovery. A header obtained
	// from ReadSecondaryHeader carries SKUL and hdr_offset 0x4000, and handing
	// it back to WriteHeader -- the documented way to repair a damaged primary --
	// wrote those secondary-only fields at offset zero:
	//
	//	bytes now at offset 0:      "SKUL\xba\xbe"
	//	bytes now at offset 0x4000: "SKUL\xba\xbe"
	//	primary still unreadable after recovery: invalid LUKS magic at offset 0
	//
	// so the repair left the container with no valid primary at all and the
	// volume no longer opened. Normalizing here fixes every caller at once
	// instead of the one that reported it, and makes the two copies symmetric:
	// the writer decides what each copy IS, the caller supplies only content.
	//
	// The caller's header is normalized in place, as HeaderSize already is, so
	// what it holds afterwards describes the primary copy that was written.
	hdr.HeaderOffset = uint64(LUKS2PrimaryHeaderOffset) // #nosec G115 -- zero
	copy(hdr.Magic[:], LUKS2Magic)

	// Calculate and set checksum
	if err := calculateHeaderChecksum(hdr, jsonData, jsonSize); err != nil {
		return err
	}

	// Write binary header (LUKS2 uses big-endian for integer fields)
	if err := binary.Write(f, binary.BigEndian, hdr); err != nil {
		return &detailError{Detail: "failed to write header", Err: err}
	}

	// Write JSON metadata with padding
	if _, err := f.Write(jsonData); err != nil {
		return &detailError{Detail: "failed to write metadata", Err: err}
	}

	// Null-terminate and pad to jsonSize
	padding := make([]byte, jsonSize-len(jsonData))
	if _, err := f.Write(padding); err != nil {
		return &detailError{Detail: "failed to write padding", Err: err}
	}

	// THE PRIMARY IS DURABLE BEFORE THE SECONDARY IS TOUCHED.
	//
	// The two copies exist so that an interrupted write can damage at most one
	// of them, and that holds only if the writes reach the medium in order. With
	// a single sync at the end, the kernel may write back the dirty pages of
	// both copies in any order, and a power loss during that writeback can tear
	// both -- leaving a container no reader can open, by this library or by
	// cryptsetup. Syncing here means a crash at any point of this function leaves
	// at least one complete, checksummed copy: the old secondary while the
	// primary is being written, the new primary while the secondary is. Every
	// header write in the package comes through here, so every multi-step
	// operation (MigrateToFIPS among them) inherits the guarantee rather than
	// re-arguing it.
	//
	// A failed sync stops the write before the secondary is touched: the
	// secondary still holds the previous header, complete, and the caller gets
	// the error rather than a second copy written on top of an unknown first.
	if err := syncDevice(f); err != nil {
		return &detailError{Detail: "failed to sync the primary header before writing the secondary", Err: err}
	}

	if err := writeSecondaryCopy(f, hdr, jsonData, jsonSize, secondaryOffset); err != nil {
		return err
	}

	return syncDevice(f)
}

// writeSecondaryCopy writes the SECOND header copy of hdr, whose fields
// describe the primary, with jsonData padded to jsonSize, at secondaryOffset.
//
// Write the backup header at the secondary offset, which is the header AREA
// SIZE -- the second copy begins where the first one ends. Seeking to a
// constant 0x4000 was correct only while the area was always 0x4000, and
// silently wrong the moment it was not.
func writeSecondaryCopy(f *os.File, hdr *LUKS2BinaryHeader, jsonData []byte, jsonSize int, secondaryOffset int64) error {
	if _, err := f.Seek(secondaryOffset, io.SeekStart); err != nil {
		return &detailError{Detail: "failed to seek to backup header", Err: err}
	}

	// Update header offset and MAGIC for the backup copy. The magic is not a
	// copy of the primary's: LUKS2 requires "SKUL\xba\xbe" on the second copy,
	// and cryptsetup that finds the primary magic there does not recognize the
	// header at all ("LUKS2 header read failed (-22)"), so the copy kept for
	// repairing a damaged primary cannot perform the repair. Measured with
	// cryptsetup 2.7.0; see #64.
	backupHdr := *hdr
	backupHdr.HeaderOffset = uint64(secondaryOffset) // #nosec G115 -- bounded by headerAreaSizeForWrite
	copy(backupHdr.Magic[:], LUKS2SecondaryMagic)

	// Recalculate checksum for backup header
	if err := calculateHeaderChecksum(&backupHdr, jsonData, jsonSize); err != nil {
		return err
	}

	// Write backup header (LUKS2 uses big-endian for integer fields)
	if err := binary.Write(f, binary.BigEndian, &backupHdr); err != nil {
		return &detailError{Detail: "failed to write backup header", Err: err}
	}

	// Write backup JSON metadata
	if _, err := f.Write(jsonData); err != nil {
		return &detailError{Detail: "failed to write backup metadata", Err: err}
	}
	if _, err := f.Write(make([]byte, jsonSize-len(jsonData))); err != nil {
		return &detailError{Detail: "failed to write backup padding", Err: err}
	}
	return nil
}

// repairSecondaryHeader rewrites ONLY the secondary header copy from the
// primary's header and metadata, at the primary's sequence id, and syncs it.
// Caller must hold the lock.
//
// It exists for an operation that is about to destroy something and must
// first know that EITHER copy, alone, opens the volume afterwards: a secondary
// left stale or torn by an earlier interrupted write would otherwise be the
// only copy a later interruption leaves, describing a volume that no longer
// exists (MigrateToFIPS). The primary is not written, and is made durable
// before the secondary is touched, so an interruption here leaves the copy
// the volume already opens through exactly as it was -- writeHeaderTo,
// which writes the primary first, would put the one good copy at risk to
// repair the bad one.
//
// It writes through the caller's pinned descriptor (#255), as one write step.
func repairSecondaryHeader(dev *keyslotDevice, hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata) error {
	if err := keyslotWriteStep(dev, "repair the secondary LUKS2 header"); err != nil {
		return err
	}
	f := dev.file

	jsonData, area, err := encodeMetadataForHeader(hdr, metadata)
	if err != nil {
		return err
	}

	// THE PRIMARY IS MADE DURABLE BEFORE A SINGLE SECONDARY BYTE IS WRITTEN.
	//
	// The primary this repair copies was READ, and a read can be served from
	// the page cache: an earlier process killed between writing the primary
	// and syncing it -- or whose sync failed -- leaves a primary that reads
	// back whole while the medium may hold only part of it, and the old
	// secondary as the one durable copy. Overwriting that secondary first
	// would put both copies at risk at once. fsync flushes the file's dirty
	// pages whoever wrote them, so after it the primary that was read is the
	// primary on the medium; if it fails, the secondary is left exactly as it
	// was.
	if err := syncDevice(f); err != nil {
		return &detailError{Detail: "failed to make the primary header durable before repairing the secondary", Err: err}
	}

	primary := *hdr
	primary.HeaderSize = uint64(area) // #nosec G115 -- headerAreaSizeForWrite bounds this to LUKS2HeaderMaxSize
	if err := writeSecondaryCopy(f, &primary, jsonData, area-LUKS2HeaderSize, int64(area)); err != nil {
		return err
	}
	if err := syncDevice(f); err != nil {
		return &detailError{Detail: "failed to sync the repaired secondary header", Err: err}
	}
	return nil
}

// headerCopiesAgree reports whether device's two header copies are both
// readable and carry the same sequence id and the same metadata, as every
// completed writeHeaderTo leaves them. A copy that cannot be read, or
// that differs, is described in the error.
//
// It reads through r -- a pinned operation's own descriptor (#255).
func headerCopiesAgree(r io.ReaderAt) error {
	hdr, metadata, err := readHeaderCopyFrom(r, LUKS2PrimaryHeaderOffset)
	if err != nil {
		return &detailError{Kind: ErrInvalidHeader, Detail: "the primary header copy is not readable", Err: err}
	}
	// The secondary is read where the primary says it is, and nowhere else.
	area, err := headerAreaSize(hdr)
	if err != nil {
		return err
	}
	shdr, smetadata, err := readHeaderCopyFrom(r, int64(area))
	if err != nil {
		return &detailError{Kind: ErrInvalidHeader, Detail: "the secondary header copy is not readable", Err: err}
	}
	if shdr.SequenceID != hdr.SequenceID {
		return &detailError{Kind: ErrInvalidHeader, Detail: fmt.Sprintf(
			"the header copies are at sequence ids %d (primary) and %d (secondary)", hdr.SequenceID, shdr.SequenceID)}
	}
	// A comparison, not a write: the two copies are encoded the way a write
	// would encode them, without the write-time structural validation.
	primary, _, err := encodeMetadata(hdr, metadata)
	if err != nil {
		return err
	}
	secondary, _, err := encodeMetadata(shdr, smetadata)
	if err != nil {
		return err
	}
	if !bytes.Equal(primary, secondary) {
		return &detailError{Kind: ErrInvalidHeader, Detail: fmt.Sprintf(
			"the header copies carry different metadata at the same sequence id %d", hdr.SequenceID)}
	}
	return nil
}

// syncDevice flushes a device written by writeHeaderTo to stable storage.
//
// It is a seam for one reason: the ORDER of the two header copies' durability
// is the crash-safety property, and it is not observable from outside a
// process -- a test substitutes this to see the device exactly as a power loss
// at each sync point would leave it, and to fail the sync between the copies.
// Unexported and substituted only by this package's own tests, like
// openFileFunc.
var syncDevice = (*os.File).Sync

// newUUID is the source of a new container's UUID.
//
// It exists for the same reason cryptoRand (util.go) does and nothing else: a
// UUID is 40 bytes of the binary header, so with no seam here no test can ever
// compare two headers byte for byte. Unexported, no setter, substituted only by
// this package's own tests.
var newUUID = uuid.New

// CreateBinaryHeader creates a new LUKS2 binary header
func CreateBinaryHeader(opts FormatOptions) (*LUKS2BinaryHeader, error) {
	hdr := &LUKS2BinaryHeader{
		Version: LUKS2Version,
	}

	// Set magic
	copy(hdr.Magic[:], LUKS2Magic)

	// Set checksum algorithm
	copy(hdr.ChecksumAlgorithm[:], headerChecksumAlgorithm)

	// Generate UUID
	u := newUUID()
	copy(hdr.UUID[:], u.String())

	// Set label if provided
	if opts.Label != "" {
		copy(hdr.Label[:], opts.Label)
	}

	// Set subsystem if provided
	if opts.Subsystem != "" {
		copy(hdr.SubsystemLabel[:], opts.Subsystem)
	}

	// Generate salt for checksum
	if _, err := io.ReadFull(cryptoRand, hdr.Salt[:]); err != nil {
		return nil, &CryptoError{Op: "generate header salt", Err: err}
	}

	// Sequence ID starts at 1
	hdr.SequenceID = 1

	// The header area size. Zero leaves it to headerAreaSizeForWrite, which
	// picks the 16 KiB default; anything else is the caller's choice and is
	// validated here as well as in ValidateFormatOptions, because this
	// function is exported and reachable without it.
	if err := validateMetadataSize(opts.MetadataSize); err != nil {
		return nil, err
	}
	hdr.HeaderSize = uint64(opts.MetadataSize) // #nosec G115 -- validateMetadataSize bounds this to 0..LUKS2HeaderMaxSize

	return hdr, nil
}

// LUKS2HeaderMaxSize bounds the header size accepted from disk. The LUKS2
// on-disk format allows a metadata area up to 4 MiB per copy; anything beyond
// that is a malformed or hostile header rather than a volume this library
// wrote.
const LUKS2HeaderMaxSize = 0x400000 // 4 MiB

// headerAreaSizeForWrite returns the header area size a write must use.
//
// The area is a property of the CONTAINER, fixed when it was formatted, not a
// function of how much metadata a particular write happens to produce. Two
// things on disk are already sized against it: the keyslots begin at 2 x area,
// and the data segment begins after the keyslots. Neither can move, so the area
// can neither grow nor shrink for the life of the container.
//
// hdr.HeaderSize carries it. CreateBinaryHeader sets it from
// FormatOptions.MetadataSize; a header that carries zero -- the default -- gets
// LUKS2HeaderMinSize, the geometry Format lays out when no size is chosen
// (keyslot material at 0x8000, immediately after two 0x4000 copies).
//
// The value is required to be a POWER OF TWO in LUKS2HeaderMinSize..
// LUKS2HeaderMaxSize. LUKS2 admits only 16 KiB, 32 KiB, ... 4 MiB, and a
// container recording anything else is malformed; propagating such a size would
// place the second header copy at an offset no LUKS2 reader looks at. The
// power-of-two requirement is also what makes every legal secondary offset
// 16 KiB-aligned, so what this writer produces and what headerAreaOffset
// accepts on read describe the same set.
func headerAreaSizeForWrite(hdr *LUKS2BinaryHeader) (int, error) {
	area := LUKS2HeaderMinSize
	if hdr.HeaderSize != 0 {
		size, err := SafeUint64ToInt(hdr.HeaderSize)
		if err != nil {
			return 0, fmt.Errorf("%w: header size %d: %v", ErrInvalidHeader, hdr.HeaderSize, err)
		}
		area = size
	}

	if area < LUKS2HeaderMinSize || area > LUKS2HeaderMaxSize || !isPowerOf2(area) {
		return 0, fmt.Errorf("%w: header area size %d is not a power of two in %d..%d",
			ErrInvalidHeader, area, LUKS2HeaderMinSize, LUKS2HeaderMaxSize)
	}

	return area, nil
}

// headerAreaSize returns the on-disk header size, bounded.
//
// hdr.HeaderSize is a uint64 read straight off the device before anything has
// been authenticated -- magic and version are the only checks in front of it,
// and both are trivially satisfiable by anyone who controls the device. It then
// sizes two allocations and two reads.
//
// Unbounded, a crafted value PANICS rather than returning an error, which no
// caller can defend against because ReadHeader returns an error they never get.
// Measured on 9132403, patching only the eight bytes at offset 8:
//
//	HeaderSize 0, 100     panic: index out of range [448]     (validateHeaderChecksum)
//	HeaderSize 510, 511   panic: index out of range [510], [511]
//	HeaderSize 2^62, 2^64-1   panic: makeslice: len out of range
//
// The checksum-field write needs 512 bytes, since the field sits at 0x1C0 and is
// 64 wide. Below that the first invalid index is 448 while the buffer is shorter
// than 448, and the buffer's own length once it is longer -- which is why the
// reported index moves. The bound enforced HERE is LUKS2HeaderSize (4096), not
// 512: a header area with no room for any JSON is malformed whether or not the
// checksum write would have fit.
func headerAreaSize(hdr *LUKS2BinaryHeader) (int, error) {
	size, err := SafeUint64ToInt(hdr.HeaderSize)
	if err != nil {
		return 0, fmt.Errorf("%w: header size %d: %v", ErrInvalidHeader, hdr.HeaderSize, err)
	}

	if size <= LUKS2HeaderSize || size > LUKS2HeaderMaxSize {
		return 0, fmt.Errorf("%w: header size %d is outside the %d..%d byte range",
			ErrInvalidHeader, size, LUKS2HeaderSize+1, LUKS2HeaderMaxSize)
	}

	return size, nil
}

// headerAreaOffset returns the on-disk offset of this header copy, bounded.
//
// hdr.HeaderOffset is the sibling of the HeaderSize field bounded by
// headerAreaSize, and it arrives the same way: eight bytes read straight off an
// attacker-controlled device with only magic and version in front of them. It
// then feeds every ReadAt this package performs on the header area. Overflow
// was already checked; RANGE was not, and the type's own documentation ("0 or
// 0x4000") was the only thing recording the expectation (#63).
//
// What is accepted: 0 for the primary copy, or a 16 KiB-aligned offset from
// LUKS2HeaderMinSize to LUKS2HeaderMaxOffset for the secondary. The range is
// the whole legal span rather than the single value 0x4000 because a container
// formatted with a larger metadata area (cryptsetup --luks2-metadata-size)
// legitimately places its second copy further out, and this library must still
// be able to read it.
func headerAreaOffset(hdr *LUKS2BinaryHeader) (int64, error) {
	offset, err := SafeUint64ToInt64(hdr.HeaderOffset)
	if err != nil {
		return 0, fmt.Errorf("%w: header offset %d: %v", ErrInvalidHeader, hdr.HeaderOffset, err)
	}

	if offset == LUKS2PrimaryHeaderOffset {
		return offset, nil
	}

	if offset < LUKS2HeaderMinSize || offset > LUKS2HeaderMaxOffset || offset%LUKS2HeaderMinSize != 0 {
		return 0, fmt.Errorf("%w: header offset %d is not 0 and not a %d-aligned offset in %d..%d",
			ErrInvalidHeader, offset, LUKS2HeaderMinSize, LUKS2HeaderMinSize, LUKS2HeaderMaxOffset)
	}

	return offset, nil
}

// checksumFieldOffset is where the 64-byte checksum field sits inside the
// 4096-byte binary header. It is a property of the on-disk layout, so it is
// stated once here rather than spelled as a literal at each site that has to
// blank the field before hashing over it.
const checksumFieldOffset = 0x1C0

// errChecksumBufferTooShort reports a header buffer too short to contain the
// checksum field.
//
// It is a DISTINCT value rather than another bare ErrInvalidHeader because a
// declared area size outside the legal range and a buffer too short to hold the
// checksum field are different faults, and #62 recorded what happens when two
// guards on one path share a sentinel: errors.Is answers "was it this class",
// never "was it this check", so a test asserting on the shared sentinel is
// satisfied by any guard upstream of the one under test. That is exactly how
// the previous attempt at this guard shipped a test that passed on the wrong
// error, from the wrong guard, and survived a mutation deleting the guard
// entirely.
//
// It is unexported: no caller can reach this condition through ReadHeader,
// which bounds the size before calling, so exporting it would add public API
// for a state only an internal caller can produce. It wraps ErrInvalidHeader,
// so callers classify it exactly as before while a test can attribute it.
var errChecksumBufferTooShort = fmt.Errorf("%w: header buffer is too short to hold the checksum field", ErrInvalidHeader)

// validateHeaderChecksum validates the checksum of the header copy at
// headerOffset. The offset is a parameter rather than something re-derived from
// hdr.HeaderOffset: the caller knows where it read the copy from, and the field
// is attacker-controlled. readHeaderCopy has already required the two to agree.
//
// headerSize is likewise a parameter rather than re-derived from
// hdr.HeaderSize: readHeaderCopy bounds it once, at the earliest point it can,
// and threads it down (#62). The consequence for this function is that its own
// length check below is LOAD-BEARING -- there is no longer a bound five lines
// above it that makes the check unreachable -- so a caller handing it a size
// too small for the checksum field gets an error rather than a panic.
func validateHeaderChecksum(hdr *LUKS2BinaryHeader, r io.ReaderAt, headerOffset int64, headerSize int) error {
	// The buffer must be able to hold the checksum field this function is about
	// to blank, because the indices it writes are fixed by the on-disk layout
	// rather than derived from the buffer. Checked BEFORE the allocation, which
	// also refuses a negative size that make() would panic on.
	if headerSize < checksumFieldOffset+len(hdr.Checksum) {
		return &detailError{Kind: errChecksumBufferTooShort, Detail: fmt.Sprintf("%d bytes, need at least %d",
			headerSize, checksumFieldOffset+len(hdr.Checksum))}
	}

	headerData := make([]byte, headerSize)
	if _, err := r.ReadAt(headerData, headerOffset); err != nil {
		return &detailError{Detail: "failed to read header for checksum", Err: err}
	}
	return validateAreaChecksum(hdr, headerData)
}

// validateAreaChecksum checks hdr's checksum against headerData, the whole
// header area it was read from. headerData is modified: its checksum field is
// zeroed, which is the form the checksum is computed over.
func validateAreaChecksum(hdr *LUKS2BinaryHeader, headerData []byte) error {
	if len(headerData) < checksumFieldOffset+len(hdr.Checksum) {
		return &detailError{Kind: errChecksumBufferTooShort, Detail: fmt.Sprintf("%d bytes, need at least %d",
			len(headerData), checksumFieldOffset+len(hdr.Checksum))}
	}

	// Zero out the checksum field, which is not part of what it covers. The
	// slice expression is bounded by the check above rather than by anything a
	// caller happens to have done first.
	clear(headerData[checksumFieldOffset : checksumFieldOffset+len(hdr.Checksum)])

	// Calculate checksum
	h := sha256.New()
	h.Write(headerData)
	calculated := h.Sum(nil)

	// Compare
	// A mismatch is a header that is not intact -- torn by an interrupted
	// write, most often -- and is classified as such, so a caller can tell it
	// from an I/O failure and reach for the other copy (RestorePrimaryHeader).
	if !bytes.Equal(calculated, hdr.Checksum[:len(calculated)]) {
		return &detailError{Kind: ErrInvalidHeader, Detail: fmt.Sprintf(
			"header checksum mismatch\nExpected: %x\nCalculated: %x\nHeaderSize: %d, HeaderOffset: %d",
			hdr.Checksum[:32], calculated[:32], hdr.HeaderSize, hdr.HeaderOffset)}
	}

	return nil
}

// calculateHeaderChecksum calculates and sets the header checksum
func calculateHeaderChecksum(hdr *LUKS2BinaryHeader, jsonData []byte, jsonSize int) error {
	// Create buffer for entire header area
	buf := new(bytes.Buffer)

	// Write binary header with zeroed checksum (LUKS2 uses big-endian for integer fields)
	// Create a clean copy to ensure padding bytes are zeroed
	tmpHdr := *hdr
	tmpHdr.Checksum = [64]byte{}

	if err := binary.Write(buf, binary.BigEndian, &tmpHdr); err != nil {
		return fmt.Errorf("failed to write header for checksum: %w", err)
	}

	// Write JSON data with padding
	buf.Write(jsonData)
	padding := make([]byte, jsonSize-len(jsonData))
	buf.Write(padding)

	// Calculate checksum
	h := sha256.New()
	h.Write(buf.Bytes())
	checksum := h.Sum(nil)

	// Set checksum in header
	copy(hdr.Checksum[:], checksum)

	return nil
}

// readJSONMetadata reads the JSON metadata that follows the header copy at
// headerOffset. As with validateHeaderChecksum, the offset and the header area
// size are passed in rather than re-derived from the attacker-controlled
// hdr.HeaderOffset and hdr.HeaderSize fields.
func readJSONMetadata(r io.ReaderAt, hdr *LUKS2BinaryHeader, headerOffset int64, headerSize int) (*LUKS2Metadata, error) {
	// headerSize arrives bounded by readHeaderCopy (#62). This function makes
	// no bound of its own, so there is exactly one place the range is decided.
	if headerSize <= LUKS2HeaderSize {
		return nil, fmt.Errorf("%w: header size %d leaves no room for JSON metadata",
			ErrInvalidHeader, headerSize)
	}
	jsonSize := headerSize - LUKS2HeaderSize
	jsonData := make([]byte, jsonSize)

	offset := headerOffset + LUKS2HeaderSize
	if _, err := r.ReadAt(jsonData, offset); err != nil {
		return nil, fmt.Errorf("failed to read JSON metadata: %w", err)
	}
	return parseJSONMetadata(jsonData, headerSize)
}

// parseJSONMetadata parses and validates jsonArea, the JSON area of a header
// whose whole area is headerSize bytes.
func parseJSONMetadata(jsonArea []byte, headerSize int) (*LUKS2Metadata, error) {
	jsonData := jsonArea

	// Find null terminator
	nullIdx := bytes.IndexByte(jsonData, 0)
	if nullIdx != -1 {
		jsonData = jsonData[:nullIdx]
	}

	// The top-level object and the four id-keyed objects are checked for
	// duplicate and case-variant members here; every modeled object below them
	// checks its own in its UnmarshalJSON. See ErrAmbiguousJSONMember.
	if err := checkTopLevelMembers(jsonData); err != nil {
		return nil, &detailError{Kind: ErrInvalidHeader, Detail: "failed to parse JSON metadata", Err: err}
	}

	var metadata LUKS2Metadata
	if err := json.Unmarshal(jsonData, &metadata); err != nil {
		return nil, &detailError{Kind: ErrInvalidHeader, Detail: "failed to parse JSON metadata", Err: err}
	}

	// A JSON null is normalized away HERE, at the one point metadata is parsed.
	// See normalizeMetadataNulls.
	if err := normalizeMetadataNulls(&metadata); err != nil {
		return nil, err
	}

	// The header as a whole is held to the structural rules cryptsetup applies
	// on every read, after the nulls are gone so the metadata checked is the
	// metadata returned. The rules about one keyslot or one token are applied
	// to every write instead; see headervalidation.go for why (#248).
	if err := validateHeaderWideStructure(headerSize, &metadata); err != nil {
		return nil, err
	}

	// Segment geometry IS validated here, and the contrast with the keyslots
	// below is the point rather than an inconsistency: a segment has no
	// redundancy to preserve, and three of its declared fields reach a
	// device-mapper ioctl unchanged. See segmentvalidation.go (#40).
	if err := validateMetadataSegments(&metadata); err != nil {
		return nil, err
	}

	// Keyslot CONTENTS are deliberately not validated here, and that is a
	// different question from the nulls dealt with above.
	//
	// One gate is tempting: no consumer can forget it. But a keyslot is a part
	// of a container, not the container, and refusing the whole header on the
	// first bad keyslot makes a volume with one damaged slot unreadable through
	// its intact ones -- permanent data loss manufactured by a safety check. An
	// operator also has to be able to LOOK at a damaged container, which is
	// precisely when they need to.
	//
	// The geometry is bounded at each point that acts on it instead, by the one
	// shared validateKeyslot; see keyslotvalidation.go for the entry points and
	// for why the failure is per-keyslot.
	//
	// That reasoning is about a keyslot whose CONTENTS are wrong -- there is
	// something there, it may be repairable, and an operator must be able to see
	// it. It says nothing about a null, and an earlier version of this comment
	// was read as though it did. A null is not a damaged keyslot; it is no
	// keyslot at all, carrying no area, no type and no KDF. Nothing is preserved
	// by keeping it and nothing can be done with it, so it is removed rather
	// than tolerated in place. Tolerating obliges every site that counts,
	// indexes or dereferences it to remember; normalizing obliges nobody.

	return &metadata, nil
}

// checkTopLevelMembers refuses a JSON area whose top-level object, or whose
// keyslots, tokens, segments or digests object, names a member twice or names
// a top-level member in a case LUKS2 does not spell it -- and one that lacks
// any of the five mandatory objects, or carries one as something other than an
// object (`"tokens":null`). cryptsetup refuses such a header outright
// (json_contains(..., json_type_object) in each hdr_validate_*), and the typed
// decode cannot tell an absent or null member from an empty one.
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

// normalizeMetadataNulls makes a JSON null unrepresentable downstream.
//
// A null in a map[string]*T does not vanish. It unmarshals to a PRESENT key
// holding a nil pointer, so len() counts it, range yields it, and -- the fact
// that has caught this package repeatedly -- the comma-ok idiom reports it as
// found:
//
//	targetKeyslot, exists := metadata.Keyslots[slotIDStr]
//	if !exists { ... }
//
// exists is true. That check reads like a nil guard and is not one, and five
// sites leaned on it as if it were (#67).
//
// # Why this is at the boundary and not at the sites
//
// Guarding the dereferencing sites individually was tried on the
// issue/3-secure-buffer branch and does not hold: a review sweeping for exactly
// this enumerated seven sites and missed an eighth. An enumeration rots as soon
// as anyone adds the next consumer. Worse, most of the sites in THIS package
// survive only because they hand the keyslot to unlockKeyslot, which validates
// -- a guarantee living in a callee, one refactor from being gone. Dealt with
// here, there is nothing left to enumerate.
//
// # Reject or drop, and why they are different
//
// The rule is not "reject every null". It is that a bad state should be
// unrepresentable where it is bad and tolerated where the tolerance is a
// feature, and the test is whether a caller can do anything USEFUL with the
// absence:
//
//   - segments, digests: REJECTED. A segment whose location is unknown cannot be
//     proved clear of, and a digest that cannot be evaluated must not be
//     silently skipped -- skipping it weakens verification rather than degrading
//     it.
//   - config: REJECTED, on a different ground worth keeping straight. LUKS2
//     REQUIRES a config object, so a header without one is malformed rather than
//     degraded, and it has no redundancy to fall back on the way a missing
//     keyslot has other keyslots.
//   - keyslots, tokens: DROPPED. Rejecting would be a data-availability
//     regression: getMasterKey deliberately keeps trying other keyslots so a
//     volume survives one damaged slot, and refusing the header would make a
//     volume with one corrupt UNUSED slot permanently unopenable. Tokens are
//     auxiliary unlock paths (TPM, FIDO2), so a malformed one must not stop a
//     volume opening by passphrase.
//
// # It is reported, and it does not choose a logging destination
//
// Every removed entry is recorded on LUKS2Metadata.DroppedNullEntries, so a
// caller can learn a header was repaired under it. It used to be silent, and
// #27 records why the obvious fixes were refused: a logger in a Layer-0
// primitive -- or a write to log/slog's process-global default -- imposes a
// logging decision on every embedding application, and widening ReadHeader's
// signature is an API break for every caller. A field costs nothing at any
// call site, adds no second way to read a header, and leaves the application
// to decide whether an operator sees it. cmd/luks2 is that application here:
// `luks2 info` prints a warning to stderr, which is what makes this a
// capability rather than an offer nobody takes up.
//
// STILL SILENT ON PURPOSE is the write side: nothing here refuses the
// subsequent WriteHeader that makes the removal permanent. The removal is the
// repair -- a volume carrying a null keyslot cannot be modified at all, since
// the slot is undeletable and blocks every future AddKey -- so the caller is
// told, not stopped.
//
// # What it does NOT fix
//
// The null dimension only. getMasterKey also skips a keyslot whose Type is not
// "luks2" -- a "reencrypt" slot is valid metadata recording an in-progress
// reencryption, so it must be preserved, not dropped, and it still cannot open
// the volume. len() is correct about nulls after this and still wrong about
// types.
//
// The prior art also rejects a non-canonical keyslot id ("01" alongside "1",
// which collapses two slots into one listing entry while both stay live for
// unlock). That is a separate defect with its own measurement and its own
// behavior change, and it is deliberately not folded in here.
func normalizeMetadataNulls(metadata *LUKS2Metadata) error {
	for id, segment := range metadata.Segments {
		if segment == nil {
			return fmt.Errorf("%w: segment %q is null", ErrInvalidHeader, id)
		}
	}

	for id, digest := range metadata.Digests {
		if digest == nil {
			return fmt.Errorf("%w: digest %q is null", ErrInvalidHeader, id)
		}
	}

	if metadata.Config == nil {
		return fmt.Errorf("%w: config is null", ErrInvalidHeader)
	}

	// TWO PHASES, and the separation is structural rather than a convenient
	// ordering.
	//
	// Phase one removes every null. Phase two repairs the references that
	// pointed at what was removed. Doing both in one pass means a nil is still
	// LIVE in one map while another map's references are being rewritten -- and
	// rewriting a token's keyslot list dereferences the token, so a header
	// carrying a null keyslot AND a null token panics inside the reader itself.
	// Each null is handled correctly alone; the combination is not, because the
	// single-pass shape allows a partially-normalized state to exist at all.
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

	// The report is ORDERED. It is built by ranging two maps, so leaving it
	// as-is would hand a caller a list that changes between runs for an
	// unchanged device -- the same defect the keyslot listing has (#57), newly
	// manufactured in a diagnostic whose whole purpose is to be compared
	// against what an operator saw last time.
	sortDroppedEntries(metadata.DroppedNullEntries)

	// Phase two. A dropped keyslot must stop being referenced by digests and
	// tokens, or the header this read produces is internally inconsistent: a
	// digest naming a keyslot that is not there.
	for _, id := range dropped {
		forgetKeyslotID(metadata, id)
	}

	return nil
}

// sortDroppedEntries puts the report in a stable, human order: keyslots before
// tokens, and within a kind ascending by numeric id, with ids that do not parse
// as a number after those in lexical order.
//
// Ids are compared numerically rather than lexically because these are slot
// numbers, and "10" sorting before "2" in a list an operator is reading against
// a luksDump is a small, avoidable confusion. Ties on the numeric value break
// on the raw spelling, so two spellings of one number ("1" and "01") are still
// ordered rather than left to the sort's instability.
func sortDroppedEntries(entries []DroppedEntry) {
	slices.SortFunc(entries, func(a, b DroppedEntry) int {
		if c := cmp.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		na, errA := strconv.Atoi(a.ID)
		nb, errB := strconv.Atoi(b.ID)
		switch {
		case errA == nil && errB == nil:
			if c := cmp.Compare(na, nb); c != 0 {
				return c
			}
		case errA == nil:
			return -1
		case errB == nil:
			return 1
		}
		return cmp.Compare(a.ID, b.ID)
	})
}

// forgetKeyslotID removes every reference to a keyslot id from the digests and
// tokens that name it.
//
// Both maps are free of nulls by the time this runs -- that is what phase one
// guarantees -- so neither loop needs a nil guard, and adding one would suggest
// the ordering is optional.
func forgetKeyslotID(metadata *LUKS2Metadata, id string) {
	for _, digest := range metadata.Digests {
		digest.Keyslots = withoutID(digest.Keyslots, id)
	}
	for _, token := range metadata.Tokens {
		token.Keyslots = withoutID(token.Keyslots, id)
	}
}

// withoutID returns ids with every occurrence of id removed. It allocates a new
// slice rather than filtering in place, because the input may be shared with a
// caller that parsed it.
func withoutID(ids []string, id string) []string {
	out := make([]string, 0, len(ids))
	for _, candidate := range ids {
		if candidate != id {
			out = append(out, candidate)
		}
	}
	return out
}

// volumeKeyBits returns the size, in bits, of the key the data in segmentID is
// encrypted with: the key size of a keyslot that a digest attests for that
// segment. It is 0 when no keyslot is attested for it. Keyslots and digests
// are visited in sorted order, so the answer does not depend on map order.
func volumeKeyBits(metadata *LUKS2Metadata, segmentID string) int {
	for _, digestID := range sortedIDs(metadata.Digests) {
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

// GetVolumeInfo extracts volume information from a LUKS device
func GetVolumeInfo(device string) (*VolumeInfo, error) {
	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		return nil, err
	}

	info := &VolumeInfo{
		UUID:     string(bytes.TrimRight(hdr.UUID[:], "\x00")),
		Label:    string(bytes.TrimRight(hdr.Label[:], "\x00")),
		Version:  int(hdr.Version),
		Metadata: metadata,
	}

	// The lowest-id crypt segment, in sorted order rather than whichever one
	// map iteration yielded first. It is the segment Unlock maps whenever
	// Unlock maps one (activationSegment), and unlike Unlock this reports on a
	// multi-segment container too, which is when an operator needs to look.
	for _, segmentID := range sortedIDs(metadata.Segments) {
		if segment := metadata.Segments[segmentID]; segment != nil && segment.Type == "crypt" {
			info.Cipher = segment.Encryption
			info.SectorSize = segment.SectorSize
			info.KeySize = volumeKeyBits(metadata, segmentID)
			break
		}
	}

	// Find active keyslots, in the order unlock attempts them rather than in Go
	// map order.
	//
	// Ranging the map put this list in a different order on every call, so
	// `luks2 info` printed "Active Keyslots: [2 0 1]" and then "[1 2 0]" for a
	// device nothing had touched. That defeats diff between two runs, makes the
	// output useless as a fixture, and invites an operator to believe something
	// changed when nothing did (#57).
	//
	// keyslotIDsInScanOrder is reused rather than sorted here, so the list an
	// operator reads is in the same order unlock tries the slots in -- one
	// ordering for the package, not two that can drift.
	for _, id := range keyslotIDsInScanOrder(metadata.Keyslots) {
		// Parse keyslot ID
		var slotNum int
		if _, err := fmt.Sscanf(id, "%d", &slotNum); err == nil {
			info.ActiveKeyslots = append(info.ActiveKeyslots, slotNum)
		}
	}

	return info, nil
}
