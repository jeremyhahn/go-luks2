// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
)

// LUKS2 header copy locations. LUKS2 stores the header twice so a torn or
// damaged primary can be recovered from the secondary; the two copies differ in
// their magic (see LUKS2SecondaryMagic) and in the hdr_offset they record.
const (
	// LUKS2PrimaryHeaderOffset is where the first header copy starts.
	LUKS2PrimaryHeaderOffset int64 = 0

	// LUKS2SecondaryHeaderOffset is where the second header copy starts for the
	// 16 KiB metadata size this library writes. It is the primary copy's total
	// area size, not a free-standing constant: a container written with a larger
	// metadata area puts its second copy correspondingly further out.
	LUKS2SecondaryHeaderOffset int64 = 0x4000
)

// ReadHeader reads and validates the PRIMARY LUKS2 header from a device.
// For the second copy -- which carries a different magic -- see
// ReadSecondaryHeader.
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
// writeHeaderInternal stamps each copy's identity -- but the named operation
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
	return readSecondaryHeader(device)
}

// RestorePrimaryHeader rebuilds a damaged primary header from the secondary
// copy, and is the operation ReadSecondaryHeader's documentation describes.
//
// It exists because "read the secondary and write it back" is a sequence a
// caller should not have to get right. The header returned by
// ReadSecondaryHeader is a SECONDARY header -- that is what it was asked for --
// and what makes writing it back safe is that writeHeaderInternal stamps each
// copy's identity itself. Naming the operation puts that guarantee behind an
// API instead of behind a comment, and makes it one locked step rather than a
// read and a write with a window between them.
//
// The secondary copy is validated in full before anything is written: magic,
// version, recorded offset, header size, checksum and JSON body. A container
// whose second copy is also damaged is left exactly as it was.
func RestorePrimaryHeader(device string) error {
	if err := ValidateDevicePath(device); err != nil {
		return err
	}

	lock, err := AcquireFileLock(device)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	hdr, metadata, err := readSecondaryHeader(device)
	if err != nil {
		return fmt.Errorf("cannot restore the primary header: %w", err)
	}

	return writeHeaderInternal(device, hdr, metadata)
}

// readSecondaryHeader is ReadSecondaryHeader without the device-path check, so
// RestorePrimaryHeader can call it while holding the lock.
func readSecondaryHeader(device string) (*LUKS2BinaryHeader, *LUKS2Metadata, error) {
	// The primary, when it is readable, states the area size outright.
	if hdr, _, err := ReadHeader(device); err == nil {
		if area, err := headerAreaSize(hdr); err == nil {
			return readHeaderCopy(device, int64(area))
		}
	}

	// The primary is damaged. Probe every legal offset; smallest first, which is
	// the overwhelmingly common geometry.
	var firstErr error
	for _, offset := range legalHeaderAreaSizes() {
		hdr, metadata, err := readHeaderCopy(device, offset)
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

	f, err := os.Open(device) // #nosec G304 -- device path validated above
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open device: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Read binary header (LUKS2 uses big-endian for integer fields)
	raw := make([]byte, LUKS2HeaderSize)
	if _, err := f.ReadAt(raw, offset); err != nil {
		return nil, nil, fmt.Errorf("failed to read header: %w", err)
	}
	var hdr LUKS2BinaryHeader
	if err := binary.Read(bytes.NewReader(raw), binary.BigEndian, &hdr); err != nil {
		return nil, nil, fmt.Errorf("failed to read header: %w", err)
	}

	// Validate magic -- which copy this is decides which magic is correct
	if !bytes.Equal(hdr.Magic[:], []byte(expectedMagic(offset))) {
		return nil, nil, fmt.Errorf("%w: invalid LUKS magic at offset %d: not a LUKS2 device",
			ErrInvalidHeader, offset)
	}

	// Validate version
	if hdr.Version != LUKS2Version {
		return nil, nil, fmt.Errorf("unsupported LUKS version: %d", hdr.Version)
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
		return nil, nil, fmt.Errorf("%w: header copy at offset %d records hdr_offset %d",
			ErrInvalidHeader, offset, recorded)
	}

	// A secondary copy begins where the primary ends, so its offset and the
	// header area size are the same number. Checking it here is what lets
	// ReadSecondaryHeader probe candidate offsets safely: a copy that merely
	// happens to carry the SKUL magic at some offset is still rejected unless
	// the container's own geometry agrees that the copy belongs there.
	if offset != LUKS2PrimaryHeaderOffset && hdr.HeaderSize != uint64(offset) { // #nosec G115 -- offset is a positive legal area size
		return nil, nil, fmt.Errorf("%w: secondary header at offset %d records header size %d, want %d",
			ErrInvalidHeader, offset, hdr.HeaderSize, offset)
	}

	// Validate checksum
	if err := validateHeaderChecksum(&hdr, f, offset); err != nil {
		return nil, nil, err
	}

	// Read JSON metadata
	metadata, err := readJSONMetadata(f, &hdr, offset)
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

	f, err := os.Open(device) // #nosec G304 -- device path validated above
	if err != nil {
		return false, fmt.Errorf("failed to open device: %w", err)
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

	f, err := os.Open(device) // #nosec G304 -- device path validated above
	if err != nil {
		return false, fmt.Errorf("failed to open device: %w", err)
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

	// Acquire file lock for exclusive access
	lock, err := AcquireFileLock(device)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	return writeHeaderInternal(device, hdr, metadata)
}

// writeHeaderInternal writes a LUKS2 header without acquiring a lock
// Caller must hold the lock
func writeHeaderInternal(device string, hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata) error {
	f, err := os.OpenFile(device, os.O_RDWR, 0600) // #nosec G304 -- device path from trusted internal call
	if err != nil {
		return fmt.Errorf("failed to open device: %w", err)
	}
	defer func() { _ = f.Close() }()

	// The header area size is FIXED by the container; it is never recomputed
	// from how much metadata happens to need writing. See headerAreaSizeForWrite.
	area, err := headerAreaSizeForWrite(hdr)
	if err != nil {
		return err
	}
	jsonSize := area - LUKS2HeaderSize
	secondaryOffset := int64(area)

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
	jsonData, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
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
		return fmt.Errorf("%w: %d bytes of JSON metadata plus its terminator do not fit the %d-byte JSON area of this container's %d-byte header (remove keyslots or tokens, or reformat with a larger metadata area)",
			ErrMetadataTooLarge, len(jsonData), jsonSize, area)
	}

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
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write JSON metadata with padding
	if _, err := f.Write(jsonData); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	// Null-terminate and pad to jsonSize
	padding := make([]byte, jsonSize-len(jsonData))
	if _, err := f.Write(padding); err != nil {
		return fmt.Errorf("failed to write padding: %w", err)
	}

	// Write backup header at the secondary offset, which is the header AREA
	// SIZE -- the second copy begins where the first one ends. Seeking to a
	// constant 0x4000 was correct only while the area was always 0x4000, and
	// silently wrong the moment it was not.
	if _, err := f.Seek(secondaryOffset, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to backup header: %w", err)
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
		return fmt.Errorf("failed to write backup header: %w", err)
	}

	// Write backup JSON metadata
	if _, err := f.Write(jsonData); err != nil {
		return fmt.Errorf("failed to write backup metadata: %w", err)
	}
	if _, err := f.Write(padding); err != nil {
		return fmt.Errorf("failed to write backup padding: %w", err)
	}

	return f.Sync()
}

// CreateBinaryHeader creates a new LUKS2 binary header
func CreateBinaryHeader(opts FormatOptions) (*LUKS2BinaryHeader, error) {
	hdr := &LUKS2BinaryHeader{
		Version: LUKS2Version,
	}

	// Set magic
	copy(hdr.Magic[:], LUKS2Magic)

	// Set checksum algorithm
	copy(hdr.ChecksumAlgorithm[:], "sha256")

	// Generate UUID
	u := uuid.New()
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
	if _, err := rand.Read(hdr.Salt[:]); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Sequence ID starts at 1
	hdr.SequenceID = 1

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
// hdr.HeaderSize carries it. For a header that has never been written --
// CreateBinaryHeader leaves it zero -- the area is LUKS2HeaderMinSize, which is
// the geometry Format lays out (keyslot material at 0x8000, immediately after
// two 0x4000 copies).
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

// validateHeaderChecksum validates the checksum of the header copy at
// headerOffset. The offset is a parameter rather than something re-derived from
// hdr.HeaderOffset: the caller knows where it read the copy from, and the field
// is attacker-controlled. readHeaderCopy has already required the two to agree.
func validateHeaderChecksum(hdr *LUKS2BinaryHeader, r io.ReaderAt, headerOffset int64) error {
	// Read entire header area
	headerSize, err := headerAreaSize(hdr)
	if err != nil {
		return err
	}
	headerData := make([]byte, headerSize)
	if _, err := r.ReadAt(headerData, headerOffset); err != nil {
		return fmt.Errorf("failed to read header for checksum: %w", err)
	}

	// Zero out checksum field.
	//
	// This writes fixed indices 0x1C0..0x1FF into headerData without checking
	// its length. What makes that safe is the headerAreaSize call above, which
	// rejects any HeaderSize at or below LUKS2HeaderSize, so headerData is
	// always at least 4097 bytes. The enforcer is named here rather than left
	// implicit because it is not visible at this line, and a reader who does not
	// know where the bound lives has no way to tell a safe fixed index from a
	// lucky one. Anything that reaches this loop by another route must bound
	// len(headerData) first -- see #62.
	checksumOffset := 0x1C0 // Offset of Checksum field

	for i := 0; i < 64; i++ {
		headerData[checksumOffset+i] = 0
	}

	// Calculate checksum
	h := sha256.New()
	h.Write(headerData)
	calculated := h.Sum(nil)

	// Compare
	if !bytes.Equal(calculated, hdr.Checksum[:len(calculated)]) {
		return fmt.Errorf("header checksum mismatch\nExpected: %x\nCalculated: %x\nHeaderSize: %d, HeaderOffset: %d",
			hdr.Checksum[:32], calculated[:32], hdr.HeaderSize, hdr.HeaderOffset)
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
// headerOffset. As with validateHeaderChecksum, the offset is passed in rather
// than re-derived from the attacker-controlled hdr.HeaderOffset field.
func readJSONMetadata(r io.ReaderAt, hdr *LUKS2BinaryHeader, headerOffset int64) (*LUKS2Metadata, error) {
	// Bounded conversion of header size
	headerSizeInt, err := headerAreaSize(hdr)
	if err != nil {
		return nil, err
	}
	jsonSize := headerSizeInt - LUKS2HeaderSize
	jsonData := make([]byte, jsonSize)

	offset := headerOffset + LUKS2HeaderSize
	if _, err := r.ReadAt(jsonData, offset); err != nil {
		return nil, fmt.Errorf("failed to read JSON metadata: %w", err)
	}

	// Find null terminator
	nullIdx := bytes.IndexByte(jsonData, 0)
	if nullIdx != -1 {
		jsonData = jsonData[:nullIdx]
	}

	var metadata LUKS2Metadata
	if err := json.Unmarshal(jsonData, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse JSON metadata: %w", err)
	}

	// A JSON null is normalized away HERE, at the one point metadata is parsed.
	// See normalizeMetadataNulls.
	if err := normalizeMetadataNulls(&metadata); err != nil {
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
// # It is silent, deliberately
//
// A caller cannot learn that entries were dropped, and that is a decided
// question rather than an oversight: issue #27 records the analysis. Narrating a
// repair needs a logger, and a Layer-0 primitive taking a logging dependency --
// or writing to log/slog's process-global default -- imposes a logging decision
// on every embedding application. Widening ReadHeader's signature is an API
// break for every caller. #27 exists so that the next person does not re-derive
// this and reach for the global logger; this comment is that person being
// stopped.
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
		}
	}
	for id, token := range metadata.Tokens {
		if token == nil {
			delete(metadata.Tokens, id)
		}
	}

	// Phase two. A dropped keyslot must stop being referenced by digests and
	// tokens, or the header this read produces is internally inconsistent: a
	// digest naming a keyslot that is not there.
	for _, id := range dropped {
		forgetKeyslotID(metadata, id)
	}

	return nil
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

	// Extract cipher info from first segment
	for _, seg := range metadata.Segments {
		if seg.Type == "crypt" {
			info.Cipher = seg.Encryption
			info.SectorSize = seg.SectorSize
			break
		}
	}

	// Find active keyslots
	for id := range metadata.Keyslots {
		// Parse keyslot ID
		var slotNum int
		if _, err := fmt.Sscanf(id, "%d", &slotNum); err == nil {
			info.ActiveKeyslots = append(info.ActiveKeyslots, slotNum)
		}
	}

	return info, nil
}
