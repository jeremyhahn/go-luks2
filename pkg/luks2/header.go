// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bytes"
	"fmt"
	"math"
	"os"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// LUKS2 header copy locations. LUKS2 stores the header twice so a torn or
// damaged primary can be recovered from the secondary; the two copies differ in
// their magic (see LUKS2SecondaryMagic) and in the hdr_offset they record.
const (
	LUKS2PrimaryHeaderOffset   = header.PrimaryHeaderOffset
	LUKS2SecondaryHeaderOffset = header.SecondaryHeaderOffset

	// LUKS2HeaderMaxSize bounds the header size accepted from disk.
	LUKS2HeaderMaxSize = header.HeaderMaxSize

	// checksumFieldOffset is where the 64-byte checksum field sits inside the
	// 4096-byte binary header.
	checksumFieldOffset = header.ChecksumFieldOffset

	// headerChecksumAlgorithm is the only checksum algorithm this package
	// reads or writes a LUKS2 binary header with.
	headerChecksumAlgorithm = header.HeaderChecksumAlgorithm
)

// The binary header, the JSON codec, canonical JSON, checksums and
// requirements now live in internal/header; see docs/design/DECISIONS.md's
// H5 entry. The pure functions below are transitional forwards, kept under
// their original names so every existing caller and test in this package
// keeps compiling unchanged. They are removed at H13.
var (
	readHeaderCopyFrom      = header.ReadHeaderCopyFrom
	legalHeaderAreaSizes    = header.LegalHeaderAreaSizes
	expectedMagic           = header.ExpectedMagic
	checkHeaderWritable     = header.CheckHeaderWritable
	headerCopiesAgree       = header.HeaderCopiesAgree
	headerAreaSizeForWrite  = header.HeaderAreaSizeForWrite
	headerAreaSize          = header.HeaderAreaSize
	headerAreaOffset        = header.HeaderAreaOffset
	calculateHeaderChecksum = header.CalculateHeaderChecksum
	readJSONMetadata        = header.ReadJSONMetadata
	forgetKeyslotID         = header.ForgetKeyslotID
	withoutID               = header.WithoutID
	volumeKeyBits           = header.VolumeKeyBits
	marshalCanonicalJSON    = header.MarshalCanonicalJSON
	encodeMetadata          = header.EncodeMetadata
	encodeMetadataForHeader = header.EncodeMetadataForHeader

	canonicalKeyslotID    = header.CanonicalKeyslotID
	keyslotIDsInScanOrder = header.KeyslotIDsInScanOrder
	volumeKeyScanOrder    = header.VolumeKeyScanOrder
	volumeKeyDigestsView  = header.VolumeKeyDigestsView
)

// validateHeaderChecksum forwards to header.ValidateHeaderChecksum.
func validateHeaderChecksum(hdr *LUKS2BinaryHeader, r readerAt, headerOffset int64, headerSize int) error {
	return header.ValidateHeaderChecksum(hdr, r, headerOffset, headerSize)
}

// readerAt is io.ReaderAt, named locally so this file's forwards do not need
// an "io" import solely for the parameter type.
type readerAt = interface {
	ReadAt(p []byte, off int64) (n int, err error)
}

// writeHeaderTo forwards to header.WriteHeaderTo, supplying this package's
// syncDevice seam.
func writeHeaderTo(f *os.File, hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata) error {
	return header.WriteHeaderTo(f, hdr, metadata, syncDevice)
}

// writeEncodedHeader forwards to header.WriteEncodedHeader, supplying this
// package's syncDevice seam.
func writeEncodedHeader(f *os.File, hdr *LUKS2BinaryHeader, jsonData []byte, area int) error {
	return header.WriteEncodedHeader(f, hdr, jsonData, area, syncDevice)
}

// ReadHeader reads and validates the PRIMARY LUKS2 header from a device.
// For the second copy -- which carries a different magic -- see
// ReadSecondaryHeader.
//
// A keyslot or token the header spells as JSON null is REMOVED from the
// returned metadata rather than handed back as a nil map entry -- see
// internal/header for why, and for why segments, digests and config are
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
// WriteHeaderTo stamps each copy's identity -- but the named operation
// takes the lock for the whole read-and-write.
func ReadSecondaryHeader(device string) (*LUKS2BinaryHeader, *LUKS2Metadata, error) {
	if err := ValidateDevicePath(device); err != nil {
		return nil, nil, err
	}
	f, err := openDevice("read the LUKS2 header", device, os.O_RDONLY)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	return header.ReadSecondaryHeaderFrom(f)
}

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
// and what makes writing it back safe is that WriteHeaderTo stamps each
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
		return &errs.Error{Detail: "failed to acquire lock", Err: err}
	}
	defer func() { _ = lock.Release() }()

	// EVERY READ AND THE WRITE GO THROUGH THE LOCKED DESCRIPTOR, so the
	// copies compared, the copy restored and the device written are the one
	// the lock is held on: the path is not resolved again (#248, as #249 does
	// for the keyslot operations).
	f := lock.locked.File()
	if err := requireLockableDevice(f, device); err != nil {
		return err
	}

	hdr, metadata, err := header.ReadSecondaryHeaderFrom(f)
	if err != nil {
		return &errs.Error{Detail: "cannot restore the primary header", Err: err}
	}

	sequence := hdr.SequenceID
	if primary, _, err := header.ReadHeaderCopyFrom(f, LUKS2PrimaryHeaderOffset); err == nil {
		if primary.SequenceID >= hdr.SequenceID && !opts.Force {
			return &errs.Error{Kind: ErrPrimaryHeaderCurrent, Detail: fmt.Sprintf(
				"%s: primary sequence id %d, secondary %d; the secondary copy is repaired by the next header write",
				device, primary.SequenceID, hdr.SequenceID)}
		}
		sequence = max(sequence, primary.SequenceID)
	}
	if sequence == math.MaxUint64 {
		return &errs.Error{Kind: ErrInvalidHeader, Detail: "the header sequence id is at its maximum and cannot be advanced past both copies"}
	}
	hdr.SequenceID = sequence + 1

	// The restore REPRODUCES a copy already on the medium; it authors nothing.
	// So it is held to the header-wide rules the secondary already passed when
	// it was read, not to the per-entry ones every other write applies. A
	// damaged keyslot or token in the secondary is the state the volume was in
	// before the primary tore, and refusing to restore it would leave the
	// volume with no readable primary at all. Remove the damaged entry once
	// the primary is back.
	jsonData, area, err := header.EncodeMetadata(hdr, metadata)
	if err != nil {
		return err
	}
	if err := header.ValidateHeaderWideStructure(area, metadata); err != nil {
		return err
	}
	return header.WriteEncodedHeader(f, hdr, jsonData, area, syncDevice)
}

// readHeaderCopy reads and validates one header copy at a known offset.
func readHeaderCopy(device string, offset int64) (*LUKS2BinaryHeader, *LUKS2Metadata, error) {
	if err := ValidateDevicePath(device); err != nil {
		return nil, nil, err
	}

	f, err := openDevice("read the LUKS2 header", device, os.O_RDONLY)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()

	return header.ReadHeaderCopyFrom(f, offset)
}

// IsLUKS checks if a device or file contains a LUKS header (either LUKS1 or LUKS2).
// This is a pure Go implementation that doesn't require the cryptsetup CLI.
// It checks for LUKS magic bytes at offset 0.
func IsLUKS(device string) (bool, error) {
	if err := ValidateDevicePath(device); err != nil {
		return false, err
	}

	f, err := openDevice("read the LUKS magic", device, os.O_RDONLY)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	magic := make([]byte, LUKS2MagicLen)
	n, err := f.Read(magic)
	if err != nil {
		return false, &errs.Error{Detail: "failed to read device", Err: err}
	}
	if n < LUKS2MagicLen {
		return false, nil // Too small to be LUKS
	}

	return bytes.Equal(magic, []byte(LUKS2Magic)), nil
}

// IsLUKS2 checks if a device contains a LUKS2 header specifically.
// Returns true only for LUKS2 (not LUKS1).
func IsLUKS2(device string) (bool, error) {
	if err := ValidateDevicePath(device); err != nil {
		return false, err
	}

	f, err := openDevice("read the LUKS magic and version", device, os.O_RDONLY)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	hdr := make([]byte, 8)
	n, err := f.Read(hdr)
	if err != nil {
		return false, &errs.Error{Detail: "failed to read device", Err: err}
	}
	if n < 8 {
		return false, nil // Too small to be LUKS
	}

	if !bytes.Equal(hdr[:LUKS2MagicLen], []byte(LUKS2Magic)) {
		return false, nil // Not LUKS at all
	}

	version := uint16(hdr[6])<<8 | uint16(hdr[7])
	return version == LUKS2Version, nil
}

// WriteHeader writes a LUKS2 header to a device (acquires lock)
func WriteHeader(device string, hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata) error {
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

// newUUID is the source of a new container's UUID.
//
// It exists for the same reason cryptoRand (util.go) does and nothing else: a
// UUID is 40 bytes of the binary header, so with no seam here no test can ever
// compare two headers byte for byte. Unexported, no setter, substituted only by
// this package's own tests.
var newUUID = uuid.New

// syncDevice flushes a device written by WriteHeaderTo to stable storage.
//
// It is a seam for one reason: the ORDER of the two header copies' durability
// is the crash-safety property, and it is not observable from outside a
// process -- a test substitutes this to see the device exactly as a power loss
// at each sync point would leave it, and to fail the sync between the copies.
// Unexported and substituted only by this package's own tests, like
// openFileFunc.
var syncDevice = (*os.File).Sync

// CreateBinaryHeader creates a new LUKS2 binary header
func CreateBinaryHeader(opts FormatOptions) (*LUKS2BinaryHeader, error) {
	if err := validateMetadataSize(opts.MetadataSize); err != nil {
		return nil, err
	}
	return header.CreateBinaryHeader(cryptoRand, newUUID, header.NewHeaderParams{
		Label:        opts.Label,
		Subsystem:    opts.Subsystem,
		MetadataSize: opts.MetadataSize,
	})
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
// the volume already opens through exactly as it was -- WriteHeaderTo,
// which writes the primary first, would put the one good copy at risk to
// repair the bad one.
//
// It writes through the caller's pinned descriptor (#255), as one write step.
func repairSecondaryHeader(dev *keyslotDevice, hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata) error {
	if err := keyslotWriteStep(dev, "repair the secondary LUKS2 header"); err != nil {
		return err
	}
	f := dev.file

	jsonData, area, err := header.EncodeMetadataForHeader(hdr, metadata)
	if err != nil {
		return err
	}

	// THE PRIMARY IS MADE DURABLE BEFORE A SINGLE SECONDARY BYTE IS WRITTEN.
	if err := syncDevice(f); err != nil {
		return &errs.Error{Detail: "failed to make the primary header durable before repairing the secondary", Err: err}
	}

	primary := *hdr
	primary.HeaderSize = uint64(area) // #nosec G115 -- HeaderAreaSizeForWrite bounds this to LUKS2HeaderMaxSize
	if err := header.WriteSecondaryCopy(f, &primary, jsonData, area-LUKS2HeaderSize, int64(area)); err != nil {
		return err
	}
	if err := syncDevice(f); err != nil {
		return &errs.Error{Detail: "failed to sync the repaired secondary header", Err: err}
	}
	return nil
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

	// Find active keyslots, in the order unlock attempts them rather than in
	// Go map order (#57).
	for _, id := range keyslotIDsInScanOrder(metadata.Keyslots) {
		var slotNum int
		if _, err := fmt.Sscanf(id, "%d", &slotNum); err == nil {
			info.ActiveKeyslots = append(info.ActiveKeyslots, slotNum)
		}
	}

	return info, nil
}
