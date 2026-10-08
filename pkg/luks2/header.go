// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// readHeaderCopyFrom reads one header copy through internal/header and folds
// header.ErrUnsupportedHeaderChecksum into the public ErrUnsupported.
func readHeaderCopyFrom(f io.ReaderAt, offset int64) (*header.BinaryHeader, *header.Metadata, error) {
	hdr, metadata, err := header.ReadHeaderCopyFrom(f, offset)
	return hdr, metadata, reclassifyUnsupportedChecksum(err)
}

// reclassifyUnsupportedChecksum is header.ErrUnsupportedHeaderChecksum
// (DESIGN.md §C.3): internal/header's own sentinel, folded into the
// public ErrUnsupported at every place a header read crosses the package
// boundary, without internal/header changing what it already matches
// (ErrInvalidHeader, via its own Is).
func reclassifyUnsupportedChecksum(err error) error {
	if err != nil && errors.Is(err, header.ErrUnsupportedHeaderChecksum) {
		return &errs.Error{Kind: ErrUnsupported, Err: err}
	}
	return err
}

// checkHeaderWritable is header.CheckHeaderWritable with
// header.ErrMetadataTooLarge folded into the public ErrNoSpace.
func checkHeaderWritable(hdr *header.BinaryHeader, metadata *header.Metadata) error {
	return reclassifyMetadataTooLarge(header.CheckHeaderWritable(hdr, metadata))
}

// reclassifyMetadataTooLarge is header.ErrMetadataTooLarge (DESIGN.md §C.3):
// internal/header's own sentinel, folded into the public ErrNoSpace at
// every place this package's metadata encoding crosses the package
// boundary.
func reclassifyMetadataTooLarge(err error) error {
	if err != nil && errors.Is(err, header.ErrMetadataTooLarge) {
		return &errs.Error{Kind: ErrNoSpace, Err: err}
	}
	return err
}

// encodeMetadata is header.EncodeMetadata with header.ErrMetadataTooLarge
// folded into the public ErrNoSpace.
func encodeMetadata(hdr *header.BinaryHeader, metadata *header.Metadata) ([]byte, int, error) {
	jsonData, area, err := header.EncodeMetadata(hdr, metadata)
	return jsonData, area, reclassifyMetadataTooLarge(err)
}

// encodeMetadataForHeader is header.EncodeMetadataForHeader with
// header.ErrMetadataTooLarge folded into the public ErrNoSpace.
func encodeMetadataForHeader(hdr *header.BinaryHeader, metadata *header.Metadata) ([]byte, int, error) {
	jsonData, area, err := header.EncodeMetadataForHeader(hdr, metadata)
	return jsonData, area, reclassifyMetadataTooLarge(err)
}

// writeHeaderTo is header.WriteHeaderTo, supplying this package's syncDevice
// seam, with header.ErrMetadataTooLarge folded into the public ErrNoSpace.
func writeHeaderTo(f *os.File, hdr *header.BinaryHeader, metadata *header.Metadata, sync func(*os.File) error) error {
	return reclassifyMetadataTooLarge(header.WriteHeaderTo(f, hdr, metadata, sync))
}

// readHeaderForTest reads and validates the PRIMARY LUKS2 header from a device.
// For the second copy -- which carries a different magic -- see
// ReadSecondaryHeader.
//
// A keyslot or token the header spells as JSON null is REMOVED from the
// returned metadata rather than handed back as a nil map entry -- see
// internal/header for why, and for why segments, digests and config are
// refused instead. The removed entries are reported on
// header.Metadata.DroppedNullEntries, so a caller can tell that a
// readHeaderForTest -> mutate -> writeHeaderForTest cycle is about to drop
// them from the header on disk.
func readHeaderForTest(device string) (*header.BinaryHeader, *header.Metadata, error) {
	return readHeaderCopy(device, header.PrimaryHeaderOffset)
}

// readHeaderForTestWithSys is readHeaderForTest, parameterized by sys so
// this package's tests can inject a seam the unparameterized helper has no
// room for.
func readHeaderForTestWithSys(device string, sys volumeSys) (*header.BinaryHeader, *header.Metadata, error) {
	return readHeaderCopyWithSys(device, header.PrimaryHeaderOffset, sys)
}

// readSecondaryHeaderForTest reads and validates the SECOND LUKS2 header copy, the one
// carrying the SKUL magic.
//
// It exists because writing a spec-correct backup header is only half of a
// recovery path: without a reader that knows the secondary magic, this library
// would produce a copy it could not itself open, which is the state #64
// describes.
//
// The header it returns is a SECONDARY header: its magic is header.SecondaryMagic
// and its hdr_offset is the copy's own offset, because that is what is on disk.
// Callers repairing a damaged primary should use (*Volume).RestorePrimaryHeader rather
// than assembling the sequence themselves; writing this header back is safe --
// WriteHeaderTo stamps each copy's identity -- but the named operation
// takes the lock for the whole read-and-write.
func readSecondaryHeaderForTest(device string) (*header.BinaryHeader, *header.Metadata, error) {
	if err := validateDevicePath(device); err != nil {
		return nil, nil, err
	}
	f, err := openDevice("read the LUKS2 header", device, os.O_RDONLY, defaultVolumeSys())
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	hdr, metadata, err := header.ReadSecondaryHeaderFrom(f)
	return hdr, metadata, reclassifyUnsupportedChecksum(err)
}

// restorePrimaryHeaderCore rewrites the primary header from the secondary
// copy read through f, refusing with ErrPrimaryHeaderCurrent when the
// primary is intact and at least as new, unless force is set. It is the
// core (*Volume).RestorePrimaryHeader and (*Volume).ReplacePrimaryHeader
// share: every read and the write go through f, so the copies compared, the
// copy restored and the device written are all the one descriptor the
// caller locked (and, for the new API, claimed) -- nothing here resolves
// path again.
//
// It exists because "read the secondary and write it back" is a sequence a
// caller should not have to get right. The header ReadSecondaryHeaderFrom
// returns is a SECONDARY header -- that is what it was asked for -- and what
// makes writing it back safe is that WriteHeaderTo stamps each copy's
// identity itself. Naming the operation puts that guarantee behind an API
// instead of behind a comment, and makes it one locked step rather than a
// read and a write with a window between them.
//
// The secondary copy is validated in full before anything is written: magic,
// version, recorded offset, header size, checksum and JSON body. A container
// whose second copy is also damaged is left exactly as it was.
//
// # It repairs; it does not roll back
//
// It refuses with ErrPrimaryHeaderCurrent when the primary is intact and its
// sequence id is not lower than the secondary's (#248), unless force is set.
// Header writes put the primary on the medium first, so an interrupted
// ChangeKey or RemoveKey can leave a NEWER primary -- the passphrase already
// revoked -- over an OLDER secondary that still lists it. Restoring that
// secondary would bring the revoked passphrase back. cryptsetup resolves the
// same state the other way, keeping the higher sequence id.
// (*Volume).ReplacePrimaryHeader sets force to restore anyway.
//
// The restored header is written at a sequence id one above both copies', so
// no reader can mistake the restored state for either earlier one.
func restorePrimaryHeaderCore(f *os.File, path string, force bool, sync func(*os.File) error) error {
	if err := requireLockableDevice(f, path); err != nil {
		return err
	}

	hdr, metadata, err := header.ReadSecondaryHeaderFrom(f)
	err = reclassifyUnsupportedChecksum(err)
	if err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "cannot restore the primary header", Err: err}
	}

	sequence := hdr.SequenceID
	if primary, _, err := header.ReadHeaderCopyFrom(f, header.PrimaryHeaderOffset); err == nil {
		if primary.SequenceID >= hdr.SequenceID && !force {
			return &errs.Error{Kind: ErrPrimaryHeaderCurrent, Detail: fmt.Sprintf(
				"%s: primary sequence id %d, secondary %d; the secondary copy is repaired by the next header write",
				path, primary.SequenceID, hdr.SequenceID)}
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
	return header.WriteEncodedHeader(f, hdr, jsonData, area, sync)
}

// readHeaderCopy reads and validates one header copy at a known offset.
func readHeaderCopy(device string, offset int64) (*header.BinaryHeader, *header.Metadata, error) {
	return readHeaderCopyWithSys(device, offset, defaultVolumeSys())
}

// readHeaderCopyWithSys is readHeaderCopy, parameterized by sys so this
// package's tests can inject a seam the unparameterized helper has no room
// for.
func readHeaderCopyWithSys(device string, offset int64, sys volumeSys) (*header.BinaryHeader, *header.Metadata, error) {
	if err := validateDevicePath(device); err != nil {
		return nil, nil, err
	}

	f, err := openDevice("read the LUKS2 header", device, os.O_RDONLY, sys)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()

	return readHeaderCopyFrom(f, offset)
}

// isLUKSForTest checks if a device or file contains a LUKS header (either LUKS1 or LUKS2).
// This is a pure Go implementation that doesn't require the cryptsetup CLI.
// It checks for LUKS magic bytes at offset 0.
func isLUKSForTest(device string) (bool, error) {
	return isLUKSForTestWithSys(device, defaultVolumeSys())
}

// isLUKSForTestWithSys is isLUKSForTest, parameterized by sys so this
// package's tests can inject a seam the unparameterized helper has no room
// for.
func isLUKSForTestWithSys(device string, sys volumeSys) (bool, error) {
	if err := validateDevicePath(device); err != nil {
		return false, err
	}

	f, err := openDevice("read the LUKS magic", device, os.O_RDONLY, sys)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	magic := make([]byte, header.MagicLen)
	n, err := f.Read(magic)
	if err != nil {
		return false, &errs.Error{Kind: errs.ErrIO, Detail: "failed to read device", Err: err}
	}
	if n < header.MagicLen {
		return false, nil // Too small to be LUKS
	}

	return bytes.Equal(magic, []byte(header.Magic)), nil
}

// isLUKS2ForTest checks if a device contains a LUKS2 header specifically.
// Returns true only for LUKS2 (not LUKS1).
func isLUKS2ForTest(device string) (bool, error) {
	return isLUKS2ForTestWithSys(device, defaultVolumeSys())
}

// isLUKS2ForTestWithSys is isLUKS2ForTest, parameterized by sys so this
// package's tests can inject a seam the unparameterized helper has no room
// for.
func isLUKS2ForTestWithSys(device string, sys volumeSys) (bool, error) {
	if err := validateDevicePath(device); err != nil {
		return false, err
	}

	f, err := openDevice("read the LUKS magic and version", device, os.O_RDONLY, sys)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	hdr := make([]byte, 8)
	n, err := f.Read(hdr)
	if err != nil {
		return false, &errs.Error{Kind: errs.ErrIO, Detail: "failed to read device", Err: err}
	}
	if n < 8 {
		return false, nil // Too small to be LUKS
	}

	if !bytes.Equal(hdr[:header.MagicLen], []byte(header.Magic)) {
		return false, nil // Not LUKS at all
	}

	version := uint16(hdr[6])<<8 | uint16(hdr[7])
	return version == header.Version, nil
}

// writeHeaderForTest writes a LUKS2 header to a device (acquires lock)
func writeHeaderForTest(device string, hdr *header.BinaryHeader, metadata *header.Metadata) error {
	return writeHeaderWithSys(device, hdr, metadata, defaultVolumeSys())
}

// writeHeaderWithSys is writeHeaderForTest, parameterized by sys so this
// package's tests can inject a seam the wrapper has no room for.
func writeHeaderWithSys(device string, hdr *header.BinaryHeader, metadata *header.Metadata, sys volumeSys) error {
	ctx := context.Background()
	if err := validateDevicePath(device); err != nil {
		return err
	}

	// Written through the descriptor the lock is held on, not a second open
	// of the path, which a re-pointed symlink could send elsewhere.
	lock, dev, err := lockKeyslotDevice(ctx, device, sys)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()

	return dev.writeHeader(ctx, hdr, metadata)
}

// createBinaryHeader creates a new LUKS2 binary header from sys's cryptoRand
// and newUUID, so formatCore and this package's tests can supply their own.
func createBinaryHeader(opts formatOptionsForTest, sys volumeSys) (*header.BinaryHeader, error) {
	if err := validateMetadataSize(opts.MetadataSize); err != nil {
		return nil, err
	}
	return header.CreateBinaryHeader(sys.cryptoRand, sys.newUUID, header.NewHeaderParams{
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
func repairSecondaryHeader(ctx context.Context, dev *keyslotDevice, hdr *header.BinaryHeader, metadata *header.Metadata) error {
	if err := dev.sys.keyslotWriteStep(ctx, dev, "repair the secondary LUKS2 header"); err != nil {
		return err
	}
	f := dev.file

	jsonData, area, err := header.EncodeMetadataForHeader(hdr, metadata)
	if err != nil {
		return reclassifyMetadataTooLarge(err)
	}

	// THE PRIMARY IS MADE DURABLE BEFORE A SINGLE SECONDARY BYTE IS WRITTEN.
	if err := dev.sys.syncDevice(f); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "failed to make the primary header durable before repairing the secondary", Err: err}
	}

	primary := *hdr
	primary.HeaderSize = uint64(area) // #nosec G115 -- HeaderAreaSizeForWrite bounds this to header.HeaderMaxSize
	if err := header.WriteSecondaryCopy(f, &primary, jsonData, area-header.HeaderSize, int64(area)); err != nil {
		return err
	}
	if err := dev.sys.syncDevice(f); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "failed to sync the repaired secondary header", Err: err}
	}
	return nil
}

// getVolumeInfoForTest extracts volume information from a LUKS device
func getVolumeInfoForTest(device string) (*volumeInfoForTest, error) {
	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		return nil, err
	}

	info := &volumeInfoForTest{
		UUID:     string(bytes.TrimRight(hdr.UUID[:], "\x00")),
		Label:    string(bytes.TrimRight(hdr.Label[:], "\x00")),
		Version:  int(hdr.Version),
		Metadata: metadata,
	}

	// The lowest-id crypt segment, in sorted order rather than whichever one
	// map iteration yielded first. It is the segment Unlock maps whenever
	// Unlock maps one (activationSegment), and unlike Unlock this reports on a
	// multi-segment container too, which is when an operator needs to look.
	for _, segmentID := range header.SortedIDs(metadata.Segments) {
		if segment := metadata.Segments[segmentID]; segment != nil && segment.Type == "crypt" {
			info.Cipher = segment.Encryption
			info.SectorSize = segment.SectorSize
			info.KeySize = header.VolumeKeyBits(metadata, segmentID)
			break
		}
	}

	// Find active keyslots, in the order unlock attempts them rather than in
	// Go map order (#57).
	for _, id := range header.KeyslotIDsInScanOrder(metadata.Keyslots) {
		var slotNum int
		if _, err := fmt.Sscanf(id, "%d", &slotNum); err == nil {
			info.ActiveKeyslots = append(info.ActiveKeyslots, slotNum)
		}
	}

	return info, nil
}
