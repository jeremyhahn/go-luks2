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

// reclassifyUnsupportedChecksum maps header.ErrUnsupportedHeaderChecksum to the public ErrUnsupported.
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

// reclassifyMetadataTooLarge maps header.ErrMetadataTooLarge to the public ErrNoSpace.
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

// readHeaderForTest reads and validates the primary header; JSON-null keyslots and tokens are removed and reported in DroppedNullEntries.
func readHeaderForTest(device string) (*header.BinaryHeader, *header.Metadata, error) {
	return readHeaderCopy(device, header.PrimaryHeaderOffset)
}

// readHeaderForTestWithSys is readHeaderForTest, parameterized by sys so
// this package's tests can inject a seam the unparameterized helper has no
// room for.
func readHeaderForTestWithSys(device string, sys volumeSys) (*header.BinaryHeader, *header.Metadata, error) {
	return readHeaderCopyWithSys(device, header.PrimaryHeaderOffset, sys)
}

// readSecondaryHeaderForTest reads and validates the second header copy, which carries the SKUL magic.
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

// restorePrimaryHeaderCore rewrites the primary from the fully validated secondary read through f, refusing an intact, newer primary unless force; sequence id goes one above both.
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

	// The restore reproduces a copy already on the medium, so only header-wide rules apply.
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

// repairSecondaryHeader rewrites only the secondary from the primary at its sequence id, through the pinned descriptor; the caller holds the lock.
func repairSecondaryHeader(ctx context.Context, dev *keyslotDevice, hdr *header.BinaryHeader, metadata *header.Metadata) error {
	if err := dev.sys.keyslotWriteStep(ctx, dev, "repair the secondary LUKS2 header"); err != nil {
		return err
	}
	f := dev.file

	jsonData, area, err := header.EncodeMetadataForHeader(hdr, metadata)
	if err != nil {
		return reclassifyMetadataTooLarge(err)
	}

	// The primary is durable before any secondary byte is written.
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

	// The lowest-id crypt segment in sorted order: the one Unlock maps.
	for _, segmentID := range header.SortedIDs(metadata.Segments) {
		if segment := metadata.Segments[segmentID]; segment != nil && segment.Type == "crypt" {
			info.Cipher = segment.Encryption
			info.SectorSize = segment.SectorSize
			info.KeySize = header.VolumeKeyBits(metadata, segmentID)
			break
		}
	}

	// Active keyslots, in the order unlock attempts them.
	for _, id := range header.KeyslotIDsInScanOrder(metadata.Keyslots) {
		var slotNum int
		if _, err := fmt.Sscanf(id, "%d", &slotNum); err == nil {
			info.ActiveKeyslots = append(info.ActiveKeyslots, slotNum)
		}
	}

	return info, nil
}
