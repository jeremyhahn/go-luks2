// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"errors"
	"io"
)

// CurrentHeader is the header copy ReadCurrentHeader chose.
type CurrentHeader struct {
	Header   *BinaryHeader
	Metadata *Metadata

	// Offset is where the chosen copy was read: PrimaryHeaderOffset, or the
	// header area size for the secondary.
	Offset int64

	// Stale is true when the other copy is invalid or at a lower sequence id,
	// so it must be rewritten from this one to bring the two level.
	Stale bool
}

// ReadCurrentHeader reads both header copies and chooses the one a reader must
// use, as cryptsetup's LUKS2_disk_hdr_read (lib/luks2/luks2_disk_metadata.c)
// does:
//
//   - a copy failing magic, checksum or JSON validation is dropped;
//   - of two valid copies the one with the higher sequence id is used, and the
//     primary at a tie -- sequence ids are compared, content is not;
//   - the secondary is read where a valid primary says it is, and only when the
//     primary is invalid is every legal offset probed for it.
//
// A crash part way through a header write tears the primary (it is written
// first), and the secondary then holds the previous header, complete. Reading
// the primary alone refused a volume cryptsetup opens.
//
// With no valid copy the primary's error is returned, so a device that is not
// LUKS2 still says why. A primary carrying the LUKS magic and another version
// fails at once without the secondary being consulted: cryptsetup dispatches on
// the primary's version before it reads either LUKS2 copy, so that device is a
// LUKS1 (or unknown) container, not a damaged LUKS2 one.
//
// Nothing is written: repairing the stale copy needs the exclusive lock, and is
// the caller's to do (see Stale).
func ReadCurrentHeader(device io.ReaderAt) (*CurrentHeader, error) {
	phdr, pmeta, perr := ReadHeaderCopyFrom(device, PrimaryHeaderOffset)
	if errors.Is(perr, ErrUnsupportedLUKSVersion) {
		return nil, perr
	}

	var (
		shdr  *BinaryHeader
		smeta *Metadata
		sAt   int64
		serr  error
	)
	if perr == nil {
		// HeaderAreaSize already passed inside ReadHeaderCopyFrom.
		area, err := HeaderAreaSize(phdr)
		if err != nil {
			return nil, err
		}
		sAt = int64(area)
		shdr, smeta, serr = ReadHeaderCopyFrom(device, sAt)
	} else {
		shdr, smeta, sAt, serr = probeSecondaryHeader(device)
	}

	switch {
	case perr != nil && serr != nil:
		return nil, perr
	case perr != nil:
		return &CurrentHeader{Header: shdr, Metadata: smeta, Offset: sAt, Stale: true}, nil
	case serr != nil:
		return &CurrentHeader{Header: phdr, Metadata: pmeta, Offset: PrimaryHeaderOffset, Stale: true}, nil
	case shdr.SequenceID > phdr.SequenceID:
		return &CurrentHeader{Header: shdr, Metadata: smeta, Offset: sAt, Stale: true}, nil
	default:
		return &CurrentHeader{Header: phdr, Metadata: pmeta, Offset: PrimaryHeaderOffset,
			Stale: phdr.SequenceID > shdr.SequenceID}, nil
	}
}

// probeSecondaryHeader tries every legal header area size for the secondary
// copy, as cryptsetup does (hdr2_offset) when the primary cannot say where it
// is. A candidate is accepted only when it passes every check
// ReadHeaderCopyFrom makes; the error is the first candidate's.
func probeSecondaryHeader(device io.ReaderAt) (*BinaryHeader, *Metadata, int64, error) {
	var firstErr error
	for _, offset := range LegalHeaderAreaSizes() {
		hdr, metadata, err := ReadHeaderCopyFrom(device, offset)
		if err == nil {
			return hdr, metadata, offset, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, nil, 0, firstErr
}
