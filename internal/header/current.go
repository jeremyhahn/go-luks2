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

// ReadCurrentHeader reads both copies and picks the valid one with the higher sequence id (primary on a tie), as cryptsetup's LUKS2_disk_hdr_read does; nothing is written.
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

// probeSecondaryHeader tries every legal area size for the secondary copy, accepting only a fully valid one.
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
