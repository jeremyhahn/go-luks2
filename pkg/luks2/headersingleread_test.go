// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"testing"
)

// The header copy was read three times -- binary header, checksum area, JSON --
// and ReadHeader takes no lock, so a header rewritten between the reads could
// be checksummed in one state and parsed in another (#248, B5).

// flippingReader serves one image for its first flipAfter reads and another
// after that: a header rewritten while it is being read.
type flippingReader struct {
	before, after []byte
	flipAfter     int
	reads         int
}

func (r *flippingReader) ReadAt(p []byte, off int64) (int, error) {
	src := r.before
	if r.reads >= r.flipAfter {
		src = r.after
	}
	r.reads++
	return copy(p, src[off:]), nil
}

// TestReadHeaderParsesOnlyBytesItChecksummed rewrites the header between every
// pair of reads the reader makes. Whatever it returns must be one state whole:
// the binary header and the metadata from the same write, never the first
// state's checksum over the second state's JSON.
func TestReadHeaderParsesOnlyBytesItChecksummed(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "flip.img")
	formatWithLibrary(t, path)
	before := readAreaBytes(t, path, 0, 2*LUKS2HeaderMinSize)
	if err := ImportToken(path, 0, &Token{Type: TokenTypeSystemdRecovery, Keyslots: []string{"0"}}); err != nil {
		t.Fatalf("ImportToken: %v", err)
	}
	after := readAreaBytes(t, path, 0, 2*LUKS2HeaderMinSize)

	beforeHdr, _, err := readHeaderCopyFrom(&flippingReader{before: before, after: before}, 0)
	if err != nil {
		t.Fatalf("the unchanging image does not read: %v", err)
	}

	for flipAfter := 1; flipAfter <= 3; flipAfter++ {
		r := &flippingReader{before: before, after: after, flipAfter: flipAfter}
		hdr, metadata, err := readHeaderCopyFrom(r, 0)
		if err != nil {
			if !errors.Is(err, ErrInvalidHeader) {
				t.Errorf("flip after %d reads: got %v, want a clean read or ErrInvalidHeader", flipAfter, err)
			}
			continue
		}
		fromBefore := hdr.SequenceID == beforeHdr.SequenceID
		if fromBefore != (len(metadata.Tokens) == 0) {
			t.Errorf("flip after %d reads: the binary header is from one write (sequence %d) and the metadata from the other (%d tokens)",
				flipAfter, hdr.SequenceID, len(metadata.Tokens))
		}
	}
}
