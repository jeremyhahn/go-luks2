// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"strings"
	"testing"
)

// The data segment's offset and size were never validated (#248, B1). An
// offset off the 512-byte sector grid is silently rounded down by
// device-mapper; an offset inside the header copies or the keyslots area maps
// them into the plaintext device, where the first filesystem write destroys
// every keyslot.

// TestReadHeaderRefusesASegmentOutOfPlace drives the read path with segments
// cryptsetup refuses on read.
func TestReadHeaderRefusesASegmentOutOfPlace(t *testing.T) {
	defer parallel(t)()

	for _, tc := range []struct {
		name   string
		mutate func(*Segment)
		says   string
	}{
		{"offset off the sector grid", func(s *Segment) { s.Offset = "16777217" }, "multiples of 512"},
		{"size off the sector grid", func(s *Segment) { s.Size = "1048000" }, "multiples of 512"},
		{"size not a whole number of encryption sectors", func(s *Segment) { s.SectorSize, s.Size = 4096, "1049088" }, "sector size"},
		{"data inside the keyslots area", func(s *Segment) { s.Offset = "1048576" }, "does not fit"},
		{"data inside the header copies", func(s *Segment) { s.Offset = "16384" }, "does not fit"},
		{"offset that is not a number", func(s *Segment) { s.Offset = "16M" }, "offset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := craftedSegmentVolume(t, "misplaced-segment.img", tc.mutate)
			_, _, err := ReadHeader(path)
			if !errors.Is(err, ErrInvalidHeader) || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("ReadHeader: got %v, want ErrInvalidHeader saying %q", err, tc.says)
			}
		})
	}
}

// TestADetachedHeaderReadsButIsNeverActivated: cryptsetup reads a segment at
// offset 0 as a DETACHED header, whose data lives on another device, so the
// reader must accept it. This package activates the data on the device that
// carries the header, where offset 0 is the header itself, so the activation
// path refuses it -- and anything else short of the end of the keyslots area.
func TestADetachedHeaderReadsButIsNeverActivated(t *testing.T) {
	defer parallel(t)()

	path := craftedSegmentVolume(t, "detached.img", func(s *Segment) { s.Offset = "0" })
	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader refused a detached header cryptsetup reads: %v", err)
	}
	if _, err := cryptTableParams(metadata, "0", metadata.Segments["0"]); !errors.Is(err, ErrInvalidHeader) || !strings.Contains(err.Error(), "detached") {
		t.Fatalf("activation of a segment at offset 0: got %v, want ErrInvalidHeader naming a detached header", err)
	}

	for _, offset := range []string{"16384", "16773120", "not-a-number"} {
		segment := *metadata.Segments["0"]
		segment.Offset = offset
		if _, err := cryptTableParams(metadata, "0", &segment); !errors.Is(err, ErrInvalidHeader) || !strings.Contains(err.Error(), "expose") {
			t.Errorf("activation of a segment at %s: got %v, want ErrInvalidHeader", offset, err)
		}
	}

	broken := *metadata
	broken.Config = &Config{JSONSize: "x", KeyslotsSize: "0"}
	if _, err := cryptTableParams(&broken, "0", metadata.Segments["0"]); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("activation with an unreadable config: got %v, want ErrInvalidHeader", err)
	}

	segment := *metadata.Segments["0"]
	segment.Offset = "16777216"
	if _, err := cryptTableParams(metadata, "0", &segment); err != nil {
		t.Errorf("activation of the data at 16 MiB was refused: %v", err)
	}
}
