// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

func TestReadJSONMetadataSucceeds(t *testing.T) {
	jsonArea := []byte(`{"keyslots":{},"tokens":{},` + minimalHeaderJSONTailForTest)
	headerSize := HeaderSize + DefaultSize
	area := make([]byte, headerSize)
	copy(area[HeaderSize:], jsonArea)

	metadata, err := ReadJSONMetadata(bytes.NewReader(area), &BinaryHeader{}, 0, headerSize)
	if err != nil {
		t.Fatalf("ReadJSONMetadata: %v", err)
	}
	if len(metadata.Segments) != 1 {
		t.Errorf("Segments = %d, want 1", len(metadata.Segments))
	}
}

// TestReadSecondaryHeaderFromProbesWhenThePrimaryIsDamaged corrupts the
// primary copy so ReadSecondaryHeaderFrom must fall back to probing every
// legal offset, and finds the secondary at the default one.
func TestReadSecondaryHeaderFromProbesWhenThePrimaryIsDamaged(t *testing.T) {
	f, _ := writtenContainer(t)
	// Destroy the primary's magic so it cannot be read.
	if _, err := f.WriteAt([]byte("XXXXXX"), 0); err != nil {
		t.Fatal(err)
	}
	hdr, _, err := ReadSecondaryHeaderFrom(f)
	if err != nil {
		t.Fatalf("ReadSecondaryHeaderFrom: %v", err)
	}
	if string(bytes.TrimRight(hdr.Magic[:], "\x00")) != SecondaryMagic {
		t.Errorf("Magic = %q", hdr.Magic)
	}
}

func TestReadSecondaryHeaderFromFailsWhenNeitherCopyIsReadable(t *testing.T) {
	f, _ := writtenContainer(t)
	if _, err := f.WriteAt([]byte("XXXXXX"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("XXXXXX"), int64(HeaderMinSize)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadSecondaryHeaderFrom(f); !errors.Is(err, errs.ErrInvalidHeader) {
		t.Fatalf("got %v, want ErrInvalidHeader", err)
	}
}

func TestValidateHeaderChecksumSucceeds(t *testing.T) {
	f, _ := writtenContainer(t)
	hdr, _, err := ReadHeaderCopyFrom(f, PrimaryHeaderOffset)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateHeaderChecksum(hdr, f, PrimaryHeaderOffset, HeaderMinSize); err != nil {
		t.Errorf("ValidateHeaderChecksum: %v", err)
	}
}

func TestEnsureRequiredObjectsFillsEveryNilMap(t *testing.T) {
	m := &Metadata{}
	m.ensureRequiredObjects()
	if m.Keyslots == nil || m.Tokens == nil || m.Segments == nil || m.Digests == nil {
		t.Errorf("ensureRequiredObjects left a nil map: %+v", m)
	}
	if m.Config != nil {
		t.Error("Config was invented; an empty config would pass the presence check and fail on its members")
	}
}

func TestEnsureRequiredObjectsLeavesPopulatedMapsAlone(t *testing.T) {
	m := &Metadata{
		Keyslots: map[string]*Keyslot{"0": {Type: "luks2"}},
		Tokens:   map[string]*Token{"0": {Type: "systemd-tpm2"}},
		Segments: map[string]*Segment{"0": {Type: "crypt"}},
		Digests:  map[string]*Digest{"0": {Type: "pbkdf2"}},
	}
	m.ensureRequiredObjects()

	if len(m.Keyslots) != 1 || len(m.Tokens) != 1 || len(m.Segments) != 1 || len(m.Digests) != 1 {
		t.Fatalf("ensureRequiredObjects modified populated maps: %+v", m)
	}
}

func TestValidateObjectCountsRefusesTooManyKeyslots(t *testing.T) {
	m := &Metadata{Keyslots: map[string]*Keyslot{}}
	for i := 0; i <= MaxKeyslots; i++ {
		m.Keyslots[string(rune('a'+i))] = &Keyslot{}
	}
	if err := validateObjectCounts(m); !errors.Is(err, errs.ErrInvalidHeader) {
		t.Fatalf("got %v, want ErrInvalidHeader", err)
	}
}

func TestValidateObjectCountsRefusesTooManyDigests(t *testing.T) {
	m := &Metadata{Digests: map[string]*Digest{}}
	for i := 0; i <= MaxKeyslots; i++ {
		m.Digests[string(rune('a'+i))] = &Digest{}
	}
	if err := validateObjectCounts(m); !errors.Is(err, errs.ErrInvalidHeader) {
		t.Fatalf("got %v, want ErrInvalidHeader", err)
	}
}

func TestHeaderCopiesAgreeDetectsADifferentSequenceID(t *testing.T) {
	f, _ := writtenContainer(t)
	hdr, metadata, err := ReadHeaderCopyFrom(f, PrimaryHeaderOffset)
	if err != nil {
		t.Fatal(err)
	}
	area, err := HeaderAreaSize(hdr)
	if err != nil {
		t.Fatal(err)
	}
	jsonData, _, err := EncodeMetadataForHeader(hdr, metadata)
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite ONLY the secondary copy, at a different sequence id, so the
	// two copies disagree.
	desynced := *hdr
	desynced.SequenceID = 99
	if err := WriteSecondaryCopy(f, &desynced, jsonData, area-HeaderSize, int64(area)); err != nil {
		t.Fatal(err)
	}
	if err := HeaderCopiesAgree(f); !errors.Is(err, errs.ErrInvalidHeader) {
		t.Fatalf("got %v, want ErrInvalidHeader", err)
	}
}

func TestValidateSegmentAcceptsNonCryptAndRefusesNull(t *testing.T) {
	if err := validateSegment("0", nil); !errors.Is(err, errs.ErrInvalidHeader) {
		t.Fatalf("nil segment: got %v, want ErrInvalidHeader", err)
	}
	if err := validateSegment("0", &Segment{Type: "linear"}); err != nil {
		t.Errorf("a linear segment should not be checked as crypt: %v", err)
	}
}

func TestIsReencryptCandidateFlag(t *testing.T) {
	tests := map[string]bool{
		"online-reencrypt":    true,
		"online-reencrypt-v2": true,
		"online-reencrypt-v":  false,
		"online-reencrypt-vx": false,
		"opal":                false,
	}
	for flag, want := range tests {
		if got := isReencryptCandidateFlag(flag); got != want {
			t.Errorf("isReencryptCandidateFlag(%q) = %v, want %v", flag, got, want)
		}
	}
}

func TestCheckTopLevelMembersRequiresEveryMandatoryObject(t *testing.T) {
	if err := checkTopLevelMembers([]byte(`{"keyslots":{}}`)); !errors.Is(err, errs.ErrInvalidHeader) {
		t.Fatalf("got %v, want ErrInvalidHeader", err)
	}
	if err := checkTopLevelMembers([]byte(`not an object`)); err != nil {
		t.Errorf("a non-object is left to the typed decode: %v", err)
	}
}

func TestDecodeMembersRefusesADuplicateMember(t *testing.T) {
	_, err := decodeMembers("keyslot", []byte(`{"type":"luks2","type":"raw"}`), []string{"type"})
	if !errors.Is(err, ErrAmbiguousJSONMember) {
		t.Fatalf("got %v, want ErrAmbiguousJSONMember", err)
	}
}

func TestDecodeMembersRefusesACaseVariantOfAKnownMember(t *testing.T) {
	_, err := decodeMembers("keyslot", []byte(`{"Type":"luks2"}`), []string{"type"})
	if !errors.Is(err, ErrAmbiguousJSONMember) {
		t.Fatalf("got %v, want ErrAmbiguousJSONMember", err)
	}
}

func TestVolumeKeyBitsReturnsZeroWhenNoDigestAttests(t *testing.T) {
	m := minimalValidMetadata()
	if bits := VolumeKeyBits(m, "0"); bits != 0 {
		t.Errorf("VolumeKeyBits = %d, want 0", bits)
	}
}

func TestSegmentsMatch(t *testing.T) {
	a := &Segment{Type: "crypt", SectorSize: 512, Encryption: "aes-xts-plain64"}
	b := &Segment{Type: "crypt", SectorSize: 512, Encryption: "aes-xts-plain64"}
	if !segmentsMatch(a, b) {
		t.Error("identical crypt segments should match")
	}
	c := &Segment{Type: "linear"}
	if segmentsMatch(a, c) {
		t.Error("different types should not match")
	}
	d := &Segment{Type: "linear"}
	if !segmentsMatch(c, d) {
		t.Error("two linear segments should match regardless of crypt fields")
	}
}

func TestSegmentLabelWithNoID(t *testing.T) {
	if got, want := segmentLabel(""), "the crypt segment"; got != want {
		t.Errorf("segmentLabel(\"\") = %q, want %q", got, want)
	}
}

func TestForgetKeyslotIDRemovesEveryReference(t *testing.T) {
	m := &Metadata{
		Digests: map[string]*Digest{"0": {Keyslots: []string{"0", "1"}}},
		Tokens:  map[string]*Token{"0": {Keyslots: []string{"0"}}},
	}
	ForgetKeyslotID(m, "0")
	if len(m.Digests["0"].Keyslots) != 1 || m.Digests["0"].Keyslots[0] != "1" {
		t.Errorf("Digests[0].Keyslots = %v", m.Digests["0"].Keyslots)
	}
	if len(m.Tokens["0"].Keyslots) != 0 {
		t.Errorf("Tokens[0].Keyslots = %v", m.Tokens["0"].Keyslots)
	}
}

func TestSortDroppedEntriesOrdersByKindThenNumericThenLexical(t *testing.T) {
	entries := []DroppedEntry{
		{Kind: DroppedKindToken, ID: "2"},
		{Kind: DroppedKindKeyslot, ID: "a"},
		{Kind: DroppedKindKeyslot, ID: "10"},
		{Kind: DroppedKindKeyslot, ID: "2"},
	}
	sortDroppedEntries(entries)
	want := []DroppedEntry{
		{Kind: DroppedKindKeyslot, ID: "2"},
		{Kind: DroppedKindKeyslot, ID: "10"},
		{Kind: DroppedKindKeyslot, ID: "a"},
		{Kind: DroppedKindToken, ID: "2"},
	}
	for i, e := range entries {
		if e != want[i] {
			t.Fatalf("entries = %+v, want %+v", entries, want)
		}
	}
}

func TestCheckHeaderChecksumAlgorithmRefusesAnythingButSHA256(t *testing.T) {
	hdr := &BinaryHeader{}
	copy(hdr.ChecksumAlgorithm[:], "sha1")
	if err := checkHeaderChecksumAlgorithm(hdr); !errors.Is(err, errs.ErrInvalidHeader) || !errors.Is(err, ErrUnsupportedHeaderChecksum) {
		t.Fatalf("got %v, want ErrInvalidHeader and ErrUnsupportedHeaderChecksum", err)
	}
	copy(hdr.ChecksumAlgorithm[:], "sha256")
	if err := checkHeaderChecksumAlgorithm(hdr); err != nil {
		t.Errorf("sha256 should be accepted: %v", err)
	}
}

func TestValidateMetadataSegmentsVisitsEveryID(t *testing.T) {
	m := &Metadata{Segments: map[string]*Segment{
		"0": {Type: "crypt", Offset: "16777216", Size: "dynamic", IVTweak: "0", Encryption: "aes-xts-plain64", SectorSize: 512},
		"1": nil,
	}}
	if err := validateMetadataSegments(m); !errors.Is(err, errs.ErrInvalidHeader) {
		t.Fatalf("got %v, want ErrInvalidHeader", err)
	}
}
