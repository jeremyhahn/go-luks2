// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

func TestVolumeHeaderReportsUUIDLabelSubsystemAndSequenceID(t *testing.T) {
	path := formattedVolumeImage(t, "header-fields.img", "my-label", "my-subsystem")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	h, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}

	oldHdr, _, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	if got := h.UUID(); got == "" || got != string(bytes.TrimRight(oldHdr.UUID[:], "\x00")) {
		t.Errorf("UUID() = %q, want the formatted volume's UUID", got)
	}
	if got := h.Label(); got != "my-label" {
		t.Errorf("Label() = %q, want %q", got, "my-label")
	}
	if got := h.Subsystem(); got != "my-subsystem" {
		t.Errorf("Subsystem() = %q, want %q", got, "my-subsystem")
	}
	if got := h.SequenceID(); got != 1 {
		t.Errorf("SequenceID() = %d, want 1 for a freshly formatted volume", got)
	}
}

func TestVolumeHeaderOnAnUnformattedFileFailsWithErrInvalidHeader(t *testing.T) {
	// An all-zero file has no LUKS magic at all, which is ErrInvalidHeader;
	// ErrNotLUKS2 (an alias of ErrUnsupportedLUKSVersion) is for a header
	// that has the right magic but names a version this package refuses.
	path := newImage(t, "unformatted.img")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if _, err := v.Header(context.Background()); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("Header on an unformatted file = %v, want ErrInvalidHeader", err)
	}
}

func TestVolumeHeaderOnALUKS1VersionFailsWithErrNotLUKS2(t *testing.T) {
	path := formattedVolumeImage(t, "luks1-version.img", "", "")

	// Patch the primary copy's version field (2 bytes, big-endian, right
	// after the 6-byte magic) to 1: the right magic, a version this package
	// refuses.
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("could not open the image to patch it: %v", err)
	}
	if _, err := f.WriteAt([]byte{0x00, 0x01}, 6); err != nil {
		t.Fatalf("could not patch the version field: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("could not close the patched image: %v", err)
	}

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if _, err := v.Header(context.Background()); !errors.Is(err, ErrNotLUKS2) {
		t.Errorf("Header on a LUKS1-versioned header = %v, want ErrNotLUKS2", err)
	}
}

func TestVolumeRequirementsIsNilWhenNoneAreDeclared(t *testing.T) {
	path := formattedVolumeImage(t, "requirements.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	h, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}
	if got := h.Requirements(); got != nil {
		t.Errorf("Requirements() = %v, want nil", got)
	}
}

func TestVolumeDroppedIsNilForAnIntactHeader(t *testing.T) {
	defer parallel(t)()
	path := formattedVolumeImage(t, "dropped.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	h, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}
	if got := h.Dropped(); got != nil {
		t.Errorf("Dropped() = %v, want nil", got)
	}
}

func TestHeaderMarshalJSONMatchesTheCanonicalEncoding(t *testing.T) {
	path := formattedVolumeImage(t, "marshal.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	h, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	want, err := header.MarshalCanonicalJSON(metadata)
	if err != nil {
		t.Fatalf("MarshalCanonicalJSON failed: %v", err)
	}

	got, err := h.MarshalJSON()
	if err != nil {
		t.Fatalf("Header.MarshalJSON failed: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("MarshalJSON() = %s, want %s", got, want)
	}
}

func TestVolumeSecondaryHeaderReadsTheSecondaryCopy(t *testing.T) {
	path := formattedVolumeImage(t, "secondary.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	oldSecondaryHdr, _, err := readSecondaryHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadSecondaryHeader failed: %v", err)
	}

	h, err := v.SecondaryHeader(context.Background())
	if err != nil {
		t.Fatalf("Volume.SecondaryHeader failed: %v", err)
	}
	if got := h.SequenceID(); got != oldSecondaryHdr.SequenceID {
		t.Errorf("SecondaryHeader SequenceID() = %d, want %d", got, oldSecondaryHdr.SequenceID)
	}
}

func TestReplacePrimaryHeaderAdvancesTheSequenceIDUnconditionally(t *testing.T) {
	path := formattedVolumeImage(t, "replace.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	before, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}

	if err := v.ReplacePrimaryHeader(context.Background()); err != nil {
		t.Fatalf("ReplacePrimaryHeader failed: %v", err)
	}

	after, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed after ReplacePrimaryHeader: %v", err)
	}
	if after.SequenceID() <= before.SequenceID() {
		t.Errorf("SequenceID after ReplacePrimaryHeader = %d, want greater than %d", after.SequenceID(), before.SequenceID())
	}
}

func TestVolumeHeaderSizeMatchesTheOnDiskHeaderSize(t *testing.T) {
	path := formattedVolumeImage(t, "size.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	h, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}

	oldHdr, _, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	if got, want := h.Size(), int64(oldHdr.HeaderSize); got != want {
		t.Errorf("Size() = %d, want %d (the binary header's own hdr_size)", got, want)
	}
}

func TestVolumeHeaderKeyslotsListsTheFormattedKeyslot(t *testing.T) {
	path := formattedVolumeImage(t, "keyslots-read.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	h, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}

	slots := h.Keyslots()
	if len(slots) != 1 {
		t.Fatalf("Keyslots() returned %d slots, want 1", len(slots))
	}
	s := slots[0]
	if s.ID != 0 {
		t.Errorf("ID = %d, want 0", s.ID)
	}
	if s.Type != "luks2" {
		t.Errorf("Type = %q, want %q", s.Type, "luks2")
	}
	if s.Priority != PriorityNormal {
		t.Errorf("Priority = %v, want PriorityNormal (cryptsetup's own default)", s.Priority)
	}
	if s.KDF.Type != KDFPBKDF2 {
		t.Errorf("KDF.Type = %q, want %q", s.KDF.Type, KDFPBKDF2)
	}
	if s.Encryption != keyslotAreaEncryption {
		t.Errorf("Encryption = %q, want %q", s.Encryption, keyslotAreaEncryption)
	}

	// Keyslots() must agree with the old ListKeyslots exactly: they share
	// listKeyslotsFrom, and this is the regression that sharing it guards.
	old, err := listKeyslotsForTest(path)
	if err != nil {
		t.Fatalf("ListKeyslots failed: %v", err)
	}
	if len(old) != 1 || old[0].ID != s.ID || old[0].KDF.Type != s.KDF.Type {
		t.Errorf("Keyslots() = %+v, ListKeyslots() = %+v; want the same shape", s, old[0])
	}
}

func TestVolumeHeaderSegmentsListsTheDataSegment(t *testing.T) {
	path := formattedVolumeImage(t, "segments-read.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	h, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}

	segments := h.Segments()
	if len(segments) != 1 {
		t.Fatalf("Segments() returned %d segments, want 1", len(segments))
	}
	seg := segments[0]
	if seg.ID != 0 {
		t.Errorf("ID = %d, want 0", seg.ID)
	}
	if seg.Type != "crypt" {
		t.Errorf("Type = %q, want %q", seg.Type, "crypt")
	}
	if seg.Size != SizeDynamic {
		t.Errorf("Size = %d, want SizeDynamic (%d): Format always writes \"dynamic\"", seg.Size, SizeDynamic)
	}
	if seg.Offset <= 0 {
		t.Errorf("Offset = %d, want a positive byte offset", seg.Offset)
	}
	if seg.Encryption != "aes-xts-plain64" {
		t.Errorf("Encryption = %q, want %q", seg.Encryption, "aes-xts-plain64")
	}
	if seg.SectorSize != 512 {
		t.Errorf("SectorSize = %d, want 512", seg.SectorSize)
	}
}

// TestVolumeHeaderTokensListsAnAddedToken pins that Header.Tokens reports a
// token added through the Volume API as a Token value.
func TestVolumeHeaderTokensListsAnAddedToken(t *testing.T) {
	path := formattedVolumeImage(t, "tokens-read.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	id, err := v.AddToken(context.Background(), Token{Type: "x-test", Keyslots: []int{0}})
	if err != nil {
		t.Fatalf("AddToken failed: %v", err)
	}

	h, err := v.Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}

	tokens := h.Tokens()
	tok, ok := tokens[id]
	if !ok {
		t.Fatalf("Tokens() = %v, want an entry for id %d", tokens, id)
	}
	if tok.Type != "x-test" {
		t.Errorf("Type = %q, want %q", tok.Type, "x-test")
	}
	if len(tok.Keyslots) != 1 || tok.Keyslots[0] != 0 {
		t.Errorf("Keyslots = %v, want [0]", tok.Keyslots)
	}
}
