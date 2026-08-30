// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// setHeaderOffset patches the big-endian uint64 HeaderOffset field, which sits
// at byte 256 (0x100): magic(6) + version(2) + header_size(8) + sequence_id(8)
// + label(48) + checksum_alg(32) + salt(64) + uuid(40) + subsystem(48). The
// offset is spelled as that sum rather than as 256 so a change to the struct
// layout is visible here, and TestSetHeaderOffsetPatchesTheRightField checks
// the sum is actually right -- eight bytes written at the wrong offset would
// corrupt a neighboring field and still make every rejection test "pass".
func setHeaderOffset(t *testing.T, device string, offset uint64) {
	t.Helper()

	const headerOffsetField = 6 + 2 + 8 + 8 + 48 + 32 + 64 + 40 + 48

	f, err := os.OpenFile(device, os.O_RDWR, 0600) // #nosec G304 -- device is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the volume: %v", err)
	}
	defer func() { _ = f.Close() }()

	var b [8]byte
	binary.BigEndian.PutUint64(b[:], offset)
	if _, err := f.WriteAt(b[:], headerOffsetField); err != nil {
		t.Fatalf("failed to patch HeaderOffset: %v", err)
	}
}

// TestSetHeaderOffsetPatchesTheRightField is the control on the patcher itself.
// A test that writes eight bytes at the wrong offset corrupts some other field
// and still observes "ReadHeader returned an error", which would make every
// case below pass for the wrong reason.
func TestSetHeaderOffsetPatchesTheRightField(t *testing.T) {
	device, _ := headerSizeVolume(t)
	setHeaderOffset(t, device, uint64(LUKS2SecondaryHeaderOffset))

	f, err := os.Open(device) // #nosec G304 -- device is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the volume: %v", err)
	}
	defer func() { _ = f.Close() }()

	raw := make([]byte, LUKS2HeaderSize)
	if _, err := f.ReadAt(raw, 0); err != nil {
		t.Fatalf("failed to read the header: %v", err)
	}

	var hdr LUKS2BinaryHeader
	if err := binary.Read(bytes.NewReader(raw), binary.BigEndian, &hdr); err != nil {
		t.Fatalf("failed to decode the header: %v", err)
	}
	if hdr.HeaderOffset != uint64(LUKS2SecondaryHeaderOffset) {
		t.Fatalf("HeaderOffset = %d after patching, want %d -- the patcher is writing the wrong field",
			hdr.HeaderOffset, LUKS2SecondaryHeaderOffset)
	}
	if hdr.HeaderSize != uint64(LUKS2HeaderSize+LUKS2DefaultSize) {
		t.Fatalf("HeaderSize = %d after patching HeaderOffset -- the patcher clobbered a neighboring field",
			hdr.HeaderSize)
	}
}

// TestReadHeaderRefusesAnOutOfRangeHeaderOffset is the regression test for #63.
//
// hdr.HeaderOffset is the sibling of the HeaderSize field bounded by #51, and
// it arrives the same way: eight bytes off an attacker-controlled device with
// only magic and version in front of them. Both read paths converted it and
// checked overflow only; the type's own documentation ("0 or 0x4000") was the
// only place the range was recorded, and documentation enforces nothing.
//
// As with HeaderSize, the assertion that matters is that the call RETURNS -- a
// caller who checks the error ReadHeader promises must actually receive one.
func TestReadHeaderRefusesAnOutOfRangeHeaderOffset(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset uint64
	}{
		{"one byte in, before any legal copy", 1},
		{"a sector in", 512},
		{"one below the minimum secondary offset", LUKS2HeaderMinSize - 1},
		{"unaligned, between two legal offsets", LUKS2HeaderMinSize + 1},
		{"unaligned by one sector", LUKS2HeaderMinSize + 512},
		{"just past the maximum offset", LUKS2HeaderMaxOffset + LUKS2HeaderMinSize},
		{"four gigabytes", 1 << 32},
		{"larger than any device", 1 << 62},
		{"the largest uint64", ^uint64(0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			device, _ := headerSizeVolume(t)
			setHeaderOffset(t, device, tc.offset)

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ReadHeader panicked on HeaderOffset=%d instead of returning an error: %v", tc.offset, r)
				}
			}()

			_, _, err := ReadHeader(device)
			if err == nil {
				t.Fatalf("ReadHeader accepted HeaderOffset=%d", tc.offset)
			}
			if !errors.Is(err, ErrInvalidHeader) {
				t.Errorf("error = %v, want it to wrap ErrInvalidHeader", err)
			}
			// An operator needs to see the value that was rejected.
			if !strings.Contains(err.Error(), fmt.Sprint(tc.offset)) {
				t.Errorf("error = %q, want it to name the rejected offset %d", err.Error(), tc.offset)
			}
		})
	}
}

// TestHeaderAreaOffsetAcceptsEveryLegalCopyLocation is the other half of the
// bound, and the half a refusal-only suite would miss.
//
// The accepted set is not just {0, 0x4000}: a container formatted with a larger
// metadata area puts its second copy further out, and this library has to keep
// reading those. The bound is therefore 0, or a 16 KiB-aligned offset up to
// LUKS2HeaderMaxOffset.
func TestHeaderAreaOffsetAcceptsEveryLegalCopyLocation(t *testing.T) {
	for _, tc := range []struct {
		offset uint64
		accept bool
	}{
		{0, true}, // the primary copy
		{1, false},
		{LUKS2HeaderMinSize - 1, false},
		{LUKS2HeaderMinSize, true}, // the secondary copy at the default 16 KiB metadata size
		{LUKS2HeaderMinSize + 1, false},
		{2 * LUKS2HeaderMinSize, true}, // 32 KiB metadata area
		{1 << 20, true},                // 1 MiB metadata area
		{LUKS2HeaderMaxOffset, true},
		{LUKS2HeaderMaxOffset + LUKS2HeaderMinSize, false},
		{^uint64(0), false},
	} {
		got, err := headerAreaOffset(&LUKS2BinaryHeader{HeaderOffset: tc.offset})
		switch {
		case tc.accept && err != nil:
			t.Errorf("headerAreaOffset(%d) = error %v, want it accepted", tc.offset, err)
		case !tc.accept && err == nil:
			t.Errorf("headerAreaOffset(%d) = %d, want it rejected", tc.offset, got)
		case tc.accept && uint64(got) != tc.offset:
			t.Errorf("headerAreaOffset(%d) = %d, want the offset back unchanged", tc.offset, got)
		}
	}
}

// TestHeaderOffsetBoundStillAdmitsTheSecondaryHeader is the interaction check
// between this bound and the SKUL fix: the secondary header legitimately lives
// at LUKS2SecondaryHeaderOffset and records that offset in its own
// HeaderOffset field, so a bound that only admitted 0 would make the backup
// unreadable -- trading one broken recovery path for another.
func TestHeaderOffsetBoundStillAdmitsTheSecondaryHeader(t *testing.T) {
	device, passphrase := headerSizeVolume(t)

	hdr, metadata, err := ReadSecondaryHeader(device)
	if err != nil {
		t.Fatalf("ReadSecondaryHeader rejected the backup this library just wrote: %v", err)
	}
	if hdr.HeaderOffset != uint64(LUKS2SecondaryHeaderOffset) {
		t.Fatalf("secondary HeaderOffset = %d, want %d", hdr.HeaderOffset, LUKS2SecondaryHeaderOffset)
	}

	// The backup is only a backup if the key material it describes still opens.
	key, err := getMasterKey(device, passphrase, metadata)
	if err != nil {
		t.Fatalf("the metadata from the secondary header does not open the volume: %v", err)
	}
	clearBytes(key)
}

// TestReadSecondaryHeaderRejectsThePrimaryMagic pins which magic each copy must
// carry, in this library's own reader.
//
// Reading the primary copy through ReadSecondaryHeader must fail: the primary
// carries "LUKS\xba\xbe" and the secondary carries "SKUL\xba\xbe", and a reader
// that accepted either would not notice a backup written with the wrong magic
// -- which is the state #64 describes.
func TestReadSecondaryHeaderRejectsThePrimaryMagic(t *testing.T) {
	device, _ := headerSizeVolume(t)

	// The primary copy read as if it were the secondary.
	if _, _, err := readHeaderCopy(device, LUKS2PrimaryHeaderOffset); err != nil {
		t.Fatalf("sanity: the primary copy should read as the primary: %v", err)
	}

	f, err := os.OpenFile(device, os.O_RDWR, 0600) // #nosec G304 -- device is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the volume: %v", err)
	}
	// Overwrite the secondary copy's magic with the primary's, which is exactly
	// what this library used to write there.
	if _, err := f.WriteAt([]byte(LUKS2Magic), LUKS2SecondaryHeaderOffset); err != nil {
		_ = f.Close()
		t.Fatalf("failed to patch the secondary magic: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close the volume: %v", err)
	}

	_, _, err = ReadSecondaryHeader(device)
	if err == nil {
		t.Fatal("ReadSecondaryHeader accepted a backup carrying the PRIMARY magic")
	}
	if !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("error = %v, want it to wrap ErrInvalidHeader", err)
	}
}

// TestExpectedMagic pins the mapping from copy location to magic.
func TestExpectedMagic(t *testing.T) {
	for _, tc := range []struct {
		offset int64
		want   string
	}{
		{LUKS2PrimaryHeaderOffset, LUKS2Magic},
		{LUKS2SecondaryHeaderOffset, LUKS2SecondaryMagic},
		{1 << 20, LUKS2SecondaryMagic}, // a larger metadata area moves the copy, not its magic
	} {
		if got := expectedMagic(tc.offset); got != tc.want {
			t.Errorf("expectedMagic(%d) = %q, want %q", tc.offset, got, tc.want)
		}
	}

	// The two magics must differ, which is the entire point of the second one.
	if LUKS2Magic == LUKS2SecondaryMagic {
		t.Fatal("the primary and secondary magics are identical")
	}
	if len(LUKS2SecondaryMagic) != LUKS2MagicLen {
		t.Fatalf("LUKS2SecondaryMagic is %d bytes, want %d", len(LUKS2SecondaryMagic), LUKS2MagicLen)
	}
}
