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

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// setHeaderOffset patches the big-endian HeaderOffset field at byte 256, spelled as the sum of the preceding fields.
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
	defer parallel(t)()

	device, _ := headerSizeVolume(t)
	setHeaderOffset(t, device, uint64(header.SecondaryHeaderOffset))

	f, err := os.Open(device) // #nosec G304 -- device is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the volume: %v", err)
	}
	defer func() { _ = f.Close() }()

	raw := make([]byte, header.HeaderSize)
	if _, err := f.ReadAt(raw, 0); err != nil {
		t.Fatalf("failed to read the header: %v", err)
	}

	var hdr header.BinaryHeader
	if err := binary.Read(bytes.NewReader(raw), binary.BigEndian, &hdr); err != nil {
		t.Fatalf("failed to decode the header: %v", err)
	}
	if hdr.HeaderOffset != uint64(header.SecondaryHeaderOffset) {
		t.Fatalf("HeaderOffset = %d after patching, want %d -- the patcher is writing the wrong field",
			hdr.HeaderOffset, header.SecondaryHeaderOffset)
	}
	if hdr.HeaderSize != uint64(header.HeaderSize+header.DefaultSize) {
		t.Fatalf("HeaderSize = %d after patching HeaderOffset -- the patcher clobbered a neighboring field",
			hdr.HeaderSize)
	}
}

// TestReadHeaderRefusesAnOutOfRangeHeaderOffset: an out-of-range HeaderOffset returns an error.
func TestReadHeaderRefusesAnOutOfRangeHeaderOffset(t *testing.T) {
	defer parallel(t)()

	for _, tc := range []struct {
		name   string
		offset uint64
	}{
		{"one byte in, before any legal copy", 1},
		{"a sector in", 512},
		{"one below the minimum secondary offset", header.HeaderMinSize - 1},
		{"unaligned, between two legal offsets", header.HeaderMinSize + 1},
		{"unaligned by one sector", header.HeaderMinSize + 512},
		{"just past the maximum offset", header.HeaderMaxOffset + header.HeaderMinSize},
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

			_, _, err := readHeaderForTest(device)
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

// TestHeaderAreaOffsetAcceptsEveryLegalCopyLocation: 0, or 16 KiB-aligned up to header.HeaderMaxOffset.
func TestHeaderAreaOffsetAcceptsEveryLegalCopyLocation(t *testing.T) {
	for _, tc := range []struct {
		offset uint64
		accept bool
	}{
		{0, true}, // the primary copy
		{1, false},
		{header.HeaderMinSize - 1, false},
		{header.HeaderMinSize, true}, // the secondary copy at the default 16 KiB metadata size
		{header.HeaderMinSize + 1, false},
		{2 * header.HeaderMinSize, true}, // 32 KiB metadata area
		{1 << 20, true},                  // 1 MiB metadata area
		{header.HeaderMaxOffset, true},
		{header.HeaderMaxOffset + header.HeaderMinSize, false},
		{^uint64(0), false},
	} {
		got, err := header.HeaderAreaOffset(&header.BinaryHeader{HeaderOffset: tc.offset})
		switch {
		case tc.accept && err != nil:
			t.Errorf("header.HeaderAreaOffset(%d) = error %v, want it accepted", tc.offset, err)
		case !tc.accept && err == nil:
			t.Errorf("header.HeaderAreaOffset(%d) = %d, want it rejected", tc.offset, got)
		case tc.accept && uint64(got) != tc.offset:
			t.Errorf("header.HeaderAreaOffset(%d) = %d, want the offset back unchanged", tc.offset, got)
		}
	}
}

// TestHeaderOffsetBoundStillAdmitsTheSecondaryHeader: the secondary header at header.SecondaryHeaderOffset stays readable.
func TestHeaderOffsetBoundStillAdmitsTheSecondaryHeader(t *testing.T) {
	defer parallel(t)()

	device, passphrase := headerSizeVolume(t)

	hdr, metadata, err := readSecondaryHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadSecondaryHeader rejected the backup this library just wrote: %v", err)
	}
	if hdr.HeaderOffset != uint64(header.SecondaryHeaderOffset) {
		t.Fatalf("secondary HeaderOffset = %d, want %d", hdr.HeaderOffset, header.SecondaryHeaderOffset)
	}

	// The backup is only a backup if the key material it describes still opens.
	key, err := getMasterKey(device, passphrase, metadata, testVolumeSys())
	if err != nil {
		t.Fatalf("the metadata from the secondary header does not open the volume: %v", err)
	}
	mustDestroy(t, key)
}

// TestReadSecondaryHeaderRejectsThePrimaryMagic: the secondary copy must carry "SKUL\xba\xbe", not the primary magic.
func TestReadSecondaryHeaderRejectsThePrimaryMagic(t *testing.T) {
	defer parallel(t)()

	device, _ := headerSizeVolume(t)

	// The primary copy read as if it were the secondary.
	if _, _, err := readHeaderCopy(device, header.PrimaryHeaderOffset); err != nil {
		t.Fatalf("sanity: the primary copy should read as the primary: %v", err)
	}

	f, err := os.OpenFile(device, os.O_RDWR, 0600) // #nosec G304 -- device is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the volume: %v", err)
	}
	// Overwrite the secondary copy's magic with the primary's, which is exactly
	// what this library used to write there.
	if _, err := f.WriteAt([]byte(header.Magic), header.SecondaryHeaderOffset); err != nil {
		_ = f.Close()
		t.Fatalf("failed to patch the secondary magic: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close the volume: %v", err)
	}

	_, _, err = readSecondaryHeaderForTest(device)
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
		{header.PrimaryHeaderOffset, header.Magic},
		{header.SecondaryHeaderOffset, header.SecondaryMagic},
		{1 << 20, header.SecondaryMagic}, // a larger metadata area moves the copy, not its magic
	} {
		if got := header.ExpectedMagic(tc.offset); got != tc.want {
			t.Errorf("header.ExpectedMagic(%d) = %q, want %q", tc.offset, got, tc.want)
		}
	}

	// The two magics must differ, which is the entire point of the second one.
	if header.Magic == header.SecondaryMagic {
		t.Fatal("the primary and secondary magics are identical")
	}
	if len(header.SecondaryMagic) != header.MagicLen {
		t.Fatalf("header.SecondaryMagic is %d bytes, want %d", len(header.SecondaryMagic), header.MagicLen)
	}
}
