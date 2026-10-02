// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// headerSizeVolume formats a genuine volume, so magic, version, checksum
// algorithm and salt are all authentic. Only HeaderSize is altered afterwards,
// which is what anyone holding the device can do with eight bytes.
//
// The Format runs once per process and each call gets a byte-for-byte copy
// (formattedImage), because a dozen tests and a table loop were each paying
// for a real Format -- digest calibration included -- to alter one field (#92).
func headerSizeVolume(t *testing.T) (device string, passphrase []byte) {
	t.Helper()

	device = formattedImage(t, "headerSizeVolume", "volume.img", 16<<20, func() FormatOptions {
		return FormatOptions{
			Passphrase:    []byte(headerSizeVolumePassphrase),
			KDFType:       KDFTypePBKDF2,
			HashAlgo:      "sha256",
			PBKDFIterTime: 1,
		}
	})
	return device, []byte(headerSizeVolumePassphrase)
}

const headerSizeVolumePassphrase = "correct horse battery staple"

// setHeaderSize patches the big-endian uint64 HeaderSize field at offset 8.
func setHeaderSize(t *testing.T, device string, size uint64) {
	t.Helper()

	f, err := os.OpenFile(device, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("failed to open the volume: %v", err)
	}
	defer func() { _ = f.Close() }()

	var b [8]byte
	binary.BigEndian.PutUint64(b[:], size)
	if _, err := f.WriteAt(b[:], 8); err != nil {
		t.Fatalf("failed to patch HeaderSize: %v", err)
	}
}

// TestReadHeaderRefusesAHeaderSizeTheLayoutCannotHold is the regression test for
// two reproduced panics.
//
// hdr.HeaderSize is a uint64 read straight off the device. Only magic and
// version stand in front of it, and both are trivially satisfiable by anyone who
// controls the device, so a crafted value reaches an allocation and a fixed-
// index write with nothing having authenticated it.
//
// The assertion that matters is NOT that an error comes back. It is that the
// call RETURNS AT ALL. Before the bound this panicked, and a panic is the one
// failure a caller cannot handle: ReadHeader's contract offers an error, so a
// caller that dutifully checks it never gets one and the process dies instead.
// Every case below therefore runs under a recover that fails the test.
func TestReadHeaderRefusesAHeaderSizeTheLayoutCannotHold(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		size uint64
	}{
		// Below the layout's floor. 0x1C0+64 = 512 is where the checksum-field
		// write ran off the end of the buffer; the cases either side of it are
		// the ones that pinned that threshold.
		{"zero", 0},
		{"far below the header size", 100},
		{"one below the old panic threshold", 511},
		{"the old panic threshold", 512},
		{"one below the header size", LUKS2HeaderSize - 1},
		{"exactly the header size, leaving no room for JSON", LUKS2HeaderSize},

		// Above the bound. 2^62 and 2^64-1 both panicked in make.
		{"just above the maximum", LUKS2HeaderMaxSize + 1},
		{"four gigabytes", 1 << 32},
		{"larger than any allocation", 1 << 62},
		{"the largest uint64", ^uint64(0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			device, _ := headerSizeVolume(t)
			setHeaderSize(t, device, tc.size)

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ReadHeader panicked on HeaderSize=%d instead of returning an error: %v", tc.size, r)
				}
			}()

			_, _, err := ReadHeader(device)
			if err == nil {
				t.Fatalf("ReadHeader accepted HeaderSize=%d", tc.size)
			}
			if !errors.Is(err, ErrInvalidHeader) {
				t.Errorf("error = %v, want it to wrap ErrInvalidHeader", err)
			}
			// An operator needs to see the value that was rejected; "invalid
			// header" alone cannot be acted on.
			if !strings.Contains(err.Error(), fmt.Sprint(tc.size)) {
				t.Errorf("error = %q, want it to name the rejected size %d", err.Error(), tc.size)
			}
		})
	}
}

// TestReadHeaderStillOpensAnUntamperedVolume is the control that keeps the fix
// from being a prohibition.
//
// A bound on a size read from disk is one careless comparison away from
// rejecting every real volume, and a test suite that only asserts refusals
// passes against exactly that mistake. This asserts the volumes the library
// itself writes are still readable, and that the passphrase still recovers the
// master key afterwards.
func TestReadHeaderStillOpensAnUntamperedVolume(t *testing.T) {
	t.Parallel()

	device, passphrase := headerSizeVolume(t)

	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader rejected a volume this library wrote: %v", err)
	}

	// The fixture is only meaningful if its HeaderSize is inside the accepted
	// band rather than incidentally at a boundary.
	if hdr.HeaderSize <= LUKS2HeaderSize || hdr.HeaderSize > LUKS2HeaderMaxSize {
		t.Fatalf("a freshly formatted volume has HeaderSize=%d, outside the %d..%d band the bound accepts",
			hdr.HeaderSize, LUKS2HeaderSize+1, LUKS2HeaderMaxSize)
	}
	t.Logf("a formatted volume reports HeaderSize=%d, inside the accepted band", hdr.HeaderSize)

	key, err := getMasterKey(device, passphrase, metadata)
	if err != nil {
		t.Fatalf("the volume no longer opens after the bound was added: %v", err)
	}
	mustDestroy(t, key)
}

// TestHeaderAreaSizeAcceptsTheWholeAcceptedBand pins the boundaries directly, so
// an off-by-one in either comparison is caught at the value rather than only
// through a volume that happens to sit in the middle.
//
// "Accepted" rather than "legal": LUKS2HeaderSize+1 is allocation-safe but is not
// a documented legal LUKS2 metadata size -- real volumes start at 16 KiB. This
// bound exists to stop panics, not to enforce the format.
func TestHeaderAreaSizeAcceptsTheWholeAcceptedBand(t *testing.T) {
	for _, tc := range []struct {
		size   uint64
		accept bool
	}{
		{LUKS2HeaderSize - 1, false},
		{LUKS2HeaderSize, false},
		{LUKS2HeaderSize + 1, true},
		{LUKS2HeaderMaxSize - 1, true},
		{LUKS2HeaderMaxSize, true},
		{LUKS2HeaderMaxSize + 1, false},
	} {
		got, err := headerAreaSize(&LUKS2BinaryHeader{HeaderSize: tc.size})
		switch {
		case tc.accept && err != nil:
			t.Errorf("headerAreaSize(%d) = error %v, want it accepted", tc.size, err)
		case !tc.accept && err == nil:
			t.Errorf("headerAreaSize(%d) = %d, want it rejected", tc.size, got)
		case tc.accept && uint64(got) != tc.size:
			t.Errorf("headerAreaSize(%d) = %d, want the size back unchanged", tc.size, got)
		}
	}
}
