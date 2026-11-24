// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// Crypt segment fields reach a dm-crypt ioctl, so one validator at the read boundary checks sector_size, iv_tweak and encryption; tested through ReadHeader and Unlock.

// craftedSegmentVolume formats a container, mutates its crypt segment through writeHeaderInternal, and returns its path.
func craftedSegmentVolume(t *testing.T, name string, mutate func(*header.Segment)) string {
	t.Helper()

	path := newImage(t, name)
	formatWithLibrary(t, path)

	hdr, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader on the freshly formatted container failed: %v", err)
	}

	segment := metadata.Segments["0"]
	if segment == nil || segment.Type != "crypt" {
		t.Fatalf("the formatted container has no crypt segment at %q: %+v", "0", metadata.Segments)
	}
	mutate(segment)

	if err := writeHeaderUnvalidated(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the crafted segment fixture: %v", err)
	}
	return path
}

// TestReadHeaderRefusesASegmentTheKernelMustNotSee: each bad segment is ErrInvalidHeader.
func TestReadHeaderRefusesASegmentTheKernelMustNotSee(t *testing.T) {
	defer parallel(t)()

	tests := []struct {
		name   string
		mutate func(*header.Segment)
		names  string // the field the message must name
	}{
		{
			name:   "negative sector size",
			mutate: func(s *header.Segment) { s.SectorSize = -1 },
			names:  "sector size",
		},
		{
			name:   "zero sector size",
			mutate: func(s *header.Segment) { s.SectorSize = 0 },
			names:  "sector size",
		},
		{
			name:   "sector size below the smallest cryptsetup writes",
			mutate: func(s *header.Segment) { s.SectorSize = 256 },
			names:  "sector size",
		},
		{
			name:   "sector size above the largest cryptsetup writes",
			mutate: func(s *header.Segment) { s.SectorSize = 8192 },
			names:  "sector size",
		},
		{
			name:   "sector size that is not a power of two",
			mutate: func(s *header.Segment) { s.SectorSize = 513 },
			names:  "sector size",
		},
		{
			name:   "iv_tweak that is not a number",
			mutate: func(s *header.Segment) { s.IVTweak = "not-a-number" },
			names:  "iv_tweak",
		},
		{
			name:   "empty iv_tweak",
			mutate: func(s *header.Segment) { s.IVTweak = "" },
			names:  "iv_tweak",
		},
		{
			name:   "negative iv_tweak",
			mutate: func(s *header.Segment) { s.IVTweak = "-1" },
			names:  "iv_tweak",
		},
		{
			name:   "iv_tweak past 64 bits",
			mutate: func(s *header.Segment) { s.IVTweak = "18446744073709551616" },
			names:  "iv_tweak",
		},
		{
			name:   "hexadecimal iv_tweak",
			mutate: func(s *header.Segment) { s.IVTweak = "0x100" },
			names:  "iv_tweak",
		},
		{
			name:   "empty encryption",
			mutate: func(s *header.Segment) { s.Encryption = "" },
			names:  "cipher",
		},
		{
			// A space alone, so the separator is tested without "/" also being present.
			name:   "encryption carrying a space and no other rejected byte",
			mutate: func(s *header.Segment) { s.Encryption = "aes-xts-plain64 plain64" },
			names:  "cipher",
		},
		{
			name:   "encryption carrying a whole injected target specification",
			mutate: func(s *header.Segment) { s.Encryption = "aes-xts-plain64 :32:logon:attacker 0 /dev/sda 0" },
			names:  "cipher",
		},
		{
			name:   "encryption carrying a newline",
			mutate: func(s *header.Segment) { s.Encryption = "aes-xts-plain64\nnull" },
			names:  "cipher",
		},
		{
			name:   "encryption carrying a NUL",
			mutate: func(s *header.Segment) { s.Encryption = "aes-xts-plain64\x00" },
			names:  "cipher",
		},
		{
			name:   "encryption longer than any cipher specification",
			mutate: func(s *header.Segment) { s.Encryption = strings.Repeat("a", header.MaxSegmentEncryptionLength+1) },
			names:  "cipher",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := craftedSegmentVolume(t, "crafted-segment.img", tt.mutate)

			_, _, err := readHeaderForTest(path)
			if err == nil {
				t.Fatal("ReadHeader ACCEPTED the crafted segment; the value reaches a device-mapper ioctl unchecked")
			}
			if !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("ReadHeader = %v, want an error wrapping ErrInvalidHeader", err)
			}
			// The error must name the field.
			if !strings.Contains(err.Error(), tt.names) {
				t.Fatalf("the refusal does not name %q: %v", tt.names, err)
			}
		})
	}
}

// TestReadHeaderAcceptsEverySectorSizeCryptsetupWrites: 512, 1024, 2048 and 4096 are accepted on read.
func TestReadHeaderAcceptsEverySectorSizeCryptsetupWrites(t *testing.T) {
	defer parallel(t)()

	for _, sectorSize := range []int{512, 1024, 2048, 4096} {
		t.Run(strconv.Itoa(sectorSize), func(t *testing.T) {
			path := craftedSegmentVolume(t, "accepted-sector-size.img", func(s *header.Segment) {
				s.SectorSize = sectorSize
			})

			_, metadata, err := readHeaderForTest(path)
			if err != nil {
				t.Fatalf("ReadHeader refused a sector size cryptsetup writes: %v", err)
			}
			if got := metadata.Segments["0"].SectorSize; got != sectorSize {
				t.Fatalf("sector size survived the read as %d, want %d", got, sectorSize)
			}
		})
	}
}

// TestReadHeaderAcceptsTheCipherSpellingsCryptsetupWrites pins the charset against cryptsetup spellings, including the capi form from cryptsetup(8).
func TestReadHeaderAcceptsTheCipherSpellingsCryptsetupWrites(t *testing.T) {
	defer parallel(t)()

	for _, encryption := range []string{
		"aes-xts-plain64",
		"aes-cbc-essiv:sha256",
		"capi:authenc(hmac(sha256),xts(aes))-plain64",
	} {
		t.Run(encryption, func(t *testing.T) {
			path := craftedSegmentVolume(t, "accepted-cipher.img", func(s *header.Segment) {
				s.Encryption = encryption
			})

			if _, _, err := readHeaderForTest(path); err != nil {
				t.Fatalf("ReadHeader refused a cipher specification cryptsetup can write: %v", err)
			}
		})
	}
}

// TestACraftedSegmentNeverReachesTheDeviceMapper: Unlock refuses the crafted segments before any table is built.
func TestACraftedSegmentNeverReachesTheDeviceMapper(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*header.Segment)
	}{
		{"negative sector size", func(s *header.Segment) { s.SectorSize = -1 }},
		{"unparseable iv_tweak", func(s *header.Segment) { s.IVTweak = "not-a-number" }},
		{"cipher specification carrying a space and no other rejected byte", func(s *header.Segment) {
			s.Encryption = "aes-xts-plain64 plain64"
		}},
		{"cipher specification carrying a whole injected target specification", func(s *header.Segment) {
			s.Encryption = "aes-xts-plain64 :32:logon:attacker 0 /dev/sda 0"
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := craftedSegmentVolume(t, "crafted-unlock.img", tt.mutate)

			v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			defer func() { _ = v.Close() }()

			pass, err := enclave.NewMemoryCopy([]byte(conformancePassphrase))
			if err != nil {
				t.Fatalf("could not build the test passphrase enclave: %v", err)
			}
			defer func() { _ = pass.Destroy() }()

			if _, err := v.Unlock(context.Background(), pass); !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("Unlock = %v, want an error wrapping ErrInvalidHeader", err)
			}
		})
	}
}

// TestTheDeviceMapperTableCarriesTheDeclaredSectorSize is the control: Target of an unmodified container reports the declared values.
func TestTheDeviceMapperTableCarriesTheDeclaredSectorSize(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	v, err := Open(context.Background(), device, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()
	v.sys.blockDeviceOf = func(*os.File) (uint64, error) { return 0x0703, nil }

	pass, err := enclave.NewMemoryCopy(passphrase)
	if err != nil {
		t.Fatalf("could not build the test passphrase enclave: %v", err)
	}
	defer func() { _ = pass.Destroy() }()

	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock of an unmodified container failed: %v", err)
	}
	defer key.Destroy()

	target, err := v.Target(context.Background(), key)
	if err != nil {
		t.Fatalf("Target of an unmodified container failed: %v", err)
	}

	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	segment := metadata.Segments["0"]

	want, accepted := header.SegmentSectorSizes[segment.SectorSize]
	if !accepted {
		t.Fatalf("the formatted container declares sector size %d, which the whitelist does not accept", segment.SectorSize)
	}
	if target.SectorSize != int(want) {
		t.Fatalf("Target carries sector size %d, the header declares %d", target.SectorSize, segment.SectorSize)
	}
	if target.Cipher != segment.Encryption {
		t.Fatalf("Target carries cipher %q, the header declares %q", target.Cipher, segment.Encryption)
	}
	if target.IVOffset != 0 {
		t.Fatalf("Target carries IV tweak %d, the header declares %q", target.IVOffset, segment.IVTweak)
	}
}
