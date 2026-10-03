// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

// A crypt segment's declared fields are handed to a KERNEL IOCTL, and until
// #40 nothing checked any of them.
//
// The three that reach devmapper.CryptTable are sector_size, iv_tweak and
// encryption. Measured on main before this file existed, with a segment
// declaring sector_size -1 and iv_tweak "not-a-number":
//
//	ReadHeader ACCEPTED it
//	SectorSize handed to the dm-crypt table: 18446744073709551615
//	IVTweak    handed to the dm-crypt table: 0 (from "not-a-number")
//
// The sector size carried a G115 suppression annotation justified as "sector
// size is validated (512 or 4096)". That validation exists in exactly one
// place -- ValidateFormatOptions, on the FORMAT path -- and has never applied
// to a segment read off a device, so a gosec finding was silenced by a
// justification that was not true of the code it annotated. (Paraphrased
// rather than quoted for the same reason as kdf.go's u32 comment: gosec finds
// its directive by literal text, in any comment.)
//
// The fix is the segment counterpart of validateKeyslot: ONE validator at the
// read boundary that every consumer inherits, rather than a check per call
// site. These tests drive it through ReadHeader and through the real Unlock
// path, because a validator nothing calls is the defect it was written to fix.

// craftedSegmentVolume writes a container whose crypt segment has been mutated
// by mutate, and returns its path.
//
// It formats for real and rewrites the header through writeHeaderInternal, so
// the container is byte-identical to a legitimate one apart from the field
// under test -- the checksums are recomputed and the JSON is well-formed. A
// hand-assembled image would prove only that a broken image is rejected.
func craftedSegmentVolume(t *testing.T, name string, mutate func(*Segment)) string {
	t.Helper()

	path := newImage(t, name)
	formatWithLibrary(t, path)

	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader on the freshly formatted container failed: %v", err)
	}

	segment := metadata.Segments["0"]
	if segment == nil || segment.Type != "crypt" {
		t.Fatalf("the formatted container has no crypt segment at %q: %+v", "0", metadata.Segments)
	}
	mutate(segment)

	if err := writeHeaderInternal(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the crafted segment fixture: %v", err)
	}
	return path
}

// TestReadHeaderRefusesASegmentTheKernelMustNotSee is the boundary itself.
//
// Every case is a value that reached a device-mapper ioctl unchecked before
// #40. They are volume-level faults and not per-keyslot ones -- a segment is
// the whole volume's data, and there is no second segment to fall back on the
// way a damaged keyslot has 31 siblings -- so each is ErrInvalidHeader.
func TestReadHeaderRefusesASegmentTheKernelMustNotSee(t *testing.T) {
	defer parallel(t)()

	tests := []struct {
		name   string
		mutate func(*Segment)
		names  string // the field the message must name
	}{
		{
			name:   "negative sector size",
			mutate: func(s *Segment) { s.SectorSize = -1 },
			names:  "sector size",
		},
		{
			name:   "zero sector size",
			mutate: func(s *Segment) { s.SectorSize = 0 },
			names:  "sector size",
		},
		{
			name:   "sector size below the smallest cryptsetup writes",
			mutate: func(s *Segment) { s.SectorSize = 256 },
			names:  "sector size",
		},
		{
			name:   "sector size above the largest cryptsetup writes",
			mutate: func(s *Segment) { s.SectorSize = 8192 },
			names:  "sector size",
		},
		{
			name:   "sector size that is not a power of two",
			mutate: func(s *Segment) { s.SectorSize = 513 },
			names:  "sector size",
		},
		{
			name:   "iv_tweak that is not a number",
			mutate: func(s *Segment) { s.IVTweak = "not-a-number" },
			names:  "iv_tweak",
		},
		{
			name:   "empty iv_tweak",
			mutate: func(s *Segment) { s.IVTweak = "" },
			names:  "iv_tweak",
		},
		{
			name:   "negative iv_tweak",
			mutate: func(s *Segment) { s.IVTweak = "-1" },
			names:  "iv_tweak",
		},
		{
			name:   "iv_tweak past 64 bits",
			mutate: func(s *Segment) { s.IVTweak = "18446744073709551616" },
			names:  "iv_tweak",
		},
		{
			name:   "hexadecimal iv_tweak",
			mutate: func(s *Segment) { s.IVTweak = "0x100" },
			names:  "iv_tweak",
		},
		{
			name:   "empty encryption",
			mutate: func(s *Segment) { s.Encryption = "" },
			names:  "cipher",
		},
		{
			// A SPACE AND NOTHING ELSE. The realistic payload below carries "/"
			// as well, which is separately outside the charset -- so a fixture
			// built from it passes even with the space admitted, and proves
			// nothing about the separator. Measured: admitting " " to the
			// whitelist left the full-payload case green.
			name:   "encryption carrying a space and no other rejected byte",
			mutate: func(s *Segment) { s.Encryption = "aes-xts-plain64 plain64" },
			names:  "cipher",
		},
		{
			name:   "encryption carrying a whole injected target specification",
			mutate: func(s *Segment) { s.Encryption = "aes-xts-plain64 :32:logon:attacker 0 /dev/sda 0" },
			names:  "cipher",
		},
		{
			name:   "encryption carrying a newline",
			mutate: func(s *Segment) { s.Encryption = "aes-xts-plain64\nnull" },
			names:  "cipher",
		},
		{
			name:   "encryption carrying a NUL",
			mutate: func(s *Segment) { s.Encryption = "aes-xts-plain64\x00" },
			names:  "cipher",
		},
		{
			name:   "encryption longer than any cipher specification",
			mutate: func(s *Segment) { s.Encryption = strings.Repeat("a", maxSegmentEncryptionLength+1) },
			names:  "cipher",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := craftedSegmentVolume(t, "crafted-segment.img", tt.mutate)

			_, _, err := ReadHeader(path)
			if err == nil {
				t.Fatal("ReadHeader ACCEPTED the crafted segment; the value reaches a device-mapper ioctl unchecked")
			}
			if !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("ReadHeader = %v, want an error wrapping ErrInvalidHeader", err)
			}
			// An operator has to be told WHICH field, or the guard is a
			// refusal with no remedy.
			if !strings.Contains(err.Error(), tt.names) {
				t.Fatalf("the refusal does not name %q: %v", tt.names, err)
			}
		})
	}
}

// TestReadHeaderAcceptsEverySectorSizeCryptsetupWrites is the other half, and
// it is the half that stops the guard becoming its own defect.
//
// cryptsetup 2.7.0 accepts --sector-size 512, 1024, 2048 and 4096 and refuses
// 256 and 8192 (measured; each accepted value was read back out of the header
// it wrote). This package's own writer emits only 512 or 4096, so validating
// the READ path against the writer's range would refuse two containers
// cryptsetup can create -- exactly the failure keyslotvalidation.go's measured
// limits exist to avoid.
func TestReadHeaderAcceptsEverySectorSizeCryptsetupWrites(t *testing.T) {
	defer parallel(t)()

	for _, sectorSize := range []int{512, 1024, 2048, 4096} {
		t.Run(strconv.Itoa(sectorSize), func(t *testing.T) {
			path := craftedSegmentVolume(t, "accepted-sector-size.img", func(s *Segment) {
				s.SectorSize = sectorSize
			})

			_, metadata, err := ReadHeader(path)
			if err != nil {
				t.Fatalf("ReadHeader refused a sector size cryptsetup writes: %v", err)
			}
			if got := metadata.Segments["0"].SectorSize; got != sectorSize {
				t.Fatalf("sector size survived the read as %d, want %d", got, sectorSize)
			}
		})
	}
}

// TestReadHeaderAcceptsTheCipherSpellingsCryptsetupWrites pins the charset
// against cipher specifications this package does not write, so the whitelist
// cannot quietly narrow to our own writer's output.
//
// "aes-xts-plain64" and "aes-cbc-essiv:sha256" were formatted with cryptsetup
// 2.7.0 and read back out of the header it wrote. The capi form was NOT
// measured -- cryptsetup probes the kernel crypto API for it and demands a real
// loop device, so it cannot be formatted unprivileged against a file -- and is
// here from the grammar in cryptsetup(8). It is also the longest spelling the
// format can express, which is what maxSegmentEncryptionLength is sized
// against.
func TestReadHeaderAcceptsTheCipherSpellingsCryptsetupWrites(t *testing.T) {
	defer parallel(t)()

	for _, encryption := range []string{
		"aes-xts-plain64",
		"aes-cbc-essiv:sha256",
		"capi:authenc(hmac(sha256),xts(aes))-plain64",
	} {
		t.Run(encryption, func(t *testing.T) {
			path := craftedSegmentVolume(t, "accepted-cipher.img", func(s *Segment) {
				s.Encryption = encryption
			})

			if _, _, err := ReadHeader(path); err != nil {
				t.Fatalf("ReadHeader refused a cipher specification cryptsetup can write: %v", err)
			}
		})
	}
}

// TestACraftedSegmentNeverReachesTheDeviceMapper is the assertion that matters:
// not that Unlock returns an error, but that the crafted value never got as far
// as the ioctl.
//
// Before #40 this test failed on the table contents, not on the error: Unlock
// ran to completion and handed device-mapper SectorSize 18446744073709551615,
// which devmapper renders with strconv.Itoa(int(...)) into the target flag
// "sector_size:-1".
func TestACraftedSegmentNeverReachesTheDeviceMapper(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Segment)
	}{
		{"negative sector size", func(s *Segment) { s.SectorSize = -1 }},
		{"unparseable iv_tweak", func(s *Segment) { s.IVTweak = "not-a-number" }},
		{"cipher specification carrying a space and no other rejected byte", func(s *Segment) {
			s.Encryption = "aes-xts-plain64 plain64"
		}},
		{"cipher specification carrying a whole injected target specification", func(s *Segment) {
			s.Encryption = "aes-xts-plain64 :32:logon:attacker 0 /dev/sda 0"
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := craftedSegmentVolume(t, "crafted-unlock.img", tt.mutate)

			fake := newFakeDeviceMapper()
			fake.install(t)

			err := Unlock(path, []byte(conformancePassphrase), "crafted-target")
			if err == nil {
				t.Fatal("Unlock reported success on a container whose segment declares a value the kernel must not see")
			}
			if !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("Unlock = %v, want an error wrapping ErrInvalidHeader", err)
			}

			// The damage plane, asserted first: device-mapper was never asked
			// to do anything at all. An error assertion alone cannot tell
			// "refused before the ioctl" from "the ioctl failed", and it is the
			// first of those this fix is about.
			if len(fake.loaded) != 0 {
				t.Fatalf("a crafted segment reached the device-mapper table: %+v", fake.loaded)
			}
			if live := fake.live(); len(live) != 0 {
				t.Fatalf("a crafted segment produced live device-mapper targets: %v", live)
			}
		})
	}
}

// TestTheDeviceMapperTableCarriesTheDeclaredSectorSize is the control that
// keeps the test above honest: an unlock of an UNMODIFIED container still
// reaches device-mapper, and reaches it with the values the header declares.
//
// Without it, "the table was never loaded" would pass just as well for a fix
// that broke every unlock.
func TestTheDeviceMapperTableCarriesTheDeclaredSectorSize(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	fake := newFakeDeviceMapper()
	fake.install(t)

	if err := Unlock(device, passphrase, "declared-geometry"); err != nil {
		t.Fatalf("Unlock of an unmodified container failed: %v", err)
	}

	_, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	segment := metadata.Segments["0"]

	table := fake.cryptTable(t)
	want, accepted := segmentSectorSizes[segment.SectorSize]
	if !accepted {
		t.Fatalf("the formatted container declares sector size %d, which the whitelist does not accept", segment.SectorSize)
	}
	if table.SectorSize != want {
		t.Fatalf("the table carries sector size %d, the header declares %d", table.SectorSize, segment.SectorSize)
	}
	if table.Encryption != segment.Encryption {
		t.Fatalf("the table carries cipher %q, the header declares %q", table.Encryption, segment.Encryption)
	}
	if table.IVTweak != 0 {
		t.Fatalf("the table carries IV tweak %d, the header declares %q", table.IVTweak, segment.IVTweak)
	}
}
