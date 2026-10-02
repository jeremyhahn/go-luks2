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
	"strconv"
	"strings"
	"testing"
)

// FormatOptions.MetadataSize (#47).
//
// The owner ruled on 2026-09-25 that callers may choose any metadata area size
// LUKS2 allows, 16 KiB to 4 MiB, rather than always getting 16 KiB. The
// reference is cryptsetup's --luks2-metadata-size, measured against cryptsetup
// 2.7.0 and recorded on #47:
//
//	--luks2-metadata-size  hdr_size  json_size  keyslots_size  data offset
//	16k                    16384     12288      16744448       16777216
//	32k                    32768     28672      16711680       16777216
//	4m                     4194304   4190208    8388608        16777216
//
// so json_size = area - 4096, the keyslots area starts at 2 * area, and
// keyslots_size = 16 MiB - 2 * area, which keeps the data segment at 16 MiB.
// Every legal size is formatted here and handed to cryptsetup, because a
// geometry only this package agrees with proves nothing.

// metadataSizeFormatOptions formats a cheap container with a chosen metadata
// area size.
func metadataSizeFormatOptions(path string, size int) FormatOptions {
	opts := standardFormatOptions(path)
	opts.MetadataSize = size
	return opts
}

// TestFormatMetadataSizeLaysOutEveryLegalSize formats with each size LUKS2
// allows and checks the geometry against cryptsetup's, both as this package
// reads it and as cryptsetup reads it.
func TestFormatMetadataSizeLaysOutEveryLegalSize(t *testing.T) {
	t.Parallel()

	requireCryptsetup(t)

	for _, size := range legalHeaderAreaSizes() {
		t.Run(fmt.Sprintf("%dKiB", size/1024), func(t *testing.T) {
			t.Parallel()

			path := newImage(t, "metadata-size.img")
			if err := Format(metadataSizeFormatOptions(path, int(size))); err != nil {
				t.Fatalf("Format with MetadataSize %d failed: %v", size, err)
			}

			hdr, metadata, err := ReadHeader(path)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			if hdr.HeaderSize != uint64(size) {
				t.Errorf("hdr_size = %d, want %d", hdr.HeaderSize, size)
			}
			if got, want := metadata.Config.JSONSize, formatSize(size-LUKS2HeaderSize); got != want {
				t.Errorf("config.json_size = %s, want %s", got, want)
			}
			wantKeyslots := int64(LUKS2HeaderDefaultSize) - 2*size
			if got, want := metadata.Config.KeyslotsSize, formatSize(wantKeyslots); got != want {
				t.Errorf("config.keyslots_size = %s, want %s", got, want)
			}
			if got, want := metadata.Keyslots["0"].Area.Offset, formatSize(2*size); got != want {
				t.Errorf("keyslot 0 area offset = %s, want %s (2 x the metadata area)", got, want)
			}
			if got, want := metadata.Segments["0"].Offset, formatSize(LUKS2HeaderDefaultSize); got != want {
				t.Errorf("segment 0 offset = %s, want %s", got, want)
			}

			secondary, _, err := ReadSecondaryHeader(path)
			if err != nil {
				t.Fatalf("ReadSecondaryHeader failed: %v", err)
			}
			if secondary.HeaderOffset != uint64(size) {
				t.Errorf("secondary hdr_offset = %d, want %d", secondary.HeaderOffset, size)
			}

			if err := TestKey(path, []byte(conformancePassphrase)); err != nil {
				t.Errorf("this package cannot open its own %d-byte-metadata container: %v", size, err)
			}

			code, out := runCryptsetup(t, "", "luksDump", path)
			if code != 0 {
				t.Fatalf("cryptsetup luksDump exited %d, want 0\n%s", code, out)
			}
			for _, want := range []string{
				fmt.Sprintf("Metadata area: \t%d [bytes]", size),
				fmt.Sprintf("Keyslots area: \t%d [bytes]", wantKeyslots),
				fmt.Sprintf("offset: %d [bytes]", LUKS2HeaderDefaultSize),
			} {
				if !strings.Contains(out, want) {
					t.Errorf("luksDump output is missing %q\n%s", want, out)
				}
			}

			if code, out := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", path); code != 0 {
				t.Errorf("cryptsetup rejected the correct passphrase (exit %d)\n%s", code, out)
			}
		})
	}
}

// TestFormatMetadataSizeRefusesIllegalSizes is the validation half: the sizes
// cryptsetup refuses ("Unsupported LUKS2 metadata size options") are refused
// here too, with a typed error, before the device is touched.
func TestFormatMetadataSizeRefusesIllegalSizes(t *testing.T) {
	t.Parallel()

	for _, size := range []int{
		-1,
		4096,
		8192,    // below the minimum
		12288,   // the JSON size, not an area size
		20480,   // 16 KiB + 4 KiB: the size the old nextPowerOf2 path produced
		16385,   // not a power of two
		3 << 20, // inside the range, not a power of two
		8 << 20, // above the maximum
		LUKS2HeaderMaxSize * 2,
	} {
		t.Run(fmt.Sprintf("%d", size), func(t *testing.T) {
			path := newImage(t, "illegal-metadata-size.img")

			err := Format(metadataSizeFormatOptions(path, size))
			if !errors.Is(err, ErrInvalidMetadataSize) {
				t.Fatalf("Format with MetadataSize %d returned %v, want ErrInvalidMetadataSize", size, err)
			}

			prefix, err := readImagePrefix(path)
			if err != nil {
				t.Fatalf("failed to read the image back: %v", err)
			}
			if !bytes.Equal(prefix, make([]byte, len(prefix))) {
				t.Fatal("a refused Format wrote to the device")
			}
		})
	}
}

// TestValidateFormatOptionsMetadataSize pins the accepted set exactly: zero
// (the default) and every power of two from 16 KiB to 4 MiB.
func TestValidateFormatOptionsMetadataSize(t *testing.T) {
	path := newImage(t, "validate.img")

	accepted := []int{0}
	for _, size := range legalHeaderAreaSizes() {
		accepted = append(accepted, int(size))
	}
	for _, size := range accepted {
		if err := ValidateFormatOptions(metadataSizeFormatOptions(path, size)); err != nil {
			t.Errorf("ValidateFormatOptions refused the legal MetadataSize %d: %v", size, err)
		}
	}

	for _, size := range []int{-16384, 1, 16383, 16385, 24576, 4194303, 4194305, 8388608} {
		if err := ValidateFormatOptions(metadataSizeFormatOptions(path, size)); !errors.Is(err, ErrInvalidMetadataSize) {
			t.Errorf("ValidateFormatOptions(MetadataSize %d) = %v, want ErrInvalidMetadataSize", size, err)
		}
	}
}

// TestFormatMetadataSizeHoldsMetadataTheDefaultRefuses is the point of the
// knob: a token too large for the default 12288-byte JSON area is refused on a
// default container and accepted on a 64 KiB one, which cryptsetup then reads.
func TestFormatMetadataSizeHoldsMetadataTheDefaultRefuses(t *testing.T) {
	t.Parallel()

	requireCryptsetup(t)

	// A token member this package does not model, carried by the passthrough,
	// sized well past what 12288 bytes can hold.
	token := fmt.Sprintf(`{"type":"x-large","keyslots":["0"],"x-blob":%q}`, strings.Repeat("A", 20000))

	t.Run("default metadata size refuses it", func(t *testing.T) {
		path := newImage(t, "default.img")
		formatWithLibrary(t, path)

		before, err := readImagePrefix(path)
		if err != nil {
			t.Fatalf("failed to read the image: %v", err)
		}
		if err := ImportTokenJSON(path, 0, []byte(token)); !errors.Is(err, ErrMetadataTooLarge) {
			t.Fatalf("ImportTokenJSON on a 16 KiB container returned %v, want ErrMetadataTooLarge", err)
		}
		after, err := readImagePrefix(path)
		if err != nil {
			t.Fatalf("failed to read the image: %v", err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("a refused ImportTokenJSON changed the device")
		}
	})

	t.Run("64 KiB metadata holds it", func(t *testing.T) {
		path := newImage(t, "large.img")
		if err := Format(metadataSizeFormatOptions(path, 64<<10)); err != nil {
			t.Fatalf("Format failed: %v", err)
		}
		if err := ImportTokenJSON(path, 0, []byte(token)); err != nil {
			t.Fatalf("ImportTokenJSON on a 64 KiB container failed: %v", err)
		}

		got, err := ExportToken(path, 0)
		if err != nil {
			t.Fatalf("ExportToken failed: %v", err)
		}
		if !bytes.Contains(got, []byte(strings.Repeat("A", 20000))) {
			t.Error("the large token did not survive the round trip")
		}
		if err := TestKey(path, []byte(conformancePassphrase)); err != nil {
			t.Errorf("the container no longer opens after the token import: %v", err)
		}

		code, out := runCryptsetup(t, "", "luksDump", path)
		if code != 0 {
			t.Fatalf("cryptsetup luksDump exited %d, want 0\n%s", code, out)
		}
		if !strings.Contains(out, "x-large") {
			t.Errorf("cryptsetup does not list the imported token\n%s", out)
		}
		if code, out := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", path); code != 0 {
			t.Errorf("cryptsetup rejected the correct passphrase (exit %d)\n%s", code, out)
		}
	})
}

// TestWipeHeaderOnlyDestroysBothCopiesOfALargerArea is the wipe consequence of
// the knob. A header-only wipe zeroed a fixed 32 KiB, which covers both copies
// only of a 16 KiB area. On a 32 KiB-area container -- which Format can now
// write, and which cryptsetup always could -- the second copy starts at 32 KiB
// and survived the wipe intact, so the "wiped" volume was still recoverable.
func TestWipeHeaderOnlyDestroysBothCopiesOfALargerArea(t *testing.T) {
	t.Parallel()

	requireCryptsetup(t)

	for _, size := range []int{LUKS2HeaderMinSize, 32 << 10, 1 << 20} {
		t.Run(fmt.Sprintf("%dKiB", size/1024), func(t *testing.T) {
			path := newImage(t, "wipe.img")
			if err := Format(metadataSizeFormatOptions(path, size)); err != nil {
				t.Fatalf("Format failed: %v", err)
			}

			if err := Wipe(WipeOptions{Device: path, Passes: 1, HeaderOnly: true}); err != nil {
				t.Fatalf("header-only Wipe failed: %v", err)
			}

			if _, _, err := ReadHeader(path); err == nil {
				t.Error("the primary header still reads after a header-only wipe")
			}
			if _, _, err := ReadSecondaryHeader(path); err == nil {
				t.Error("the secondary header still reads after a header-only wipe")
			}
			if code, out := runCryptsetup(t, "", "isLuks", path); code == 0 {
				t.Errorf("cryptsetup still recognizes the container after a header-only wipe\n%s", out)
			}

			// Both copies, and nothing past them: the data segment is not
			// touched by a header-only wipe.
			f, err := os.Open(path) // #nosec G304 -- path is under t.TempDir()
			if err != nil {
				t.Fatalf("failed to open the image: %v", err)
			}
			defer func() { _ = f.Close() }()
			region := make([]byte, 2*size)
			if _, err := f.ReadAt(region, 0); err != nil {
				t.Fatalf("failed to read the header region: %v", err)
			}
			if !bytes.Equal(region, make([]byte, len(region))) {
				t.Errorf("the %d-byte header region is not all zeroes after a header-only wipe", len(region))
			}
			// The keyslots area begins at 2 x area and was filled with random
			// by Format; the first block of it must still be random.
			next := make([]byte, 4096)
			if _, err := f.ReadAt(next, int64(2*size)); err != nil {
				t.Fatalf("failed to read past the header region: %v", err)
			}
			if bytes.Equal(next, make([]byte, len(next))) {
				t.Error("the header-only wipe zeroed past the two header copies")
			}
		})
	}
}

// TestWipeHeaderOnlyDoesNotTrustADamagedPrimarysSize pins the review finding
// on #47: the primary's declared size is not checksum-verified before a wipe
// sizes itself by it. A 64 KiB-area container whose damaged primary declares
// a smaller LEGAL size (16 KiB) had only 32 KiB zeroed, and the intact
// secondary at 64 KiB survived a "successful" header-only wipe -- so the
// volume was still recoverable from its second copy.
func TestWipeHeaderOnlyDoesNotTrustADamagedPrimarysSize(t *testing.T) {
	t.Parallel()

	const size = 64 << 10

	path := newImage(t, "wipe-damaged-primary.img")
	if err := Format(metadataSizeFormatOptions(path, size)); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Rewrite the primary's hdr_size (offset 8, after the 6-byte magic and the
	// 2-byte version) to 16 KiB, leaving its checksum stale.
	f, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the image: %v", err)
	}
	var declared [8]byte
	binary.BigEndian.PutUint64(declared[:], LUKS2HeaderMinSize)
	if _, err := f.WriteAt(declared[:], 8); err != nil {
		_ = f.Close()
		t.Fatalf("failed to damage the primary: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close the image: %v", err)
	}

	// Precondition: the damage leaves the secondary as the recoverable copy.
	if _, _, err := ReadSecondaryHeader(path); err != nil {
		t.Fatalf("precondition: the secondary does not read after damaging the primary: %v", err)
	}

	if err := Wipe(WipeOptions{Device: path, Passes: 1, HeaderOnly: true}); err != nil {
		t.Fatalf("header-only Wipe failed: %v", err)
	}

	if _, _, err := ReadHeader(path); err == nil {
		t.Error("the container still reads after a header-only wipe")
	}
	if _, _, err := ReadSecondaryHeader(path); err == nil {
		t.Error("the secondary header survived a header-only wipe of a container whose primary understated its size")
	}

	region := make([]byte, 2*size)
	g, err := os.Open(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the image: %v", err)
	}
	defer func() { _ = g.Close() }()
	if _, err := g.ReadAt(region, 0); err != nil {
		t.Fatalf("failed to read the header region: %v", err)
	}
	if !bytes.Equal(region, make([]byte, len(region))) {
		t.Errorf("the %d-byte region holding both copies is not all zeroes after a header-only wipe", len(region))
	}
}

// damageDeclaredSize rewrites the hdr_size field (offset 8, after the 6-byte
// magic and the 2-byte version) of the header copy at offset, leaving its
// checksum stale.
func damageDeclaredSize(t *testing.T, path string, offset int64, size uint64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the image: %v", err)
	}
	defer func() { _ = f.Close() }()
	var declared [8]byte
	binary.BigEndian.PutUint64(declared[:], size)
	if _, err := f.WriteAt(declared[:], offset+8); err != nil {
		t.Fatalf("failed to damage the header copy at %d: %v", offset, err)
	}
}

// readImageAt reads size bytes of the image at offset.
func readImageAt(t *testing.T, path string, offset int64, size int) []byte {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the image: %v", err)
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, size)
	if _, err := f.ReadAt(buf, offset); err != nil {
		t.Fatalf("failed to read %d bytes at %d: %v", size, offset, err)
	}
	return buf
}

// TestWipeHeaderOnlyDoesNotTrustAnOverstatedPrimarySize pins the second review
// finding on #47: sizing the wipe by the LARGEST declared area let a damaged
// primary that overstates its size to 4 MiB zero 8 MiB -- on a cryptsetup
// container with 32 KiB headers and its data segment at 4 MiB, that is 4 MiB
// of payload destroyed, although the intact secondary stated the real geometry.
func TestWipeHeaderOnlyDoesNotTrustAnOverstatedPrimarySize(t *testing.T) {
	t.Parallel()

	requireCryptsetup(t)

	const (
		area       = 32 << 10
		dataOffset = 4 << 20
	)
	path := newForeignContainer(t, "wipe-overstated-primary.img", foreignGeometry{
		metadataSize:     "32k",
		keyslotsSize:     "1m",
		dataOffsetSec:    strconv.Itoa(dataOffset / 512),
		wantArea:         area,
		wantKeyslotsSize: 1 << 20,
	})

	// Recognizable payload at the start of the data segment.
	payload := bytes.Repeat([]byte("payload!"), 8192)
	f, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the image: %v", err)
	}
	if _, err := f.WriteAt(payload, dataOffset); err != nil {
		_ = f.Close()
		t.Fatalf("failed to write the payload: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close the image: %v", err)
	}

	damageDeclaredSize(t, path, LUKS2PrimaryHeaderOffset, LUKS2HeaderMaxSize)
	if _, _, err := ReadSecondaryHeader(path); err != nil {
		t.Fatalf("precondition: the secondary does not read after damaging the primary: %v", err)
	}

	if err := Wipe(WipeOptions{Device: path, Passes: 1, HeaderOnly: true}); err != nil {
		t.Fatalf("header-only Wipe failed: %v", err)
	}

	if !bytes.Equal(readImageAt(t, path, dataOffset, len(payload)), payload) {
		t.Error("a header-only wipe destroyed payload because a damaged primary overstated its size")
	}
	if _, _, err := ReadSecondaryHeader(path); err == nil {
		t.Error("the secondary header survived a header-only wipe")
	}
	if region := readImageAt(t, path, 0, 2*area); !bytes.Equal(region, make([]byte, len(region))) {
		t.Errorf("the %d-byte region holding both copies is not all zeroes", len(region))
	}
}

// TestWipeHeaderOnlyWithNoValidCopy covers the ambiguous case: every copy is
// damaged, so no geometry can be trusted. The wipe zeroes the default 32 KiB
// front and nothing beyond it but the binary header of each copy still
// recognizable as a LUKS2 header -- here the damaged secondary of a 64 KiB
// container -- so no copy is left locatable and no payload-sized span is
// guessed at.
func TestWipeHeaderOnlyWithNoValidCopy(t *testing.T) {
	t.Parallel()

	const size = 64 << 10

	path := newImage(t, "wipe-no-valid-copy.img")
	if err := Format(metadataSizeFormatOptions(path, size)); err != nil {
		t.Fatalf("Format failed: %v", err)
	}
	// Primary overstates, secondary's checksum is broken by a JSON byte.
	damageDeclaredSize(t, path, LUKS2PrimaryHeaderOffset, LUKS2HeaderMaxSize)
	f, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the image: %v", err)
	}
	if _, err := f.WriteAt([]byte{'X'}, size+LUKS2HeaderSize); err != nil {
		_ = f.Close()
		t.Fatalf("failed to damage the secondary: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close the image: %v", err)
	}
	keyslots := readImageAt(t, path, 2*size, 4096)

	if err := Wipe(WipeOptions{Device: path, Passes: 1, HeaderOnly: true}); err != nil {
		t.Fatalf("header-only Wipe failed: %v", err)
	}

	if front := readImageAt(t, path, 0, 2*LUKS2HeaderMinSize); !bytes.Equal(front, make([]byte, len(front))) {
		t.Error("the default 32 KiB front is not all zeroes")
	}
	if magic := readImageAt(t, path, size, LUKS2HeaderSize); !bytes.Equal(magic, make([]byte, len(magic))) {
		t.Error("the damaged secondary's binary header is still present")
	}
	if !bytes.Equal(readImageAt(t, path, 2*size, len(keyslots)), keyslots) {
		t.Error("the wipe reached past the header copies into the keyslots area")
	}
}
