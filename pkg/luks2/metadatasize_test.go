// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
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
func metadataSizeFormatOptions(path string, size int) formatOptionsForTest {
	opts := standardFormatOptions(path)
	opts.MetadataSize = size
	return opts
}

// TestFormatMetadataSizeLaysOutEveryLegalSize formats with each size LUKS2
// allows and checks the geometry against cryptsetup's, both as this package
// reads it and as cryptsetup reads it.
func TestFormatMetadataSizeLaysOutEveryLegalSize(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	for _, size := range header.LegalHeaderAreaSizes() {
		t.Run(fmt.Sprintf("%dKiB", size/1024), func(t *testing.T) {
			defer parallel(t)()

			path := newImage(t, "metadata-size.img")
			if err := formatForTest(metadataSizeFormatOptions(path, int(size))); err != nil {
				t.Fatalf("Format with MetadataSize %d failed: %v", size, err)
			}

			hdr, metadata, err := readHeaderForTest(path)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			if hdr.HeaderSize != uint64(size) {
				t.Errorf("hdr_size = %d, want %d", hdr.HeaderSize, size)
			}
			if got, want := metadata.Config.JSONSize, formatSize(size-header.HeaderSize); got != want {
				t.Errorf("config.json_size = %s, want %s", got, want)
			}
			wantKeyslots := int64(header.HeaderDefaultSize) - 2*size
			if got, want := metadata.Config.KeyslotsSize, formatSize(wantKeyslots); got != want {
				t.Errorf("config.keyslots_size = %s, want %s", got, want)
			}
			if got, want := metadata.Keyslots["0"].Area.Offset, formatSize(2*size); got != want {
				t.Errorf("keyslot 0 area offset = %s, want %s (2 x the metadata area)", got, want)
			}
			if got, want := metadata.Segments["0"].Offset, formatSize(header.HeaderDefaultSize); got != want {
				t.Errorf("segment 0 offset = %s, want %s", got, want)
			}

			secondary, _, err := readSecondaryHeaderForTest(path)
			if err != nil {
				t.Fatalf("ReadSecondaryHeader failed: %v", err)
			}
			if secondary.HeaderOffset != uint64(size) {
				t.Errorf("secondary hdr_offset = %d, want %d", secondary.HeaderOffset, size)
			}

			if err := testKeyForTest(path, []byte(conformancePassphrase)); err != nil {
				t.Errorf("this package cannot open its own %d-byte-metadata container: %v", size, err)
			}

			code, out := runCryptsetup(t, "", "luksDump", path)
			if code != 0 {
				t.Fatalf("cryptsetup luksDump exited %d, want 0\n%s", code, out)
			}
			for _, want := range []string{
				fmt.Sprintf("Metadata area: \t%d [bytes]", size),
				fmt.Sprintf("Keyslots area: \t%d [bytes]", wantKeyslots),
				fmt.Sprintf("offset: %d [bytes]", header.HeaderDefaultSize),
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
	defer parallel(t)()

	for _, size := range []int{
		-1,
		4096,
		8192,    // below the minimum
		12288,   // the JSON size, not an area size
		20480,   // 16 KiB + 4 KiB: the size the old nextPowerOf2 path produced
		16385,   // not a power of two
		3 << 20, // inside the range, not a power of two
		8 << 20, // above the maximum
		header.HeaderMaxSize * 2,
	} {
		t.Run(fmt.Sprintf("%d", size), func(t *testing.T) {
			path := newImage(t, "illegal-metadata-size.img")

			err := formatForTest(metadataSizeFormatOptions(path, size))
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("Format with MetadataSize %d returned %v, want ErrInvalidArgument", size, err)
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

// TestvalidateFormatOptionsForTestMetadataSize pins the accepted set exactly: zero
// (the default) and every power of two from 16 KiB to 4 MiB.
func TestValidateFormatOptionsForTestMetadataSize(t *testing.T) {
	path := newImage(t, "validate.img")

	accepted := []int{0}
	for _, size := range header.LegalHeaderAreaSizes() {
		accepted = append(accepted, int(size))
	}
	for _, size := range accepted {
		if err := validateFormatOptionsForTest(metadataSizeFormatOptions(path, size)); err != nil {
			t.Errorf("validateFormatOptionsForTest refused the legal MetadataSize %d: %v", size, err)
		}
	}

	for _, size := range []int{-16384, 1, 16383, 16385, 24576, 4194303, 4194305, 8388608} {
		if err := validateFormatOptionsForTest(metadataSizeFormatOptions(path, size)); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("validateFormatOptionsForTest(MetadataSize %d) = %v, want ErrInvalidArgument", size, err)
		}
	}
}

// TestFormatMetadataSizeHoldsMetadataTheDefaultRefuses is the point of the
// knob: a token too large for the default 12288-byte JSON area is refused on a
// default container and accepted on a 64 KiB one, which cryptsetup then reads.
func TestFormatMetadataSizeHoldsMetadataTheDefaultRefuses(t *testing.T) {
	defer parallel(t)()

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
		if err := setTokenJSONForTest(path, 0, []byte(token)); !errors.Is(err, ErrNoSpace) {
			t.Fatalf("SetToken on a 16 KiB container returned %v, want ErrNoSpace", err)
		}
		after, err := readImagePrefix(path)
		if err != nil {
			t.Fatalf("failed to read the image: %v", err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("a refused SetToken changed the device")
		}
	})

	t.Run("64 KiB metadata holds it", func(t *testing.T) {
		path := newImage(t, "large.img")
		if err := formatForTest(metadataSizeFormatOptions(path, 64<<10)); err != nil {
			t.Fatalf("Format failed: %v", err)
		}
		if err := setTokenJSONForTest(path, 0, []byte(token)); err != nil {
			t.Fatalf("SetToken on a 64 KiB container failed: %v", err)
		}

		tok, ok, err := getTokenForTest(path, 0)
		if err != nil {
			t.Fatalf("getTokenForTest failed: %v", err)
		}
		if !ok {
			t.Fatalf("Tokens()[0] missing after SetToken")
		}
		got, err := json.Marshal(tok)
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}
		if !bytes.Contains(got, []byte(strings.Repeat("A", 20000))) {
			t.Error("the large token did not survive the round trip")
		}
		if err := testKeyForTest(path, []byte(conformancePassphrase)); err != nil {
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
//
// Since #246 (D3) the wipe also zeroes the whole keyslots area, so the region
// checked runs to the end of it -- and stops there: the data segment is not
// touched.
func TestWipeHeaderOnlyDestroysBothCopiesOfALargerArea(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	for _, size := range []int{header.HeaderMinSize, 32 << 10, 1 << 20} {
		t.Run(fmt.Sprintf("%dKiB", size/1024), func(t *testing.T) {
			path := newImage(t, "wipe.img")
			if err := formatForTest(metadataSizeFormatOptions(path, size)); err != nil {
				t.Fatalf("Format failed: %v", err)
			}
			hdr, metadata, err := readHeaderForTest(path)
			if err != nil {
				t.Fatalf("ReadHeader: %v", err)
			}
			_, keyslotsEnd, err := keyslotsAreaBounds(hdr, metadata)
			if err != nil {
				t.Fatalf("keyslotsAreaBounds: %v", err)
			}
			dataOffset := firstDataOffset(metadata)
			payload := bytes.Repeat([]byte("payload!"), 512)
			writeImageAt(t, path, dataOffset, payload)

			v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			if err := v.Erase(context.Background()); err != nil {
				t.Fatalf("header-only Erase failed: %v", err)
			}
			_ = v.Close()

			if _, _, err := readHeaderForTest(path); err == nil {
				t.Error("the primary header still reads after a header-only wipe")
			}
			if _, _, err := readSecondaryHeaderForTest(path); err == nil {
				t.Error("the secondary header still reads after a header-only wipe")
			}
			if code, out := runCryptsetup(t, "", "isLuks", path); code == 0 {
				t.Errorf("cryptsetup still recognizes the container after a header-only wipe\n%s", out)
			}

			// Both copies and the whole keyslots area, and nothing past them.
			if region := readImageAt(t, path, 0, int(keyslotsEnd)); !bytes.Equal(region, make([]byte, len(region))) {
				t.Errorf("the %d bytes holding both copies and the keyslots area are not all zeroes after a header-only wipe", len(region))
			}
			if !bytes.Equal(readImageAt(t, path, dataOffset, len(payload)), payload) {
				t.Error("the header-only wipe reached the data segment")
			}
		})
	}
}

// writeImageAt writes data into the image at offset.
func writeImageAt(t *testing.T, path string, offset int64, data []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the image: %v", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteAt(data, offset); err != nil {
		t.Fatalf("failed to write %d bytes at %d: %v", len(data), offset, err)
	}
}

// TestWipeHeaderOnlyDoesNotTrustADamagedPrimarysSize pins the review finding
// on #47: the primary's declared size is not checksum-verified before a wipe
// sizes itself by it. A 64 KiB-area container whose damaged primary declares
// a smaller LEGAL size (16 KiB) had only 32 KiB zeroed, and the intact
// secondary at 64 KiB survived a "successful" header-only wipe -- so the
// volume was still recoverable from its second copy.
func TestWipeHeaderOnlyDoesNotTrustADamagedPrimarysSize(t *testing.T) {
	defer parallel(t)()

	const size = 64 << 10

	path := newImage(t, "wipe-damaged-primary.img")
	if err := formatForTest(metadataSizeFormatOptions(path, size)); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Rewrite the primary's hdr_size (offset 8, after the 6-byte magic and the
	// 2-byte version) to 16 KiB, leaving its checksum stale.
	f, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the image: %v", err)
	}
	var declared [8]byte
	binary.BigEndian.PutUint64(declared[:], header.HeaderMinSize)
	if _, err := f.WriteAt(declared[:], 8); err != nil {
		_ = f.Close()
		t.Fatalf("failed to damage the primary: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close the image: %v", err)
	}

	// Precondition: the damage leaves the secondary as the recoverable copy.
	if _, _, err := readSecondaryHeaderForTest(path); err != nil {
		t.Fatalf("precondition: the secondary does not read after damaging the primary: %v", err)
	}

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := v.Erase(context.Background()); err != nil {
		t.Fatalf("header-only Erase failed: %v", err)
	}
	_ = v.Close()

	if _, _, err := readHeaderForTest(path); err == nil {
		t.Error("the container still reads after a header-only wipe")
	}
	if _, _, err := readSecondaryHeaderForTest(path); err == nil {
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
	defer parallel(t)()

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

	damageDeclaredSize(t, path, header.PrimaryHeaderOffset, header.HeaderMaxSize)
	if _, _, err := readSecondaryHeaderForTest(path); err != nil {
		t.Fatalf("precondition: the secondary does not read after damaging the primary: %v", err)
	}

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := v.Erase(context.Background()); err != nil {
		t.Fatalf("header-only Erase failed: %v", err)
	}
	_ = v.Close()

	if !bytes.Equal(readImageAt(t, path, dataOffset, len(payload)), payload) {
		t.Error("a header-only wipe destroyed payload because a damaged primary overstated its size")
	}
	if _, _, err := readSecondaryHeaderForTest(path); err == nil {
		t.Error("the secondary header survived a header-only wipe")
	}
	if region := readImageAt(t, path, 0, 2*area); !bytes.Equal(region, make([]byte, len(region))) {
		t.Errorf("the %d-byte region holding both copies is not all zeroes", len(region))
	}
}

// TestWipeHeaderOnlyWithNoValidCopy covers the ambiguous case: every copy is
// damaged, so no geometry can be trusted. The wipe zeroes the default 32 KiB
// front and, of each copy still recognizable as a LUKS2 header -- here the
// damaged secondary of a 64 KiB container -- its binary header and its JSON
// up to the terminating NUL (#246 D3: the JSON carries the keyslot salts, and
// a binary header is cheap to rebuild in front of it). No payload-sized span
// is guessed at: the keyslots area is left alone.
func TestWipeHeaderOnlyWithNoValidCopy(t *testing.T) {
	defer parallel(t)()

	const size = 64 << 10

	path := newImage(t, "wipe-no-valid-copy.img")
	if err := formatForTest(metadataSizeFormatOptions(path, size)); err != nil {
		t.Fatalf("Format failed: %v", err)
	}
	// Primary overstates, secondary's checksum is broken by a JSON byte.
	damageDeclaredSize(t, path, header.PrimaryHeaderOffset, header.HeaderMaxSize)
	f, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the image: %v", err)
	}
	if _, err := f.WriteAt([]byte{'X'}, size+header.HeaderSize); err != nil {
		_ = f.Close()
		t.Fatalf("failed to damage the secondary: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close the image: %v", err)
	}
	keyslots := readImageAt(t, path, 2*size, 4096)

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := v.Erase(context.Background()); err != nil {
		t.Fatalf("header-only Erase failed: %v", err)
	}
	_ = v.Close()

	if front := readImageAt(t, path, 0, 2*header.HeaderMinSize); !bytes.Equal(front, make([]byte, len(front))) {
		t.Error("the default 32 KiB front is not all zeroes")
	}
	if copy2 := readImageAt(t, path, size, size); !bytes.Equal(copy2, make([]byte, len(copy2))) {
		t.Error("the damaged secondary's binary header or JSON is still present")
	}
	if !bytes.Equal(readImageAt(t, path, 2*size, len(keyslots)), keyslots) {
		t.Error("the wipe reached past the header copies into the keyslots area")
	}
}
