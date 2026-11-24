// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// Header-area tests: the area is fixed and metadata that does not fit is refused, never grown over the keyslots.

// keyslotJSONCost is the measured size of one keyslot in the indented JSON this
// package writes. It is used only to choose test sizes that straddle the
// thresholds; the tests assert on observed bytes, not on this number.
const keyslotJSONCost = 514

// padKeyslots adds synthetic, non-overlapping keyslots, each assigned to keyslot 0's digest, until metadata holds n.
func padKeyslots(t *testing.T, metadata *header.Metadata, n int) {
	t.Helper()

	template, ok := metadata.Keyslots["0"]
	if !ok {
		t.Fatal("fixture has no keyslot 0 to clone")
	}
	baseOffset, err := parseSize(template.Area.Offset)
	if err != nil {
		t.Fatalf("keyslot 0 has an unparseable area offset: %v", err)
	}
	slotSize, err := parseSize(template.Area.Size)
	if err != nil {
		t.Fatalf("keyslot 0 has an unparseable area size: %v", err)
	}

	for i := 1; len(metadata.Keyslots) < n; i++ {
		id := strconv.Itoa(i)

		clone := *template
		kdf := *template.KDF
		area := *template.Area
		af := *template.AF
		area.Offset = formatSize(baseOffset + int64(i)*slotSize)
		clone.KDF, clone.Area, clone.AF = &kdf, &area, &af
		metadata.Keyslots[id] = &clone

		for _, digest := range metadata.Digests {
			if slices.Contains(digest.Keyslots, "0") {
				digest.Keyslots = append(digest.Keyslots, id)
			}
		}
	}
}

// jsonAreaBytes returns the JSON bytes stored after the header copy at offset,
// truncated at the terminator, exactly as header.ReadJSONMetadata would see them.
func jsonAreaBytes(t *testing.T, device string, offset int64, jsonSize int) []byte {
	t.Helper()

	f, err := os.Open(device) // #nosec G304 -- device is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the volume: %v", err)
	}
	defer func() { _ = f.Close() }()

	raw := make([]byte, jsonSize)
	if _, err := f.ReadAt(raw, offset+header.HeaderSize); err != nil {
		t.Fatalf("failed to read the JSON area at %d: %v", offset, err)
	}
	if i := bytes.IndexByte(raw, 0); i != -1 {
		raw = raw[:i]
	}
	return raw
}

// TestWriteHeaderKeepsTheBackupOutOfThePrimaryArea writes 16 keyslots and requires a clean header.
func TestWriteHeaderKeepsTheBackupOutOfThePrimaryArea(t *testing.T) {
	defer parallel(t)()

	const keyslots = 16

	device, passphrase := headerSizeVolume(t)

	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	padKeyslots(t, metadata, keyslots)

	// Confirm the fixture's indented JSON crosses 8192 bytes while its canonical encoding still fits.
	indented, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal the fixture: %v", err)
	}
	if len(indented) <= 8192 {
		t.Fatalf("fixture JSON is %d indented bytes, which does not exceed the 8192 at which the old sizing overflowed"+
			" (a keyslot costs about %d bytes; raise the keyslot count)", len(indented), keyslotJSONCost)
	}

	encoded, err := header.MarshalCanonicalJSON(metadata)
	if err != nil {
		t.Fatalf("failed to marshal the fixture: %v", err)
	}
	if len(encoded) >= header.DefaultSize {
		t.Fatalf("fixture JSON is %d bytes, which does not fit the %d-byte area at all;"+
			" this test needs the window where the old code corrupted and the new code succeeds",
			len(encoded), header.DefaultSize)
	}
	t.Logf("fixture: %d keyslots, %d bytes of JSON (%d indented; area %d, JSON area %d)",
		keyslots, len(encoded), len(indented), header.HeaderMinSize, header.DefaultSize)

	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		t.Fatalf("writeHeaderInternal refused metadata that fits: %v", err)
	}

	// The area must still be the legal 16 KiB the container was formatted with.
	if hdr.HeaderSize != header.HeaderMinSize {
		t.Fatalf("HeaderSize = %d after writing %d keyslots, want %d -- the area was resized",
			hdr.HeaderSize, keyslots, header.HeaderMinSize)
	}

	// The primary must still parse, with all its keyslots. Under the old code
	// the backup landed at 16384, inside a 20480-byte primary area, and
	// truncated exactly this.
	_, primary, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("the primary header no longer parses after a large write: %v", err)
	}
	if len(primary.Keyslots) != keyslots {
		t.Errorf("primary header has %d keyslots after writing %d", len(primary.Keyslots), keyslots)
	}

	// The backup must sit at the area size and carry the same JSON.
	secondaryHdr, secondary, err := readSecondaryHeaderForTest(device)
	if err != nil {
		t.Fatalf("the secondary header no longer parses after a large write: %v", err)
	}
	if secondaryHdr.HeaderOffset != header.HeaderMinSize {
		t.Errorf("secondary hdr_offset = %d, want %d", secondaryHdr.HeaderOffset, header.HeaderMinSize)
	}
	if len(secondary.Keyslots) != keyslots {
		t.Errorf("secondary header has %d keyslots after writing %d", len(secondary.Keyslots), keyslots)
	}

	primaryJSON := jsonAreaBytes(t, device, header.PrimaryHeaderOffset, header.DefaultSize)
	secondaryJSON := jsonAreaBytes(t, device, header.HeaderMinSize, header.DefaultSize)
	if !bytes.Equal(primaryJSON, secondaryJSON) {
		t.Errorf("the two header copies carry different JSON (%d vs %d bytes)",
			len(primaryJSON), len(secondaryJSON))
	}

	// config.json_size must describe the area that was actually written.
	if want := formatSize(header.DefaultSize); primary.Config.JSONSize != want {
		t.Errorf("config.json_size = %s, want %s", primary.Config.JSONSize, want)
	}

	// And the volume must still open, which is what the header is for.
	key, err := getMasterKey(device, passphrase, primary, testVolumeSys())
	if err != nil {
		t.Fatalf("the volume no longer opens after a large header write: %v", err)
	}
	mustDestroy(t, key)
}

// TestWriteHeaderRefusesMetadataThatDoesNotFit: a token on a full keyslot set overflows the area and the device is left unchanged.
func TestWriteHeaderRefusesMetadataThatDoesNotFit(t *testing.T) {
	defer parallel(t)()

	const keyslots = MaxKeyslots // 32, the LUKS2 maximum

	device, passphrase := headerSizeVolume(t)

	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	padKeyslots(t, metadata, keyslots)
	// Built by decoding: TPM2 members reach a token only through the passthrough.
	oversized := fmt.Sprintf(`{"type":"systemd-tpm2","keyslots":["0"],"tpm2-blob":%q}`,
		encodeBase64(bytes.Repeat([]byte{0x5A}, header.DefaultSize)))
	var token LegacyToken
	if err := json.Unmarshal([]byte(oversized), &token); err != nil {
		t.Fatalf("building the oversized token: %v", err)
	}
	metadata.Tokens["0"] = &token

	encoded, err := header.MarshalCanonicalJSON(metadata)
	if err != nil {
		t.Fatalf("failed to marshal the fixture: %v", err)
	}
	if len(encoded) < header.DefaultSize {
		t.Fatalf("fixture JSON is %d bytes, which still fits the %d-byte area; this test needs it not to",
			len(encoded), header.DefaultSize)
	}

	// Snapshot both header copies and the start of the keyslot area. The last
	// of those is the one that matters: growing the area to hold this metadata
	// would put the backup header on top of it.
	before := deviceHead(t, device, 2*header.HeaderMinSize+4096)

	err = writeHeaderInternal(device, hdr, metadata)
	if !errors.Is(err, ErrNoSpace) {
		t.Fatalf("writeHeaderInternal(%d bytes of JSON) = %v, want ErrNoSpace", len(encoded), err)
	}
	// The operator has to be able to act on this: which numbers, not just that
	// something did not fit.
	for _, want := range []string{
		strconv.Itoa(len(encoded)),
		strconv.Itoa(header.DefaultSize),
		strconv.Itoa(header.HeaderMinSize),
	} {
		if !bytes.Contains([]byte(err.Error()), []byte(want)) {
			t.Errorf("error %q does not name %s", err.Error(), want)
		}
	}

	after := deviceHead(t, device, 2*header.HeaderMinSize+4096)
	if !bytes.Equal(before, after) {
		t.Fatal("a refused header write still modified the device")
	}

	// The container is untouched, so it still opens.
	_, reread, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed after a refused write: %v", err)
	}
	key, err := getMasterKey(device, passphrase, reread, testVolumeSys())
	if err != nil {
		t.Fatalf("the volume no longer opens after a refused write: %v", err)
	}
	mustDestroy(t, key)
}

// TestWriteHeaderAcceptsTheMaximumKeyslotCount: 32 keyslots fit the 12288-byte area.
func TestWriteHeaderAcceptsTheMaximumKeyslotCount(t *testing.T) {
	defer parallel(t)()

	const keyslots = MaxKeyslots

	device, passphrase := headerSizeVolume(t)

	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	padKeyslots(t, metadata, keyslots)

	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		t.Fatalf("writeHeaderInternal refused the %d keyslots LUKS2 permits: %v", keyslots, err)
	}
	if hdr.HeaderSize != header.HeaderMinSize {
		t.Fatalf("HeaderSize = %d, want %d -- the area was resized to hold the keyslots", hdr.HeaderSize, header.HeaderMinSize)
	}

	_, primary, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("the primary header no longer parses: %v", err)
	}
	if len(primary.Keyslots) != keyslots {
		t.Fatalf("primary header has %d keyslots after writing %d", len(primary.Keyslots), keyslots)
	}
	_, secondary, err := readSecondaryHeaderForTest(device)
	if err != nil {
		t.Fatalf("the secondary header no longer parses: %v", err)
	}
	if len(secondary.Keyslots) != keyslots {
		t.Fatalf("secondary header has %d keyslots after writing %d", len(secondary.Keyslots), keyslots)
	}

	key, err := getMasterKey(device, passphrase, primary, testVolumeSys())
	if err != nil {
		t.Fatalf("the volume no longer opens with a full keyslot complement: %v", err)
	}
	mustDestroy(t, key)
}

// TestWriteHeaderRefusesOversizedTokenMetadata covers the other way the JSON
// grows. A single token can carry an arbitrarily large blob, so the limit is
// reachable without any keyslots at all.
func TestWriteHeaderRefusesOversizedTokenMetadata(t *testing.T) {
	defer parallel(t)()

	device, _ := headerSizeVolume(t)

	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	// Decoded: TPM2 members reach a LegacyToken only through the passthrough.
	oversized := fmt.Sprintf(`{"type":"systemd-tpm2","keyslots":["0"],`+
		`"tpm2-blob":%q,"tpm2-pcrs":[0,7],"tpm2-pcr-bank":"sha256"}`,
		encodeBase64(bytes.Repeat([]byte{0x5A}, header.DefaultSize)))
	var token LegacyToken
	if err := json.Unmarshal([]byte(oversized), &token); err != nil {
		t.Fatalf("building the oversized token: %v", err)
	}
	metadata.Tokens["0"] = &token

	before := deviceHead(t, device, 2*header.HeaderMinSize+4096)

	if err := writeHeaderInternal(device, hdr, metadata); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("writeHeaderInternal(oversized token) = %v, want ErrNoSpace", err)
	}
	if after := deviceHead(t, device, 2*header.HeaderMinSize+4096); !bytes.Equal(before, after) {
		t.Fatal("a refused header write still modified the device")
	}
}

// TestWriteHeaderAcceptsATokenThatFits is the control: the refusal above must
// be about size, not about tokens.
func TestWriteHeaderAcceptsATokenThatFits(t *testing.T) {
	defer parallel(t)()

	device, passphrase := headerSizeVolume(t)

	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	fits := fmt.Sprintf(`{"type":"systemd-tpm2","keyslots":["0"],"tpm2-blob":%q}`,
		encodeBase64(bytes.Repeat([]byte{0x5A}, 1024)))
	var token LegacyToken
	if err := json.Unmarshal([]byte(fits), &token); err != nil {
		t.Fatalf("building the token: %v", err)
	}
	metadata.Tokens["0"] = &token

	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		t.Fatalf("writeHeaderInternal refused a token that fits: %v", err)
	}

	_, reread, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed after writing a token: %v", err)
	}
	if len(reread.Tokens) != 1 {
		t.Fatalf("token count = %d, want 1", len(reread.Tokens))
	}
	if _, _, err := readSecondaryHeaderForTest(device); err != nil {
		t.Fatalf("the secondary header no longer parses after writing a token: %v", err)
	}
	key, err := getMasterKey(device, passphrase, reread, testVolumeSys())
	if err != nil {
		t.Fatalf("the volume no longer opens after writing a token: %v", err)
	}
	mustDestroy(t, key)
}

// deviceHead reads the first n bytes of a device.
func deviceHead(t *testing.T, device string, n int) []byte {
	t.Helper()

	f, err := os.Open(device) // #nosec G304 -- device is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the volume: %v", err)
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, 0); err != nil {
		t.Fatalf("failed to read the head of the volume: %v", err)
	}
	return buf
}

// TestHeaderAreaSizeForWrite: the writer accepts the same power-of-two sizes header.HeaderAreaOffset reads.
func TestHeaderAreaSizeForWrite(t *testing.T) {
	for _, tc := range []struct {
		name   string
		size   uint64
		want   int
		accept bool
	}{
		{"unwritten header defaults to the minimum area", 0, header.HeaderMinSize, true},
		{"the default 16 KiB area", header.HeaderMinSize, header.HeaderMinSize, true},
		{"a 32 KiB area", 2 * header.HeaderMinSize, 2 * header.HeaderMinSize, true},
		{"a 1 MiB area", 1 << 20, 1 << 20, true},
		{"the maximum area", header.HeaderMaxSize, header.HeaderMaxSize, true},

		{"below the minimum", header.HeaderMinSize - 1, 0, false},
		{"the old grown size, not a power of two", 20480, 0, false},
		{"a power of two below the minimum", 8192, 0, false},
		{"above the maximum", header.HeaderMaxSize * 2, 0, false},
		{"the largest uint64", ^uint64(0), 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := header.HeaderAreaSizeForWrite(&header.BinaryHeader{HeaderSize: tc.size})
			switch {
			case tc.accept && err != nil:
				t.Fatalf("header.HeaderAreaSizeForWrite(%d) = error %v, want %d", tc.size, err, tc.want)
			case !tc.accept && err == nil:
				t.Fatalf("header.HeaderAreaSizeForWrite(%d) = %d, want it rejected", tc.size, got)
			case tc.accept && got != tc.want:
				t.Fatalf("header.HeaderAreaSizeForWrite(%d) = %d, want %d", tc.size, got, tc.want)
			case !tc.accept && !errors.Is(err, ErrInvalidHeader):
				t.Fatalf("header.HeaderAreaSizeForWrite(%d) = %v, want it to wrap ErrInvalidHeader", tc.size, err)
			}

			// Every accepted area doubles as a secondary offset, so the read
			// side must accept it there.
			if tc.accept {
				if _, err := header.HeaderAreaOffset(&header.BinaryHeader{HeaderOffset: uint64(got)}); err != nil {
					t.Errorf("the write side would place the secondary copy at %d, which the read side rejects: %v",
						got, err)
				}
			}
		})
	}
}

// TestReadHeaderRefusesAMismatchedHeaderOffset: hdr_offset must match where the copy was read.
func TestReadHeaderRefusesAMismatchedHeaderOffset(t *testing.T) {
	defer parallel(t)()

	device, _ := headerSizeVolume(t)

	// In range for the bound, wrong for the copy it sits in.
	setHeaderOffset(t, device, uint64(header.SecondaryHeaderOffset))

	_, _, err := readHeaderForTest(device)
	if err == nil {
		t.Fatal("ReadHeader accepted a primary header recording hdr_offset 0x4000")
	}
	if !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("error = %v, want it to wrap ErrInvalidHeader", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte(strconv.Itoa(int(header.SecondaryHeaderOffset)))) {
		t.Errorf("error = %q, want it to name the recorded offset", err.Error())
	}
}
