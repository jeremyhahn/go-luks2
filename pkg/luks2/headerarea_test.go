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
)

// Regression tests for the header-area overlap.
//
// writeHeaderInternal used to SIZE THE HEADER AREA FROM THE METADATA:
// `nextPowerOf2(len(jsonData)+1)`, floored at LUKS2DefaultSize, while the
// backup copy was written at a hardcoded 0x4000. Those two disagree the moment
// the JSON outgrows the floor.
//
// MEASURED, marshaling this package's own metadata with MarshalIndent: a
// keyslot costs 514 bytes, and the JSON crosses 8192 bytes at 15 keyslots --
// well inside the 32 LUKS2 permits. At that point nextPowerOf2 jumps to 16384,
// HeaderSize becomes 4096+16384 = 20480, the primary area spans 0..20480, and
// the backup written at 16384 lands INSIDE it and overwrites its own JSON tail.
// 20480 is not a power of two either, so the area size was not a legal LUKS2
// metadata size in the first place.
//
// The fix does not grow the area. It cannot: the keyslots begin at 2 x area and
// the data segment after them, both already fixed on disk, so enlarging the
// area would move the second copy onto whatever follows it -- for this
// library's geometry, the keyslot key material at 0x8000. Every key on the
// device. The area is instead taken as fixed and metadata that does not fit is
// REFUSED.

// keyslotJSONCost is the measured size of one keyslot in the indented JSON this
// package writes. It is used only to choose test sizes that straddle the
// thresholds; the tests assert on observed bytes, not on this number.
const keyslotJSONCost = 514

// padKeyslots adds synthetic keyslots to metadata until it holds n of them.
//
// Each clone gets its OWN area, tiled after keyslot 0's at that keyslot's size.
// Identical offsets would be cheaper to produce but cryptsetup rejects
// overlapping keyslot areas, and these fixtures are handed to cryptsetup: the
// point is a header that is structurally valid and merely large.
//
// Each clone is also registered with the digest that covers keyslot 0. LUKS2
// requires every keyslot to be assigned to exactly one digest -- measured:
// without it cryptsetup reports "Keyslot 1 is not assigned to exactly 1 digest"
// and fails validation -- and it is what AddKey does for a real keyslot.
//
// The cloned key material is of course garbage, which does not matter. Keyslot
// 0 is tried first in ascending scan order and succeeds before any clone is
// reached, and cryptsetup's luksDump does not decrypt keyslots at all.
func padKeyslots(t *testing.T, metadata *LUKS2Metadata, n int) {
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
// truncated at the terminator, exactly as readJSONMetadata would see them.
func jsonAreaBytes(t *testing.T, device string, offset int64, jsonSize int) []byte {
	t.Helper()

	f, err := os.Open(device) // #nosec G304 -- device is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the volume: %v", err)
	}
	defer func() { _ = f.Close() }()

	raw := make([]byte, jsonSize)
	if _, err := f.ReadAt(raw, offset+LUKS2HeaderSize); err != nil {
		t.Fatalf("failed to read the JSON area at %d: %v", offset, err)
	}
	if i := bytes.IndexByte(raw, 0); i != -1 {
		raw = raw[:i]
	}
	return raw
}

// TestWriteHeaderKeepsTheBackupOutOfThePrimaryArea is the core regression test.
//
// It uses 16 keyslots: past the 15 at which the old sizing overflowed the
// 12288-byte JSON area, and short of the 23 at which the metadata genuinely
// stops fitting. In that window the old code silently corrupted the header and
// the new code must write it cleanly.
func TestWriteHeaderKeepsTheBackupOutOfThePrimaryArea(t *testing.T) {
	defer parallel(t)()

	const keyslots = 16

	device, passphrase := headerSizeVolume(t)

	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	padKeyslots(t, metadata, keyslots)

	// Confirm the fixture actually straddles the old threshold. Without this,
	// the test could pass by never reaching the condition it exists to check.
	//
	// TWO ORACLES, TWO QUESTIONS, and they are not interchangeable. The
	// threshold this regression is about is a property of the INDENTED encoding
	// the writer used at the time -- nextPowerOf2(len(indented)+1) crossing 8192
	// is what moved the backup header -- so that measurement stays on
	// MarshalIndent. Whether the fixture FITS is a question about the bytes the
	// writer produces TODAY, which is marshalCanonicalJSON.
	indented, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal the fixture: %v", err)
	}
	if len(indented) <= 8192 {
		t.Fatalf("fixture JSON is %d indented bytes, which does not exceed the 8192 at which the old sizing overflowed"+
			" (a keyslot costs about %d bytes; raise the keyslot count)", len(indented), keyslotJSONCost)
	}

	encoded, err := marshalCanonicalJSON(metadata)
	if err != nil {
		t.Fatalf("failed to marshal the fixture: %v", err)
	}
	if len(encoded) >= LUKS2DefaultSize {
		t.Fatalf("fixture JSON is %d bytes, which does not fit the %d-byte area at all;"+
			" this test needs the window where the old code corrupted and the new code succeeds",
			len(encoded), LUKS2DefaultSize)
	}
	t.Logf("fixture: %d keyslots, %d bytes of JSON (%d indented; area %d, JSON area %d)",
		keyslots, len(encoded), len(indented), LUKS2HeaderMinSize, LUKS2DefaultSize)

	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		t.Fatalf("writeHeaderInternal refused metadata that fits: %v", err)
	}

	// The area must still be the legal 16 KiB the container was formatted with.
	if hdr.HeaderSize != LUKS2HeaderMinSize {
		t.Fatalf("HeaderSize = %d after writing %d keyslots, want %d -- the area was resized",
			hdr.HeaderSize, keyslots, LUKS2HeaderMinSize)
	}

	// The primary must still parse, with all its keyslots. Under the old code
	// the backup landed at 16384, inside a 20480-byte primary area, and
	// truncated exactly this.
	_, primary, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("the primary header no longer parses after a large write: %v", err)
	}
	if len(primary.Keyslots) != keyslots {
		t.Errorf("primary header has %d keyslots after writing %d", len(primary.Keyslots), keyslots)
	}

	// The backup must sit at the area size and carry the same JSON.
	secondaryHdr, secondary, err := ReadSecondaryHeader(device)
	if err != nil {
		t.Fatalf("the secondary header no longer parses after a large write: %v", err)
	}
	if secondaryHdr.HeaderOffset != LUKS2HeaderMinSize {
		t.Errorf("secondary hdr_offset = %d, want %d", secondaryHdr.HeaderOffset, LUKS2HeaderMinSize)
	}
	if len(secondary.Keyslots) != keyslots {
		t.Errorf("secondary header has %d keyslots after writing %d", len(secondary.Keyslots), keyslots)
	}

	primaryJSON := jsonAreaBytes(t, device, LUKS2PrimaryHeaderOffset, LUKS2DefaultSize)
	secondaryJSON := jsonAreaBytes(t, device, LUKS2HeaderMinSize, LUKS2DefaultSize)
	if !bytes.Equal(primaryJSON, secondaryJSON) {
		t.Errorf("the two header copies carry different JSON (%d vs %d bytes)",
			len(primaryJSON), len(secondaryJSON))
	}

	// config.json_size must describe the area that was actually written.
	if want := formatSize(LUKS2DefaultSize); primary.Config.JSONSize != want {
		t.Errorf("config.json_size = %s, want %s", primary.Config.JSONSize, want)
	}

	// And the volume must still open, which is what the header is for.
	key, err := getMasterKey(device, passphrase, primary)
	if err != nil {
		t.Fatalf("the volume no longer opens after a large header write: %v", err)
	}
	mustDestroy(t, key)
}

// TestWriteHeaderRefusesMetadataThatDoesNotFit is the other half: once the
// metadata genuinely exceeds the container's fixed JSON area, the write is
// refused and the device is left exactly as it was. Enlarging the area to make
// it fit would move the second header copy onto the keyslot key material.
//
// HOW THE FIXTURE REACHES THE LIMIT CHANGED, and the change is the point of the
// compact encoding. Under MarshalIndent, 32 keyslots -- the LUKS2 maximum --
// produced 17558 bytes and were refused; the container could not hold the
// keyslot complement the format defines. Compact, the same 32 keyslots fit with
// room to spare (see TestWriteHeaderAcceptsTheMaximumKeyslotCount), so the
// overflow is now reached the way a real header reaches it: a token on top of a
// full set of keyslots.
func TestWriteHeaderRefusesMetadataThatDoesNotFit(t *testing.T) {
	defer parallel(t)()

	const keyslots = LUKS2MaxKeyslots // 32, the LUKS2 maximum

	device, passphrase := headerSizeVolume(t)

	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	padKeyslots(t, metadata, keyslots)
	// Built by DECODING, because the bulk is an unmodeled member: this
	// package stopped modeling TPM2 in #189 and carries such members through
	// the passthrough, so a token big enough to overflow the area has to be
	// constructed the way a real one arrives -- from JSON.
	oversized := fmt.Sprintf(`{"type":"systemd-tpm2","keyslots":["0"],"tpm2-blob":%q}`,
		encodeBase64(bytes.Repeat([]byte{0x5A}, LUKS2DefaultSize)))
	var token Token
	if err := json.Unmarshal([]byte(oversized), &token); err != nil {
		t.Fatalf("building the oversized token: %v", err)
	}
	metadata.Tokens["0"] = &token

	encoded, err := marshalCanonicalJSON(metadata)
	if err != nil {
		t.Fatalf("failed to marshal the fixture: %v", err)
	}
	if len(encoded) < LUKS2DefaultSize {
		t.Fatalf("fixture JSON is %d bytes, which still fits the %d-byte area; this test needs it not to",
			len(encoded), LUKS2DefaultSize)
	}

	// Snapshot both header copies and the start of the keyslot area. The last
	// of those is the one that matters: growing the area to hold this metadata
	// would put the backup header on top of it.
	before := deviceHead(t, device, 2*LUKS2HeaderMinSize+4096)

	err = writeHeaderInternal(device, hdr, metadata)
	if !errors.Is(err, ErrMetadataTooLarge) {
		t.Fatalf("writeHeaderInternal(%d bytes of JSON) = %v, want ErrMetadataTooLarge", len(encoded), err)
	}
	// The operator has to be able to act on this: which numbers, not just that
	// something did not fit.
	for _, want := range []string{
		strconv.Itoa(len(encoded)),
		strconv.Itoa(LUKS2DefaultSize),
		strconv.Itoa(LUKS2HeaderMinSize),
	} {
		if !bytes.Contains([]byte(err.Error()), []byte(want)) {
			t.Errorf("error %q does not name %s", err.Error(), want)
		}
	}

	after := deviceHead(t, device, 2*LUKS2HeaderMinSize+4096)
	if !bytes.Equal(before, after) {
		t.Fatal("a refused header write still modified the device")
	}

	// The container is untouched, so it still opens.
	_, reread, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed after a refused write: %v", err)
	}
	key, err := getMasterKey(device, passphrase, reread)
	if err != nil {
		t.Fatalf("the volume no longer opens after a refused write: %v", err)
	}
	mustDestroy(t, key)
}

// TestWriteHeaderAcceptsTheMaximumKeyslotCount is the behavioral consequence
// of the compact encoding, asserted on a real container rather than on byte
// counts.
//
// LUKS2 defines 32 keyslots. Under MarshalIndent this package could write 22 of
// them into the 12288-byte area and refused the rest -- a container that could
// not hold the complement the format allows, for no reason but whitespace.
// cryptsetup, writing the same metadata through json-c, has never had that
// limit.
func TestWriteHeaderAcceptsTheMaximumKeyslotCount(t *testing.T) {
	defer parallel(t)()

	const keyslots = LUKS2MaxKeyslots

	device, passphrase := headerSizeVolume(t)

	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	padKeyslots(t, metadata, keyslots)

	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		t.Fatalf("writeHeaderInternal refused the %d keyslots LUKS2 permits: %v", keyslots, err)
	}
	if hdr.HeaderSize != LUKS2HeaderMinSize {
		t.Fatalf("HeaderSize = %d, want %d -- the area was resized to hold the keyslots", hdr.HeaderSize, LUKS2HeaderMinSize)
	}

	_, primary, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("the primary header no longer parses: %v", err)
	}
	if len(primary.Keyslots) != keyslots {
		t.Fatalf("primary header has %d keyslots after writing %d", len(primary.Keyslots), keyslots)
	}
	_, secondary, err := ReadSecondaryHeader(device)
	if err != nil {
		t.Fatalf("the secondary header no longer parses: %v", err)
	}
	if len(secondary.Keyslots) != keyslots {
		t.Fatalf("secondary header has %d keyslots after writing %d", len(secondary.Keyslots), keyslots)
	}

	key, err := getMasterKey(device, passphrase, primary)
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

	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	// Decoded rather than constructed, for the reason given at the other
	// oversized-token fixture: TPM2 members are unmodeled (#189) and reach a
	// Token only through the passthrough.
	oversized := fmt.Sprintf(`{"type":"systemd-tpm2","keyslots":["0"],`+
		`"tpm2-blob":%q,"tpm2-pcrs":[0,7],"tpm2-pcr-bank":"sha256"}`,
		encodeBase64(bytes.Repeat([]byte{0x5A}, LUKS2DefaultSize)))
	var token Token
	if err := json.Unmarshal([]byte(oversized), &token); err != nil {
		t.Fatalf("building the oversized token: %v", err)
	}
	metadata.Tokens["0"] = &token

	before := deviceHead(t, device, 2*LUKS2HeaderMinSize+4096)

	if err := writeHeaderInternal(device, hdr, metadata); !errors.Is(err, ErrMetadataTooLarge) {
		t.Fatalf("writeHeaderInternal(oversized token) = %v, want ErrMetadataTooLarge", err)
	}
	if after := deviceHead(t, device, 2*LUKS2HeaderMinSize+4096); !bytes.Equal(before, after) {
		t.Fatal("a refused header write still modified the device")
	}
}

// TestWriteHeaderAcceptsATokenThatFits is the control: the refusal above must
// be about size, not about tokens.
func TestWriteHeaderAcceptsATokenThatFits(t *testing.T) {
	defer parallel(t)()

	device, passphrase := headerSizeVolume(t)

	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	fits := fmt.Sprintf(`{"type":"systemd-tpm2","keyslots":["0"],"tpm2-blob":%q}`,
		encodeBase64(bytes.Repeat([]byte{0x5A}, 1024)))
	var token Token
	if err := json.Unmarshal([]byte(fits), &token); err != nil {
		t.Fatalf("building the token: %v", err)
	}
	metadata.Tokens["0"] = &token

	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		t.Fatalf("writeHeaderInternal refused a token that fits: %v", err)
	}

	_, reread, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed after writing a token: %v", err)
	}
	if len(reread.Tokens) != 1 {
		t.Fatalf("token count = %d, want 1", len(reread.Tokens))
	}
	if _, _, err := ReadSecondaryHeader(device); err != nil {
		t.Fatalf("the secondary header no longer parses after writing a token: %v", err)
	}
	key, err := getMasterKey(device, passphrase, reread)
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

// TestHeaderAreaSizeForWrite pins which area sizes a write will use.
//
// The accepted set is the powers of two LUKS2 admits. It matters that this
// agrees with headerAreaOffset's accepted set on the read side: the secondary
// offset IS the area size, so a writer that emitted a non-power-of-two would
// produce a copy at an offset the reader rejects -- read and write disagreeing
// about the format, which is the failure this branch exists to end.
func TestHeaderAreaSizeForWrite(t *testing.T) {
	for _, tc := range []struct {
		name   string
		size   uint64
		want   int
		accept bool
	}{
		{"unwritten header defaults to the minimum area", 0, LUKS2HeaderMinSize, true},
		{"the default 16 KiB area", LUKS2HeaderMinSize, LUKS2HeaderMinSize, true},
		{"a 32 KiB area", 2 * LUKS2HeaderMinSize, 2 * LUKS2HeaderMinSize, true},
		{"a 1 MiB area", 1 << 20, 1 << 20, true},
		{"the maximum area", LUKS2HeaderMaxSize, LUKS2HeaderMaxSize, true},

		{"below the minimum", LUKS2HeaderMinSize - 1, 0, false},
		{"the old grown size, not a power of two", 20480, 0, false},
		{"a power of two below the minimum", 8192, 0, false},
		{"above the maximum", LUKS2HeaderMaxSize * 2, 0, false},
		{"the largest uint64", ^uint64(0), 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := headerAreaSizeForWrite(&LUKS2BinaryHeader{HeaderSize: tc.size})
			switch {
			case tc.accept && err != nil:
				t.Fatalf("headerAreaSizeForWrite(%d) = error %v, want %d", tc.size, err, tc.want)
			case !tc.accept && err == nil:
				t.Fatalf("headerAreaSizeForWrite(%d) = %d, want it rejected", tc.size, got)
			case tc.accept && got != tc.want:
				t.Fatalf("headerAreaSizeForWrite(%d) = %d, want %d", tc.size, got, tc.want)
			case !tc.accept && !errors.Is(err, ErrInvalidHeader):
				t.Fatalf("headerAreaSizeForWrite(%d) = %v, want it to wrap ErrInvalidHeader", tc.size, err)
			}

			// Every accepted area doubles as a secondary offset, so the read
			// side must accept it there.
			if tc.accept {
				if _, err := headerAreaOffset(&LUKS2BinaryHeader{HeaderOffset: uint64(got)}); err != nil {
					t.Errorf("the write side would place the secondary copy at %d, which the read side rejects: %v",
						got, err)
				}
			}
		})
	}
}

// TestReadHeaderRefusesAMismatchedHeaderOffset covers the pairing check.
//
// The field is attacker-controlled and the caller already knows where it read
// the copy from. A header at offset 0 claiming hdr_offset 0x4000 is in range,
// so the #63 bound alone lets it through; before the pairing check the
// downstream reads would then have taken the field's word for it and paired a
// header with the wrong copy's JSON.
func TestReadHeaderRefusesAMismatchedHeaderOffset(t *testing.T) {
	defer parallel(t)()

	device, _ := headerSizeVolume(t)

	// In range for the bound, wrong for the copy it sits in.
	setHeaderOffset(t, device, uint64(LUKS2SecondaryHeaderOffset))

	_, _, err := ReadHeader(device)
	if err == nil {
		t.Fatal("ReadHeader accepted a primary header recording hdr_offset 0x4000")
	}
	if !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("error = %v, want it to wrap ErrInvalidHeader", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte(strconv.Itoa(int(LUKS2SecondaryHeaderOffset)))) {
		t.Errorf("error = %q, want it to name the recorded offset", err.Error())
	}
}
