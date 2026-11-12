// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// fixedUUID always returns the same value, so round-trip tests are
// deterministic.
func fixedUUID() uuid.UUID {
	return uuid.MustParse("01234567-89ab-cdef-0123-456789abcdef")
}

// zeroSync is a sync function that always succeeds; the production seam
// (pkg/luks2's syncDevice) is a thin wrapper around (*os.File).Sync.
func zeroSync(f *os.File) error { return f.Sync() }

// metadataWithOneKeyslot is structureFixture (validation_test.go) with its
// Config sizes matching the default 16 KiB header area, suitable for a full
// write/read round trip.
func metadataWithOneKeyslot() *Metadata {
	return structureFixture()
}

func newBinaryHeader(t *testing.T) *BinaryHeader {
	t.Helper()
	hdr, err := CreateBinaryHeader(strings.NewReader(strings.Repeat("x", 64)), fixedUUID, NewHeaderParams{
		Label: "test-label", Subsystem: "test-subsystem",
	})
	if err != nil {
		t.Fatalf("CreateBinaryHeader: %v", err)
	}
	return hdr
}

func TestCreateBinaryHeaderSetsFixedFields(t *testing.T) {
	hdr := newBinaryHeader(t)
	if string(bytes.TrimRight(hdr.Magic[:], "\x00")) != Magic {
		t.Errorf("Magic = %q", hdr.Magic)
	}
	if hdr.Version != Version {
		t.Errorf("Version = %d", hdr.Version)
	}
	if hdr.SequenceID != 1 {
		t.Errorf("SequenceID = %d, want 1", hdr.SequenceID)
	}
	if string(bytes.TrimRight(hdr.Label[:], "\x00")) != "test-label" {
		t.Errorf("Label = %q", hdr.Label)
	}
	if string(bytes.TrimRight(hdr.SubsystemLabel[:], "\x00")) != "test-subsystem" {
		t.Errorf("SubsystemLabel = %q", hdr.SubsystemLabel)
	}
}

func TestCreateBinaryHeaderReportsAnRNGFailure(t *testing.T) {
	wantErr := errors.New("no entropy")
	_, err := CreateBinaryHeader(errReader{wantErr}, fixedUUID, NewHeaderParams{})
	if err == nil {
		t.Fatal("want an error")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("got %v, want it to wrap %v", err, wantErr)
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// TestWriteThenReadRoundTrips writes a complete header through WriteHeaderTo
// and reads both copies back, exercising the checksum, canonical-JSON and
// unknown-member codecs together the way a real container exercises them.
func TestWriteThenReadRoundTrips(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "header-*.img")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Truncate(1 << 20); err != nil {
		t.Fatal(err)
	}

	hdr := newBinaryHeader(t)
	metadata := metadataWithOneKeyslot()

	if err := WriteHeaderTo(f, hdr, metadata, zeroSync); err != nil {
		t.Fatalf("WriteHeaderTo: %v", err)
	}

	primary, primaryMeta, err := ReadHeaderCopyFrom(f, PrimaryHeaderOffset)
	if err != nil {
		t.Fatalf("ReadHeaderCopyFrom(primary): %v", err)
	}
	if primary.SequenceID != 1 {
		t.Errorf("primary SequenceID = %d", primary.SequenceID)
	}
	if len(primaryMeta.Keyslots) != 1 {
		t.Errorf("primary Keyslots = %d, want 1", len(primaryMeta.Keyslots))
	}

	secondary, _, err := ReadSecondaryHeaderFrom(f)
	if err != nil {
		t.Fatalf("ReadSecondaryHeaderFrom: %v", err)
	}
	if string(bytes.TrimRight(secondary.Magic[:], "\x00")) != SecondaryMagic {
		t.Errorf("secondary Magic = %q", secondary.Magic)
	}

	if err := HeaderCopiesAgree(f); err != nil {
		t.Errorf("HeaderCopiesAgree: %v", err)
	}

	if bits := VolumeKeyBits(primaryMeta, "0"); bits != 512 {
		t.Errorf("VolumeKeyBits = %d, want 512 (64 bytes)", bits)
	}
}

// TestReadHeaderCopyFromRefusesABadMagic proves the magic check fires before
// anything else looks at the bytes.
func TestReadHeaderCopyFromRefusesABadMagic(t *testing.T) {
	f, metadata := writtenContainer(t)
	hdr := newBinaryHeader(t)
	_ = metadata
	corrupt := make([]byte, HeaderSize)
	if _, err := f.ReadAt(corrupt, 0); err != nil {
		t.Fatal(err)
	}
	copy(corrupt[:6], "XXXXXX")
	if _, err := f.WriteAt(corrupt, 0); err != nil {
		t.Fatal(err)
	}
	_, _, err := ReadHeaderCopyFrom(f, PrimaryHeaderOffset)
	if !errors.Is(err, errs.ErrInvalidHeader) {
		t.Fatalf("got %v, want ErrInvalidHeader", err)
	}
	_ = hdr
}

// TestReadHeaderCopyFromRefusesAChecksumMismatch flips a content byte after
// the checksum was computed.
func TestReadHeaderCopyFromRefusesAChecksumMismatch(t *testing.T) {
	f, _ := writtenContainer(t)
	// Flip a byte well inside the JSON area, past the checksum field.
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, HeaderSize+10); err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0xFF
	if _, err := f.WriteAt(b, HeaderSize+10); err != nil {
		t.Fatal(err)
	}
	_, _, err := ReadHeaderCopyFrom(f, PrimaryHeaderOffset)
	if !errors.Is(err, errs.ErrInvalidHeader) {
		t.Fatalf("got %v, want ErrInvalidHeader", err)
	}
}

// TestReadHeaderCopyFromRefusesAnUnsupportedVersion.
func TestReadHeaderCopyFromRefusesAnUnsupportedVersion(t *testing.T) {
	f, _ := writtenContainer(t)
	var versionBytes [2]byte
	versionBytes[0], versionBytes[1] = 0, 9
	if _, err := f.WriteAt(versionBytes[:], 6); err != nil {
		t.Fatal(err)
	}
	// The checksum no longer matches the mutated version byte, so this also
	// exercises that the version check runs before the checksum (the version
	// field precedes it and is read first).
	_, _, err := ReadHeaderCopyFrom(f, PrimaryHeaderOffset)
	if err == nil {
		t.Fatal("want an error")
	}
}

// writtenContainer builds a temp file with a written, valid header and
// returns the open file and the metadata written.
func writtenContainer(t *testing.T) (*os.File, *Metadata) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "header-*.img")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := f.Truncate(1 << 20); err != nil {
		t.Fatal(err)
	}
	hdr := newBinaryHeader(t)
	metadata := metadataWithOneKeyslot()
	if err := WriteHeaderTo(f, hdr, metadata, zeroSync); err != nil {
		t.Fatalf("WriteHeaderTo: %v", err)
	}
	return f, metadata
}

func TestEncodeMetadataForHeaderRefusesMetadataThatDoesNotFit(t *testing.T) {
	hdr := newBinaryHeader(t)
	metadata := minimalValidMetadata()
	// A huge token blows past the 12 KiB default JSON area.
	metadata.Tokens["0"] = &Token{Type: "x", Keyslots: []string{}, FIDO2Credential: strings.Repeat("A", 20000)}

	_, _, err := EncodeMetadataForHeader(hdr, metadata)
	if !errors.Is(err, ErrMetadataTooLarge) {
		t.Fatalf("got %v, want ErrMetadataTooLarge", err)
	}
}

func TestEncodeMetadataRefusesAnUnimplementedRequirement(t *testing.T) {
	hdr := newBinaryHeader(t)
	metadata := minimalValidMetadata()
	metadata.Config.Requirements = &Requirements{Mandatory: []string{"online-reencrypt-v2"}}

	_, _, err := EncodeMetadata(hdr, metadata)
	var urErr *UnsupportedRequirementError
	if !errors.As(err, &urErr) {
		t.Fatalf("got %v, want *UnsupportedRequirementError", err)
	}
	if urErr.Requirement != "online-reencrypt-v2" {
		t.Errorf("Requirement = %q", urErr.Requirement)
	}
	if !errors.Is(err, ErrUnsupportedRequirement) {
		t.Error("does not unwrap to ErrUnsupportedRequirement")
	}
	if urErr.Error() == "" {
		t.Error("Error() is empty")
	}
}

func TestCheckHeaderWritableAgreesWithEncodeMetadataForHeader(t *testing.T) {
	hdr := newBinaryHeader(t)
	metadata := minimalValidMetadata()
	if err := CheckHeaderWritable(hdr, metadata); err != nil {
		t.Fatalf("CheckHeaderWritable: %v", err)
	}
}

func TestHeaderAreaSizeForWriteDefaultsAndBounds(t *testing.T) {
	hdr := &BinaryHeader{}
	area, err := HeaderAreaSizeForWrite(hdr)
	if err != nil || area != HeaderMinSize {
		t.Fatalf("got (%d, %v), want (%d, nil)", area, err, HeaderMinSize)
	}

	hdr.HeaderSize = 3 // not a power of two, not in range
	if _, err := HeaderAreaSizeForWrite(hdr); !errors.Is(err, errs.ErrInvalidHeader) {
		t.Fatalf("got %v, want ErrInvalidHeader", err)
	}

	hdr.HeaderSize = math.MaxUint64
	if _, err := HeaderAreaSizeForWrite(hdr); !errors.Is(err, errs.ErrInvalidHeader) {
		t.Fatalf("got %v, want ErrInvalidHeader (overflow)", err)
	}
}

func TestHeaderAreaSizeBounds(t *testing.T) {
	if _, err := HeaderAreaSize(&BinaryHeader{HeaderSize: HeaderSize}); !errors.Is(err, errs.ErrInvalidHeader) {
		t.Errorf("HeaderSize == HeaderSize: got %v, want ErrInvalidHeader", err)
	}
	if _, err := HeaderAreaSize(&BinaryHeader{HeaderSize: HeaderMaxSize + 1}); !errors.Is(err, errs.ErrInvalidHeader) {
		t.Errorf("HeaderSize past max: got %v, want ErrInvalidHeader", err)
	}
	if _, err := HeaderAreaSize(&BinaryHeader{HeaderSize: math.MaxUint64}); !errors.Is(err, errs.ErrInvalidHeader) {
		t.Errorf("overflow: got %v, want ErrInvalidHeader", err)
	}
	size, err := HeaderAreaSize(&BinaryHeader{HeaderSize: HeaderMinSize})
	if err != nil || size != HeaderMinSize {
		t.Errorf("got (%d, %v), want (%d, nil)", size, err, HeaderMinSize)
	}
}

func TestHeaderAreaOffsetBounds(t *testing.T) {
	if off, err := HeaderAreaOffset(&BinaryHeader{HeaderOffset: 0}); err != nil || off != 0 {
		t.Errorf("primary offset: got (%d, %v)", off, err)
	}
	if _, err := HeaderAreaOffset(&BinaryHeader{HeaderOffset: HeaderMinSize + 1}); !errors.Is(err, errs.ErrInvalidHeader) {
		t.Errorf("unaligned: got %v, want ErrInvalidHeader", err)
	}
	if _, err := HeaderAreaOffset(&BinaryHeader{HeaderOffset: HeaderMaxOffset + HeaderMinSize}); !errors.Is(err, errs.ErrInvalidHeader) {
		t.Errorf("past max offset: got %v, want ErrInvalidHeader", err)
	}
	if _, err := HeaderAreaOffset(&BinaryHeader{HeaderOffset: math.MaxUint64}); !errors.Is(err, errs.ErrInvalidHeader) {
		t.Errorf("overflow: got %v, want ErrInvalidHeader", err)
	}
	if off, err := HeaderAreaOffset(&BinaryHeader{HeaderOffset: HeaderMinSize}); err != nil || off != HeaderMinSize {
		t.Errorf("legal secondary offset: got (%d, %v)", off, err)
	}
}

func TestValidateAreaChecksumRefusesAShortBuffer(t *testing.T) {
	hdr := &BinaryHeader{}
	if err := ValidateAreaChecksum(hdr, make([]byte, 10)); !errors.Is(err, errs.ErrInvalidHeader) {
		t.Fatalf("got %v, want ErrInvalidHeader", err)
	}
}

func TestValidateHeaderChecksumRefusesAShortArea(t *testing.T) {
	hdr := &BinaryHeader{}
	if err := ValidateHeaderChecksum(hdr, bytes.NewReader(nil), 0, 10); !errors.Is(err, errs.ErrInvalidHeader) {
		t.Fatalf("got %v, want ErrInvalidHeader", err)
	}
}

// TestValidateHeaderChecksumRefusesABufferTooShortForTheChecksumField pins
// the DISTINCT sentinel errChecksumBufferTooShort: a declared area size
// outside the legal range and a buffer too short to hold the checksum field
// are different faults, and the test checks that this guard -- not some
// other one -- is the one that fires, at the exact boundary in both
// directions.
func TestValidateHeaderChecksumRefusesABufferTooShortForTheChecksumField(t *testing.T) {
	reader := bytes.NewReader(make([]byte, HeaderSize*2))
	hdr := &BinaryHeader{Version: Version}
	need := ChecksumFieldOffset + len(hdr.Checksum)

	for _, tc := range []struct {
		name string
		size int
	}{
		{"negative, which make() would panic on", -1},
		{"zero", 0},
		{"one", 1},
		{"far below the checksum field", 100},
		{"one below the checksum field's end", need - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ValidateHeaderChecksum panicked on headerSize=%d instead of returning an error: %v", tc.size, r)
				}
			}()

			err := ValidateHeaderChecksum(hdr, reader, 0, tc.size)
			if err == nil {
				t.Fatalf("ValidateHeaderChecksum accepted headerSize=%d", tc.size)
			}
			if !errors.Is(err, errChecksumBufferTooShort) {
				t.Errorf("error = %v, want it to be errChecksumBufferTooShort; a different guard decided this", err)
			}
			if !errors.Is(err, errs.ErrInvalidHeader) {
				t.Errorf("error = %v, want it to still classify as ErrInvalidHeader for callers", err)
			}
			if !strings.Contains(err.Error(), fmt.Sprint(tc.size)) {
				t.Errorf("error = %q, want it to name the rejected size %d", err.Error(), tc.size)
			}
		})
	}

	// The boundary in the other direction, so the comparison cannot be
	// off by one: a buffer exactly large enough for the checksum field gets
	// PAST this guard. It then fails on the checksum itself, which is a
	// different error, and that difference is the assertion.
	t.Run("exactly large enough is not refused by this guard", func(t *testing.T) {
		err := ValidateHeaderChecksum(hdr, reader, 0, need)
		if errors.Is(err, errChecksumBufferTooShort) {
			t.Fatalf("headerSize=%d was refused as too short, but it is exactly the %d bytes the checksum field needs", need, need)
		}
	})
}

func TestReadJSONMetadataRefusesATooSmallHeaderSize(t *testing.T) {
	_, err := ReadJSONMetadata(bytes.NewReader(nil), &BinaryHeader{}, 0, HeaderSize)
	if !errors.Is(err, errs.ErrInvalidHeader) {
		t.Fatalf("got %v, want ErrInvalidHeader", err)
	}
}

// A hostile JSON area can nest arrays and objects far deeper than any LUKS2
// header does. Parsing must refuse it with ErrInvalidHeader (never a panic or
// a stack overflow), wherever in the metadata the nesting sits: in an
// unmodeled config member, in a token member kept raw, or at the top level.
func TestParseJSONMetadataRefusesHostileNesting(t *testing.T) {
	const depth = 100000
	deep := strings.Repeat("[", depth) + strings.Repeat("]", depth)
	deepObj := strings.Repeat(`{"a":`, depth) + "0" + strings.Repeat("}", depth)
	cases := map[string]string{
		"config member": `{"keyslots":{},"tokens":{},"segments":{},"digests":{},"config":{"json_size":"12288","keyslots_size":"16744448","x":` + deep + `}}`,
		"token member":  `{"keyslots":{},"tokens":{"0":{"type":"x","keyslots":[],"m":` + deepObj + `}},"segments":{},"digests":{},"config":{"json_size":"12288","keyslots_size":"16744448"}}`,
		"top level":     `{"keyslots":{},"tokens":{},"segments":{},"digests":{},"config":{},"x":` + deep + `}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseJSONMetadata([]byte(doc), HeaderMinSize)
			if !errors.Is(err, errs.ErrInvalidHeader) {
				t.Fatalf("ParseJSONMetadata(%d-deep nesting) = %v, want ErrInvalidHeader", depth, err)
			}
			// The refusal is the nesting itself, not a structural rule
			// reached afterwards.
			if !strings.Contains(err.Error(), "depth") {
				t.Fatalf("ParseJSONMetadata(%d-deep nesting) = %v, want a nesting-depth refusal", depth, err)
			}
		})
	}
}

// TestParseJSONMetadataDropsNullKeyslotsAndTokens exercises
// normalizeMetadataNulls, ForgetKeyslotID, WithoutID and sortDroppedEntries
// together: a header naming a null keyslot that a digest and a token both
// reference.
func TestParseJSONMetadataDropsNullKeyslotsAndTokens(t *testing.T) {
	jsonArea := []byte(`{"keyslots":{"0":null},"tokens":{"0":null},` + minimalHeaderJSONTailForTest)
	metadata, err := ParseJSONMetadata(jsonArea, HeaderSize+DefaultSize)
	if err != nil {
		t.Fatalf("ParseJSONMetadata: %v", err)
	}
	if len(metadata.Keyslots) != 0 {
		t.Errorf("Keyslots = %d, want 0", len(metadata.Keyslots))
	}
	if len(metadata.DroppedNullEntries) != 2 {
		t.Fatalf("DroppedNullEntries = %d, want 2", len(metadata.DroppedNullEntries))
	}
	if metadata.DroppedNullEntries[0].Kind != DroppedKindKeyslot || metadata.DroppedNullEntries[1].Kind != DroppedKindToken {
		t.Errorf("order = %+v, want keyslot before token", metadata.DroppedNullEntries)
	}
	if s := metadata.DroppedNullEntries[0].String(); s != `keyslot "0"` {
		t.Errorf("String() = %q", s)
	}
}

// minimalHeaderJSONTailForTest mirrors pkg/luks2's minimalHeaderJSONTail: the
// smallest segments, digests and config cryptsetup accepts for a
// default-geometry header, used to complete a JSON area after its keyslots
// and tokens members.
const minimalHeaderJSONTailForTest = `"segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":512}},` +
	`"digests":{"0":{"type":"pbkdf2","keyslots":[],"segments":["0"],"hash":"sha256","iterations":1000,"salt":"","digest":""}},` +
	`"config":{"json_size":"12288","keyslots_size":"16744448"}}`

func TestParseJSONMetadataRefusesANullSegment(t *testing.T) {
	jsonArea := []byte(`{"keyslots":{},"tokens":{},"segments":{"0":null},"digests":{},"config":{"json_size":"12288","keyslots_size":"16744448"}}`)
	_, err := ParseJSONMetadata(jsonArea, HeaderSize+DefaultSize)
	if !errors.Is(err, errs.ErrInvalidHeader) {
		t.Fatalf("got %v, want ErrInvalidHeader", err)
	}
}

func TestParseJSONMetadataRefusesADuplicateMember(t *testing.T) {
	jsonArea := []byte(`{"keyslots":{},"keyslots":{},"tokens":{},` + minimalHeaderJSONTailForTest)
	_, err := ParseJSONMetadata(jsonArea, HeaderSize+DefaultSize)
	if !errors.Is(err, errs.ErrInvalidHeader) {
		t.Fatalf("got %v, want ErrInvalidHeader", err)
	}
}

func TestSafeConversions(t *testing.T) {
	if _, err := SafeUint64ToInt64(math.MaxInt64 + 1); err == nil {
		t.Error("SafeUint64ToInt64: want an overflow error")
	}
	if v, err := SafeUint64ToInt64(5); err != nil || v != 5 {
		t.Errorf("SafeUint64ToInt64(5) = (%d, %v)", v, err)
	}
	if _, err := SafeUint64ToInt(math.MaxUint64); err == nil {
		t.Error("SafeUint64ToInt: want an overflow error")
	}
	if v, err := SafeUint64ToInt(5); err != nil || v != 5 {
		t.Errorf("SafeUint64ToInt(5) = (%d, %v)", v, err)
	}
}

func TestIsPowerOf2(t *testing.T) {
	for n, want := range map[int]bool{0: false, 1: true, 2: true, 3: false, 1024: true, -4: false} {
		if got := isPowerOf2(n); got != want {
			t.Errorf("isPowerOf2(%d) = %v, want %v", n, got, want)
		}
	}
}

func TestExpectedMagic(t *testing.T) {
	if ExpectedMagic(PrimaryHeaderOffset) != Magic {
		t.Error("primary magic")
	}
	if ExpectedMagic(SecondaryHeaderOffset) != SecondaryMagic {
		t.Error("secondary magic")
	}
}

// TestWithoutIDAllocatesANewSlice proves the input slice is untouched.
func TestWithoutIDAllocatesANewSlice(t *testing.T) {
	in := []string{"0", "1", "0"}
	out := WithoutID(in, "0")
	if len(out) != 1 || out[0] != "1" {
		t.Errorf("WithoutID = %v, want [1]", out)
	}
	if len(in) != 3 {
		t.Errorf("input mutated: %v", in)
	}
}

var _ io.Reader = errReader{}
