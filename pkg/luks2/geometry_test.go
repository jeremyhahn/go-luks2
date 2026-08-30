// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"os"
	"strconv"
	"testing"
)

// Foreign-geometry tests.
//
// This branch taught the reader to accept containers whose metadata area is
// larger than the 16 KiB this library formats with. Two places still assumed
// the default geometry as a constant, which is the same mistake as the
// hardcoded 0x4000 secondary header offset, and both only misbehave on exactly
// the containers the new support was for:
//
//   - ReadSecondaryHeader fell back to 0x4000 when the primary was unreadable,
//     so recovery -- the only reason that API exists -- was impossible for a
//     container with a larger metadata area.
//   - AddKey placed new keyslots from a hardcoded 0x8000 and bounded them only
//     against the data segment, never against config.keyslots_size, so on a
//     container whose data offset sits past its keyslots area a keyslot could
//     be written into the gap between the two.
//
// The fixtures are written by cryptsetup rather than constructed here, for the
// same reason the conformance suite exists: a container this package builds
// agrees with this package's assumptions by construction.

// foreignGeometry describes a cryptsetup-formatted fixture.
type foreignGeometry struct {
	metadataSize  string // --luks2-metadata-size
	keyslotsSize  string // --luks2-keyslots-size
	dataOffsetSec string // --offset, in 512-byte sectors

	// wantArea and wantKeyslotsSize are what the geometry above must produce,
	// asserted so a change in cryptsetup's interpretation surfaces here rather
	// than as a confusing failure downstream.
	wantArea         uint64
	wantKeyslotsSize int64
}

// newForeignContainer formats an image with cryptsetup using a non-default
// geometry and returns its path.
func newForeignContainer(t *testing.T, name string, geo foreignGeometry) string {
	t.Helper()

	path := newImage(t, name)

	args := []string{
		"luksFormat", "--type", "luks2",
		"--pbkdf", "pbkdf2",
		"--hash", "sha512",
		"--cipher", "aes-xts-plain64",
		"--key-size", "512",
		"--pbkdf-force-iterations", "1000",
		"--luks2-metadata-size", geo.metadataSize,
		"--luks2-keyslots-size", geo.keyslotsSize,
	}
	if geo.dataOffsetSec != "" {
		args = append(args, "--offset", geo.dataOffsetSec)
	}
	args = append(args, "--batch-mode", path)

	if code, out := runCryptsetup(t, conformancePassphrase, args...); code != 0 {
		t.Fatalf("cryptsetup luksFormat exited %d for geometry %+v, want 0\n%s", code, geo, out)
	}

	// Confirm the fixture is the shape the test needs before relying on it.
	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed on the cryptsetup fixture: %v", err)
	}
	if hdr.HeaderSize != geo.wantArea {
		t.Fatalf("fixture header area = %d, want %d", hdr.HeaderSize, geo.wantArea)
	}
	got, err := parseSize(metadata.Config.KeyslotsSize)
	if err != nil {
		t.Fatalf("fixture config.keyslots_size is unparseable: %v", err)
	}
	if got != geo.wantKeyslotsSize {
		t.Fatalf("fixture config.keyslots_size = %d, want %d", got, geo.wantKeyslotsSize)
	}

	return path
}

// TestForeignGeometry_RecoverSecondaryHeaderWithoutThePrimary is the regression
// test for the 0x4000 fallback.
//
// The container has a 32 KiB metadata area -- cryptsetup's
// --luks2-metadata-size is the size of ONE copy -- so its second header copy is
// at 0x8000 and nothing at 0x4000 is a header at all. With the primary destroyed
// there is no way to be told the area size, which is exactly the situation the
// second copy exists for: the offset has to be found, and the old fallback
// looked in one place and gave up.
func TestForeignGeometry_RecoverSecondaryHeaderWithoutThePrimary(t *testing.T) {
	requireCryptsetup(t)

	path := newForeignContainer(t, "foreign-metadata.img", foreignGeometry{
		metadataSize:     "32k",
		keyslotsSize:     "1m",
		wantArea:         0x8000, // --luks2-metadata-size is the PER-COPY area
		wantKeyslotsSize: 1 << 20,
	})

	// Sanity: with the primary intact, the area size is simply read off it.
	if _, _, err := ReadSecondaryHeader(path); err != nil {
		t.Fatalf("ReadSecondaryHeader failed while the primary was intact: %v", err)
	}

	// Destroy the whole primary copy.
	f, err := os.OpenFile(path, os.O_RDWR, 0600) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the fixture: %v", err)
	}
	if _, err := f.WriteAt(make([]byte, 0x8000), 0); err != nil {
		_ = f.Close()
		t.Fatalf("failed to destroy the primary header: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close the fixture: %v", err)
	}

	if _, _, err := ReadHeader(path); err == nil {
		t.Fatal("the primary header still reads after being zeroed; the fixture is not testing recovery")
	}

	hdr, metadata, err := ReadSecondaryHeader(path)
	if err != nil {
		t.Fatalf("ReadSecondaryHeader could not recover a 32 KiB-metadata container with a destroyed primary: %v", err)
	}
	if hdr.HeaderOffset != 0x8000 {
		t.Errorf("recovered secondary hdr_offset = %d, want %d", hdr.HeaderOffset, 0x8000)
	}
	if hdr.HeaderSize != 0x8000 {
		t.Errorf("recovered secondary header size = %d, want %d", hdr.HeaderSize, 0x8000)
	}

	// The recovered metadata has to be usable, not merely parseable.
	key, err := getMasterKey(path, []byte(conformancePassphrase), metadata)
	if err != nil {
		t.Fatalf("the recovered metadata does not open the volume: %v", err)
	}
	clearBytes(key)
}

// TestForeignGeometry_ProbeRejectsEveryWrongOffset is the control on the probe.
//
// Searching a set of offsets is only safe if a candidate that is not really a
// header is refused. With every header copy destroyed, the probe must report
// failure rather than accepting whatever happens to sit at one of the nine
// legal offsets.
func TestForeignGeometry_ProbeRejectsEveryWrongOffset(t *testing.T) {
	requireCryptsetup(t)

	path := newForeignContainer(t, "no-headers.img", foreignGeometry{
		metadataSize:     "32k",
		keyslotsSize:     "1m",
		wantArea:         0x8000, // --luks2-metadata-size is the PER-COPY area
		wantKeyslotsSize: 1 << 20,
	})

	// Wipe both copies: 0..2*area.
	f, err := os.OpenFile(path, os.O_RDWR, 0600) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the fixture: %v", err)
	}
	if _, err := f.WriteAt(make([]byte, 2*0x8000), 0); err != nil {
		_ = f.Close()
		t.Fatalf("failed to destroy the headers: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close the fixture: %v", err)
	}

	_, _, err = ReadSecondaryHeader(path)
	if err == nil {
		t.Fatal("ReadSecondaryHeader found a secondary header on a device with none")
	}
	if !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("error = %v, want it to wrap ErrInvalidHeader", err)
	}
}

// TestLegalHeaderAreaSizes pins the probe's search space.
func TestLegalHeaderAreaSizes(t *testing.T) {
	sizes := legalHeaderAreaSizes()

	if len(sizes) == 0 {
		t.Fatal("no legal header area sizes")
	}
	if sizes[0] != LUKS2HeaderMinSize {
		t.Errorf("first legal size = %d, want %d", sizes[0], LUKS2HeaderMinSize)
	}
	if last := sizes[len(sizes)-1]; last != LUKS2HeaderMaxSize {
		t.Errorf("last legal size = %d, want %d", last, LUKS2HeaderMaxSize)
	}

	// Every entry must be one the writer can emit and the reader will accept as
	// a secondary offset. If those three sets ever diverge, a container becomes
	// writable-but-unrecoverable, or recoverable-but-unwritable.
	for _, size := range sizes {
		if !isPowerOf2(int(size)) {
			t.Errorf("legal size %d is not a power of two", size)
		}
		if _, err := headerAreaSizeForWrite(&LUKS2BinaryHeader{HeaderSize: uint64(size)}); err != nil {
			t.Errorf("the probe searches offset %d, which the writer cannot produce: %v", size, err)
		}
		if _, err := headerAreaOffset(&LUKS2BinaryHeader{HeaderOffset: uint64(size)}); err != nil {
			t.Errorf("the probe searches offset %d, which the reader rejects: %v", size, err)
		}
	}
}

// TestForeignGeometry_AddKeyStaysInsideTheDeclaredKeyslotsArea is the
// regression test for the unbounded keyslot placement.
//
// The fixture is deliberately shaped so the two boundaries disagree: a 1 MiB
// keyslots area starting at 0x10000 ends at 1114112, while the data segment is
// pushed out to 4 MiB. Everything between is space the container has not
// reserved for keyslots. Bounding only against the data segment -- which is all
// AddKey used to do -- lets keyslots be placed there.
//
// MEASURED for this geometry: a keyslot area costs 258048 bytes, so slots land
// at 65536, 323584, 581632 and 839680; the fifth would start at 1097728 and end
// at 1355776, past the 1114112 the container declares and far short of the
// 4194304 where the data begins.
func TestForeignGeometry_AddKeyStaysInsideTheDeclaredKeyslotsArea(t *testing.T) {
	requireCryptsetup(t)

	const (
		keyslotsStart = 0x10000 // 2 x a 32 KiB metadata area
		keyslotsEnd   = 1114112 // keyslotsStart + 1 MiB
		dataOffset    = 4 << 20 // pushed well past the keyslots area
		slotSize      = 258048  // 64-byte key x 4000 AF stripes, 4 KiB aligned
	)

	path := newForeignContainer(t, "foreign-keyslots.img", foreignGeometry{
		metadataSize:     "32k",
		keyslotsSize:     "1m",
		dataOffsetSec:    strconv.Itoa(dataOffset / 512),
		wantArea:         0x8000, // --luks2-metadata-size is the PER-COPY area
		wantKeyslotsSize: 1 << 20,
	})

	// Confirm the fixture really does leave a gap; without it this test proves
	// nothing, because the two boundaries would coincide.
	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	segmentOffset, err := parseSize(metadata.Segments["0"].Offset)
	if err != nil {
		t.Fatalf("fixture segment offset is unparseable: %v", err)
	}
	if segmentOffset != dataOffset {
		t.Fatalf("fixture data offset = %d, want %d", segmentOffset, dataOffset)
	}
	if segmentOffset <= keyslotsEnd {
		t.Fatalf("fixture data offset %d does not sit past the keyslots area end %d;"+
			" the two boundaries must disagree for this test to mean anything", segmentOffset, keyslotsEnd)
	}

	opts := &AddKeyOptions{KDFType: KDFTypePBKDF2, Hash: "sha256", PBKDFIterTime: 1}

	// Fill the declared area. Slot 0 already occupies the first span, so three
	// more fit.
	added := 0
	for i := 0; ; i++ {
		next := []byte("foreign-added-passphrase-" + strconv.Itoa(i))
		err := AddKey(path, []byte(conformancePassphrase), next, opts)
		if err != nil {
			if !errors.Is(err, ErrKeyslotsAreaFull) {
				t.Fatalf("AddKey #%d failed with an unexpected error: %v", i, err)
			}
			t.Logf("AddKey refused after %d additions: %v", added, err)
			break
		}
		added++
		if added > MaxKeyslots {
			t.Fatal("AddKey never ran out of room inside a 1 MiB keyslots area")
		}
	}

	if added == 0 {
		t.Fatal("AddKey refused the very first addition; the bound is too tight")
	}

	// Nothing may have been placed outside the declared area.
	_, metadata, err = ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed after AddKey: %v", err)
	}
	for id, ks := range metadata.Keyslots {
		offset, err := parseSize(ks.Area.Offset)
		if err != nil {
			t.Fatalf("keyslot %s has an unparseable area offset: %v", id, err)
		}
		size, err := parseSize(ks.Area.Size)
		if err != nil {
			t.Fatalf("keyslot %s has an unparseable area size: %v", id, err)
		}
		if offset < keyslotsStart || offset+size > keyslotsEnd {
			t.Errorf("keyslot %s occupies %d..%d, outside the container's declared keyslots area %d..%d",
				id, offset, offset+size, keyslotsStart, keyslotsEnd)
		}
	}

	// cryptsetup must still accept the container, and every passphrase added
	// before the refusal must still work.
	if code, out := runCryptsetup(t, "", "luksDump", path); code != 0 {
		t.Fatalf("cryptsetup luksDump exited %d after AddKey, want 0\n%s", code, out)
	}
	for i := 0; i < added; i++ {
		next := "foreign-added-passphrase-" + strconv.Itoa(i)
		if code, out := runCryptsetup(t, next, "luksOpen", "--test-passphrase", path); code != 0 {
			t.Errorf("cryptsetup rejected added passphrase %d (exit %d)\n%s", i, code, out)
		}
	}
}

// TestKeyslotsAreaBounds reads the area out of a header, which is the whole
// point: neither end may be a constant.
func TestKeyslotsAreaBounds(t *testing.T) {
	for _, tc := range []struct {
		name       string
		headerSize uint64
		config     *Config
		wantStart  int64
		wantEnd    int64
		wantErr    bool
	}{
		{
			name:       "the default 16 KiB geometry",
			headerSize: LUKS2HeaderMinSize,
			config:     &Config{KeyslotsSize: "16744448"},
			wantStart:  0x8000,
			wantEnd:    0x8000 + 16744448,
		},
		{
			name:       "a 32 KiB metadata area moves the start",
			headerSize: 2 * LUKS2HeaderMinSize,
			config:     &Config{KeyslotsSize: "1048576"},
			wantStart:  0x10000,
			wantEnd:    0x10000 + 1048576,
		},
		{
			name:       "a 1 MiB metadata area moves it further",
			headerSize: 1 << 20,
			config:     &Config{KeyslotsSize: "1048576"},
			wantStart:  2 << 20,
			wantEnd:    (2 << 20) + 1048576,
		},
		{
			name:       "no config",
			headerSize: LUKS2HeaderMinSize,
			config:     nil,
			wantErr:    true,
		},
		{
			name:       "unparseable keyslots_size",
			headerSize: LUKS2HeaderMinSize,
			config:     &Config{KeyslotsSize: "lots"},
			wantErr:    true,
		},
		{
			name:       "zero keyslots_size",
			headerSize: LUKS2HeaderMinSize,
			config:     &Config{KeyslotsSize: "0"},
			wantErr:    true,
		},
		{
			name:       "negative keyslots_size",
			headerSize: LUKS2HeaderMinSize,
			config:     &Config{KeyslotsSize: "-4096"},
			wantErr:    true,
		},
		{
			name:       "unusable header size",
			headerSize: 1,
			config:     &Config{KeyslotsSize: "16744448"},
			wantErr:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hdr := &LUKS2BinaryHeader{HeaderSize: tc.headerSize}
			metadata := &LUKS2Metadata{Config: tc.config}

			start, end, err := keyslotsAreaBounds(hdr, metadata)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("keyslotsAreaBounds = %d..%d, want an error", start, end)
				}
				if !errors.Is(err, ErrInvalidHeader) {
					t.Errorf("error = %v, want it to wrap ErrInvalidHeader", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("keyslotsAreaBounds returned %v", err)
			}
			if start != tc.wantStart || end != tc.wantEnd {
				t.Errorf("keyslotsAreaBounds = %d..%d, want %d..%d", start, end, tc.wantStart, tc.wantEnd)
			}
		})
	}
}
