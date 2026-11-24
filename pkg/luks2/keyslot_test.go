// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/af"
	"github.com/jeremyhahn/go-luks2/internal/areacipher"
	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

func TestFindAvailableKeyslot(t *testing.T) {
	tests := []struct {
		name          string
		existingSlots []int
		requestedSlot *int
		expectedSlot  int
		expectError   bool
	}{
		{
			name:          "first slot available",
			existingSlots: []int{},
			requestedSlot: nil,
			expectedSlot:  0,
			expectError:   false,
		},
		{
			name:          "slot 0 taken, find next",
			existingSlots: []int{0},
			requestedSlot: nil,
			expectedSlot:  1,
			expectError:   false,
		},
		{
			name:          "multiple slots taken",
			existingSlots: []int{0, 1, 2},
			requestedSlot: nil,
			expectedSlot:  3,
			expectError:   false,
		},
		{
			name:          "request specific available slot",
			existingSlots: []int{0},
			requestedSlot: intPtr(5),
			expectedSlot:  5,
			expectError:   false,
		},
		{
			name:          "request specific taken slot",
			existingSlots: []int{0, 1},
			requestedSlot: intPtr(1),
			expectedSlot:  0,
			expectError:   true,
		},
		{
			name:          "request invalid slot number",
			existingSlots: []int{0},
			requestedSlot: intPtr(32),
			expectedSlot:  0,
			expectError:   true,
		},
		{
			name:          "request negative slot number",
			existingSlots: []int{0},
			requestedSlot: intPtr(-1),
			expectedSlot:  0,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build metadata with existing slots
			metadata := &header.Metadata{
				Keyslots: make(map[string]*header.Keyslot),
			}
			for _, slot := range tt.existingSlots {
				metadata.Keyslots[strconv.Itoa(slot)] = &header.Keyslot{Type: "luks2"}
			}

			opts := &addKeyOptionsForTest{}
			if tt.requestedSlot != nil {
				opts.Keyslot = tt.requestedSlot
			}

			slot, err := findAvailableKeyslot(metadata, opts)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if slot != tt.expectedSlot {
					t.Errorf("expected slot %d, got %d", tt.expectedSlot, slot)
				}
			}
		})
	}
}

func TestCalculateNextKeyslotOffset(t *testing.T) {
	tests := []struct {
		name           string
		keyslotsStart  int64
		keyslots       map[string]*header.Keyslot
		expectedOffset int64
	}{
		{
			name:           "no existing keyslots",
			keyslotsStart:  0x8000,
			keyslots:       map[string]*header.Keyslot{},
			expectedOffset: 0x8000, // 32KB: twice a 16 KiB header area
		},
		{
			// The start is the container's, not this library's. A 32 KiB
			// metadata area puts the keyslots at 0x10000, and an empty
			// container of that shape must place its first keyslot there
			// rather than at the 0x8000 this function used to hardcode.
			name:           "no existing keyslots, 32 KiB metadata area",
			keyslotsStart:  0x10000,
			keyslots:       map[string]*header.Keyslot{},
			expectedOffset: 0x10000,
		},
		{
			name:          "one keyslot",
			keyslotsStart: 0x8000,
			keyslots: map[string]*header.Keyslot{
				"0": {
					Area: &header.KeyslotArea{
						Offset: "32768",  // 0x8000
						Size:   "262144", // 256KB
					},
				},
			},
			expectedOffset: 294912, // 32768 + 262144 = 294912
		},
		{
			name:          "multiple keyslots",
			keyslotsStart: 0x8000,
			keyslots: map[string]*header.Keyslot{
				"0": {
					Area: &header.KeyslotArea{
						Offset: "32768",
						Size:   "262144",
					},
				},
				"1": {
					Area: &header.KeyslotArea{
						Offset: "294912",
						Size:   "262144",
					},
				},
			},
			expectedOffset: 557056, // 294912 + 262144 = 557056
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := &header.Metadata{
				Keyslots: tt.keyslots,
			}

			offset, err := calculateNextKeyslotOffset(metadata, tt.keyslotsStart)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if offset != tt.expectedOffset {
				t.Errorf("expected offset %d, got %d", tt.expectedOffset, offset)
			}
		})
	}
}

func TestMaxKeyslotsConstant(t *testing.T) {
	if MaxKeyslots != 32 {
		t.Errorf("expected MaxKeyslots to be 32, got %d", MaxKeyslots)
	}
}

func TestKeyslotAreaAlignment(t *testing.T) {
	if keyslotAreaAlignment != 4096 {
		t.Errorf("expected keyslotAreaAlignment to be 4096, got %d", keyslotAreaAlignment)
	}
}

// keyslotRemovalPath is one of the four ways to destroy a keyslot, enumerated once so every guard covers all of them.
type keyslotRemovalPath struct {
	name   string
	remove func(device string, passphrase []byte, slot int) error
}

// killKeyslotForTest removes slot unconditionally, the way the pre-redesign
// library's luks2.KillKeyslot did before B.6 renamed it to
// (*luks2.Volume).RemoveKeyslot(ctx, slot).
func killKeyslotForTest(device string, slot int) error {
	v, err := Open(context.Background(), device, withTestSys(testVolumeSys()))
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()
	return v.RemoveKeyslot(context.Background(), slot)
}

// removeKeyForTest and killSlotForTest are in writeheaderpath_test.go (no
// build constraint): lockcompat_integration_test.go and
// lockwait_integration_test.go need them too.

var keyslotRemovalPaths = []keyslotRemovalPath{
	{"RemoveKey", func(device string, passphrase []byte, slot int) error {
		return removeKeyForTest(device, passphrase, slot)
	}},
	{"KillSlot", func(device string, passphrase []byte, slot int) error {
		return killSlotForTest(device, passphrase, slot)
	}},
	{"RemoveKeyslot", func(device string, _ []byte, slot int) error {
		v, err := Open(context.Background(), device, withTestSys(testVolumeSys()))
		if err != nil {
			return err
		}
		defer func() { _ = v.Close() }()
		return v.RemoveKeyslot(context.Background(), slot)
	}},
}

// TestEveryKeyslotRemovalPathRefusesToDestroyTheLastUsableKeyslot: the guard counts openable keyslots, over every path and every unopenableKeyslotShapes shape.
func TestEveryKeyslotRemovalPathRefusesToDestroyTheLastUsableKeyslot(t *testing.T) {
	defer parallel(t)()

	passphrase := []byte(conformancePassphrase)

	for _, shape := range unopenableKeyslotShapes {
		// Formatted once per shape and copied onto a fresh file per path; see goldenSiblingVolume.
		golden := goldenSiblingVolume(t, shape.apply)
		offset, size := keyslotAreaExtent(t, restoreVolume(t, "extent.img", golden), "0")

		for _, path := range keyslotRemovalPaths {
			t.Run(shape.name+"/"+path.name, func(t *testing.T) {
				defer parallel(t)()

				device := restoreVolume(t, "guarded.img", golden)
				before := readAreaBytes(t, device, offset, size)

				err := path.remove(device, passphrase, 0)
				if err == nil {
					t.Fatal("the only keyslot that can open this volume was destroyed, and the call reported success")
				}
				if !errors.Is(err, ErrLastKeyslot) {
					t.Fatalf("the removal was refused for some other reason than the guard: %v", err)
				}

				// The key material must be byte-identical after a refused removal.
				if !bytes.Equal(before, readAreaBytes(t, device, offset, size)) {
					t.Fatal("the removal was refused AND the last usable keyslot's key material was destroyed")
				}
			})
		}

		// And once per shape, end to end: the volume genuinely still opens.
		// Once rather than per path because it costs a full derivation and the
		// per-path claim -- that this path destroyed nothing -- is already made
		// on the bytes above, which is the stronger of the two statements.
		t.Run(shape.name+"/the volume still opens", func(t *testing.T) {
			defer parallel(t)()

			device := restoreVolume(t, "survives.img", golden)
			for _, path := range keyslotRemovalPaths {
				if err := path.remove(device, passphrase, 0); err == nil {
					t.Fatalf("%s destroyed the only keyslot that can open this volume", path.name)
				}
			}
			if err := testKeyForTest(device, passphrase); err != nil {
				t.Fatalf("the volume no longer opens after four REFUSED removals: %v", err)
			}
		})
	}
}

// keyslotAreaExtent reads a keyslot's area range out of a fixture, so a test can
// snapshot the bytes a removal would have destroyed.
func keyslotAreaExtent(t *testing.T, device, id string) (offset, size int64) {
	t.Helper()

	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	keyslot := metadata.Keyslots[id]
	if keyslot == nil || keyslot.Area == nil {
		t.Fatalf("keyslot %s has no area in the fixture", id)
	}
	if offset, err = parseSize(keyslot.Area.Offset); err != nil {
		t.Fatalf("unreadable area offset: %v", err)
	}
	if size, err = parseSize(keyslot.Area.Size); err != nil {
		t.Fatalf("unreadable area size: %v", err)
	}
	return offset, size
}

// TestEveryKeyslotRemovalPathPermitsARemovalThatLeavesASurvivor is the control: a removal leaving a counted survivor succeeds.
func TestEveryKeyslotRemovalPathPermitsARemovalThatLeavesASurvivor(t *testing.T) {
	defer parallel(t)()

	passphrase := []byte(conformancePassphrase)

	golden := goldenSiblingVolume(t, nil)

	for _, path := range keyslotRemovalPaths {
		t.Run(path.name, func(t *testing.T) {
			device := restoreVolume(t, "permitted.img", golden)

			if err := path.remove(device, passphrase, 0); err != nil {
				t.Fatalf("a removal leaving a counted survivor was refused: %v", err)
			}

			_, metadata, err := readHeaderForTest(device)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			if _, present := metadata.Keyslots["0"]; present {
				t.Fatal("the removal reported success and the keyslot is still in the header")
			}
		})
	}
}

// overlappingSiblingVolume gives a container two well-formed keyslots whose areas overlap by shift bytes (0: identical).
func goldenOverlappingVolume(t *testing.T, shift int64) (golden []byte, sharedOffset, sharedSize int64) {
	t.Helper()

	device, sharedOffset, sharedSize := overlappingSiblingVolume(t, "golden-overlap.img", shift)
	return goldenBytes(t, device), sharedOffset, sharedSize
}

func overlappingSiblingVolume(t *testing.T, name string, shift int64) (device string, sharedOffset, sharedSize int64) {
	t.Helper()

	device = newImage(t, name)
	formatWithLibrary(t, device)

	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	original := metadata.Keyslots["0"]
	sharedOffset, err = parseSize(original.Area.Offset)
	if err != nil {
		t.Fatalf("unreadable area offset: %v", err)
	}
	sharedSize, err = parseSize(original.Area.Size)
	if err != nil {
		t.Fatalf("unreadable area size: %v", err)
	}

	sibling := cloneKeyslot(original)
	sibling.Area.Offset = formatSize(sharedOffset + shift)
	metadata.Keyslots[siblingSlotID] = sibling
	for _, digest := range metadata.Digests {
		digest.Keyslots = append(digest.Keyslots, siblingSlotID)
	}

	if err := writeHeaderUnvalidated(device, hdr, metadata); err != nil {
		t.Fatalf("failed to write the overlapping fixture: %v", err)
	}
	return device, sharedOffset, sharedSize
}

// readAreaBytes returns the raw contents of a byte range of the device.
func readAreaBytes(t *testing.T, device string, offset, size int64) []byte {
	t.Helper()

	f, err := os.Open(device)
	if err != nil {
		t.Fatalf("failed to open %s: %v", device, err)
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, size)
	if _, err := f.ReadAt(buf, offset); err != nil {
		t.Fatalf("failed to read %d bytes at %d: %v", size, offset, err)
	}
	return buf
}

// TestRemovingAKeyslotRefusesWhenItsAreaOverlapsAKeyslotThatStillWorks: removal refuses when its wipe would destroy a working slot's material.
func TestRemovingAKeyslotRefusesWhenItsAreaOverlapsAKeyslotThatStillWorks(t *testing.T) {
	defer parallel(t)()

	passphrase := []byte(conformancePassphrase)

	for _, overlap := range []struct {
		name  string
		shift int64
	}{
		{"identical areas", 0},
		// A partial overlap is the case a "same offset" check would miss.
		{"partially overlapping areas", keyslotAreaAlignment},
	} {
		golden, offset, size := goldenOverlappingVolume(t, overlap.shift)

		for _, path := range keyslotRemovalPaths {
			t.Run(overlap.name+"/"+path.name, func(t *testing.T) {
				device := restoreVolume(t, "overlap.img", golden)
				before := readAreaBytes(t, device, offset, size)

				// Slot 0 is removed and slot 1 survives by count, so only the byte-level check can refuse.
				err := path.remove(device, passphrase, 0)
				if err == nil {
					t.Fatal("a keyslot was wiped over another keyslot's key material, and the call reported success")
				}
				if !errors.Is(err, ErrKeyslotAreaOverlap) {
					t.Fatalf("the removal was refused for some other reason than the overlap: %v", err)
				}

				if !bytes.Equal(before, readAreaBytes(t, device, offset, size)) {
					t.Fatal("the removal was refused AND the surviving keyslot's key material was modified")
				}
				if err := testKeyForTest(device, passphrase); err != nil {
					t.Fatalf("the volume no longer opens after a REFUSED removal: %v", err)
				}
			})
		}
	}
}

// TestChangeKeyRefusesToZeroAKeyslotThatStillWorks: ChangeKey takes the byte-level half of the removal gate.
func TestChangeKeyRefusesToZeroAKeyslotThatStillWorks(t *testing.T) {
	defer parallel(t)()

	passphrase := []byte(conformancePassphrase)
	device, offset, size := overlappingSiblingVolume(t, "changekey-overlap.img", 0)
	before := readAreaBytes(t, device, offset, size)

	err := changeKeyForTest(device, passphrase, []byte("a-replacement-credential"), 1)
	if err == nil {
		t.Fatal("ChangeKey zeroed an area another keyslot still needs, and reported success")
	}
	if !errors.Is(err, ErrKeyslotAreaOverlap) {
		t.Fatalf("ChangeKey was refused for some other reason than the overlap: %v", err)
	}
	if !bytes.Equal(before, readAreaBytes(t, device, offset, size)) {
		t.Fatal("ChangeKey was refused AND the overlapping keyslot's key material was modified")
	}
	if err := testKeyForTest(device, passphrase); err != nil {
		t.Fatalf("the volume no longer opens after a REFUSED ChangeKey: %v", err)
	}
}

// TestChangeKeyOnASingleKeyslotVolumeIsStillAllowed pins the asymmetry above.
// A guard that took the entry-level half here would refuse the operation
// ChangeKey exists to perform.
func TestChangeKeyOnASingleKeyslotVolumeIsStillAllowed(t *testing.T) {
	defer parallel(t)()

	device := newImage(t, "changekey-single.img")
	formatWithLibrary(t, device)

	old := []byte(conformancePassphrase)
	updated := []byte("the-replacement-credential")

	if err := changeKeyForTest(device, old, updated, 0); err != nil {
		t.Fatalf("ChangeKey was refused on the one-keyslot volume it exists for: %v", err)
	}
	if err := testKeyForTest(device, updated); err != nil {
		t.Fatalf("the new passphrase does not open the volume: %v", err)
	}
	if err := testKeyForTest(device, old); err == nil {
		t.Fatal("the old passphrase still opens the volume after ChangeKey")
	}
}

// TestChangeKeyWritesTheNewMaterialBeforeDestroyingTheOld: the new material goes to an area disjoint from the old.
func TestChangeKeyWritesTheNewMaterialBeforeDestroyingTheOld(t *testing.T) {
	defer parallel(t)()

	device := newImage(t, "changekey-relocates.img")
	formatWithLibrary(t, device)

	old := []byte(conformancePassphrase)
	updated := []byte("the-replacement-credential")

	_, before, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	oldOffset, err := parseSize(before.Keyslots["0"].Area.Offset)
	if err != nil {
		t.Fatalf("unreadable area offset: %v", err)
	}
	oldSize, err := parseSize(before.Keyslots["0"].Area.Size)
	if err != nil {
		t.Fatalf("unreadable area size: %v", err)
	}

	materialBefore := readAreaBytes(t, device, oldOffset, oldSize)

	if err := changeKeyForTest(device, old, updated, 0); err != nil {
		t.Fatalf("ChangeKey failed: %v", err)
	}

	_, after, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader after ChangeKey failed: %v", err)
	}
	newOffset, err := parseSize(after.Keyslots["0"].Area.Offset)
	if err != nil {
		t.Fatalf("unreadable area offset after ChangeKey: %v", err)
	}
	newSize, err := parseSize(after.Keyslots["0"].Area.Size)
	if err != nil {
		t.Fatalf("unreadable area size after ChangeKey: %v", err)
	}

	if newOffset == oldOffset {
		t.Fatal("ChangeKey rewrote the keyslot in place; there is a window in which the header names material neither passphrase can derive")
	}
	if newOffset < oldOffset+oldSize && oldOffset < newOffset+newSize {
		t.Fatalf("the new area [%d,%d) overlaps the old one [%d,%d), so the write still lands on the material it replaces",
			newOffset, newOffset+newSize, oldOffset, oldOffset+oldSize)
	}
	if newSize != oldSize {
		t.Fatalf("the keyslot area changed size from %d to %d; only its offset should move", oldSize, newSize)
	}

	// The freed area no longer holds the old material; it is filled with random data, not zeroes.
	leftovers := readAreaBytes(t, device, oldOffset, oldSize)
	if bytes.Equal(leftovers, materialBefore) {
		t.Fatal("the old keyslot area still holds key material after ChangeKey")
	}
	if bytes.Equal(leftovers, make([]byte, oldSize)) {
		t.Fatal("the old keyslot area was zeroed; that discloses which slots have been retired")
	}

	if err := testKeyForTest(device, updated); err != nil {
		t.Fatalf("the new passphrase does not open the volume: %v", err)
	}
	if err := testKeyForTest(device, old); err == nil {
		t.Fatal("the old passphrase still opens the volume after ChangeKey")
	}
}

// TestChangeKeyRefusesRatherThanRewriteInPlaceWhenThereIsNoFreeArea: with no free area ChangeKey refuses and leaves the volume unchanged.
func TestChangeKeyRefusesRatherThanRewriteInPlaceWhenThereIsNoFreeArea(t *testing.T) {
	defer parallel(t)()

	device := newImage(t, "changekey-full.img")
	formatWithLibrary(t, device)

	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	offset, err := parseSize(metadata.Keyslots["0"].Area.Offset)
	if err != nil {
		t.Fatalf("unreadable area offset: %v", err)
	}
	size, err := parseSize(metadata.Keyslots["0"].Area.Size)
	if err != nil {
		t.Fatalf("unreadable area size: %v", err)
	}
	start, _, err := keyslotsAreaBounds(hdr, metadata)
	if err != nil {
		t.Fatalf("keyslotsAreaBounds failed: %v", err)
	}
	// Shrink the declared keyslots area to exactly the one slot in use.
	metadata.Config.KeyslotsSize = formatSize(offset + size - start)
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		t.Fatalf("failed to write the full-keyslots-area fixture: %v", err)
	}

	old := []byte(conformancePassphrase)
	before := readAreaBytes(t, device, offset, size)

	err = changeKeyForTest(device, old, []byte("a-replacement-credential"), 0)
	if err == nil {
		t.Fatal("ChangeKey rewrote a keyslot in place when it had nowhere safe to relocate")
	}
	if !errors.Is(err, ErrNoSpace) {
		t.Fatalf("ChangeKey was refused for some other reason: %v", err)
	}
	if !bytes.Equal(before, readAreaBytes(t, device, offset, size)) {
		t.Fatal("ChangeKey was refused AND the keyslot's key material was modified")
	}
	if err := testKeyForTest(device, old); err != nil {
		t.Fatalf("the volume no longer opens with the original passphrase after a REFUSED ChangeKey: %v", err)
	}
}

// TestFindFreeKeyslotAreaReusesGaps pins the gap-reusing allocator ChangeKey depends on.
func TestFindFreeKeyslotAreaReusesGaps(t *testing.T) {
	hdr := &header.BinaryHeader{HeaderSize: header.HeaderMinSize}
	area := func(offset, size int64) *header.Keyslot {
		return &header.Keyslot{
			Type: "luks2",
			Area: &header.KeyslotArea{Offset: formatSize(offset), Size: formatSize(size)},
		}
	}
	const start int64 = 2 * header.HeaderMinSize // where keyslots begin for this geometry

	metadata := func(keyslots map[string]*header.Keyslot, keyslotsSize int64) *header.Metadata {
		return &header.Metadata{
			Keyslots: keyslots,
			Config:   &header.Config{KeyslotsSize: formatSize(keyslotsSize)},
		}
	}

	t.Run("the first fit is the gap, not the end", func(t *testing.T) {
		// Slot 0 relocated forward and left a hole at the start of the area.
		md := metadata(map[string]*header.Keyslot{
			"0": area(start+0x40000, 0x40000),
		}, 0x200000)
		got, err := findFreeKeyslotArea(hdr, md, 0x40000)
		if err != nil {
			t.Fatalf("findFreeKeyslotArea failed: %v", err)
		}
		if got != start {
			t.Fatalf("placed the area at %d, want the hole at %d", got, start)
		}
	})

	t.Run("a gap too small is skipped", func(t *testing.T) {
		md := metadata(map[string]*header.Keyslot{
			"0": area(start+0x1000, 0x40000),
		}, 0x200000)
		got, err := findFreeKeyslotArea(hdr, md, 0x40000)
		if err != nil {
			t.Fatalf("findFreeKeyslotArea failed: %v", err)
		}
		if want := start + 0x41000; got != want {
			t.Fatalf("placed the area at %d, want %d (after the slot in use)", got, want)
		}
	})

	t.Run("no room at all is refused", func(t *testing.T) {
		md := metadata(map[string]*header.Keyslot{
			"0": area(start, 0x40000),
		}, 0x40000)
		if _, err := findFreeKeyslotArea(hdr, md, 0x40000); !errors.Is(err, ErrNoSpace) {
			t.Fatalf("a full keyslots area was not refused: %v", err)
		}
	})

	t.Run("the data segment is a second ceiling", func(t *testing.T) {
		// config.keyslots_size overstates the space available; the encrypted
		// data starts before the area it declares ends.
		md := metadata(map[string]*header.Keyslot{
			"0": area(start, 0x40000),
		}, 0x1000000)
		md.Segments = map[string]*header.Segment{
			"0": {Type: "crypt", Offset: formatSize(start + 0x40000)},
		}
		if _, err := findFreeKeyslotArea(hdr, md, 0x40000); !errors.Is(err, ErrNoSpace) {
			t.Fatalf("a keyslot was placed on top of the encrypted data: %v", err)
		}
	})
}

// heterogeneousVolume gives a container two keyslots disagreeing on key size, the weaker (reduced) one first.
func heterogeneousVolume(t *testing.T, name string) (device string, strongPassphrase []byte) {
	t.Helper()

	device = newImage(t, name)
	formatWithLibrary(t, device)

	strongPassphrase = []byte("the-second-credential")
	if _, err := addKeyForTest(device, []byte(conformancePassphrase), strongPassphrase, &addKeyOptionsForTest{
		KDFType:       kdfTypePBKDF2,
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("AddKey failed while building the fixture: %v", err)
	}

	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Keyslots["0"].KeySize = 32
	metadata.Keyslots["0"].Area.KeySize = 32
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		t.Fatalf("failed to write the heterogeneous fixture: %v", err)
	}
	return device, strongPassphrase
}

// TestAddKeyDerivesTheNewKeyslotsKeySizeFromTheVolumeKey: the new keyslot's size comes from the recovered master key, and the credential opens the volume.
func TestAddKeyDerivesTheNewKeyslotsKeySizeFromTheVolumeKey(t *testing.T) {
	defer parallel(t)()

	device, strong := heterogeneousVolume(t, "heterogeneous.img")
	added := []byte("a-third-credential")

	if _, err := addKeyForTest(device, strong, added, &addKeyOptionsForTest{
		KDFType:       kdfTypePBKDF2,
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("AddKey failed on a container whose keyslots disagree: %v", err)
	}

	if err := testKeyForTest(device, added); err != nil {
		t.Fatalf("AddKey reported success and the credential it added does not open the volume: %v", err)
	}

	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	added2 := metadata.Keyslots["2"]
	if added2 == nil {
		t.Fatal("AddKey reported success and wrote no keyslot 2")
	}
	// 64 is this fixture's real volume key length; the template slot declares 32.
	if added2.KeySize != 64 || added2.Area.KeySize != 64 {
		t.Fatalf("the new keyslot declares key size %d/%d; it took the template's rather than the volume key's",
			added2.KeySize, added2.Area.KeySize)
	}
}

// TestAddKeyslotWithMasterKeyCancelledBeforeWriteLeavesNoPartialKeyslot pins
// the write-transaction rule: ctx is consulted only at
// keyslotWriteStep's boundaries, so a ctx already canceled before the first
// write of a new keyslot stops the operation there, before a byte of key
// material or header reaches the device, and leaves no partial keyslot.
func TestAddKeyslotWithMasterKeyCancelledBeforeWriteLeavesNoPartialKeyslot(t *testing.T) {
	defer parallel(t)()

	device := filepath.Join(t.TempDir(), "volume.img")
	if err := os.WriteFile(device, make([]byte, 32<<20), 0600); err != nil {
		t.Fatalf("failed to create the backing file: %v", err)
	}

	passphrase := []byte("the original credential")
	if err := formatForTest(formatOptionsForTest{
		Device:        device,
		Passphrase:    passphrase,
		KDFType:       kdfTypePBKDF2,
		HashAlgo:      "sha256",
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("Format returned error: %v", err)
	}

	dev := lockedDevice(t, device)
	hdr, metadata, err := dev.readHeader()
	if err != nil {
		t.Fatalf("readHeader: %v", err)
	}
	beforeCount := len(metadata.Keyslots)

	masterKey, _, err := getVolumeKey(context.Background(), dev.reader(), device, passphrase, metadata, dev.sys)
	if err != nil {
		t.Fatalf("getVolumeKey: %v", err)
	}
	defer custody.Release(masterKey)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	slot, err := addKeyslotWithMasterKey(ctx, dev, hdr, metadata, masterKey, []byte("a new credential"),
		&addKeyOptionsForTest{KDFType: kdfTypePBKDF2, Hash: "sha256", PBKDFIterTime: 1}, callerSuppliedCredential)
	if slot != -1 {
		t.Fatalf("addKeyslotWithMasterKey canceled before its write returned slot %d, want -1", slot)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("addKeyslotWithMasterKey canceled before its write = %v, want context.Canceled", err)
	}

	_, after, err := dev.readHeader()
	if err != nil {
		t.Fatalf("readHeader after cancellation: %v", err)
	}
	if len(after.Keyslots) != beforeCount {
		t.Fatalf("a canceled add left %d keyslots on the device, want the original %d (no partial keyslot)",
			len(after.Keyslots), beforeCount)
	}
}

// TestRollBackAddedKeyslotRunsDespiteACancelledCtx pins the rollback rule
// for a keyslot: cleanup that must undo an
// already-written keyslot runs under context.WithoutCancel and is never
// skipped because the ctx that started the operation was canceled.
func TestRollBackAddedKeyslotRunsDespiteACancelledCtx(t *testing.T) {
	defer parallel(t)()

	device := filepath.Join(t.TempDir(), "volume.img")
	if err := os.WriteFile(device, make([]byte, 32<<20), 0600); err != nil {
		t.Fatalf("failed to create the backing file: %v", err)
	}

	passphrase := []byte("the original credential")
	if err := formatForTest(formatOptionsForTest{
		Device:        device,
		Passphrase:    passphrase,
		KDFType:       kdfTypePBKDF2,
		HashAlgo:      "sha256",
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("Format returned error: %v", err)
	}

	dev := lockedDevice(t, device)
	hdr, metadata, err := dev.readHeader()
	if err != nil {
		t.Fatalf("readHeader: %v", err)
	}

	masterKey, _, err := getVolumeKey(context.Background(), dev.reader(), device, passphrase, metadata, dev.sys)
	if err != nil {
		t.Fatalf("getVolumeKey: %v", err)
	}
	defer custody.Release(masterKey)

	slot, err := addKeyslotWithMasterKey(context.Background(), dev, hdr, metadata, masterKey, []byte("to be rolled back"),
		&addKeyOptionsForTest{KDFType: kdfTypePBKDF2, Hash: "sha256", PBKDFIterTime: 1}, callerSuppliedCredential)
	if err != nil {
		t.Fatalf("addKeyslotWithMasterKey: %v", err)
	}
	slotIDStr := strconv.Itoa(slot)
	written := metadata.Keyslots[slotIDStr]
	if written == nil {
		t.Fatalf("keyslot %s was not written", slotIDStr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cause := errors.New("verification failed (simulated)")
	rollbackErr := rollBackAddedKeyslot(ctx, dev, slotIDStr, written, cause)
	if !errors.Is(rollbackErr, cause) {
		t.Fatalf("rollBackAddedKeyslot = %v, want it to carry the original cause", rollbackErr)
	}

	_, after, err := dev.readHeader()
	if err != nil {
		t.Fatalf("readHeader after rollback: %v", err)
	}
	if _, present := after.Keyslots[slotIDStr]; present {
		t.Fatalf("rollBackAddedKeyslot with a canceled ctx left keyslot %s in place instead of rolling it back", slotIDStr)
	}
}

// TestAddKeyAndUnlockRoundTripOnAES192CBCVolume: a hand-built 24-byte master key keyslot, wrapped under a 64-byte area key as cryptsetup --key-size 192 writes it, round-trips.
func TestAddKeyAndUnlockRoundTripOnAES192CBCVolume(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "aes192-cbc.img")
	firstPassphrase := []byte("the-first-credential")
	if err := formatForTest(formatOptionsForTest{
		Device:        path,
		Passphrase:    firstPassphrase,
		Cipher:        "aes",
		CipherMode:    "xts-plain64",
		KeySize:       512,
		HashAlgo:      "sha256",
		SectorSize:    512,
		KDFType:       kdfTypePBKDF2,
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	hdr, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Segments["0"].Encryption = "aes-cbc-essiv:sha256"

	const newKeySize = 24 // AES-192, a cryptsetup --key-size 192 volume
	areaKeySize := areacipher.WritableAreaKeySize(newKeySize)

	rawKey, err := randomBytes(newKeySize, testVolumeSys().cryptoRand)
	if err != nil {
		t.Fatalf("randomBytes failed: %v", err)
	}
	masterKey, err := custody.Adopt("fixture 192-bit master key", rawKey)
	if err != nil {
		t.Fatalf("failed to hold the fixture master key: %v", err)
	}
	defer mustDestroy(t, masterKey)

	// Rewrite keyslot 0 from scratch so calculateNextKeyslotOffset places it
	// at the start of the keyslots area again, as cryptsetup's own first
	// keyslot would be.
	delete(metadata.Keyslots, "0")

	kdf, err := createKDFStrict(formatOptionsForTest{KDFType: kdfTypePBKDF2, HashAlgo: "sha256", PBKDFIterTime: 1}, areaKeySize)
	if err != nil {
		t.Fatalf("CreateKDF failed: %v", err)
	}
	passphraseKey, err := deriveKeyEnclave(context.Background(), firstPassphrase, kdf, areaKeySize, defaultVolumeSys())
	if err != nil {
		t.Fatalf("deriveKeyEnclave failed: %v", err)
	}
	defer mustDestroy(t, passphraseKey)

	afData, err := afCodec(testVolumeSys()).Split(masterKey, af.Params{Stripes: header.AFStripes, Hash: defaultHashAlgo})
	if err != nil {
		t.Fatalf("af Split failed: %v", err)
	}
	defer mustDestroy(t, afData)

	encrypted, err := areacipher.Default().EncryptEnclave(custody, afData, passphraseKey)
	if err != nil {
		t.Fatalf("EncryptEnclave failed: %v", err)
	}
	defer clearBytes(encrypted)
	t.Logf("EncryptEnclave produced %d ciphertext bytes for %d AF-split bytes (afSplitSize=%d)",
		len(encrypted), newKeySize*header.AFStripes, newKeySize*header.AFStripes)

	// The unlock path reads whole sectors of ciphertext, as cryptsetup writes them.
	afSplitSize := newKeySize * header.AFStripes
	wantCiphertextLen := ((afSplitSize + areacipher.SectorSize - 1) / areacipher.SectorSize) * areacipher.SectorSize
	if len(encrypted) != wantCiphertextLen {
		t.Fatalf("EncryptEnclave produced %d ciphertext bytes, want %d (afSplitSize rounded up to a whole %d-byte sector, as cryptsetup writes it)",
			len(encrypted), wantCiphertextLen, areacipher.SectorSize)
	}

	keyslotsStart, keyslotsEnd, err := keyslotsAreaBounds(hdr, metadata)
	if err != nil {
		t.Fatalf("keyslotsAreaBounds failed: %v", err)
	}
	offset, err := calculateNextKeyslotOffset(metadata, keyslotsStart)
	if err != nil {
		t.Fatalf("calculateNextKeyslotOffset failed: %v", err)
	}
	alignedSize := alignTo(int64(len(encrypted)), keyslotAreaAlignment)
	if offset+alignedSize > keyslotsEnd {
		t.Fatalf("the fixture keyslot would end at %d, past the keyslots area end %d", offset+alignedSize, keyslotsEnd)
	}

	func() {
		f, ferr := os.OpenFile(path, os.O_WRONLY, 0o600) // #nosec G304 -- path is under t.TempDir()
		if ferr != nil {
			t.Fatalf("failed to open the image for writing: %v", ferr)
		}
		defer f.Close()
		if _, ferr := f.WriteAt(encrypted, offset); ferr != nil {
			t.Fatalf("failed to write the fixture keyslot area: %v", ferr)
		}
	}()

	priority := 1
	metadata.Keyslots["0"] = &header.Keyslot{
		Type:     "luks2",
		KeySize:  newKeySize,
		Priority: &priority,
		Area: &header.KeyslotArea{
			Type:       "raw",
			KeySize:    areaKeySize,
			Offset:     formatSize(offset),
			Size:       formatSize(alignedSize),
			Encryption: keyslotAreaEncryption,
		},
		KDF: kdf,
		AF: &header.AntiForensic{
			Type:    "luks1",
			Stripes: header.AFStripes,
			Hash:    defaultHashAlgo,
		},
	}

	digestKDF, digestValue, err := createDigest(masterKey, "sha256", testVolumeSys())
	if err != nil {
		t.Fatalf("createDigest failed: %v", err)
	}
	metadata.Digests["0"] = &header.Digest{
		Type:       "pbkdf2",
		Keyslots:   []string{"0"},
		Segments:   []string{"0"},
		Hash:       digestKDF.Hash,
		Iterations: *digestKDF.Iterations,
		Salt:       digestKDF.Salt,
		Digest:     digestValue,
	}

	if err := writeHeaderInternal(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the AES-192-CBC fixture: %v", err)
	}

	if err := testKeyForTest(path, firstPassphrase); err != nil {
		t.Fatalf("the hand-written 192-bit keyslot does not open under its own passphrase: %v", err)
	}

	added := []byte("a-second-credential")
	if _, err := addKeyForTest(path, firstPassphrase, added, &addKeyOptionsForTest{
		KDFType:       kdfTypePBKDF2,
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("AddKey failed on a volume whose AF split is not sector-aligned: %v", err)
	}

	if err := testKeyForTest(path, added); err != nil {
		t.Fatalf("AddKey reported success and the credential it added does not open the volume: %v", err)
	}
}

// shrinkHeaderArea patches the declared header size and checksum, making a header this library reads but will not write.
func shrinkHeaderArea(t *testing.T, device string, area int64) {
	t.Helper()

	f, err := os.OpenFile(device, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("failed to open %s: %v", device, err)
	}
	defer func() { _ = f.Close() }() // failure paths only: success closes, checked, below

	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(area))
	if _, err := f.WriteAt(size[:], 8); err != nil {
		t.Fatalf("failed to patch the header size: %v", err)
	}

	// The checksum covers the whole header area with its own field zeroed --
	// see header.ValidateHeaderChecksum, whose layout this mirrors.
	headerData := make([]byte, area)
	if _, err := f.ReadAt(headerData, 0); err != nil {
		t.Fatalf("failed to read the header area back: %v", err)
	}
	for i := 0; i < 64; i++ {
		headerData[0x1C0+i] = 0
	}
	sum := sha256.Sum256(headerData)
	if _, err := f.WriteAt(sum[:], 0x1C0); err != nil {
		t.Fatalf("failed to restore the header checksum: %v", err)
	}
	// Closed, not fsynced: see stampImagePrefix.
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close the patched header: %v", err)
	}
}

// TestNoRemovalPathDestroysMaterialBeforeProvingTheHeaderWritable: a refused header write leaves the key material byte-identical.
func TestNoRemovalPathDestroysMaterialBeforeProvingTheHeaderWritable(t *testing.T) {
	defer parallel(t)()

	passphrase := []byte(conformancePassphrase)

	// Two keyslots, so the last-keyslot guard permits the removal and the header
	// pre-flight is what has to refuse it.
	golden := goldenSiblingVolume(t, nil)

	for _, path := range keyslotRemovalPaths {
		t.Run(path.name, func(t *testing.T) {
			device := restoreVolume(t, "unwritable-header.img", golden)

			hdr, metadata, err := readHeaderForTest(device)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			offset, err := parseSize(metadata.Keyslots["0"].Area.Offset)
			if err != nil {
				t.Fatalf("unreadable area offset: %v", err)
			}
			size, err := parseSize(metadata.Keyslots["0"].Area.Size)
			if err != nil {
				t.Fatalf("unreadable area size: %v", err)
			}

			shrinkHeaderArea(t, device, header.HeaderSize*2)
			// The secondary too: with only the primary damaged the removal reads
			// the secondary, as cryptsetup does, and rightly goes ahead.
			tearSecondary(t, device, int64(hdr.HeaderSize)) // #nosec G115 -- a legal header area size
			before := readAreaBytes(t, device, offset, size)

			err = path.remove(device, passphrase, 0)
			if err == nil {
				t.Fatal("a removal succeeded on a container whose header cannot be written")
			}
			if !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("the removal failed for some other reason than the unwritable header: %v", err)
			}

			if !bytes.Equal(before, readAreaBytes(t, device, offset, size)) {
				t.Fatal("the removal was refused AND the key material was already destroyed")
			}
		})
	}
}

// TestLegacyMislabeledKeyslotIsRefusedAndLeftAlone: XTS material under a CBC label is refused, AddKey refuses too, and nothing is written.
func TestLegacyMislabeledKeyslotIsRefusedAndLeftAlone(t *testing.T) {
	defer parallel(t)()

	device := newImage(t, "legacy-area-cipher.img")
	formatWithLibrary(t, device)

	// Precondition: the unmodified container opens, so the refusal below is
	// about the label and not a broken fixture.
	if err := testKeyForTest(device, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("control: the unmodified fixture does not open: %v", err)
	}

	// The legacy shape, written directly because Format does not produce it.
	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Keyslots["0"].Area.Encryption = "aes-cbc-essiv:sha256"
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		t.Fatalf("failed to write the legacy fixture: %v", err)
	}
	before := readAreaBytes(t, device, 0, goldenPrefixBytes)

	// The declared CBC is what is run now that CBC areas are implemented, and
	// its 64-byte area key cannot key AES-CBC: the keyslot is refused as
	// invalid, before any derivation and without decrypting it as XTS.
	if err := testKeyForTest(device, []byte(conformancePassphrase)); !errors.Is(err, ErrKeyslotNotFound) {
		t.Fatalf("TestKey on XTS material declared as CBC: got %v, want ErrInvalidKeyslot", err)
	}

	if slot, err := addKeyForTest(device, []byte(conformancePassphrase), []byte("a-second-credential"), &addKeyOptionsForTest{
		KDFType:       kdfTypePBKDF2,
		PBKDFIterTime: 1,
	}); err == nil {
		t.Fatalf("AddKey on a mislabeled container wrote slot %d", slot)
	}

	if !bytes.Equal(before, readAreaBytes(t, device, 0, goldenPrefixBytes)) {
		t.Fatal("a refused AddKey changed the container; a refusal must write nothing")
	}
}

// TestFormatDeclaresTheKeyslotAreaCipherItActuallyUses: Format declares AES-XTS for the keyslot area whatever the data cipher.
func TestFormatDeclaresTheKeyslotAreaCipherItActuallyUses(t *testing.T) {
	defer parallel(t)()

	device := newImage(t, "format-cbc-data.img")

	// A non-XTS data cipher; the keyslot area still declares what wraps the key material.
	if err := formatForTest(formatOptionsForTest{
		Device:        device,
		Passphrase:    []byte(conformancePassphrase),
		Cipher:        "aes",
		CipherMode:    "cbc-essiv:sha256",
		KeySize:       256, // CBC-ESSIV takes one AES key; there is no 512-bit form
		HashAlgo:      "sha512",
		SectorSize:    512,
		KDFType:       kdfTypePBKDF2,
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	if got := metadata.Keyslots["0"].Area.Encryption; got != keyslotAreaEncryption {
		t.Fatalf("the keyslot area declares %q; the material is %s and nothing else", got, keyslotAreaEncryption)
	}

	// The caller's choice still reaches the data segment.
	if got := metadata.Segments["0"].Encryption; got != "aes-cbc-essiv:sha256" {
		t.Fatalf("the data segment declares %q, want the caller's aes-cbc-essiv:sha256", got)
	}

	// And the container is still fully usable: it opens, and AddKey can
	// template off it rather than refusing a slot this library just wrote.
	if err := testKeyForTest(device, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("the volume does not open: %v", err)
	}
	if _, err := addKeyForTest(device, []byte(conformancePassphrase), []byte("a-second-credential"), &addKeyOptionsForTest{
		KDFType:       kdfTypePBKDF2,
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("AddKey refused a template this library itself wrote: %v", err)
	}
	if err := testKeyForTest(device, []byte("a-second-credential")); err != nil {
		t.Fatalf("the added credential does not open the volume: %v", err)
	}
}

// TestEveryKeyslotRemovalPathAdvancesTheSequenceID: every removal path advances the sequence id; Format, WriteHeader and RestorePrimaryHeader are excluded by design.
func TestEveryKeyslotRemovalPathAdvancesTheSequenceID(t *testing.T) {
	defer parallel(t)()

	passphrase := []byte(conformancePassphrase)
	golden := goldenSiblingVolume(t, nil)

	for _, path := range keyslotRemovalPaths {
		t.Run(path.name, func(t *testing.T) {
			device := restoreVolume(t, "sequence.img", golden)

			before, _, err := readHeaderForTest(device)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}

			if err := path.remove(device, passphrase, 0); err != nil {
				t.Fatalf("the removal was refused: %v", err)
			}

			// Read back from the device, not the in-memory header.
			after, _, err := readHeaderForTest(device)
			if err != nil {
				t.Fatalf("ReadHeader after the removal failed: %v", err)
			}

			if after.SequenceID <= before.SequenceID {
				t.Fatalf("the persisted sequence id went %d -> %d; two header copies could now carry different metadata at the same version, and a reader could not tell which is current",
					before.SequenceID, after.SequenceID)
			}
		})
	}
}

// TestAddKeyOptionsDoesNotSilentlyDiscardANegativeArgon2Cost: a negative Argon2 cost reaches validation instead of becoming the default.
func TestAddKeyOptionsDoesNotSilentlyDiscardANegativeArgon2Cost(t *testing.T) {
	for _, tc := range []struct {
		field string
		opts  addKeyOptionsForTest
		got   func(formatOptionsForTest) int
		deflt int
	}{
		{"Argon2Time", addKeyOptionsForTest{Argon2Time: -1}, func(f formatOptionsForTest) int { return f.Argon2Time }, 4},
		{"Argon2Memory", addKeyOptionsForTest{Argon2Memory: -1}, func(f formatOptionsForTest) int { return f.Argon2Memory }, 1048576},
		{"Argon2Parallel", addKeyOptionsForTest{Argon2Parallel: -1}, func(f formatOptionsForTest) int { return f.Argon2Parallel }, 4},
	} {
		t.Run(tc.field, func(t *testing.T) {
			opts := tc.opts
			formatOpts, _ := addKeyFormatOptions(&opts, nil, fips.Probe)
			got := tc.got(formatOpts)
			if got == tc.deflt {
				t.Fatalf("%s: -1 was discarded and the default %d used instead. The caller passed a "+
					"value and the library ignored it without saying so (#112).", tc.field, tc.deflt)
			}
			if got != -1 {
				t.Fatalf("%s = %d, want the caller's -1 carried through to where it can be refused", tc.field, got)
			}
		})
	}
}

// TestZeroStillMeansUseTheDefault is the control. `!= 0` must not turn an
// unset field into a propagated zero, or every caller using AddKeyOptions{}
// would get a KDF with zero cost.
func TestZeroStillMeansUseTheDefault(t *testing.T) {
	f, _ := addKeyFormatOptions(&addKeyOptionsForTest{}, nil, fips.Probe)
	if f.Argon2Time != 4 || f.Argon2Memory != 1048576 || f.Argon2Parallel != 4 {
		t.Fatalf("an unset AddKeyOptions no longer yields the defaults: time=%d memory=%d parallel=%d",
			f.Argon2Time, f.Argon2Memory, f.Argon2Parallel)
	}
}

// argon2Derivations is every function that converts a signed KDF cost to uint32 and calls x/crypto/argon2; the tests below are tables over it.
var argon2Derivations = map[string]func([]byte, []byte, *header.KDF, int) ([]byte, error){
	"deriveArgon2i":  deriveArgon2i,
	"deriveArgon2id": deriveArgon2id,
}

// aboveUint32 returns a value above MaxUint32 and true where an int can hold one, false on 32-bit.
func aboveUint32() int {
	if strconv.IntSize > 32 {
		// Via a variable, so the conversion is a runtime one and still builds on 32-bit targets.
		v := uint64(math.MaxUint32) + 4
		return int(v)
	}
	return math.MaxInt
}

func canExceedUint32() bool { return strconv.IntSize > 32 }

// TestAboveUint32AgreesWithCanExceedUint32 pins the invariant the tables rely on, on every architecture.
func TestAboveUint32AgreesWithCanExceedUint32(t *testing.T) {
	over := uint64(aboveUint32()) > math.MaxUint32
	if over != canExceedUint32() {
		t.Fatalf("canExceedUint32() = %v but aboveUint32() = %d %s MaxUint32 -- the tables gate on "+
			"the first and pass the second, so they must agree",
			canExceedUint32(), aboveUint32(), map[bool]string{true: ">", false: "<="}[over])
	}
	if !canExceedUint32() && uint64(aboveUint32()) > math.MaxUint32 {
		t.Fatal("a 32-bit platform produced a value above MaxUint32, which no int there can hold")
	}
}

// TestEveryArgon2DerivationRefusesACostItCannotRepresent: negative costs (which wrap) and over-range costs (which truncate) are refused.
func TestEveryArgon2DerivationRefusesACostItCannotRepresent(t *testing.T) {
	if len(argon2Derivations) < 2 {
		t.Fatalf("argon2Derivations has %d entries; both derivations must be covered",
			len(argon2Derivations))
	}

	neg := -1
	big := aboveUint32()
	ok := 4
	mem := 1048576

	type costCase struct {
		name string
		kdf  header.KDF
	}

	// Over-range cases are appended only where an int can exceed MaxUint32.
	cases := []costCase{
		{"negative time", header.KDF{Time: &neg, Memory: &mem, CPUs: &ok}},
		{"negative memory", header.KDF{Time: &ok, Memory: &neg, CPUs: &ok}},
		{"negative cpus", header.KDF{Time: &ok, Memory: &mem, CPUs: &neg}},
	}
	if canExceedUint32() {
		cases = append(cases,
			costCase{"time above MaxUint32", header.KDF{Time: &big, Memory: &mem, CPUs: &ok}},
			costCase{"memory above MaxUint32", header.KDF{Time: &ok, Memory: &big, CPUs: &ok}},
		)
	}

	for fname, derive := range argon2Derivations {
		for _, tc := range cases {
			t.Run(fname+"/"+tc.name, func(t *testing.T) {
				kdf := tc.kdf
				if _, err := derive([]byte("pass"), []byte("saltsaltsaltsalt"), &kdf, 32); err == nil {
					t.Fatalf("%s accepted a %s -- uint32 changes the value rather than refusing it",
						fname, tc.name)
				}
			})
		}
	}
}

// TestANegativeCostIsRefusedAsTooSmallNotTooLarge pins the guard order by asserting the refusal reason.
func TestANegativeCostIsRefusedAsTooSmallNotTooLarge(t *testing.T) {
	neg := -1
	ok := 4
	mem := 1048576

	for fname, derive := range argon2Derivations {
		for _, tc := range []struct {
			name string
			kdf  header.KDF
		}{
			{"time", header.KDF{Time: &neg, Memory: &mem, CPUs: &ok}},
			{"memory", header.KDF{Time: &ok, Memory: &neg, CPUs: &ok}},
		} {
			t.Run(fname+"/"+tc.name, func(t *testing.T) {
				kdf := tc.kdf
				_, err := derive([]byte("pass"), []byte("saltsaltsaltsalt"), &kdf, 32)
				if err == nil {
					t.Fatalf("%s accepted a negative %s cost", fname, tc.name)
				}
				if strings.Contains(err.Error(), "can represent") {
					t.Fatalf("%s refused a NEGATIVE %s cost as though it were too large: %v\n"+
						"The representable-range check ran before the floor -- uint64(-1) is "+
						"enormous, so the diagnosis points at the wrong end of the range.",
						fname, tc.name, err)
				}
			})
		}
	}
}

// TestEveryArgon2DerivationRefusesAKeySizeItCannotRepresent: a key size above uint32 is refused, not truncated.
func TestEveryArgon2DerivationRefusesAKeySizeItCannotRepresent(t *testing.T) {
	time, mem, cpus := 1, 8, 1

	for fname, derive := range argon2Derivations {
		type sizeCase struct {
			name       string
			keySize    int
			wantReason string
		}
		sizes := []sizeCase{{"negative", -1, "must not be negative"}}
		if canExceedUint32() {
			// Same reason as the cost table: on 32-bit this value clamps to
			// MaxInt, which the guard accepts, and argon2 would be asked to
			// allocate a ~2 GiB key.
			sizes = append(sizes, sizeCase{"above MaxUint32", aboveUint32(), "can represent"})
		}

		for _, tc := range sizes {
			t.Run(fname+"/"+tc.name, func(t *testing.T) {
				kdf := header.KDF{Time: &time, Memory: &mem, CPUs: &cpus}
				key, err := derive([]byte("pass"), []byte("saltsaltsaltsalt"), &kdf, tc.keySize)
				if err == nil {
					t.Fatalf("%s accepted a %s key size and returned %d bytes -- the caller asked "+
						"for %d and received a key it did not request, with no error",
						fname, tc.name, len(key), tc.keySize)
				}
				// Assert the reason: a negative is also caught by the maximum check, so only the message distinguishes the branches.
				if !strings.Contains(err.Error(), tc.wantReason) {
					t.Errorf("%s refused a %s key size for the wrong stated reason: %v\n"+
						"want a message containing %q", fname, tc.name, err, tc.wantReason)
				}
			})
		}
	}
}

// TestEveryArgon2DerivationAcceptsOrdinaryCosts is the control. Without it a
// derivation that refused everything would pass every case above.
func TestEveryArgon2DerivationAcceptsOrdinaryCosts(t *testing.T) {
	defer parallel(t)()

	time, mem, cpus := 4, 65536, 4
	for fname, derive := range argon2Derivations {
		t.Run(fname, func(t *testing.T) {
			kdf := header.KDF{Time: &time, Memory: &mem, CPUs: &cpus}
			if _, err := derive([]byte("pass"), []byte("saltsaltsaltsalt"), &kdf, 32); err != nil {
				t.Fatalf("%s refused an ordinary cost set: %v", fname, err)
			}
		})
	}
}

// TestKeyslotPlacementRefusesAnUnreadableSiblingExtent: AddKey and ChangeKey placement refuse a keyslot whose area does not parse, instead of skipping it.
func TestKeyslotPlacementRefusesAnUnreadableSiblingExtent(t *testing.T) {
	hdr := &header.BinaryHeader{HeaderSize: header.HeaderMinSize}
	const start int64 = 2 * header.HeaderMinSize

	good := &header.Keyslot{Type: "luks2", Area: &header.KeyslotArea{Offset: formatSize(start), Size: formatSize(0x40000)}}
	md := func(ks map[string]*header.Keyslot) *header.Metadata {
		return &header.Metadata{Keyslots: ks, Config: &header.Config{KeyslotsSize: formatSize(0x200000)}}
	}

	// Positive control first, so a function refusing everything fails.
	t.Run("an ordinary container still places a keyslot", func(t *testing.T) {
		m := md(map[string]*header.Keyslot{"0": good})
		if _, err := calculateNextKeyslotOffset(m, start); err != nil {
			t.Fatalf("calculateNextKeyslotOffset on a healthy container = %v, want success", err)
		}
		if _, err := findFreeKeyslotArea(hdr, m, 0x40000); err != nil {
			t.Fatalf("findFreeKeyslotArea on a healthy container = %v, want success", err)
		}
	})

	for _, tc := range []struct {
		name string
		bad  *header.Keyslot
	}{
		{"an unparseable area offset", &header.Keyslot{Type: "luks2", Area: &header.KeyslotArea{Offset: "not-a-size", Size: formatSize(0x40000)}}},
		{"an unparseable area size", &header.Keyslot{Type: "luks2", Area: &header.KeyslotArea{Offset: formatSize(start), Size: "enormous"}}},
	} {
		t.Run(tc.name+" is refused by AddKey's placement", func(t *testing.T) {
			m := md(map[string]*header.Keyslot{"0": good, "3": tc.bad})
			_, err := calculateNextKeyslotOffset(m, start)
			if err == nil {
				t.Fatal("calculateNextKeyslotOffset accepted a sibling whose extent it could not read -- " +
					"AddKey would place new key material without knowing where that keyslot ends")
			}
			if !errors.Is(err, ErrInvalidHeader) {
				t.Errorf("errors.Is(err, ErrInvalidHeader) = false for %v", err)
			}
			// The offending keyslot must be named: an operator has to know
			// which one to look at.
			if !strings.Contains(err.Error(), "keyslot 3") {
				t.Errorf("error %q does not name the offending keyslot", err)
			}
		})

		t.Run(tc.name+" is refused by ChangeKey's allocator", func(t *testing.T) {
			m := md(map[string]*header.Keyslot{"0": good, "3": tc.bad})
			_, err := findFreeKeyslotArea(hdr, m, 0x40000)
			if err == nil {
				t.Fatal("findFreeKeyslotArea accepted a sibling whose extent it could not read -- " +
					"ChangeKey would relocate over that keyslot's real bytes")
			}
			if !errors.Is(err, ErrInvalidHeader) {
				t.Errorf("errors.Is(err, ErrInvalidHeader) = false for %v", err)
			}
		})
	}

	// A declared empty extent parsed and occupies nothing; it is accepted.
	t.Run("a zero-size area is not an unreadable one", func(t *testing.T) {
		m := md(map[string]*header.Keyslot{
			"0": good,
			"3": {Type: "luks2", Area: &header.KeyslotArea{Offset: formatSize(start + 0x100000), Size: formatSize(0)}},
		})
		if _, err := findFreeKeyslotArea(hdr, m, 0x40000); err != nil {
			t.Fatalf("findFreeKeyslotArea refused a zero-size extent: %v", err)
		}
	})
}

// TestCanonicalKeyslotID pins addressability as cryptsetup 2.7.0 behaves: "31" is listed, "32" is not, and non-canonical spellings fail the round trip.
func TestCanonicalKeyslotID(t *testing.T) {
	for _, tc := range []struct {
		key    string
		id     int
		wantOK bool
	}{
		{"0", 0, true},
		{"7", 7, true},
		{"31", 31, true},   // cryptsetup: listed
		{"32", 0, false},   // cryptsetup: header valid, keyslot omitted
		{"1000", 0, false}, // cryptsetup: header valid, keyslot omitted
		{"007", 0, false},  // cryptsetup: "not a valid LUKS device"
		{"+3", 0, false},   // cryptsetup: "not a valid LUKS device"
		{"-1", 0, false},   // cryptsetup: "not a valid LUKS device"
		{" 1", 0, false},
		{"", 0, false},
		{"reencrypt-in-progress", 0, false}, // cryptsetup: "not a valid LUKS device"
	} {
		id, ok := header.CanonicalKeyslotID(tc.key)
		if ok != tc.wantOK {
			t.Errorf("header.CanonicalKeyslotID(%q) ok = %v, want %v", tc.key, ok, tc.wantOK)
			continue
		}
		if ok && id != tc.id {
			t.Errorf("header.CanonicalKeyslotID(%q) = %d, want %d", tc.key, id, tc.id)
		}
	}
}

// TestKeyslotEntryPointsRefuseInvalidInputBeforeWriting covers the front door
// of every keyslot operation: an unusable path, a passphrase too short to be
// one, a keyslot number outside the header's range, and a device that holds no
// LUKS2 header. Each is refused with its own error, and -- the property that
// matters on the destructive ones -- the device is byte-identical afterwards.
func TestKeyslotEntryPointsRefuseInvalidInputBeforeWriting(t *testing.T) {
	defer parallel(t)()

	good := []byte(conformancePassphrase)
	short := []byte("short")
	other := []byte("a-different-credential")

	// A new credential too short for the policy and an existing one that opens nothing are refused differently.
	type call func(device string) error
	type refusal struct {
		call call
		want error
	}
	newTooShort := func(c call) refusal { return refusal{c, ErrInvalidCredential} }
	existingEmpty := func(c call) refusal { return refusal{c, ErrInvalidCredential} }
	entryPoints := map[string]struct {
		valid        call
		passphrases  []refusal // each with exactly one passphrase argument refused
		keyslotRange []call    // each with exactly one keyslot number out of range
	}{
		"TestKey": {
			valid:       func(d string) error { return testKeyForTest(d, good) },
			passphrases: []refusal{existingEmpty(func(d string) error { return testKeyForTest(d, nil) })},
		},
		"AddKey": {
			valid: func(d string) error { _, err := addKeyForTest(d, good, other, fipsSafeAddKeyOptions()); return err },
			passphrases: []refusal{
				existingEmpty(func(d string) error { _, err := addKeyForTest(d, nil, other, fipsSafeAddKeyOptions()); return err }),
				newTooShort(func(d string) error { _, err := addKeyForTest(d, good, short, fipsSafeAddKeyOptions()); return err }),
			},
		},
		"RemoveKey": {
			// No passphrases/existingEmpty entry: credential checks are CLI
			// policy now (Unlock/UnlockKeyslot, then RemoveKeyslot), not the
			// library's -- the same reason KillKeyslot below has none.
			valid:        func(d string) error { return removeKeyForTest(d, good, 0) },
			keyslotRange: []call{func(d string) error { return removeKeyForTest(d, good, -1) }, func(d string) error { return removeKeyForTest(d, good, MaxKeyslots) }},
		},
		"KillSlot": {
			valid:        func(d string) error { return killSlotForTest(d, good, 0) },
			keyslotRange: []call{func(d string) error { return killSlotForTest(d, good, -1) }, func(d string) error { return killSlotForTest(d, good, MaxKeyslots) }},
		},
		"ChangeKey": {
			valid: func(d string) error { return changeKeyForTest(d, good, other, 0) },
			passphrases: []refusal{
				existingEmpty(func(d string) error { return changeKeyForTest(d, nil, other, 0) }),
				newTooShort(func(d string) error { return changeKeyForTest(d, good, short, 0) }),
			},
			keyslotRange: []call{func(d string) error { return changeKeyForTest(d, good, other, -1) }, func(d string) error { return changeKeyForTest(d, good, other, MaxKeyslots) }},
		},
		"KillKeyslot": {
			valid:        func(d string) error { return killKeyslotForTest(d, 0) },
			keyslotRange: []call{func(d string) error { return killKeyslotForTest(d, -1) }, func(d string) error { return killKeyslotForTest(d, MaxKeyslots) }},
		},
		"ListKeyslots": {
			valid: func(d string) error { _, err := listKeyslotsForTest(d); return err },
		},
	}

	for name, ep := range entryPoints {
		t.Run(name, func(t *testing.T) {
			if err := ep.valid(""); !errors.Is(err, ErrInvalidArgument) {
				t.Errorf("an empty path: %v, want ErrInvalidArgument", err)
			}
			if err := ep.valid(filepath.Join(t.TempDir(), "absent.img")); !errors.Is(err, ErrDeviceNotFound) {
				t.Errorf("a missing device: %v, want ErrDeviceNotFound", err)
			}

			blank := newImage(t, "not-luks.img")
			if err := ep.valid(blank); !errors.Is(err, ErrInvalidHeader) {
				t.Errorf("a device with no LUKS2 header: %v, want ErrInvalidHeader", err)
			}
			if b := readAreaBytes(t, blank, 0, goldenPrefixBytes); !bytes.Equal(b, make([]byte, goldenPrefixBytes)) {
				t.Error("the refusal wrote to a device that holds no LUKS2 header")
			}

			device := newImage(t, "volume.img")
			formatWithLibrary(t, device)
			before := readAreaBytes(t, device, 0, goldenPrefixBytes)
			for i, r := range ep.passphrases {
				if err := r.call(device); !errors.Is(err, r.want) {
					t.Errorf("refused passphrase, argument %d: %v, want %v", i, err, r.want)
				}
			}
			for i, c := range ep.keyslotRange {
				if err := c(device); err == nil || !strings.Contains(err.Error(), "invalid keyslot") {
					t.Errorf("out-of-range keyslot, case %d: %v, want an invalid-keyslot refusal", i, err)
				}
			}
			if !bytes.Equal(before, readAreaBytes(t, device, 0, goldenPrefixBytes)) {
				t.Error("a refused call changed the container")
			}
		})
	}
}
