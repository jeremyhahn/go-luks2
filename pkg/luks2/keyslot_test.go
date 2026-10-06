// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
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
			metadata := &LUKS2Metadata{
				Keyslots: make(map[string]*Keyslot),
			}
			for _, slot := range tt.existingSlots {
				metadata.Keyslots[strconv.Itoa(slot)] = &Keyslot{Type: "luks2"}
			}

			opts := &AddKeyOptions{}
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
		keyslots       map[string]*Keyslot
		expectedOffset int64
	}{
		{
			name:           "no existing keyslots",
			keyslotsStart:  0x8000,
			keyslots:       map[string]*Keyslot{},
			expectedOffset: 0x8000, // 32KB: twice a 16 KiB header area
		},
		{
			// The start is the container's, not this library's. A 32 KiB
			// metadata area puts the keyslots at 0x10000, and an empty
			// container of that shape must place its first keyslot there
			// rather than at the 0x8000 this function used to hardcode.
			name:           "no existing keyslots, 32 KiB metadata area",
			keyslotsStart:  0x10000,
			keyslots:       map[string]*Keyslot{},
			expectedOffset: 0x10000,
		},
		{
			name:          "one keyslot",
			keyslotsStart: 0x8000,
			keyslots: map[string]*Keyslot{
				"0": {
					Area: &KeyslotArea{
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
			keyslots: map[string]*Keyslot{
				"0": {
					Area: &KeyslotArea{
						Offset: "32768",
						Size:   "262144",
					},
				},
				"1": {
					Area: &KeyslotArea{
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
			metadata := &LUKS2Metadata{
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

func TestKeyslotInfoList(t *testing.T) {
	// Test KeyslotInfo struct fields
	info := KeyslotInfo{
		ID:         1,
		Type:       "luks2",
		KeySize:    64,
		Priority:   1,
		KDFType:    "argon2id",
		Encryption: "aes-xts-plain64",
	}

	if info.ID != 1 {
		t.Errorf("expected ID 1, got %d", info.ID)
	}
	if info.Type != "luks2" {
		t.Errorf("expected Type 'luks2', got %s", info.Type)
	}
	if info.KeySize != 64 {
		t.Errorf("expected KeySize 64, got %d", info.KeySize)
	}
	if info.Priority != 1 {
		t.Errorf("expected Priority 1, got %d", info.Priority)
	}
	if info.KDFType != "argon2id" {
		t.Errorf("expected KDFType 'argon2id', got %s", info.KDFType)
	}
	if info.Encryption != "aes-xts-plain64" {
		t.Errorf("expected Encryption 'aes-xts-plain64', got %s", info.Encryption)
	}
}

func TestAddKeyOptionsDefaults(t *testing.T) {
	// Test that nil options doesn't cause panic
	opts := &AddKeyOptions{}

	if opts.Keyslot != nil {
		t.Error("expected Keyslot to be nil by default")
	}
	if opts.KDFType != "" {
		t.Error("expected KDFType to be empty by default")
	}
	if opts.Argon2Time != 0 {
		t.Error("expected Argon2Time to be 0 by default")
	}
	if opts.Argon2Memory != 0 {
		t.Error("expected Argon2Memory to be 0 by default")
	}
	if opts.Argon2Parallel != 0 {
		t.Error("expected Argon2Parallel to be 0 by default")
	}
}

func TestMaxKeyslotsConstant(t *testing.T) {
	if MaxKeyslots != 32 {
		t.Errorf("expected MaxKeyslots to be 32, got %d", MaxKeyslots)
	}
}

func TestKeyslotAreaAlignment(t *testing.T) {
	if KeyslotAreaAlignment != 4096 {
		t.Errorf("expected KeyslotAreaAlignment to be 4096, got %d", KeyslotAreaAlignment)
	}
}

// keyslotRemovalPath is one way to destroy a keyslot. There are four, and they
// are enumerated HERE, once, so that a guard cannot be applied to three of them.
//
// That is not a hypothetical arrangement to avoid: the last-keyslot guard was
// applied to the paths a review finding named and missed WipeKeyslot entirely,
// which then destroyed a single-keyslot volume that KillKeyslot refused to
// touch. A rule and the set it must cover have to come from the same place.
type keyslotRemovalPath struct {
	name   string
	remove func(device string, passphrase []byte, slot int) error
}

var keyslotRemovalPaths = []keyslotRemovalPath{
	{"RemoveKey", func(device string, passphrase []byte, slot int) error {
		return RemoveKey(device, passphrase, slot)
	}},
	{"KillSlot", func(device string, passphrase []byte, slot int) error {
		return KillSlot(device, passphrase, slot)
	}},
	{"KillKeyslot", func(device string, _ []byte, slot int) error {
		return KillKeyslot(device, slot)
	}},
	{"WipeKeyslot", func(device string, _ []byte, slot int) error {
		return WipeKeyslot(device, slot)
	}},
}

// TestEveryKeyslotRemovalPathRefusesToDestroyTheLastUsableKeyslot is the
// regression test for #37, #45 and #71, over every path and every shape.
//
// The defect in all three is one sentence: the guard counted MAP ENTRIES while
// the unlock counted keyslots it could open. A `reencrypt` slot, a slot with no
// af object, a slot whose cipher nothing implements -- each satisfies
// len(metadata.Keyslots) > 1 and opens nothing, so destroying the only working
// credential was permitted, returned nil, and was discovered at the next
// unlock. Silent, catastrophic, and blamed on the operator's memory: the volume
// then reports "incorrect passphrase" for a passphrase that is correct.
//
// The shapes come from unopenableKeyslotShapes, which is shared with
// TestTheUnlockPathRefusesEveryShapeTheRemovalGuardMustNotCount -- so every
// shape asserted here has been shown, in that test, to be one the unlock path
// really does refuse. Neither test is allowed to be the only definition.
func TestEveryKeyslotRemovalPathRefusesToDestroyTheLastUsableKeyslot(t *testing.T) {
	defer parallel(t)()

	passphrase := []byte(conformancePassphrase)

	for _, shape := range unopenableKeyslotShapes {
		// Formatted ONCE per shape and stamped onto a fresh file per path: the
		// fixture is a property of the shape, and the four paths differ only in
		// which function is asked to destroy it. See goldenSiblingVolume.
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

				// THE DAMAGE PLANE, not the return value. "The error is the
				// diagnosis; the record is the damage." A path that zeroed the
				// area and then returned the guard's error would satisfy every
				// error-shaped assertion above and still have destroyed the
				// volume, so what is asserted per path is that the key material
				// is byte-identical.
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
			if err := TestKey(device, passphrase); err != nil {
				t.Fatalf("the volume no longer opens after four REFUSED removals: %v", err)
			}
		})
	}
}

// keyslotAreaExtent reads a keyslot's area range out of a fixture, so a test can
// snapshot the bytes a removal would have destroyed.
func keyslotAreaExtent(t *testing.T, device, id string) (offset, size int64) {
	t.Helper()

	_, metadata, err := ReadHeader(device)
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

// TestEveryKeyslotRemovalPathPermitsARemovalThatLeavesASurvivor is the control
// for the test above, and without it a guard that refused everything would pass
// every case there.
//
// The sibling is undamaged metadata over an area of zeros, so the guard counts
// it -- see keyslotCanOpenVolume's documented residual, which cannot be removed
// without a passphrase to try.
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

			_, metadata, err := ReadHeader(device)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			if _, present := metadata.Keyslots["0"]; present {
				t.Fatal("the removal reported success and the keyslot is still in the header")
			}
		})
	}
}

// overlappingSiblingVolume gives a container two keyslots whose areas share
// bytes, both of them well-formed.
//
// This is #38's reproduction and it needs NO malformed metadata at all. The
// sibling is a byte-for-byte metadata copy of keyslot 0 pointed at keyslot 0's
// own area, so both slots are openable by the same passphrase and either one's
// removal would zero the other's key material.
//
// shift moves the sibling's area to produce a PARTIAL overlap; 0 makes the two
// areas identical.
func goldenOverlappingVolume(t *testing.T, shift int64) (golden []byte, sharedOffset, sharedSize int64) {
	t.Helper()

	device, sharedOffset, sharedSize := overlappingSiblingVolume(t, "golden-overlap.img", shift)
	return goldenBytes(t, device), sharedOffset, sharedSize
}

func overlappingSiblingVolume(t *testing.T, name string, shift int64) (device string, sharedOffset, sharedSize int64) {
	t.Helper()

	device = newImage(t, name)
	formatWithLibrary(t, device)

	hdr, metadata, err := ReadHeader(device)
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

// readAreaBytes returns the raw contents of a byte range of the device, so a
// test can assert that a REFUSED removal left key material byte-identical
// rather than merely that an error came back. The error is the diagnosis; the
// bytes are the damage.
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

// TestRemovingAKeyslotRefusesWhenItsAreaOverlapsAKeyslotThatStillWorks is #38.
//
// Reproduced permanent data loss with entirely well-formed metadata: the guard
// reasoned over keyslot ENTRIES and the wipe acted on BYTES, so removing one of
// two slots that share an area destroyed the other's key material while the
// guard happily counted it as a survivor. The volume then reported the
// operator's correct passphrase as invalid.
func TestRemovingAKeyslotRefusesWhenItsAreaOverlapsAKeyslotThatStillWorks(t *testing.T) {
	defer parallel(t)()

	passphrase := []byte(conformancePassphrase)

	for _, overlap := range []struct {
		name  string
		shift int64
	}{
		{"identical areas", 0},
		// A partial overlap is the case a "same offset" check would miss.
		{"partially overlapping areas", KeyslotAreaAlignment},
	} {
		golden, offset, size := goldenOverlappingVolume(t, overlap.shift)

		for _, path := range keyslotRemovalPaths {
			t.Run(overlap.name+"/"+path.name, func(t *testing.T) {
				device := restoreVolume(t, "overlap.img", golden)
				before := readAreaBytes(t, device, offset, size)

				// Keyslot 0 is the one removed, and keyslot 1 is a survivor by
				// the guard's count, so the ENTRY-level half of the gate
				// permits this and only the BYTE-level half can refuse it.
				//
				// Removing slot 0 rather than slot 1 is what makes the partial
				// overlap testable at all: a slot whose area starts part-way
				// into another's decrypts to nothing, so RemoveKey could not
				// authenticate against it -- and the entry-level guard would
				// still count it, which is precisely the residual that makes
				// the byte-level half necessary.
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
				if err := TestKey(device, passphrase); err != nil {
					t.Fatalf("the volume no longer opens after a REFUSED removal: %v", err)
				}
			})
		}
	}
}

// TestChangeKeyRefusesToZeroAKeyslotThatStillWorks covers the fifth path that
// zeroes a keyslot area.
//
// ChangeKey is not a removal, so an enumeration of "removal paths" misses it --
// and it destroys an area exactly as a removal does. It must NOT take the
// entry-level half of the gate, because changing the passphrase on a
// single-keyslot volume is precisely what it is for; it must take the byte-level
// half.
func TestChangeKeyRefusesToZeroAKeyslotThatStillWorks(t *testing.T) {
	defer parallel(t)()

	passphrase := []byte(conformancePassphrase)
	device, offset, size := overlappingSiblingVolume(t, "changekey-overlap.img", 0)
	before := readAreaBytes(t, device, offset, size)

	err := ChangeKey(device, passphrase, []byte("a-replacement-credential"), 1)
	if err == nil {
		t.Fatal("ChangeKey zeroed an area another keyslot still needs, and reported success")
	}
	if !errors.Is(err, ErrKeyslotAreaOverlap) {
		t.Fatalf("ChangeKey was refused for some other reason than the overlap: %v", err)
	}
	if !bytes.Equal(before, readAreaBytes(t, device, offset, size)) {
		t.Fatal("ChangeKey was refused AND the overlapping keyslot's key material was modified")
	}
	if err := TestKey(device, passphrase); err != nil {
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

	if err := ChangeKey(device, old, updated, 0); err != nil {
		t.Fatalf("ChangeKey was refused on the one-keyslot volume it exists for: %v", err)
	}
	if err := TestKey(device, updated); err != nil {
		t.Fatalf("the new passphrase does not open the volume: %v", err)
	}
	if err := TestKey(device, old); err == nil {
		t.Fatal("the old passphrase still opens the volume after ChangeKey")
	}
}

// TestChangeKeyWritesTheNewMaterialBeforeDestroyingTheOld is #39.
//
// The old ordering was: wipe the area, write material derived from the NEW
// passphrase into it, and only then make the new KDF durable. Between the
// material write and the header write the on-disk state was material under the
// new passphrase and a salt from the old one, which NEITHER passphrase derives
// -- so on a single-keyslot volume an ordinary power failure in that window was
// permanent data loss. The wipe also destroyed the old material before anything
// replacing it existed.
//
// The property that removes the window is that the two ranges are DISJOINT: the
// new material is written somewhere the old material is not, so no intermediate
// state exists in which the header names an area holding material no passphrase
// can derive. That is what this asserts, because it is what a crash-free run can
// actually observe -- the ordering itself is pinned by the guard on the wipe
// coming last in the source, and by the old area no longer holding the material
// it held before the change.
func TestChangeKeyWritesTheNewMaterialBeforeDestroyingTheOld(t *testing.T) {
	defer parallel(t)()

	device := newImage(t, "changekey-relocates.img")
	formatWithLibrary(t, device)

	old := []byte(conformancePassphrase)
	updated := []byte("the-replacement-credential")

	_, before, err := ReadHeader(device)
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

	if err := ChangeKey(device, old, updated, 0); err != nil {
		t.Fatalf("ChangeKey failed: %v", err)
	}

	_, after, err := ReadHeader(device)
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

	// The old material is gone: relocating must not leave a second copy of the
	// keyslot's key material behind, encrypted under a passphrase that has just
	// been retired.
	//
	// The freed area is checked against WHAT IT HELD, not against zeroes. It is
	// overwritten with CSPRNG data rather than zeroed (wipeKeyslotArea), because
	// a zeroed range is distinguishable from live key material at a glance and
	// so announces that a credential was revoked here -- see
	// TestWipeKeyslotAreaLeavesRandomNotZeroes. Comparing against zeroes would
	// therefore assert the disclosure rather than the destruction.
	leftovers := readAreaBytes(t, device, oldOffset, oldSize)
	if bytes.Equal(leftovers, materialBefore) {
		t.Fatal("the old keyslot area still holds key material after ChangeKey")
	}
	if bytes.Equal(leftovers, make([]byte, oldSize)) {
		t.Fatal("the old keyslot area was zeroed; that discloses which slots have been retired")
	}

	if err := TestKey(device, updated); err != nil {
		t.Fatalf("the new passphrase does not open the volume: %v", err)
	}
	if err := TestKey(device, old); err == nil {
		t.Fatal("the old passphrase still opens the volume after ChangeKey")
	}
}

// TestChangeKeyRefusesRatherThanRewriteInPlaceWhenThereIsNoFreeArea is the
// fail-closed half of #39.
//
// Relocating needs somewhere to relocate TO. On a container whose keyslots area
// has no gap, the only in-place alternative is the ordering that loses data on a
// power failure, so the operation is REFUSED and the volume is left exactly as
// it was. An operator has a crash-safe route to the same result: add a new key
// and remove the old slot.
func TestChangeKeyRefusesRatherThanRewriteInPlaceWhenThereIsNoFreeArea(t *testing.T) {
	defer parallel(t)()

	device := newImage(t, "changekey-full.img")
	formatWithLibrary(t, device)

	hdr, metadata, err := ReadHeader(device)
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

	err = ChangeKey(device, old, []byte("a-replacement-credential"), 0)
	if err == nil {
		t.Fatal("ChangeKey rewrote a keyslot in place when it had nowhere safe to relocate")
	}
	if !errors.Is(err, ErrKeyslotsAreaFull) {
		t.Fatalf("ChangeKey was refused for some other reason: %v", err)
	}
	if !bytes.Equal(before, readAreaBytes(t, device, offset, size)) {
		t.Fatal("ChangeKey was refused AND the keyslot's key material was modified")
	}
	if err := TestKey(device, old); err != nil {
		t.Fatalf("the volume no longer opens with the original passphrase after a REFUSED ChangeKey: %v", err)
	}
}

// TestFindFreeKeyslotAreaReusesGaps pins the allocator ChangeKey depends on.
//
// A bump allocator -- max end, rounded up, which is what AddKey uses to place a
// brand new slot -- would be wrong here: ChangeKey frees the area it relocates
// out of, so a bump allocator would march up the keyslots area and make the
// number of times a passphrase can be changed a function of how much room the
// container was formatted with.
func TestFindFreeKeyslotAreaReusesGaps(t *testing.T) {
	hdr := &LUKS2BinaryHeader{HeaderSize: LUKS2HeaderMinSize}
	area := func(offset, size int64) *Keyslot {
		return &Keyslot{
			Type: "luks2",
			Area: &KeyslotArea{Offset: formatSize(offset), Size: formatSize(size)},
		}
	}
	const start int64 = 2 * LUKS2HeaderMinSize // where keyslots begin for this geometry

	metadata := func(keyslots map[string]*Keyslot, keyslotsSize int64) *LUKS2Metadata {
		return &LUKS2Metadata{
			Keyslots: keyslots,
			Config:   &Config{KeyslotsSize: formatSize(keyslotsSize)},
		}
	}

	t.Run("the first fit is the gap, not the end", func(t *testing.T) {
		// Slot 0 relocated forward and left a hole at the start of the area.
		md := metadata(map[string]*Keyslot{
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
		md := metadata(map[string]*Keyslot{
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
		md := metadata(map[string]*Keyslot{
			"0": area(start, 0x40000),
		}, 0x40000)
		if _, err := findFreeKeyslotArea(hdr, md, 0x40000); !errors.Is(err, ErrKeyslotsAreaFull) {
			t.Fatalf("a full keyslots area was not refused: %v", err)
		}
	})

	t.Run("the data segment is a second ceiling", func(t *testing.T) {
		// config.keyslots_size overstates the space available; the encrypted
		// data starts before the area it declares ends.
		md := metadata(map[string]*Keyslot{
			"0": area(start, 0x40000),
		}, 0x1000000)
		md.Segments = map[string]*Segment{
			"0": {Type: "crypt", Offset: formatSize(start + 0x40000)},
		}
		if _, err := findFreeKeyslotArea(hdr, md, 0x40000); !errors.Is(err, ErrKeyslotsAreaFull) {
			t.Fatalf("a keyslot was placed on top of the encrypted data: %v", err)
		}
	})
}

// heterogeneousVolume gives a container two real keyslots that DISAGREE about
// key size, with the weaker one first in scan order.
//
// Neither WriteHeader nor ReadHeader requires keyslots to agree, and cryptsetup
// does not either -- so any container this library did not create may be one.
// Slot 0's declared key size is reduced after the fact, which is exactly what an
// external tool or a partially completed operation can leave behind; slot 1 is
// real and openable and is what the caller authenticates with.
func heterogeneousVolume(t *testing.T, name string) (device string, strongPassphrase []byte) {
	t.Helper()

	device = newImage(t, name)
	formatWithLibrary(t, device)

	strongPassphrase = []byte("the-second-credential")
	if _, err := AddKey(device, []byte(conformancePassphrase), strongPassphrase, &AddKeyOptions{
		KDFType:       KDFTypePBKDF2,
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("AddKey failed while building the fixture: %v", err)
	}

	hdr, metadata, err := ReadHeader(device)
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

// TestAddKeyDerivesTheNewKeyslotsKeySizeFromTheVolumeKey is #55.
//
// AddKey took the new keyslot's key size from a TEMPLATE slot, which is right
// only while every keyslot agrees. On a container whose keyslots disagree -- and
// nothing in this package or in cryptsetup refuses one -- the new slot inherited
// whichever slot the template rule picked. If that slot's declared key size is
// not the length of the actual volume key, the result is not merely a weaker
// credential: it is a DEAD one. The stripes written are the full master key's,
// the declaration says half that, so the unlock merges half of them, recovers a
// candidate no digest can verify, and AddKey has already returned nil.
//
// The fix is a derivation, not an option: the size comes from the master key the
// call just recovered, which is the only value that can ever work.
//
// This asserts the credential OPENS THE VOLUME, not that some keyslot appeared.
// The defect's whole signature is a keyslot that appears, looks well-formed, and
// opens nothing -- an assertion on the header alone passes straight over it.
func TestAddKeyDerivesTheNewKeyslotsKeySizeFromTheVolumeKey(t *testing.T) {
	defer parallel(t)()

	device, strong := heterogeneousVolume(t, "heterogeneous.img")
	added := []byte("a-third-credential")

	if _, err := AddKey(device, strong, added, &AddKeyOptions{
		KDFType:       KDFTypePBKDF2,
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("AddKey failed on a container whose keyslots disagree: %v", err)
	}

	if err := TestKey(device, added); err != nil {
		t.Fatalf("AddKey reported success and the credential it added does not open the volume: %v", err)
	}

	_, metadata, err := ReadHeader(device)
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

// TestAddKeyAndUnlockRoundTripOnAES192CBCVolume reproduces, at the unit
// level, the local Codex review's PR #279 finding: a cryptsetup
// "aes-cbc-essiv:sha256" --key-size 192 volume has a 24-byte master key.
// 4000 AF stripes puts the AF split at 96000 bytes, 256 short of a whole
// 512-byte sector, and WritableAreaKeySize(24) wraps the keyslot area in
// AES-256-XTS (a 64-byte area key, not 24), so the write path runs exactly
// the EncryptEnclave/xtsPartialSector code the finding names.
//
// Format() itself refuses a 192-bit master key (ValidateFormatOptions and
// the cbc-essiv entry in formatCiphers both only admit 256/512-bit keys), so
// this fixture is built the way heterogeneousVolume and twoVolumeKeyContainer
// build theirs: format a normal volume for the on-disk skeleton, then
// hand-write keyslot 0 to wrap a real 24-byte master key under its own
// 64-byte area key, exactly as cryptsetup's own luksFormat --key-size 192
// would leave it. writeKeyslot is not reused here because it derives the
// area key to the volume key's own length, which is only correct while the
// volume key itself keys AES-XTS -- not the shape this fixture needs.
func TestAddKeyAndUnlockRoundTripOnAES192CBCVolume(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "aes192-cbc.img")
	firstPassphrase := []byte("the-first-credential")
	if err := Format(FormatOptions{
		Device:        path,
		Passphrase:    firstPassphrase,
		Cipher:        "aes",
		CipherMode:    "xts-plain64",
		KeySize:       512,
		HashAlgo:      "sha256",
		SectorSize:    512,
		KDFType:       KDFTypePBKDF2,
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Segments["0"].Encryption = "aes-cbc-essiv:sha256"

	const newKeySize = 24 // AES-192, a cryptsetup --key-size 192 volume
	areaKeySize := areacipher.WritableAreaKeySize(newKeySize)

	rawKey, err := randomBytes(newKeySize)
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

	kdf, err := CreateKDF(FormatOptions{KDFType: KDFTypePBKDF2, HashAlgo: "sha256", PBKDFIterTime: 1}, areaKeySize)
	if err != nil {
		t.Fatalf("CreateKDF failed: %v", err)
	}
	passphraseKey, err := DeriveKeyEnclave(firstPassphrase, kdf, areaKeySize)
	if err != nil {
		t.Fatalf("DeriveKeyEnclave failed: %v", err)
	}
	defer mustDestroy(t, passphraseKey)

	afData, err := afCodec().Split(masterKey, af.Params{Stripes: AFStripes, Hash: DefaultHashAlgo})
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
		len(encrypted), newKeySize*AFStripes, newKeySize*AFStripes)

	// screenKeyslot/recoverKeyslotKey round decryptLen UP to a whole sector,
	// never the raw AF-split length, so the unlock path always asks for a
	// whole number of sectors' worth of ciphertext. cryptsetup writes exactly
	// that many ciphertext bytes for the same AF split; a shorter ciphertext
	// here means the bytes beyond it are on-disk zero padding (writeArea)
	// standing in for real ciphertext.
	afSplitSize := newKeySize * AFStripes
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
	alignedSize := alignTo(int64(len(encrypted)), KeyslotAreaAlignment)
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
	metadata.Keyslots["0"] = &Keyslot{
		Type:     "luks2",
		KeySize:  newKeySize,
		Priority: &priority,
		Area: &KeyslotArea{
			Type:       "raw",
			KeySize:    areaKeySize,
			Offset:     formatSize(offset),
			Size:       formatSize(alignedSize),
			Encryption: KeyslotAreaEncryption,
		},
		KDF: kdf,
		AF: &AntiForensic{
			Type:    "luks1",
			Stripes: AFStripes,
			Hash:    DefaultHashAlgo,
		},
	}

	digestKDF, digestValue, err := createDigest(masterKey, "sha256")
	if err != nil {
		t.Fatalf("createDigest failed: %v", err)
	}
	metadata.Digests["0"] = &Digest{
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

	if err := TestKey(path, firstPassphrase); err != nil {
		t.Fatalf("the hand-written 192-bit keyslot does not open under its own passphrase: %v", err)
	}

	added := []byte("a-second-credential")
	if _, err := AddKey(path, firstPassphrase, added, &AddKeyOptions{
		KDFType:       KDFTypePBKDF2,
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("AddKey failed on a volume whose AF split is not sector-aligned: %v", err)
	}

	if err := TestKey(path, added); err != nil {
		t.Fatalf("AddKey reported success and the credential it added does not open the volume: %v", err)
	}
}

// TestAddKeyRefusesATemplateWhoseAreaCipherItWouldNotHonor is DELETED, and the
// deletion is part of the fix rather than a concession to it.
//
// It asserted that AddKey REFUSES a keyslot whose area cipher this writer cannot
// reproduce, and that behavior is now known to be wrong: it rejected every
// keyslot of every container this library itself created with a non-XTS data
// cipher, so AddKey turned away volumes it could unlock. The test was green and
// it was defending a data-availability regression -- the same classification
// exercise as the two integration tests this branch inverted, applied to a test
// this branch had written days earlier.
//
// What it was protecting -- that no wrong area cipher is ever written into a new
// keyslot -- is now guaranteed by construction rather than by a screen, because
// AddKey states KeyslotAreaEncryption instead of copying a neighbour's label.
// TestAddKeyStatesItsOwnAreaCipherAndDoesNotRefuseALegacyContainer asserts both
// halves of that, and its two assertions fail against the two ways of getting
// this wrong: copying the stale label, and refusing the container.

// shrinkHeaderArea patches the container's declared header size and restores the
// checksum, producing a header this library can READ and will not WRITE.
//
// That combination is what makes #50 reachable. ReadHeader accepts any header
// area above 4096 bytes, while the writer additionally requires at least 16 KiB
// and a power of two -- so a container declaring 8 KiB is perfectly readable and
// every write against it is refused. A container this library wrote cannot get
// here, which is why the fixture is patched directly rather than produced by
// Format.
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
	// see validateHeaderChecksum, whose layout this mirrors.
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

// TestNoRemovalPathDestroysMaterialBeforeProvingTheHeaderWritable is #50.
//
// Every removal wiped the keyslot area first and wrote the header second, so a
// header write that was going to be refused was refused AFTER the key material
// was already gone: a failure that could have been a clean refusal instead cost
// a keyslot. Comparable harm to a corruption, better diagnosis, and no less
// permanent.
//
// The assertion is on the DAMAGE PLANE, not the return value. Both orderings
// return an error; only one of them leaves the key material byte-identical.
func TestNoRemovalPathDestroysMaterialBeforeProvingTheHeaderWritable(t *testing.T) {
	defer parallel(t)()

	passphrase := []byte(conformancePassphrase)

	// Two keyslots, so the last-keyslot guard permits the removal and the header
	// pre-flight is what has to refuse it.
	golden := goldenSiblingVolume(t, nil)

	for _, path := range keyslotRemovalPaths {
		t.Run(path.name, func(t *testing.T) {
			device := restoreVolume(t, "unwritable-header.img", golden)

			_, metadata, err := ReadHeader(device)
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

			shrinkHeaderArea(t, device, LUKS2HeaderSize*2)
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

// TestLegacyMislabeledKeyslotIsRefusedAndLeftAlone covers the containers
// v0.1.x Format wrote, and is where #106 deliberately changes behavior.
//
// Before #91, Format wrote the container's DATA cipher into the keyslot area,
// so a volume created with a non-XTS data cipher carries AES-XTS key material
// under, say, an "aes-cbc-essiv:sha256" label. While the read path consulted
// only the algorithm, those keyslots OPENED here -- and in nothing else:
// cryptsetup decrypts the declared CBC and fails. This test used to assert that
// they open and that AddKey works on them.
//
// #106 (owner ruling 2026-09-25) makes the reader honor the declared mode and
// refuse any spec it cannot actually decrypt, which is exactly this shape. A
// container only this library can open is not a container, and a reader that
// ignores the mode is what let the mislabel go unnoticed. So the property now
// held is the opposite, and it has three parts:
//
//   - the keyslot is REFUSED, not decrypted as XTS -- since CBC areas are
//     implemented, as the CBC it declares, whose key its 64-byte area key
//     cannot be;
//   - AddKey, which must unlock first, refuses the same way; and
//   - the refusal WRITES NOTHING: the header comes back byte-identical, so no
//     label is silently rewritten and no new keyslot is authored off a key
//     this package would not recover.
func TestLegacyMislabeledKeyslotIsRefusedAndLeftAlone(t *testing.T) {
	defer parallel(t)()

	device := newImage(t, "legacy-area-cipher.img")
	formatWithLibrary(t, device)

	// Precondition: the unmodified container opens, so the refusal below is
	// about the label and not a broken fixture.
	if err := TestKey(device, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("control: the unmodified fixture does not open: %v", err)
	}

	// The legacy shape, written directly because current Format no longer
	// produces it.
	hdr, metadata, err := ReadHeader(device)
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
	if err := TestKey(device, []byte(conformancePassphrase)); !errors.Is(err, ErrInvalidKeyslot) {
		t.Fatalf("TestKey on XTS material declared as CBC: got %v, want ErrInvalidKeyslot", err)
	}

	if slot, err := AddKey(device, []byte(conformancePassphrase), []byte("a-second-credential"), &AddKeyOptions{
		KDFType:       KDFTypePBKDF2,
		PBKDFIterTime: 1,
	}); err == nil {
		t.Fatalf("AddKey on a mislabeled container wrote slot %d", slot)
	}

	if !bytes.Equal(before, readAreaBytes(t, device, 0, goldenPrefixBytes)) {
		t.Fatal("a refused AddKey changed the container; a refusal must write nothing")
	}
}

// TestFormatDeclaresTheKeyslotAreaCipherItActuallyUses covers where the wrong
// declaration ORIGINATES, which is not AddKey.
//
// Format wrote the container's DATA cipher into the keyslot area, and those are
// different things: a caller may format with any cipher dm-crypt supports, and
// keyslot key material is wrapped with AES-XTS regardless. For the default
// aes/xts-plain64 the two strings coincide, which is why it survived -- and for
// any other choice Format produced a keyslot whose declaration its own material
// did not match.
//
// Without this, the read path -- which since #106 honors the declared mode --
// would refuse every keyslot Format wrote for a non-XTS data cipher, so such a
// container would not open at all. The two changes are one fix.
func TestFormatDeclaresTheKeyslotAreaCipherItActuallyUses(t *testing.T) {
	defer parallel(t)()

	device := newImage(t, "format-cbc-data.img")

	// A non-XTS DATA cipher. Only the segment is affected by this choice; the
	// keyslot area must still describe what wraps the key material.
	if err := Format(FormatOptions{
		Device:        device,
		Passphrase:    []byte(conformancePassphrase),
		Cipher:        "aes",
		CipherMode:    "cbc-essiv:sha256",
		KeySize:       256, // CBC-ESSIV takes one AES key; there is no 512-bit form (#248)
		HashAlgo:      "sha512",
		SectorSize:    512,
		KDFType:       KDFTypePBKDF2,
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	_, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	if got := metadata.Keyslots["0"].Area.Encryption; got != KeyslotAreaEncryption {
		t.Fatalf("the keyslot area declares %q; the material is %s and nothing else", got, KeyslotAreaEncryption)
	}

	// The caller's choice still reaches the DATA segment, which is what it was
	// about -- so this is a correction, not a silent override of the caller.
	if got := metadata.Segments["0"].Encryption; got != "aes-cbc-essiv:sha256" {
		t.Fatalf("the data segment declares %q, want the caller's aes-cbc-essiv:sha256", got)
	}

	// And the container is still fully usable: it opens, and AddKey can
	// template off it rather than refusing a slot this library just wrote.
	if err := TestKey(device, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("the volume does not open: %v", err)
	}
	if _, err := AddKey(device, []byte(conformancePassphrase), []byte("a-second-credential"), &AddKeyOptions{
		KDFType:       KDFTypePBKDF2,
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("AddKey refused a template this library itself wrote: %v", err)
	}
	if err := TestKey(device, []byte("a-second-credential")); err != nil {
		t.Fatalf("the added credential does not open the volume: %v", err)
	}
}

// TestEveryKeyslotRemovalPathAdvancesTheSequenceID asserts over the SET, which
// is the only form of this test worth having.
//
// LUKS2 keeps two header copies and uses the sequence id to decide which is
// current. writeHeaderInternal writes both, so a mutating path that leaves the
// id alone can produce two copies carrying DIFFERENT metadata at the SAME
// sequence number -- and a reader then cannot tell which is newer. That defeats
// the format's recovery mechanism on paths whose purpose is destroying key
// material.
//
// Seven of the eight mutating paths advanced it. WipeKeyslot did not, and had
// not since before this branch -- it became conspicuous only once WipeKeyslot
// was made a full peer of the other removal paths. That is this change's
// recurring shape one more time: a rule applied to the sites someone
// enumerated, and one site nobody enumerated.
//
// So this asserts over keyslotRemovalPaths as a group rather than naming
// WipeKeyslot, for the same reason TestEveryKeyslotRemovalPathIsGuarded does: a
// sixth path cannot be added without one.
//
// Format, WriteHeader and RestorePrimaryHeader deliberately do NOT advance it
// and are excluded: Format creates a container with no older copy to
// disambiguate, WriteHeader is the primitive whose caller owns the header, and
// RestorePrimaryHeader clones the secondary onto the primary, where advancing
// would make the repaired copy falsely claim to be newer than its source.
func TestEveryKeyslotRemovalPathAdvancesTheSequenceID(t *testing.T) {
	defer parallel(t)()

	passphrase := []byte(conformancePassphrase)
	golden := goldenSiblingVolume(t, nil)

	for _, path := range keyslotRemovalPaths {
		t.Run(path.name, func(t *testing.T) {
			device := restoreVolume(t, "sequence.img", golden)

			before, _, err := ReadHeader(device)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}

			if err := path.remove(device, passphrase, 0); err != nil {
				t.Fatalf("the removal was refused: %v", err)
			}

			// Read back from the DEVICE. Asserting on the in-memory header
			// would pass for a path that incremented the field and never
			// persisted it, which is the same shape as asserting an error
			// instead of the damage.
			after, _, err := ReadHeader(device)
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

// TestAddKeyOptionsDoesNotSilentlyDiscardANegativeArgon2Cost is #112.
//
// addKeyFormatOptions copied each Argon2 cost only when it was `> 0`, so a
// caller passing -1 got the package DEFAULT and no indication that the value
// had been ignored. The sibling parameter PBKDFIterTime had used `!= 0` since
// #102, so one struct carried two contracts for the same kind of field.
func TestAddKeyOptionsDoesNotSilentlyDiscardANegativeArgon2Cost(t *testing.T) {
	for _, tc := range []struct {
		field string
		opts  AddKeyOptions
		got   func(FormatOptions) int
		deflt int
	}{
		{"Argon2Time", AddKeyOptions{Argon2Time: -1}, func(f FormatOptions) int { return f.Argon2Time }, 4},
		{"Argon2Memory", AddKeyOptions{Argon2Memory: -1}, func(f FormatOptions) int { return f.Argon2Memory }, 1048576},
		{"Argon2Parallel", AddKeyOptions{Argon2Parallel: -1}, func(f FormatOptions) int { return f.Argon2Parallel }, 4},
	} {
		t.Run(tc.field, func(t *testing.T) {
			opts := tc.opts
			formatOpts, _ := addKeyFormatOptions(&opts, nil)
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
	f, _ := addKeyFormatOptions(&AddKeyOptions{}, nil)
	if f.Argon2Time != 4 || f.Argon2Memory != 1048576 || f.Argon2Parallel != 4 {
		t.Fatalf("an unset AddKeyOptions no longer yields the defaults: time=%d memory=%d parallel=%d",
			f.Argon2Time, f.Argon2Memory, f.Argon2Parallel)
	}
}

// argon2Derivations is every function that converts a signed KDF cost with
// uint32 and calls into x/crypto/argon2. The tests below are TABLES OVER IT,
// not one function tested and its twin assumed.
//
// The first version of this PR guarded BOTH derivations and tested ONE.
// deriveArgon2i was never invoked by any test in the package -- so the fix was
// two-of-two and the evidence was one-of-two, which is the exact shape this
// branch diagnosed four hours earlier: a partial demonstration reads as the
// most convincing possible argument that the rest was considered.
//
// A table forces the enumeration to be written down where a reviewer can count
// it. Adding a third derivation here without a guard fails immediately.
var argon2Derivations = map[string]func([]byte, []byte, *KDF, int) ([]byte, error){
	"deriveArgon2i":  deriveArgon2i,
	"deriveArgon2id": deriveArgon2id,
}

// aboveUint32 returns a value larger than MaxUint32 where an int can hold one,
// and reports whether it could.
//
// On a 64-bit platform that is MaxUint32+4. On a 32-bit platform no int can
// exceed MaxUint32, so the over-range condition cannot be constructed and the
// caller must not assert it -- which is different from skipping a test that
// could have run, and is why this returns the fact rather than calling t.Skip.
func aboveUint32() int {
	if strconv.IntSize > 32 {
		// Via a variable: int(uint64(...) + 4) is a CONSTANT expression, so
		// the conversion is range-checked at compile time and still does not
		// build on a 32-bit target. Assigning first makes it an ordinary
		// runtime conversion, which this branch never reaches there.
		v := uint64(math.MaxUint32) + 4
		return int(v)
	}
	return math.MaxInt
}

func canExceedUint32() bool { return strconv.IntSize > 32 }

// TestAboveUint32AgreesWithCanExceedUint32 pins the invariant the tables rely
// on, and it holds on every architecture rather than only where it matters.
//
// canExceedUint32 existed and was NEVER CALLED while a comment claimed it was
// what kept the over-range cases off 32-bit. An unused helper reads exactly
// like an enforced one.
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

// TestEveryArgon2DerivationRefusesACostItCannotRepresent covers both directions
// of the uint32 conversion, for every derivation.
//
// A NEGATIVE wraps to something enormous: -1 KiB becomes 4294967295 KiB, and
// argon2 is asked for a ~4 TiB matrix. That is an allocation, not an error.
//
// A huge POSITIVE truncates to something small: 2^32+4 becomes 3. The caller
// asks for an expensive KDF and silently gets a trivial one, which is the
// dangerous direction for a work factor.
//
// Neither is reported by the conversion itself, which is what the blanket
// G115 suppression on those lines used to hide (see u32 in kdf.go). Not
// quoting the directive itself here for the same reason u32's comment gives:
// gosec finds it by literal text, in any comment.
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
		kdf  KDF
	}

	// The negative cases run everywhere. The over-range cases are APPENDED
	// only where an int can actually exceed MaxUint32.
	//
	// This is not decoration and the comment used to be a lie: an earlier
	// version said the over-range cases "are not run" on 32-bit and nothing
	// enforced it, while canExceedUint32 sat unused three functions away. On a
	// 32-bit target aboveUint32() clamps to MaxInt, which IS representable as
	// a uint32 -- so the guard accepts it and argon2 is asked for 2.1 billion
	// iterations, or two terabytes. The suite would hang or be killed on an
	// architecture this PR added a CI leg for.
	//
	// A case that cannot exist on a platform is INEXPRESSIBLE there, not
	// skipped -- but the difference only holds if something actually omits it.
	// Prose asserting a property the code does not have is the shape this
	// branch has now produced three times.
	cases := []costCase{
		{"negative time", KDF{Time: &neg, Memory: &mem, CPUs: &ok}},
		{"negative memory", KDF{Time: &ok, Memory: &neg, CPUs: &ok}},
		{"negative cpus", KDF{Time: &ok, Memory: &mem, CPUs: &neg}},
	}
	if canExceedUint32() {
		cases = append(cases,
			costCase{"time above MaxUint32", KDF{Time: &big, Memory: &mem, CPUs: &ok}},
			costCase{"memory above MaxUint32", KDF{Time: &ok, Memory: &big, CPUs: &ok}},
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

// TestANegativeCostIsRefusedAsTooSmallNotTooLarge pins the ORDER of the two
// guards, which is not visible from either one alone.
//
// The representable-range check uses uint64 on the operand, and uint64(-1) is
// enormous. If it ran first, a negative would be refused by the MAXIMUM branch
// and told it is too large: the right refusal with the wrong diagnosis, sending
// the next reader to the opposite end of the range.
//
// Both orderings produce an error, so a test asserting only "it failed" cannot
// tell them apart -- which is why this asserts the REASON. A later tidy-up that
// hoists the range check fails here rather than silently degrading the message.
func TestANegativeCostIsRefusedAsTooSmallNotTooLarge(t *testing.T) {
	neg := -1
	ok := 4
	mem := 1048576

	for fname, derive := range argon2Derivations {
		for _, tc := range []struct {
			name string
			kdf  KDF
		}{
			{"time", KDF{Time: &neg, Memory: &mem, CPUs: &ok}},
			{"memory", KDF{Time: &ok, Memory: &neg, CPUs: &ok}},
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

// TestEveryArgon2DerivationRefusesAKeySizeItCannotRepresent is the THIRD field
// on that conversion line, and the one whose justification was false.
//
// The old comment said a key longer than 4 GiB "would exhaust memory first".
// MEASURED: it does not. The truncation happens BEFORE argon2 allocates, so a
// request for 4294967300 bytes returned a FOUR BYTE KEY and no error -- the
// caller asked for a long key and got a short one, silently. That is the
// truncation direction, which succeeds and has no symptom, applied to the one
// field whose value is the key material itself.
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
				kdf := KDF{Time: &time, Memory: &mem, CPUs: &cpus}
				key, err := derive([]byte("pass"), []byte("saltsaltsaltsalt"), &kdf, tc.keySize)
				if err == nil {
					t.Fatalf("%s accepted a %s key size and returned %d bytes -- the caller asked "+
						"for %d and received a key it did not request, with no error",
						fname, tc.name, len(key), tc.keySize)
				}
				// ASSERT THE REASON. uint64(-1) is enormous, so a negative is
				// refused by the MAXIMUM branch too -- the negative branch of
				// u32 exists only to say which end of the range was wrong, and
				// without this assertion deleting it changes nothing that any
				// test can see. Measured: removing it left the suite green.
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
			kdf := KDF{Time: &time, Memory: &mem, CPUs: &cpus}
			if _, err := derive([]byte("pass"), []byte("saltsaltsaltsalt"), &kdf, 32); err != nil {
				t.Fatalf("%s refused an ordinary cost set: %v", fname, err)
			}
		})
	}
}

// TestKeyslotPlacementRefusesAnUnreadableSiblingExtent is the regression test
// for the silent-overwrite class (#142).
//
// calculateNextKeyslotOffset is the ONLY thing AddKey uses to choose where new
// key material goes, and findFreeKeyslotArea is the only thing ChangeKey uses.
// Both used to SKIP a keyslot whose area offset or size would not parse, which
// silently lowered the maximum -- or removed an extent from the used set -- and
// let the new slot land inside that keyslot's real bytes.
//
// Nothing downstream catches it: keyslotAreaDisjointFrom has two call sites,
// ChangeKey on the OLD area it is about to wipe and the removal path. The new
// offset is checked by nobody, so the write went ahead and reported success
// while destroying another credential's key material.
//
// A comment at the skip asserted that "the overlap checks in AddKey are what
// refuse that". There are no such checks. That comment is why this survived
// review, and it is deleted by the same change these cases cover.
func TestKeyslotPlacementRefusesAnUnreadableSiblingExtent(t *testing.T) {
	hdr := &LUKS2BinaryHeader{HeaderSize: LUKS2HeaderMinSize}
	const start int64 = 2 * LUKS2HeaderMinSize

	good := &Keyslot{Type: "luks2", Area: &KeyslotArea{Offset: formatSize(start), Size: formatSize(0x40000)}}
	md := func(ks map[string]*Keyslot) *LUKS2Metadata {
		return &LUKS2Metadata{Keyslots: ks, Config: &Config{KeyslotsSize: formatSize(0x200000)}}
	}

	// THE POSITIVE CONTROL FIRST. Without it, every case below is also
	// satisfied by a function that refuses everything -- which would make the
	// library unable to add or change a key at all.
	t.Run("an ordinary container still places a keyslot", func(t *testing.T) {
		m := md(map[string]*Keyslot{"0": good})
		if _, err := calculateNextKeyslotOffset(m, start); err != nil {
			t.Fatalf("calculateNextKeyslotOffset on a healthy container = %v, want success", err)
		}
		if _, err := findFreeKeyslotArea(hdr, m, 0x40000); err != nil {
			t.Fatalf("findFreeKeyslotArea on a healthy container = %v, want success", err)
		}
	})

	for _, tc := range []struct {
		name string
		bad  *Keyslot
	}{
		{"an unparseable area offset", &Keyslot{Type: "luks2", Area: &KeyslotArea{Offset: "not-a-size", Size: formatSize(0x40000)}}},
		{"an unparseable area size", &Keyslot{Type: "luks2", Area: &KeyslotArea{Offset: formatSize(start), Size: "enormous"}}},
	} {
		t.Run(tc.name+" is refused by AddKey's placement", func(t *testing.T) {
			m := md(map[string]*Keyslot{"0": good, "3": tc.bad})
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
			m := md(map[string]*Keyslot{"0": good, "3": tc.bad})
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

	// A DECLARED empty extent is not an unreadable one. It parsed; it occupies
	// nothing to avoid. Refusing it would reject containers that are fine.
	t.Run("a zero-size area is not an unreadable one", func(t *testing.T) {
		m := md(map[string]*Keyslot{
			"0": good,
			"3": {Type: "luks2", Area: &KeyslotArea{Offset: formatSize(start + 0x100000), Size: formatSize(0)}},
		})
		if _, err := findFreeKeyslotArea(hdr, m, 0x40000); err != nil {
			t.Fatalf("findFreeKeyslotArea refused a zero-size extent: %v", err)
		}
	})
}

// TestCanonicalKeyslotID pins the addressability rule against what cryptsetup
// 2.7.0 actually does, measured on crafted headers rather than assumed.
//
// The 31/32 pair is the boundary and is not decoration: cryptsetup lists a
// keyslot at "31" and silently omits one at "32", so LUKS2MaxKeyslots is where
// addressability stops. "007" and "+3" parse with Atoi to numbers in range and
// are still unreachable, which is why the round trip is checked and not just
// the parse.
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
		id, ok := canonicalKeyslotID(tc.key)
		if ok != tc.wantOK {
			t.Errorf("canonicalKeyslotID(%q) ok = %v, want %v", tc.key, ok, tc.wantOK)
			continue
		}
		if ok && id != tc.id {
			t.Errorf("canonicalKeyslotID(%q) = %d, want %d", tc.key, id, tc.id)
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

	// A NEW credential too short for the policy, and an EXISTING one nothing
	// can open a keyslot with -- the two refusals are different since #249
	// (A7), because an existing credential is not this package's to judge.
	type call func(device string) error
	type refusal struct {
		call call
		want error
	}
	newTooShort := func(c call) refusal { return refusal{c, ErrPassphraseTooShort} }
	existingEmpty := func(c call) refusal { return refusal{c, ErrCredentialEmpty} }
	entryPoints := map[string]struct {
		valid        call
		passphrases  []refusal // each with exactly one passphrase argument refused
		keyslotRange []call    // each with exactly one keyslot number out of range
	}{
		"TestKey": {
			valid:       func(d string) error { return TestKey(d, good) },
			passphrases: []refusal{existingEmpty(func(d string) error { return TestKey(d, nil) })},
		},
		"AddKey": {
			valid: func(d string) error { _, err := AddKey(d, good, other, fipsSafeAddKeyOptions()); return err },
			passphrases: []refusal{
				existingEmpty(func(d string) error { _, err := AddKey(d, nil, other, fipsSafeAddKeyOptions()); return err }),
				newTooShort(func(d string) error { _, err := AddKey(d, good, short, fipsSafeAddKeyOptions()); return err }),
			},
		},
		"RemoveKey": {
			valid:        func(d string) error { return RemoveKey(d, good, 0) },
			passphrases:  []refusal{existingEmpty(func(d string) error { return RemoveKey(d, nil, 0) })},
			keyslotRange: []call{func(d string) error { return RemoveKey(d, good, -1) }, func(d string) error { return RemoveKey(d, good, MaxKeyslots) }},
		},
		"KillSlot": {
			valid:        func(d string) error { return KillSlot(d, good, 0) },
			passphrases:  []refusal{existingEmpty(func(d string) error { return KillSlot(d, nil, 0) })},
			keyslotRange: []call{func(d string) error { return KillSlot(d, good, -1) }, func(d string) error { return KillSlot(d, good, MaxKeyslots) }},
		},
		"ChangeKey": {
			valid: func(d string) error { return ChangeKey(d, good, other, 0) },
			passphrases: []refusal{
				existingEmpty(func(d string) error { return ChangeKey(d, nil, other, 0) }),
				newTooShort(func(d string) error { return ChangeKey(d, good, short, 0) }),
			},
			keyslotRange: []call{func(d string) error { return ChangeKey(d, good, other, -1) }, func(d string) error { return ChangeKey(d, good, other, MaxKeyslots) }},
		},
		"KillKeyslot": {
			valid:        func(d string) error { return KillKeyslot(d, 0) },
			keyslotRange: []call{func(d string) error { return KillKeyslot(d, -1) }, func(d string) error { return KillKeyslot(d, MaxKeyslots) }},
		},
		"ListKeyslots": {
			valid: func(d string) error { _, err := ListKeyslots(d); return err },
		},
	}

	for name, ep := range entryPoints {
		t.Run(name, func(t *testing.T) {
			if err := ep.valid(""); !errors.Is(err, ErrInvalidPath) {
				t.Errorf("an empty path: %v, want ErrInvalidPath", err)
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
