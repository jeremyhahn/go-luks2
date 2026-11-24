// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"errors"
	"github.com/jeremyhahn/go-luks2/internal/fips"
	"os"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/areacipher"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// For each damaged shape the unlock path refuses the keyslot and the removal guard does not count it.

// damagedSibling is one way to make a keyslot that reads as a keyslot and can
// open nothing. `apply` is handed the whole metadata as well as the sibling,
// because one shape -- a keyslot no digest attests -- is damage to the header's
// statement about the slot rather than to the slot.
type damagedSibling struct {
	name  string
	apply func(metadata *header.Metadata, sibling *header.Keyslot)
}

// unopenableKeyslotShapes are keyslots well-formed enough to count but unable to yield a key.
var unopenableKeyslotShapes = []damagedSibling{
	{
		// #71. `reencrypt` is legitimate metadata recording an in-progress
		// reencryption, so it must be preserved -- and no unlock path will try
		// it. It reads as a keyslot to len(metadata.Keyslots).
		name: "a reencrypt keyslot",
		apply: func(_ *header.Metadata, sibling *header.Keyslot) {
			sibling.Type = "reencrypt"
		},
	},
	{
		// #37, the shape that reproduced permanent data loss.
		name: "a luks2 keyslot with no anti-forensic object",
		apply: func(_ *header.Metadata, sibling *header.Keyslot) {
			sibling.AF = nil
		},
	},
	{
		name: "a luks2 keyslot with no kdf object",
		apply: func(_ *header.Metadata, sibling *header.Keyslot) {
			sibling.KDF = nil
		},
	},
	{
		// #45: the area cannot hold the AF material the keyslot declares, so
		// the merge can never be satisfied.
		name: "an area smaller than the keyslot's own AF split",
		apply: func(_ *header.Metadata, sibling *header.Keyslot) {
			sibling.Area.Size = "4096"
		},
	},
	{
		// #45: the rejection lived as an inline literal inside the XTS transform and
		// nothing else could consult it.
		name: "an area cipher nothing implements",
		apply: func(_ *header.Metadata, sibling *header.Keyslot) {
			sibling.Area.Encryption = "serpent-xts-plain64"
		},
	},
	{
		// #45: resolved inside the anti-forensic merge.
		name: "an anti-forensic hash nothing implements",
		apply: func(_ *header.Metadata, sibling *header.Keyslot) {
			sibling.AF.Hash = "nosuchhash"
		},
	},
	{
		// #45: resolved inside the derivation.
		name: "a PBKDF2 hash nothing implements",
		apply: func(_ *header.Metadata, sibling *header.Keyslot) {
			sibling.KDF.Hash = "nosuchhash"
		},
	},
	{
		// #45: decoded inside the derivation.
		name: "a KDF salt that is not base64",
		apply: func(_ *header.Metadata, sibling *header.Keyslot) {
			sibling.KDF.Salt = "this is not base64!!"
		},
	},
	{
		name: "a KDF type nothing implements",
		apply: func(_ *header.Metadata, sibling *header.Keyslot) {
			sibling.KDF.Type = "scrypt"
		},
	},
	{
		// #45: an Argon2 keyslot with no parallelism. Written as argon2id so
		// the cost fields are the ones actually consulted.
		name: "an argon2 KDF with a parallelism outside the accepted range",
		apply: func(_ *header.Metadata, sibling *header.Keyslot) {
			zero, four, memory := 0, 4, 65536
			sibling.KDF.Type = "argon2id"
			sibling.KDF.Iterations = nil
			sibling.KDF.Time = &four
			sibling.KDF.Memory = &memory
			sibling.KDF.CPUs = &zero
		},
	},
	{
		// A cost ceiling this package applies before spending it.
		name: "a PBKDF2 iteration count past the accepted ceiling",
		apply: func(_ *header.Metadata, sibling *header.Keyslot) {
			absurd := header.MaxKDFIterations + 1
			sibling.KDF.Iterations = &absurd
		},
	},
	{
		// A volume key no AES data cipher can be keyed with. Well-formed by
		// every other measure; its AF merge yields a key nothing can use.
		name: "a volume key size no AES data cipher can use",
		apply: func(_ *header.Metadata, sibling *header.Keyslot) {
			sibling.KeySize = 40
		},
	},
	{
		// verifyMasterKey refuses to authenticate a keyslot no digest names,
		// so a key recovered from it is never returned.
		name: "a keyslot no digest in the header attests",
		apply: func(metadata *header.Metadata, _ *header.Keyslot) {
			for _, digest := range metadata.Digests {
				digest.Keyslots = header.WithoutID(digest.Keyslots, siblingSlotID)
			}
		},
	},
	{
		// The sibling's only digest is not base64, so it can never be authenticated; keyslot 0 stays openable.
		name: "a keyslot whose only digest cannot be evaluated",
		apply: func(metadata *header.Metadata, _ *header.Keyslot) {
			for _, digest := range metadata.Digests {
				digest.Keyslots = header.WithoutID(digest.Keyslots, siblingSlotID)
			}
			metadata.Digests["9"] = &header.Digest{
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       encodeBase64([]byte("removal-guard-salt")),
				Iterations: 1000,
				Digest:     "this is not base64 !!!",
				Keyslots:   []string{siblingSlotID},
				Segments:   []string{"0"},
			}
		},
	},
	{
		// The same fail-open through a different member of the digest screen:
		// a hash nothing implements, so the length the derivation must match
		// cannot even be established.
		name: "a keyslot whose only digest declares a hash nothing implements",
		apply: func(metadata *header.Metadata, _ *header.Keyslot) {
			for _, digest := range metadata.Digests {
				digest.Keyslots = header.WithoutID(digest.Keyslots, siblingSlotID)
			}
			metadata.Digests["9"] = &header.Digest{
				Type:       "pbkdf2",
				Hash:       "md5",
				Salt:       encodeBase64([]byte("removal-guard-salt")),
				Iterations: 1000,
				Digest:     encodeBase64(make([]byte, 32)),
				Keyslots:   []string{siblingSlotID},
				Segments:   []string{"0"},
			}
		},
	},
	{
		// And through the cost ceiling, which is the digest KDF rather than the
		// keyslot's -- the one that is easy to miss because it is not where a
		// reader looks for a keyslot's cost.
		name: "a keyslot whose only digest costs more than a header may ask",
		apply: func(metadata *header.Metadata, _ *header.Keyslot) {
			for _, digest := range metadata.Digests {
				digest.Keyslots = header.WithoutID(digest.Keyslots, siblingSlotID)
			}
			metadata.Digests["9"] = &header.Digest{
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       encodeBase64([]byte("removal-guard-salt")),
				Iterations: header.MaxKDFIterations + 1,
				Digest:     encodeBase64(make([]byte, 32)),
				Keyslots:   []string{siblingSlotID},
				Segments:   []string{"0"},
			}
		},
	},
	{
		// The area lies past the end of the device, so the unlock's ReadAt can
		// never return the material. Counted as a survivor whenever the bound
		// could not be established -- which, before the measurement was fixed,
		// was every block device.
		name: "a keyslot whose area lies beyond the end of the device",
		apply: func(_ *header.Metadata, sibling *header.Keyslot) {
			sibling.Area.Offset = formatSize(conformanceImageSize)
		},
	},
	{
		name: "an area offset that is not a number",
		apply: func(_ *header.Metadata, sibling *header.Keyslot) {
			sibling.Area.Offset = "0x8000"
		},
	},
	{
		// parseSize accepts this, but the guard does arithmetic with it.
		name: "a negative area offset",
		apply: func(_ *header.Metadata, sibling *header.Keyslot) {
			sibling.Area.Offset = "-4096"
		},
	},
}

// siblingSlotID is where every fixture in this file puts the second keyslot.
const siblingSlotID = "1"

// volumeWithSibling adds a second keyslot copied from the first, over a zeroed disjoint area, with damage applied (nil for the control).
func volumeWithSibling(t *testing.T, name string, damage func(*header.Metadata, *header.Keyslot)) string {
	t.Helper()
	return restoreVolume(t, name, goldenSiblingVolume(t, damage))
}

// goldenVolumePrefix is how much of a fixture image is captured: the headers and keyslot areas.
const goldenVolumePrefix = 2 << 20

// goldenSiblingVolume formats the two-keyslot fixture once and returns its bytes for restoreVolume; costs are unchanged.
func goldenSiblingVolume(t *testing.T, damage func(*header.Metadata, *header.Keyslot)) []byte {
	t.Helper()
	return goldenBytes(t, buildVolumeWithSibling(t, "golden-sibling.img", damage))
}

// goldenBytes captures the leading, interesting part of a fixture image.
func goldenBytes(t *testing.T, device string) []byte {
	t.Helper()

	f, err := os.Open(device)
	if err != nil {
		t.Fatalf("failed to open the golden volume: %v", err)
	}
	defer func() { _ = f.Close() }()

	golden := make([]byte, goldenVolumePrefix)
	if _, err := f.ReadAt(golden, 0); err != nil {
		t.Fatalf("failed to read the golden volume: %v", err)
	}
	return golden
}

// restoreVolume stamps golden bytes onto a fresh sparse image for one subtest.
func restoreVolume(t *testing.T, name string, golden []byte) string {
	t.Helper()

	device := newImage(t, name)
	f, err := os.OpenFile(device, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("failed to open the restored volume: %v", err)
	}
	defer func() { _ = f.Close() }() // failure paths only: success closes, checked, below

	if _, err := f.WriteAt(golden, 0); err != nil {
		t.Fatalf("failed to restore the golden volume: %v", err)
	}
	// Closed, not fsynced: see stampImagePrefix.
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close the restored volume: %v", err)
	}
	return device
}

func buildVolumeWithSibling(t *testing.T, name string, damage func(*header.Metadata, *header.Keyslot)) string {
	t.Helper()

	path := newImage(t, name)
	formatWithLibrary(t, path)

	hdr, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	original := metadata.Keyslots["0"]
	sibling := cloneKeyslot(original)

	// Placed immediately after slot 0's area, aligned, so the two are disjoint:
	// an overlap would make every case in this table pass through the overlap
	// guard instead of the one it is testing.
	offset, err := parseSize(original.Area.Offset)
	if err != nil {
		t.Fatalf("the formatted keyslot has an unreadable area offset: %v", err)
	}
	size, err := parseSize(original.Area.Size)
	if err != nil {
		t.Fatalf("the formatted keyslot has an unreadable area size: %v", err)
	}
	sibling.Area.Offset = formatSize(alignTo(offset+size, keyslotAreaAlignment))
	metadata.Keyslots[siblingSlotID] = sibling

	for _, digest := range metadata.Digests {
		digest.Keyslots = append(digest.Keyslots, siblingSlotID)
	}

	if damage != nil {
		damage(metadata, sibling)
	}

	if err := writeHeaderUnvalidated(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the fixture header: %v", err)
	}
	return path
}

// TestTheUnlockPathRefusesEveryShapeTheRemovalGuardMustNotCount: each shape is refused by unlockKeyslot with the correct passphrase.
func TestTheUnlockPathRefusesEveryShapeTheRemovalGuardMustNotCount(t *testing.T) {
	defer parallel(t)()

	for _, shape := range unopenableKeyslotShapes {
		t.Run(shape.name, func(t *testing.T) {
			path := volumeWithSibling(t, "yardstick.img", shape.apply)

			hdr, metadata, err := readHeaderForTest(path)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			sibling, present := metadata.Keyslots[siblingSlotID]
			if !present {
				t.Fatalf("the fixture lost its sibling keyslot")
			}

			key, err := unlockKeyslot(context.Background(), path, siblingSlotID, []byte(conformancePassphrase), sibling, metadata.Digests, testVolumeSys())
			if err == nil {
				mustDestroy(t, key)
				t.Fatal("the unlock path accepted a keyslot this test asserts it cannot open; the shape is not damaged the way it claims")
			}

			// And the guard must reach the same verdict, off the same metadata.
			f, err := os.Open(path)
			if err != nil {
				t.Fatalf("failed to open the fixture: %v", err)
			}
			defer func() { _ = f.Close() }()

			if keyslotCanOpenVolume(f, hdr, metadata, siblingSlotID, deviceSizeFromFile) {
				t.Fatalf("the removal guard counts a keyslot the unlock path refuses (%v); counting one too many is how a removal destroys the last working credential", err)
			}
		})
	}
}

// TestTheRemovalGuardCountsTheSlotsTheUnlockPathWouldOpen: the positive control; an undamaged sibling over zeros is still counted.
func TestTheRemovalGuardCountsTheSlotsTheUnlockPathWouldOpen(t *testing.T) {
	defer parallel(t)()

	path := volumeWithSibling(t, "control.img", nil)

	hdr, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open the fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	for _, id := range []string{"0", siblingSlotID} {
		if !keyslotCanOpenVolume(f, hdr, metadata, id, deviceSizeFromFile) {
			t.Fatalf("keyslot %s is not counted, so every refusal this file asserts could come from a predicate that counts nothing", id)
		}
	}

	if got := usableKeyslotsAfterRemoving(f, hdr, metadata, "0", deviceSizeFromFile); got != 1 {
		t.Fatalf("removing keyslot 0 leaves %d counted keyslots, want 1", got)
	}
	if got := usableKeyslotsAfterRemoving(f, hdr, metadata, "nosuchslot", deviceSizeFromFile); got != 2 {
		t.Fatalf("removing a keyslot that does not exist leaves %d counted keyslots, want 2", got)
	}
}

// TestScreenKeyslotAcceptsAKeyslotThisLibraryWrote is the other half of the
// control: the screen must not refuse the ordinary case, and it must hand back
// values the unlock path can use.
func TestScreenKeyslotAcceptsAKeyslotThisLibraryWrote(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "screen-accepts.img")
	formatWithLibrary(t, path)

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	keyslot := metadata.Keyslots["0"]

	plan, err := screenKeyslot("0", keyslot, metadata.Digests, fips.Probe)
	if err != nil {
		t.Fatalf("the screen refused a keyslot this library just wrote: %v", err)
	}

	wantOffset, err := parseSize(keyslot.Area.Offset)
	if err != nil {
		t.Fatalf("unreadable area offset: %v", err)
	}
	wantSize, err := parseSize(keyslot.Area.Size)
	if err != nil {
		t.Fatalf("unreadable area size: %v", err)
	}

	if plan.areaOffset != wantOffset || plan.areaSize != wantSize {
		t.Fatalf("plan describes area %d..%d, want %d..%d",
			plan.areaOffset, plan.areaOffset+plan.areaSize, wantOffset, wantOffset+wantSize)
	}
	if plan.area != areacipher.Default() {
		t.Fatalf("plan names transform %+v, want AES-XTS plain64", plan.area)
	}
	if want := keyslot.KeySize * keyslot.AF.Stripes; plan.afSplitSize != want {
		t.Fatalf("plan needs %d bytes of AF material, want %d", plan.afSplitSize, want)
	}
	if plan.decryptLen < int64(plan.afSplitSize) || plan.decryptLen%keyslotSectorSize != 0 {
		t.Fatalf("plan decrypts %d bytes, which is not the %d bytes of AF material rounded up to a whole %d-byte sector",
			plan.decryptLen, plan.afSplitSize, keyslotSectorSize)
	}
	if plan.decryptLen > plan.areaSize {
		t.Fatalf("plan decrypts %d bytes out of an area of %d", plan.decryptLen, plan.areaSize)
	}
}

// TestScreenKeyslotKeepsTheDigestBindingClassification: a keyslot no digest attests stays ErrInvalidHeader.
func TestScreenKeyslotKeepsTheDigestBindingClassification(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "screen-digest-binding.img")
	formatWithLibrary(t, path)

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	for _, digest := range metadata.Digests {
		digest.Keyslots = nil
	}

	_, err = screenKeyslot("0", metadata.Keyslots["0"], metadata.Digests, fips.Probe)
	if err == nil {
		t.Fatal("the screen accepted a keyslot no digest authenticates")
	}
	if !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("a keyslot no digest names is not reported as a header fault: %v", err)
	}
	if errors.Is(err, ErrWrongKey) {
		t.Fatalf("a keyslot no digest names was reported as a failed verification: %v", err)
	}
}

// TestValidateXTSKeySize pins the sizes AES-XTS accepts, because a wrong answer
// here is a guard that either counts an unopenable keyslot or refuses a working
// one. XTS halves its key and gives each half to AES, so the legal sizes are
// exactly twice AES's 16, 24 and 32.
func TestValidateXTSKeySize(t *testing.T) {
	for _, tc := range []struct {
		keySize int
		wantOK  bool
	}{
		{32, true}, {48, true}, {64, true},
		{0, false}, {16, false}, {31, false}, {40, false}, {63, false}, {65, false}, {128, false},
	} {
		err := areacipher.ValidateXTSKeySize(tc.keySize)
		if tc.wantOK && err != nil {
			t.Errorf("key size %d rejected: %v", tc.keySize, err)
		}
		if !tc.wantOK && err == nil {
			t.Errorf("key size %d accepted; AES-XTS cannot be keyed with it", tc.keySize)
		}
	}
}

// TestValidateKeyslotRefusesAreaArithmeticThatCannotBeReasonedAbout: a negative start or a wrapping sum is refused.
func TestValidateKeyslotRefusesAreaArithmeticThatCannotBeReasonedAbout(t *testing.T) {
	base := func() *header.Keyslot {
		stripes := header.AFStripes
		return &header.Keyslot{
			Type:    "luks2",
			KeySize: 64,
			Area:    &header.KeyslotArea{Type: "raw", Offset: "32768", Size: "258048", Encryption: "aes-xts-plain64"},
			KDF:     &header.KDF{Type: "pbkdf2", Hash: "sha256", Salt: "", Iterations: intPtr(1000)},
			AF:      &header.AntiForensic{Type: "luks1", Stripes: stripes, Hash: "sha256"},
		}
	}

	if err := header.ValidateKeyslot("0", base()); err != nil {
		t.Fatalf("the control keyslot is refused, so the cases below prove nothing: %v", err)
	}

	negative := base()
	negative.Area.Offset = "-4096"
	if err := header.ValidateKeyslot("0", negative); !errors.Is(err, ErrKeyslotNotFound) {
		t.Fatalf("a negative area offset is accepted: %v", err)
	}

	// 2^63-1 minus a fraction of the area size: the sum wraps negative.
	overflowing := base()
	overflowing.Area.Offset = "9223372036854775807"
	if err := header.ValidateKeyslot("0", overflowing); !errors.Is(err, ErrKeyslotNotFound) {
		t.Fatalf("an area whose offset plus size overflows int64 is accepted: %v", err)
	}
}

// TestAKeyslotWithOneUsableDigestIsStillCounted: one usable digest beside a bad one suffices.
func TestAKeyslotWithOneUsableDigestIsStillCounted(t *testing.T) {
	defer parallel(t)()

	device := volumeWithSibling(t, "one-good-digest.img", func(metadata *header.Metadata, _ *header.Keyslot) {
		metadata.Digests["9"] = &header.Digest{
			Type:       "pbkdf2",
			Hash:       "sha256",
			Salt:       encodeBase64([]byte("removal-guard-salt")),
			Iterations: 1000,
			Digest:     "this is not base64 !!!",
			Keyslots:   []string{"0", siblingSlotID},
			Segments:   []string{"0"},
		}
	})

	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	f, err := os.Open(device)
	if err != nil {
		t.Fatalf("failed to open the fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	for _, id := range []string{"0", siblingSlotID} {
		if !keyslotCanOpenVolume(f, hdr, metadata, id, deviceSizeFromFile) {
			t.Fatalf("keyslot %s stopped being counted because ONE of its digests is unusable; the screen must require any, not all", id)
		}
	}

	// And end to end: the volume still opens, so the count is not merely
	// self-consistent.
	if err := testKeyForTest(device, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("the volume no longer opens with an unusable digest alongside a usable one: %v", err)
	}
}

// TestTheRemovalGuardRefusesWhenTheDeviceSizeCannotBeEstablished: through the measurement seam, an unmeasurable device is refused.
func TestTheRemovalGuardRefusesWhenTheDeviceSizeCannotBeEstablished(t *testing.T) {
	passphrase := []byte(conformancePassphrase)
	golden := goldenSiblingVolume(t, nil)

	// What a block device answers Stat with, which is the case the old code
	// read as "no bound to check".
	unmeasurable := func(*os.File) (int64, error) { return 0, nil }

	paths := []struct {
		name   string
		remove func(device string, passphrase []byte, slot int) error
	}{
		{"RemoveKey", func(device string, passphrase []byte, slot int) error {
			sys := testVolumeSys()
			sys.measureDeviceSize = unmeasurable
			return removeKeyForTest(device, passphrase, slot, withTestSys(sys))
		}},
		{"KillSlot", func(device string, passphrase []byte, slot int) error {
			sys := testVolumeSys()
			sys.measureDeviceSize = unmeasurable
			return killSlotForTest(device, passphrase, slot, withTestSys(sys))
		}},
		{"RemoveKeyslot", func(device string, _ []byte, slot int) error {
			v, err := Open(context.Background(), device, withTestSys(testVolumeSys()))
			if err != nil {
				return err
			}
			defer func() { _ = v.Close() }()
			v.sys.measureDeviceSize = unmeasurable
			return v.RemoveKeyslot(context.Background(), slot)
		}},
	}

	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			device := restoreVolume(t, "unmeasurable.img", golden)
			offset, size := keyslotAreaExtent(t, device, "0")
			before := readAreaBytes(t, device, offset, size)

			err := path.remove(device, passphrase, 0)
			if err == nil {
				t.Fatal("a removal was authorized on a device whose size could not be established")
			}

			// The damage plane, not the return value: a path that zeroed the
			// area and then reported an error satisfies the check above.
			if !bytes.Equal(before, readAreaBytes(t, device, offset, size)) {
				t.Fatal("the removal failed AND the key material was destroyed")
			}
		})
	}
}

// TestDeviceSizeIsMeasuredNotAssumed is the control for the seam above: with
// the real measurement in place, an ordinary container is measured correctly
// and removals proceed. Without it, the test above would pass against a guard
// that refuses everything.
func TestDeviceSizeIsMeasuredNotAssumed(t *testing.T) {
	device := newImage(t, "measured.img")
	formatWithLibrary(t, device)

	f, err := os.Open(device)
	if err != nil {
		t.Fatalf("failed to open the image: %v", err)
	}
	defer func() { _ = f.Close() }()

	size, err := deviceSizeFromFile(f)
	if err != nil {
		t.Fatalf("failed to measure the image: %v", err)
	}
	if size != conformanceImageSize {
		t.Fatalf("measured %d bytes, want %d", size, conformanceImageSize)
	}

	// And the bound it feeds accepts an area inside the device and refuses one
	// past its end -- both halves, so neither a permissive nor a rejecting
	// implementation passes.
	if err := checkAreaWithinDevice(f, 0x8000, 0x40000, deviceSizeFromFile); err != nil {
		t.Fatalf("a keyslot area well inside the device was refused: %v", err)
	}
	if err := checkAreaWithinDevice(f, conformanceImageSize, 0x40000, deviceSizeFromFile); !errors.Is(err, ErrKeyslotNotFound) {
		t.Fatalf("a keyslot area past the end of the device was accepted: %v", err)
	}
}

// TestScreenDigestNeverAcceptsWhatTheDerivationRefuses compares the screen with the derivation in the process's FIPS mode.
func TestScreenDigestNeverAcceptsWhatTheDerivationRefuses(t *testing.T) {
	defer parallel(t)()

	shapes := unusableDigests(t)
	shapes["a usable digest"] = usableDigest(t, []byte("digest-scan-master-key-32-bytes!"), 32)
	// The hash that is legal outside FIPS 140-3 and refused inside it. Its
	// length is sha1's, so the length check cannot be what decides it and the
	// hash question is isolated.
	shapes["a sha1 digest, which FIPS mode refuses"] = &header.Digest{
		Type:       "pbkdf2",
		Hash:       "sha1",
		Salt:       encodeBase64([]byte("digest-screen-salt")),
		Iterations: 1000,
		Digest:     encodeBase64(make([]byte, 20)),
	}

	accepted := 0
	for name, digest := range shapes {
		t.Run(name, func(t *testing.T) {
			expected, _, screenErr := screenDigest(digest, fips.Probe)
			deriveLen := len(expected)
			clearBytes(expected)
			if deriveLen == 0 {
				deriveLen = 32
			}

			if screenErr != nil {
				// The screen may be stricter; skip the yardstick, which would ask PBKDF2 for huge outputs.
				return
			}
			accepted++

			// The yardstick: the derivation verifyMasterKey runs.
			kdf := &header.KDF{
				Type:       digest.Type,
				Hash:       digest.Hash,
				Salt:       digest.Salt,
				Iterations: &digest.Iterations,
			}
			derived, deriveErr := deriveKeyPlain([]byte("yardstick-key"), kdf, deriveLen)
			clearBytes(derived)

			if deriveErr != nil {
				t.Fatalf("the screen ACCEPTS a digest the derivation refuses (%v); the removal guard would count a keyslot this digest can never authenticate", deriveErr)
			}
		})
	}

	// Without this the assertion above is satisfied by a screen that refuses
	// everything, which would refuse every volume rather than lose one -- safe,
	// and still broken.
	if accepted == 0 {
		t.Fatal("the screen accepted no digest at all, so the implication it asserts is vacuous")
	}
}

// TestScreenKeyslotRefusalsAreTypedAndAttributed pins that every refusal
// screenKeyslot makes on the keyslot's own account is an InvalidKeyslotError
// naming the keyslot, still matching ErrInvalidKeyslot -- which keeps the unlock
// scan moving -- and still reaching whatever cause it wraps.
func TestScreenKeyslotRefusalsAreTypedAndAttributed(t *testing.T) {
	path := newImage(t, "screen-typed.img")
	formatWithLibrary(t, path)

	cases := []struct {
		name      string
		nilSlot   bool
		apply     func(*header.Keyslot)
		wantCause error
	}{
		{name: "a null keyslot", nilSlot: true},
		{name: "a reencrypt keyslot", apply: func(ks *header.Keyslot) { ks.Type = "reencrypt" }},
		{name: "a PBKDF2 iteration count past the accepted ceiling", apply: func(ks *header.Keyslot) {
			absurd := header.MaxKDFIterations + 1
			ks.KDF.Iterations = &absurd
		}},
		{name: "a KDF type nothing implements", apply: func(ks *header.Keyslot) { ks.KDF.Type = "scrypt" }},
		{name: "a volume key size no AES data cipher can use", apply: func(ks *header.Keyslot) { ks.KeySize = 40 }},
		{name: "an anti-forensic hash nothing implements", apply: func(ks *header.Keyslot) { ks.AF.Hash = "nosuchhash" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, metadata, err := readHeaderForTest(path)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			keyslot := metadata.Keyslots["0"]
			if tc.nilSlot {
				keyslot = nil
			} else {
				tc.apply(keyslot)
			}

			_, err = screenKeyslot("0", keyslot, metadata.Digests, fips.Probe)
			if err == nil {
				t.Fatal("the screen accepted the keyslot")
			}
			if !errors.Is(err, ErrKeyslotNotFound) {
				t.Fatalf("refusal does not match ErrInvalidKeyslot: %v", err)
			}
			var typed *Error
			if !errors.As(err, &typed) {
				t.Fatalf("refusal is %T, want *Error: %v", err, err)
			}
			if !strings.Contains(typed.Detail, `"0"`) {
				t.Fatalf("refusal does not name keyslot %q: %q", "0", typed.Detail)
			}
			if typed.Detail == "" {
				t.Fatal("refusal carries no detail")
			}
		})
	}
}

// TestInvalidKeyslotErrorKeepsItsCause pins that the classified wrapper
// neither reclassifies nor hides what it wraps.
func TestInvalidKeyslotErrorKeepsItsCause(t *testing.T) {
	err := error(&Error{Kind: ErrKeyslotNotFound, Detail: "keyslot 3 declares an anti-forensic", Err: ErrUnsupported})
	if !errors.Is(err, ErrKeyslotNotFound) || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("wrapper lost a classification: %v", err)
	}
	if errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrapper matches a sentinel it does not stand for: %v", err)
	}
	want := ErrKeyslotNotFound.Error() + `: keyslot 3 declares an anti-forensic: ` + ErrUnsupported.Error()
	if err.Error() != want {
		t.Fatalf("message is %q, want %q", err.Error(), want)
	}

	bare := &Error{Kind: ErrKeyslotNotFound, Detail: `luks2 keyslot "3": is null`}
	if got, want := bare.Error(), ErrKeyslotNotFound.Error()+`: luks2 keyslot "3": is null`; got != want {
		t.Fatalf("message is %q, want %q", got, want)
	}
	if len(bare.Unwrap()) != 1 {
		t.Fatal("a wrapper with no cause unwraps to more than its Kind")
	}
}
