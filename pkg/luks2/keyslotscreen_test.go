// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// The removal guard and the unlock path must answer ONE question -- can this
// keyslot open this volume? -- and for a long time they answered it separately.
// The guard's copy was wrong three times (#45), and each time the volume paid:
// a keyslot it counted as a survivor could open nothing, so removing the last
// working credential was permitted and reported as a success (#37, #71).
//
// These tests hold the two together. They do not check that the guard has some
// particular list of checks in it; they check that for each damaged shape, the
// UNLOCK PATH refuses the keyslot and the GUARD does not count it -- with the
// unlock path as the yardstick, which is the only way to notice the two
// disagreeing about a shape nobody thought to enumerate.

// damagedSibling is one way to make a keyslot that reads as a keyslot and can
// open nothing. `apply` is handed the whole metadata as well as the sibling,
// because one shape -- a keyslot no digest attests -- is damage to the header's
// statement about the slot rather than to the slot.
type damagedSibling struct {
	name  string
	apply func(metadata *LUKS2Metadata, sibling *Keyslot)
}

// unopenableKeyslotShapes is the set of ways a keyslot can be well-formed
// enough to be counted and unable to yield a key.
//
// Every entry here was a live counting-too-many defect at some point, or is a
// rejection the unlock path makes that no previous version of the guard knew
// about. The last four came out of walking the unlock path rather than out of a
// review finding, which is the point: enumeration from findings is what was
// too narrow three times running.
var unopenableKeyslotShapes = []damagedSibling{
	{
		// #71. `reencrypt` is legitimate metadata recording an in-progress
		// reencryption, so it must be preserved -- and no unlock path will try
		// it. It reads as a keyslot to len(metadata.Keyslots).
		name: "a reencrypt keyslot",
		apply: func(_ *LUKS2Metadata, sibling *Keyslot) {
			sibling.Type = "reencrypt"
		},
	},
	{
		// #37, the shape that reproduced permanent data loss.
		name: "a luks2 keyslot with no anti-forensic object",
		apply: func(_ *LUKS2Metadata, sibling *Keyslot) {
			sibling.AF = nil
		},
	},
	{
		name: "a luks2 keyslot with no kdf object",
		apply: func(_ *LUKS2Metadata, sibling *Keyslot) {
			sibling.KDF = nil
		},
	},
	{
		// #45: the area cannot hold the AF material the keyslot declares, so
		// the merge can never be satisfied.
		name: "an area smaller than the keyslot's own AF split",
		apply: func(_ *LUKS2Metadata, sibling *Keyslot) {
			sibling.Area.Size = "4096"
		},
	},
	{
		// #45: the rejection lived as an inline literal inside xtsSectors and
		// nothing else could consult it.
		name: "an area cipher nothing implements",
		apply: func(_ *LUKS2Metadata, sibling *Keyslot) {
			sibling.Area.Encryption = "serpent-xts-plain64"
		},
	},
	{
		// #45: resolved inside the anti-forensic merge.
		name: "an anti-forensic hash nothing implements",
		apply: func(_ *LUKS2Metadata, sibling *Keyslot) {
			sibling.AF.Hash = "nosuchhash"
		},
	},
	{
		// #45: resolved inside the derivation.
		name: "a PBKDF2 hash nothing implements",
		apply: func(_ *LUKS2Metadata, sibling *Keyslot) {
			sibling.KDF.Hash = "nosuchhash"
		},
	},
	{
		// #45: decoded inside the derivation.
		name: "a KDF salt that is not base64",
		apply: func(_ *LUKS2Metadata, sibling *Keyslot) {
			sibling.KDF.Salt = "this is not base64!!"
		},
	},
	{
		name: "a KDF type nothing implements",
		apply: func(_ *LUKS2Metadata, sibling *Keyslot) {
			sibling.KDF.Type = "scrypt"
		},
	},
	{
		// #45: an Argon2 keyslot with no parallelism. Written as argon2id so
		// the cost fields are the ones actually consulted.
		name: "an argon2 KDF with a parallelism outside the accepted range",
		apply: func(_ *LUKS2Metadata, sibling *Keyslot) {
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
		apply: func(_ *LUKS2Metadata, sibling *Keyslot) {
			absurd := maxKDFIterations + 1
			sibling.KDF.Iterations = &absurd
		},
	},
	{
		// A volume key AES-XTS cannot be keyed with. Well-formed by every
		// other measure, and xts.NewCipher refuses it -- a rejection that lived
		// only inside the cipher constructor, where no guard could see it.
		name: "a volume key size AES-XTS cannot use",
		apply: func(_ *LUKS2Metadata, sibling *Keyslot) {
			sibling.KeySize = 40
		},
	},
	{
		// verifyMasterKey refuses to authenticate a keyslot no digest names,
		// so a key recovered from it is never returned.
		name: "a keyslot no digest in the header attests",
		apply: func(metadata *LUKS2Metadata, _ *Keyslot) {
			for _, digest := range metadata.Digests {
				digest.Keyslots = withoutID(digest.Keyslots, siblingSlotID)
			}
		},
	},
	{
		// ASSOCIATION IS NOT USABILITY, and treating it as such was a
		// fail-open the guard's first version shipped with. The sibling is
		// attested -- by a digest verifyMasterKey will skip, because its value
		// is not base64. It can never be authenticated and could never open the
		// volume, so counting it authorizes destroying the keyslot that works.
		//
		// The digest is given ONLY to the sibling, so keyslot 0 keeps the real
		// one and stays openable; that is what makes this a removal-guard case
		// rather than a broken container.
		name: "a keyslot whose only digest cannot be evaluated",
		apply: func(metadata *LUKS2Metadata, _ *Keyslot) {
			for _, digest := range metadata.Digests {
				digest.Keyslots = withoutID(digest.Keyslots, siblingSlotID)
			}
			metadata.Digests["9"] = &Digest{
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
		apply: func(metadata *LUKS2Metadata, _ *Keyslot) {
			for _, digest := range metadata.Digests {
				digest.Keyslots = withoutID(digest.Keyslots, siblingSlotID)
			}
			metadata.Digests["9"] = &Digest{
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
		apply: func(metadata *LUKS2Metadata, _ *Keyslot) {
			for _, digest := range metadata.Digests {
				digest.Keyslots = withoutID(digest.Keyslots, siblingSlotID)
			}
			metadata.Digests["9"] = &Digest{
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       encodeBase64([]byte("removal-guard-salt")),
				Iterations: maxKDFIterations + 1,
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
		apply: func(_ *LUKS2Metadata, sibling *Keyslot) {
			sibling.Area.Offset = formatSize(conformanceImageSize)
		},
	},
	{
		name: "an area offset that is not a number",
		apply: func(_ *LUKS2Metadata, sibling *Keyslot) {
			sibling.Area.Offset = "0x8000"
		},
	},
	{
		// parseSize is ParseInt, so this parses. Every consumer used to hand it
		// to a syscall that refused it, which is why it survived -- but a guard
		// does ARITHMETIC with it.
		name: "a negative area offset",
		apply: func(_ *LUKS2Metadata, sibling *Keyslot) {
			sibling.Area.Offset = "-4096"
		},
	},
}

// siblingSlotID is where every fixture in this file puts the second keyslot.
const siblingSlotID = "1"

// volumeWithSibling formats a container and gives it a SECOND keyslot whose
// metadata is a copy of the first, in a disjoint area, with `damage` applied.
//
// The sibling's area holds zeros rather than key material, so it cannot open
// the volume whatever its metadata says. That is deliberate and it is what
// makes the control below meaningful: an undamaged sibling is counted by the
// guard and still cannot open anything, which is the irreducible residual the
// guard cannot remove (only trying the passphrase would tell). Everything these
// tests assert is about the shapes the guard CAN see.
//
// damage may be nil, for the control.
func volumeWithSibling(t *testing.T, name string, damage func(*LUKS2Metadata, *Keyslot)) string {
	t.Helper()
	return restoreVolume(t, name, goldenSiblingVolume(t, damage))
}

// goldenVolumePrefix is how much of a fixture image is captured and stamped back.
//
// A formatted container's header copies and every keyslot area these tests
// create live inside the first megabyte -- two 16 KiB headers, then keyslot
// areas of 252 KiB each from offset 0x8000. Everything past that is the zeroed
// data segment, which no fixture writes and no assertion reads, so copying it
// would be a megabyte of nothing per case. 2 MiB leaves generous room for the
// three-keyslot fixtures without making the copy interesting.
const goldenVolumePrefix = 2 << 20

// goldenSiblingVolume formats the two-keyslot fixture ONCE and returns its
// bytes, for restoreVolume to stamp onto a fresh file per case.
//
// This is the idiom the issue/3-secure-buffer branch arrived at after its unit
// package crossed Go's default 600s test timeout on a loaded CI runner, having
// finished comfortably on the developer's box -- load-dependent, and local
// non-reproduction was no more exculpatory there than it is for a race. Measured
// on that branch under -race: Format ~900ms, restoring from golden bytes ~1.5ms.
// The guard tables here are fifteen damage shapes by four removal paths, so a
// format per CASE pays for sixty where fifteen would do.
//
// NOTHING IS MADE CRYPTOGRAPHICALLY CHEAPER by this. The KDF cost, the AF split
// and the XTS pass are exactly what they were; only the number of times they are
// paid changes. Weakening a fixture to buy time is how a control stops catching
// what it was written for.
func goldenSiblingVolume(t *testing.T, damage func(*LUKS2Metadata, *Keyslot)) []byte {
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

// The per-fixture digest cheapening that used to live here is GONE: it is baked
// into the shared golden now (cheapenGoldenDigests, conformance_test.go), so
// every fixture in the package inherits it and the expensive unlock it costs
// is paid once per process rather than once per shape.

func buildVolumeWithSibling(t *testing.T, name string, damage func(*LUKS2Metadata, *Keyslot)) string {
	t.Helper()

	path := newImage(t, name)
	formatWithLibrary(t, path)

	hdr, metadata, err := ReadHeader(path)
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
	sibling.Area.Offset = formatSize(alignTo(offset+size, KeyslotAreaAlignment))
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

// TestTheUnlockPathRefusesEveryShapeTheRemovalGuardMustNotCount is the
// yardstick, and it is measured against the UNLOCK PATH rather than against the
// predicate under test.
//
// #45's whole argument is that a predicate maintained beside unlockKeyslot
// drifts from it. A test that asserted "the guard rejects these fifteen shapes"
// would be a third copy of the same list and would drift with the second. So
// each shape is put through unlockKeyslot with the CORRECT passphrase first: if
// the unlock refuses it, no removal guard may count it, and the next assertion
// is entitled to demand that.
func TestTheUnlockPathRefusesEveryShapeTheRemovalGuardMustNotCount(t *testing.T) {
	defer parallel(t)()

	for _, shape := range unopenableKeyslotShapes {
		t.Run(shape.name, func(t *testing.T) {
			path := volumeWithSibling(t, "yardstick.img", shape.apply)

			hdr, metadata, err := ReadHeader(path)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			sibling, present := metadata.Keyslots[siblingSlotID]
			if !present {
				t.Fatalf("the fixture lost its sibling keyslot")
			}

			key, err := unlockKeyslot(path, siblingSlotID, []byte(conformancePassphrase), sibling, metadata.Digests)
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

			if keyslotCanOpenVolume(f, hdr, metadata, siblingSlotID) {
				t.Fatalf("the removal guard counts a keyslot the unlock path refuses (%v); counting one too many is how a removal destroys the last working credential", err)
			}
		})
	}
}

// TestTheRemovalGuardCountsTheSlotsTheUnlockPathWouldOpen is the positive
// control, and without it every assertion above is satisfied by a predicate
// that returns false unconditionally.
//
// It also pins the direction of the guard's inexactness. The sibling here is
// undamaged metadata over an area of zeros: it cannot actually open the volume,
// and the guard counts it anyway, because only trying the passphrase would tell
// and KillKeyslot has none to try. That residual is documented on
// keyslotCanOpenVolume and it falls on the counting-MORE side; this test states
// it rather than leaving a reader to assume the predicate is exact.
func TestTheRemovalGuardCountsTheSlotsTheUnlockPathWouldOpen(t *testing.T) {
	defer parallel(t)()

	path := volumeWithSibling(t, "control.img", nil)

	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open the fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	for _, id := range []string{"0", siblingSlotID} {
		if !keyslotCanOpenVolume(f, hdr, metadata, id) {
			t.Fatalf("keyslot %s is not counted, so every refusal this file asserts could come from a predicate that counts nothing", id)
		}
	}

	if got := usableKeyslotsAfterRemoving(f, hdr, metadata, "0"); got != 1 {
		t.Fatalf("removing keyslot 0 leaves %d counted keyslots, want 1", got)
	}
	if got := usableKeyslotsAfterRemoving(f, hdr, metadata, "nosuchslot"); got != 2 {
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

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	keyslot := metadata.Keyslots["0"]

	plan, err := screenKeyslot("0", keyslot, metadata.Digests)
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
	if plan.cipherAlgo != "aes" {
		t.Fatalf("plan names cipher %q, want aes", plan.cipherAlgo)
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

// TestScreenKeyslotKeepsTheDigestBindingClassification pins the one rejection
// the screen moves that does NOT carry ErrInvalidKeyslot.
//
// The safety argument for moving rejections earlier is that they are the SAME
// rejections, sooner. A keyslot no digest attests is a header fault -- the
// passphrase may be right and the material intact -- and verifyMasterKey says
// so with ErrInvalidHeader. Restating it as a keyslot fault while moving it
// would have changed what an operator is told, which is the one thing this
// refactor may not do.
func TestScreenKeyslotKeepsTheDigestBindingClassification(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "screen-digest-binding.img")
	formatWithLibrary(t, path)

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	for _, digest := range metadata.Digests {
		digest.Keyslots = nil
	}

	_, err = screenKeyslot("0", metadata.Keyslots["0"], metadata.Digests)
	if err == nil {
		t.Fatal("the screen accepted a keyslot no digest authenticates")
	}
	if !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("a keyslot no digest names is not reported as a header fault: %v", err)
	}
	if errors.Is(err, ErrMasterKeyVerification) {
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
		err := validateXTSKeySize(tc.keySize)
		if tc.wantOK && err != nil {
			t.Errorf("key size %d rejected: %v", tc.keySize, err)
		}
		if !tc.wantOK && err == nil {
			t.Errorf("key size %d accepted; AES-XTS cannot be keyed with it", tc.keySize)
		}
	}
}

// TestValidateKeyslotRefusesAreaArithmeticThatCannotBeReasonedAbout covers the
// two checks harvested out of the issue/3-secure-buffer branch's
// keyslotAreaBounds.
//
// Neither mattered while every consumer handed the offset straight to a syscall
// that refused it. Both matter now that the removal guard computes
// [offset, offset+size) and compares it against other keyslots: a negative
// start intersects nothing, and a sum that wraps is "before everything".
func TestValidateKeyslotRefusesAreaArithmeticThatCannotBeReasonedAbout(t *testing.T) {
	base := func() *Keyslot {
		stripes := AFStripes
		return &Keyslot{
			Type:    "luks2",
			KeySize: 64,
			Area:    &KeyslotArea{Type: "raw", Offset: "32768", Size: "258048", Encryption: "aes-xts-plain64"},
			KDF:     &KDF{Type: "pbkdf2", Hash: "sha256", Salt: "", Iterations: intPtr(1000)},
			AF:      &AntiForensic{Type: "luks1", Stripes: stripes, Hash: "sha256"},
		}
	}

	if err := validateKeyslot("0", base()); err != nil {
		t.Fatalf("the control keyslot is refused, so the cases below prove nothing: %v", err)
	}

	negative := base()
	negative.Area.Offset = "-4096"
	if err := validateKeyslot("0", negative); !errors.Is(err, ErrInvalidKeyslot) {
		t.Fatalf("a negative area offset is accepted: %v", err)
	}

	// 2^63-1 minus a fraction of the area size: the sum wraps negative.
	overflowing := base()
	overflowing.Area.Offset = "9223372036854775807"
	if err := validateKeyslot("0", overflowing); !errors.Is(err, ErrInvalidKeyslot) {
		t.Fatalf("an area whose offset plus size overflows int64 is accepted: %v", err)
	}
}

// TestAKeyslotWithOneUsableDigestIsStillCounted is the #58 half of the digest
// screen, and without it the screen above could be "every applicable digest
// must be usable" -- which would refuse a volume that opens perfectly well.
//
// A keyslot carrying one unusable digest and one good one is openable: the scan
// skips the bad and verifies against the good. So the guard must count it, and
// a removal that leaves it must be permitted.
func TestAKeyslotWithOneUsableDigestIsStillCounted(t *testing.T) {
	defer parallel(t)()

	device := volumeWithSibling(t, "one-good-digest.img", func(metadata *LUKS2Metadata, _ *Keyslot) {
		metadata.Digests["9"] = &Digest{
			Type:       "pbkdf2",
			Hash:       "sha256",
			Salt:       encodeBase64([]byte("removal-guard-salt")),
			Iterations: 1000,
			Digest:     "this is not base64 !!!",
			Keyslots:   []string{"0", siblingSlotID},
			Segments:   []string{"0"},
		}
	})

	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	f, err := os.Open(device)
	if err != nil {
		t.Fatalf("failed to open the fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	for _, id := range []string{"0", siblingSlotID} {
		if !keyslotCanOpenVolume(f, hdr, metadata, id) {
			t.Fatalf("keyslot %s stopped being counted because ONE of its digests is unusable; the screen must require any, not all", id)
		}
	}

	// And end to end: the volume still opens, so the count is not merely
	// self-consistent.
	if err := TestKey(device, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("the volume no longer opens with an unusable digest alongside a usable one: %v", err)
	}
}

// TestTheRemovalGuardRefusesWhenTheDeviceSizeCannotBeEstablished is the
// block-device half of the area bound, and it is a unit test only because the
// measurement is reachable through a seam.
//
// checkAreaWithinDevice measured with Stat alone and read a size of 0 as
// "nothing to compare against". A regular file reports its real size, so every
// test passed and every file-backed container was checked -- and a BLOCK DEVICE,
// which is what this package is built for, reports 0 through Stat. The bound was
// therefore not approximate on real hardware: it was absent, and a keyslot whose
// area lies past the end of the device counted as a survivor. Raised by Codex
// review of fb29c6d; the fix measures with BLKGETSIZE64 first and refuses when
// neither that nor Stat can answer.
//
// The seam presents what such a device reports. Injecting the FAILURE to measure
// is the sharper case of the two: it asserts the guard refuses rather than waves
// through, which is the property "a guard that cannot verify its condition must
// not report success".
func TestTheRemovalGuardRefusesWhenTheDeviceSizeCannotBeEstablished(t *testing.T) {
	passphrase := []byte(conformancePassphrase)
	golden := goldenSiblingVolume(t, nil)

	for _, path := range keyslotRemovalPaths {
		t.Run(path.name, func(t *testing.T) {
			device := restoreVolume(t, "unmeasurable.img", golden)
			offset, size := keyslotAreaExtent(t, device, "0")
			before := readAreaBytes(t, device, offset, size)

			// What a block device answers Stat with, which is the case the old
			// code read as "no bound to check".
			original := measureDeviceSize
			measureDeviceSize = func(*os.File) (int64, error) { return 0, nil }
			t.Cleanup(func() { measureDeviceSize = original })

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

	size, err := measureDeviceSize(f)
	if err != nil {
		t.Fatalf("failed to measure the image: %v", err)
	}
	if size != conformanceImageSize {
		t.Fatalf("measured %d bytes, want %d", size, conformanceImageSize)
	}

	// And the bound it feeds accepts an area inside the device and refuses one
	// past its end -- both halves, so neither a permissive nor a rejecting
	// implementation passes.
	if err := checkAreaWithinDevice(f, 0x8000, 0x40000); err != nil {
		t.Fatalf("a keyslot area well inside the device was refused: %v", err)
	}
	if err := checkAreaWithinDevice(f, conformanceImageSize, 0x40000); !errors.Is(err, ErrInvalidKeyslot) {
		t.Fatalf("a keyslot area past the end of the device was accepted: %v", err)
	}
}

// TestScreenDigestNeverAcceptsWhatTheDerivationRefuses pins the thesis of #45
// one layer below the keyslot, where it kept drifting back.
//
// The guard's predicate may be STRICTER than the path it screens for. It may
// never be weaker. Everything else in this file asserts that for keyslots; this
// asserts it for the digests a keyslot is authenticated by, and it asserts it
// against the DERIVATION ITSELF rather than against a list of conditions
// somebody wrote down. A list is the thing that drifts.
//
// # It is deliberately mode-sensitive, and that is the point
//
// PBKDF2-HMAC-SHA1 is a hash this package supports outside FIPS 140-3 and
// refuses inside it, so the correct answer for that shape DIFFERS between the
// default suite and the FIPS job. The assertion does not branch on the mode: it
// compares the screen against the derivation, in whatever mode the process is
// running, so one test covers both and neither run is a no-op.
//
// Measured rather than reasoned about, because "does hashOutputLen know this
// hash" and "will the crypto layer let me compute it" are different questions
// that happen to share an implementation -- hashOutputLen resolves through
// getPBKDF2HashFunc, which is where the FIPS refusal lives. That is a property
// of the current code, not a law, and this test is what keeps it true.
func TestScreenDigestNeverAcceptsWhatTheDerivationRefuses(t *testing.T) {
	defer parallel(t)()

	shapes := unusableDigests(t)
	shapes["a usable digest"] = usableDigest(t, []byte("digest-scan-master-key-32-bytes!"), 32)
	// The hash that is legal outside FIPS 140-3 and refused inside it. Its
	// length is sha1's, so the length check cannot be what decides it and the
	// hash question is isolated.
	shapes["a sha1 digest, which FIPS mode refuses"] = &Digest{
		Type:       "pbkdf2",
		Hash:       "sha1",
		Salt:       encodeBase64([]byte("digest-screen-salt")),
		Iterations: 1000,
		Digest:     encodeBase64(make([]byte, 20)),
	}

	accepted := 0
	for name, digest := range shapes {
		t.Run(name, func(t *testing.T) {
			expected, _, screenErr := screenDigest(digest)
			deriveLen := len(expected)
			clearBytes(expected)
			if deriveLen == 0 {
				deriveLen = 32
			}

			if screenErr != nil {
				// The screen refused. It is ALLOWED to be stricter than the
				// derivation, so there is nothing to compare against and the
				// yardstick is not run.
				//
				// Not merely an optimisation: one shape here is a digest of
				// absurd length, and running the yardstick on it asks PBKDF2
				// for a MEGABYTE of output. That single subtest dominated this
				// test's 154s on the CI runner, to establish a case the
				// assertion never reads.
				return
			}
			accepted++

			// THE YARDSTICK, taken from the path being screened for rather than
			// from the predicate under test. verifyMasterKey ends up here.
			kdf := &KDF{
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
		apply     func(*Keyslot)
		wantCause error
	}{
		{name: "a null keyslot", nilSlot: true},
		{name: "a reencrypt keyslot", apply: func(ks *Keyslot) { ks.Type = "reencrypt" }},
		{name: "a PBKDF2 iteration count past the accepted ceiling", apply: func(ks *Keyslot) {
			absurd := maxKDFIterations + 1
			ks.KDF.Iterations = &absurd
		}},
		{name: "a KDF type nothing implements", apply: func(ks *Keyslot) { ks.KDF.Type = "scrypt" }},
		{name: "a volume key size AES-XTS cannot use", apply: func(ks *Keyslot) { ks.KeySize = 40 }},
		{name: "an anti-forensic hash nothing implements", apply: func(ks *Keyslot) { ks.AF.Hash = "nosuchhash" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, metadata, err := ReadHeader(path)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			keyslot := metadata.Keyslots["0"]
			if tc.nilSlot {
				keyslot = nil
			} else {
				tc.apply(keyslot)
			}

			_, err = screenKeyslot("0", keyslot, metadata.Digests)
			if err == nil {
				t.Fatal("the screen accepted the keyslot")
			}
			if !errors.Is(err, ErrInvalidKeyslot) {
				t.Fatalf("refusal does not match ErrInvalidKeyslot: %v", err)
			}
			var typed *InvalidKeyslotError
			if !errors.As(err, &typed) {
				t.Fatalf("refusal is %T, want *InvalidKeyslotError: %v", err, err)
			}
			if typed.Keyslot != "0" {
				t.Fatalf("refusal names keyslot %q, want \"0\"", typed.Keyslot)
			}
			if typed.Reason == "" {
				t.Fatal("refusal carries no reason")
			}
		})
	}
}

// TestInvalidKeyslotErrorKeepsItsCause pins that the typed wrapper neither
// reclassifies nor hides what it wraps.
func TestInvalidKeyslotErrorKeepsItsCause(t *testing.T) {
	err := error(&InvalidKeyslotError{Keyslot: "3", Reason: "declares an anti-forensic", Err: ErrUnsupportedHash})
	if !errors.Is(err, ErrInvalidKeyslot) || !errors.Is(err, ErrUnsupportedHash) {
		t.Fatalf("wrapper lost a classification: %v", err)
	}
	if errors.Is(err, ErrMasterKeyVerification) {
		t.Fatalf("wrapper matches a sentinel it does not stand for: %v", err)
	}
	want := `invalid keyslot: luks2 keyslot "3": declares an anti-forensic: ` + ErrUnsupportedHash.Error()
	if err.Error() != want {
		t.Fatalf("message is %q, want %q", err.Error(), want)
	}

	bare := &InvalidKeyslotError{Keyslot: "3", Reason: "is null"}
	if got, want := bare.Error(), `invalid keyslot: luks2 keyslot "3": is null`; got != want {
		t.Fatalf("message is %q, want %q", got, want)
	}
	if bare.Unwrap() != nil {
		t.Fatal("a wrapper with no cause unwraps to one")
	}
}
