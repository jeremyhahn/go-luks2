// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The ONE answer to "can this keyslot open this volume?", asked without the
// passphrase.
//
// # Why this file exists at all
//
// The removal guard needs to know which keyslots would survive a removal, and
// [unlockKeyslot] needs to know which keyslots are worth spending a derivation
// on. Those are the same question, and it was answered twice: once by the
// unlock path, and once by a predicate maintained alongside it by hand.
//
// The hand-maintained copy was wrong three times (#45). Each pass was derived
// by reading unlockKeyslot and enumerating what it rejects, and each
// enumeration was too narrow -- the first named only the shape check; the
// second added the area bounds and missed KDF cost; the third added those and
// still missed the KDF hash, the KDF salt, the area cipher, the AF hash and the
// area-too-small-for-its-own-AF-split case. Enumeration kept failing because
// the conditions are not in unlockKeyslot: they are scattered through
// deriveKeyPlain, xtsSectors, getHashFunc and verifyMasterKey, interleaved with
// the work they guard, and several were inline literals rather than callable
// validators.
//
// Counting one keyslot too many is not a cosmetic error. It is how a removal
// destroys the last slot that actually opens the volume, which this package has
// reproduced as permanent data loss three times (#37, #38, #71).
//
// So the predicate is not maintained. It is CONSUMED:
//
//	unlockKeyslot        calls screenKeyslot as its prefix, and uses what it returns
//	keyslotCanOpenVolume calls screenKeyslot and nothing else
//
// A metadata rejection added to the unlock path is therefore screened by the
// guard automatically, because there is one implementation rather than two. The
// package already states the principle, on getMasterKey's volume-level branch:
// *the hot path must consume the predicate, not match it. Matching is a copy
// that agrees today.*
//
// # What makes the coupling mechanical rather than a convention
//
// screenKeyslot returns a [keyslotPlan] holding the values unlockKeyslot needs
// next -- the area bounds, the cipher name, the AF split length, the number of
// bytes to decrypt. unlockKeyslot cannot skip the screen and still function,
// and it cannot recompute those values without the compiler pointing at an
// unused result. A comment asking the next author to keep two functions in step
// is what failed three times; a return value they have to use does not depend
// on anyone reading anything.
//
// # THE INVARIANT
//
// **The guard may count FEWER keyslots than the unlock loop will try. It may
// never count MORE.** The two errors are not symmetric: counting fewer costs a
// spurious refusal, and the operator still has their data; counting more costs
// the VOLUME.
//
// # The residual, stated rather than implied
//
// Screening every metadata rejection does not make the predicate exact, and two
// residuals remain -- both, unavoidably, on the counting-MORE side:
//
//   - A keyslot whose metadata is perfect and whose MATERIAL is corrupt is
//     counted. Only trying the passphrase would tell, and [KillKeyslot] has none
//     to try.
//   - [checkAreaWithinDevice] can only bound the area on a device whose size it
//     can measure. It measures with BLKGETSIZE64 and falls back to Stat, and
//     REFUSES when neither answers -- so this is no longer the fail-open it was
//     when a block device's Stat size of 0 read as "no bound to check".
//
// Whether a passphrase-less destructive operation should require explicit force
// when it cannot PROVE a survivor is a separate design question (#45), left
// deliberately open rather than answered here by accident.
//
// unlockKeyslot's device-open and locked-memory failures are excluded on
// purpose and are NOT part of that residual: they are VOLUME-level, defeat
// every keyslot equally, and so cannot distinguish a survivor from a casualty.

// keyslotSectorSize is the sector size the keyslot area's XTS transform tweaks
// on. It is a property of the LUKS2 format -- key material is always processed
// in 512-byte sectors, independent of the data segment's sector size.
const keyslotSectorSize = 512

// keyslotPlan is what a screened keyslot yields: every value derived from its
// metadata that the unlock path needs afterwards.
//
// It exists so unlockKeyslot CONSUMES the screen rather than re-deriving beside
// it. Each field was computed inline in unlockKeyslot before, next to the check
// that bounded it -- which is exactly the arrangement that let the removal
// guard hold a different answer to the same question.
type keyslotPlan struct {
	// areaOffset and areaSize are the keyslot area's byte range on the device,
	// parsed and bounded.
	areaOffset int64
	areaSize   int64

	// afSplitSize is how many bytes of anti-forensic material the merge
	// consumes: KeySize * AF.Stripes.
	afSplitSize int

	// decryptLen is afSplitSize rounded UP to a whole sector. The area is
	// 4 KiB-aligned and so usually larger than the stripes; only this much is
	// decrypted, which is what keeps the locked region to the material itself.
	decryptLen int64

	// cipherAlgo is the area cipher's algorithm name, taken from
	// area.encryption ("aes-xts-plain64" -> "aes").
	cipherAlgo string
}

// screenKeyslot performs every rejection [unlockKeyslot] can make WITHOUT the
// passphrase, and returns the values the unlock needs if it makes none.
//
// The membership is not a list someone maintains. It is the passphrase-
// independent prefix of the unlock path itself, walked in order, and each check
// delegates to the same validator the deep call site uses:
//
//	keyslot type                unlockKeyslot's own first check
//	geometry and shape          validateKeyslot          (keyslotvalidation.go)
//	KDF cost                    validateKDFCost          (keyslotvalidation.go)
//	KDF approval, salt, hash    screenKDFParameters      (below, over deriveKeyPlain's rejections)
//	area cipher                 validateAreaCipher       (format.go, shared with xtsSectors)
//	volume key size for XTS     validateXTSKeySize       (format.go, shared with xtsSectors)
//	anti-forensic hash          getHashFunc              (antiforensic.go)
//	area holds its own AF split computed here, from bounds validateKeyslot established
//	a digest that can attest it keyslotDigestCounts     (over screenDigest, which
//	                            verifyMasterKey also consumes)
//
// Every one of those is a condition on which the unlock ALREADY fails. This
// function only moves the failure earlier -- before a KDF is paid for, and
// before a removal guard can mistake the keyslot for a survivor. No container
// that opened before this existed is refused by it.
//
// Each failure keeps the sentinel the rejection it moves already carried --
// ErrInvalidKeyslot for everything the keyslot itself gets wrong, and
// verifyMasterKey's ErrInvalidHeader for a keyslot the header attests with no
// digest. Both are entry-level to the keyslot scan, which is what matters: a
// failure that aborted the scan would deny a volume the keyslots that still
// work, which is the data loss this package spends most of its guards avoiding.
// getMasterKey aborts on ErrProtectedMemory and on nothing else.
func screenKeyslot(id string, keyslot *Keyslot, digests map[string]*Digest) (keyslotPlan, error) {
	var plan keyslotPlan

	// A LUKS2 "reencrypt" keyslot has no kdf object and its area is a checksum
	// region rather than key material, so it holds no passphrase-wrapped volume
	// key. It is valid metadata that cannot open anything.
	if keyslot == nil {
		return plan, fmt.Errorf("%w: keyslot %q is null", ErrInvalidKeyslot, id)
	}
	if keyslot.Type != "luks2" {
		return plan, fmt.Errorf("%w: keyslot type %q cannot be opened; only luks2 keyslots hold a passphrase-wrapped volume key",
			ErrInvalidKeyslot, keyslot.Type)
	}

	// THE GATE. Everything below trusts the keyslot's declared geometry: that
	// the objects it needs exist, that its offsets and sizes parse and are in
	// range, and that its key size, stripe count and area describe an amount of
	// work worth doing.
	if err := validateKeyslot(id, keyslot); err != nil {
		return plan, err
	}

	// What the KDF would COST, checked before any of it is spent. Kept out of
	// validateKeyslot because a deliberately expensive KDF is still a fine
	// template for a new keyslot; see validateKDFCost.
	if err := validateKDFCost(keyslot.KDF); err != nil {
		return plan, fmt.Errorf("%w: %w", ErrInvalidKeyslot, err)
	}

	// What the KDF would REFUSE, as opposed to what it would cost.
	if err := screenKDFParameters(keyslot.KDF); err != nil {
		return plan, fmt.Errorf("%w: %w", ErrInvalidKeyslot, err)
	}

	// From here the order MIRRORS unlockKeyslot's, and that is deliberate rather
	// than incidental: this function predicts which rejection that path reaches
	// FIRST, so a keyslot must be refused here for the same reason, with the
	// same attribution, that it would be refused there. Reordering these would
	// silently change which cause an operator is shown.
	//
	// The bounds are re-read rather than carried out of validateKeyslot, because
	// they are what the caller acts on and this is the only place that hands
	// them over.
	var err error
	plan.areaOffset, err = parseSize(keyslot.Area.Offset)
	if err != nil {
		return plan, fmt.Errorf("%w: keyslot %q declares an area offset %q that is not a number",
			ErrInvalidKeyslot, id, keyslot.Area.Offset)
	}
	plan.areaSize, err = parseSize(keyslot.Area.Size)
	if err != nil {
		return plan, fmt.Errorf("%w: keyslot %q declares an area size %q that is not a number",
			ErrInvalidKeyslot, id, keyslot.Area.Size)
	}

	// validateKeyslot has already established that this product does not
	// overflow and fits the area, so it is computed rather than re-checked.
	plan.afSplitSize = keyslot.KeySize * keyslot.AF.Stripes
	plan.decryptLen = alignTo(int64(plan.afSplitSize), keyslotSectorSize)

	if plan.decryptLen > plan.areaSize {
		// Only reachable for an area size that is not a whole number of
		// sectors, which LUKS2's 4096-byte keyslot alignment rules out for any
		// container cryptsetup or this library writes.
		//
		// It is refused rather than clamped. Clamping would send the final
		// sector through the zero-padding partial-sector path, which decrypts
		// to something other than what was written -- so the merge would fail
		// with a message about the AF material rather than about the geometry
		// that caused it, and an operator would go looking in the wrong place.
		return plan, fmt.Errorf("%w: area of %d bytes is not a whole number of %d-byte sectors and cannot hold the %d bytes of AF material this keyslot declares",
			ErrInvalidKeyslot, plan.areaSize, keyslotSectorSize, plan.afSplitSize)
	}

	// The area cipher and the volume key size both reach xts.NewCipher, which
	// refuses either independently of the passphrase. Both are checked through
	// the validators xtsSectors itself calls, so neither can drift.
	plan.cipherAlgo = keyslotAreaCipherAlgo(keyslot.Area.Encryption)
	if err := validateAreaCipher(plan.cipherAlgo); err != nil {
		return plan, fmt.Errorf("%w: %w", ErrInvalidKeyslot, err)
	}
	if err := validateXTSKeySize(keyslot.KeySize); err != nil {
		return plan, fmt.Errorf("%w: luks2 keyslot %q: %w", ErrInvalidKeyslot, id, err)
	}

	// The anti-forensic merge resolves this name and fails if it cannot.
	if _, err := getHashFunc(keyslot.AF.Hash); err != nil {
		return plan, fmt.Errorf("%w: luks2 keyslot %q declares an anti-forensic %w",
			ErrInvalidKeyslot, id, err)
	}

	// A keyslot no digest attests cannot be authenticated at all -- see
	// verifyMasterKey -- so a key recovered from it is never returned. Screening
	// it here saves a whole derivation on the unlock path and, more importantly,
	// stops the removal guard counting a keyslot the unlock provably refuses.
	//
	// It keeps verifyMasterKey's sentinel and verifyMasterKey's wording, rather
	// than restating it as a keyslot fault. That classification was decided
	// deliberately and is pinned by a test: the passphrase may be right and the
	// key material intact, and what is broken is the container's own statement
	// about which digest attests this slot. Moving a rejection EARLIER must not
	// also change what it says -- the safety of this whole screen rests on it
	// being the same rejections, sooner. ErrInvalidHeader does not abort the
	// keyslot scan; getMasterKey aborts only on ErrProtectedMemory.
	// Worded by unverifiableKeyslotError, which verifyMasterKey also uses.
	// Screening earlier must not change WHAT the operator is told: the same
	// header reached from two places is one fault.
	applicable, usable := keyslotDigestCounts(id, digests)
	if usable == 0 {
		return plan, unverifiableKeyslotError(id, applicable)
	}

	return plan, nil
}

// screenKDFParameters rejects a KDF that deriveKeyPlain would refuse, without
// running it and without a passphrase.
//
// It mirrors deriveKeyPlain's prefix in order and delegates to the same helpers,
// so the two cannot disagree about which KDF is usable:
//
//	requireFIPSApprovedKDF   Argon2 in a FIPS 140-3 process
//	decodeBase64             a salt that is not base64
//	the type switch          a KDF type nothing implements
//	getPBKDF2HashFunc        a PBKDF2 hash nothing implements, and SHA-1 in FIPS mode
//
// The type switch is deliberately over kdf.Type RAW, not normalized. That is
// what deriveKeyPlain switches on, and this function exists to predict
// deriveKeyPlain rather than to have an opinion of its own: a header declaring
// "PBKDF2" in capitals is refused there, so it must be refused here or the
// guard would count a keyslot the unlock cannot open. (validateKDFCost DOES
// normalize, which is why a screen built only from it was too permissive.)
//
// The Argon2 cost fields are not re-checked: validateKDFCost has already
// bounded time, memory and cpus more tightly than deriveArgon2i/deriveArgon2id
// do, and screenKeyslot runs it first.
func screenKDFParameters(kdf *KDF) error {
	if kdf == nil {
		return fmt.Errorf("no KDF object")
	}

	if err := requireFIPSApprovedKDF(kdf.Type); err != nil {
		return err
	}

	if _, err := decodeBase64(kdf.Salt); err != nil {
		return fmt.Errorf("invalid salt: %w", err)
	}

	switch kdf.Type {
	case "pbkdf2":
		if _, err := getPBKDF2HashFunc(kdf.Hash); err != nil {
			return err
		}
	case "argon2i", "argon2id":
		// Nothing further is decidable without the passphrase: cost is
		// validateKDFCost's, and argon2 has no algorithm name to resolve.
	default:
		return fmt.Errorf("unsupported KDF type: %s", kdf.Type)
	}

	return nil
}

// keyslotAreaCipherAlgo extracts the cipher algorithm from an area encryption
// name -- "aes-xts-plain64" yields "aes".
//
// It is a function rather than an inline Split so the unlock path and the
// removal guard cannot come to spell it differently, which is the whole failure
// mode this file exists to remove.
func keyslotAreaCipherAlgo(encryption string) string {
	return strings.Split(encryption, "-")[0]
}

// digestCovers reports whether a digest attests the named keyslot.
//
// A LUKS2 digest carries a "keyslots" array and it is not advisory: a container
// can hold more than one volume key, and each digest attests one of them. See
// verifyMasterKey, which uses this to filter the digest set it will try.
func digestCovers(digest *Digest, keyslotID string) bool {
	return digest != nil && slices.Contains(digest.Keyslots, keyslotID)
}

// screenDigest performs every check verifyMasterKey makes on a digest BEFORE
// deriving anything, and returns what the derivation needs if it makes none.
//
// The caller owns `expected` and must clearBytes it on every path, including
// the error path -- the decode happens first, so a later check can fail with
// bytes already allocated.
//
// It exists because association is not usability, and the removal guard was
// treating them as the same thing. verifyMasterKey skips an associated digest
// whose value is not base64, whose hash is unknown or FIPS-refused, whose
// length agrees with neither the declared hash nor the legacy carve-out, whose
// KDF costs more than a header may ask, or whose KDF parameters nothing can
// run. A keyslot whose applicable digests are ALL of those can never be
// authenticated -- so counting it as a survivor authorizes destroying the last
// keyslot that works, which is #45's failure one layer further down than the
// keyslot itself.
//
// verifyMasterKey CONSUMES this rather than repeating it, and the return
// signature is what enforces that: the decoded digest and the KDF are values it
// cannot obtain another way. Same reasoning as screenKeyslot and the same
// reason the predicate cannot drift.
//
// The order mirrors verifyMasterKey's, and the decode comes first because its
// LENGTH is what the derivation has to match.
func screenDigest(digest *Digest) ([]byte, *KDF, error) {
	if digest == nil {
		return nil, nil, fmt.Errorf("digest is null")
	}

	expected, err := decodeBase64(digest.Digest)
	if err != nil {
		return nil, nil, fmt.Errorf("digest value is not base64: %w", err)
	}

	// Which lengths are derived to is a whitelist, not a range: the length the
	// declared hash implies, plus legacyDigestLen for containers an earlier
	// version of this package wrote. See legacyDigestLen.
	wantLen, err := hashOutputLen(digest.Hash)
	if err != nil {
		return expected, nil, err
	}
	if len(expected) != wantLen && len(expected) != legacyDigestLen {
		return expected, nil, fmt.Errorf("digest is %d bytes, which agrees with neither %s nor the legacy carve-out",
			len(expected), digest.Hash)
	}

	kdf := &KDF{
		Type:       digest.Type,
		Hash:       digest.Hash,
		Salt:       digest.Salt,
		Iterations: &digest.Iterations,
	}

	// The digest's KDF is header-supplied too, and it is the one that is easy to
	// miss: it is not the keyslot's.
	if err := validateKDFCost(kdf); err != nil {
		return expected, nil, err
	}
	if err := screenKDFParameters(kdf); err != nil {
		return expected, nil, err
	}

	return expected, kdf, nil
}

// keyslotDigestCounts reports how many digests in the header attest this
// keyslot, and how many of those can actually be evaluated.
//
// Association alone is not enough, and treating it as enough was a fail-open:
// a structurally perfect keyslot whose sole associated digest is unusable
// reaches verifyMasterKey, is skipped there, and can never yield a verified
// key -- while the removal guard counted it and authorized destroying the
// keyslot that still worked.
//
// ANY usable digest is enough, which is the other half and is #58: a keyslot
// with one FIPS-refused digest and one good one is perfectly openable, and
// requiring all of them to be usable would refuse a volume that opens.
//
// Both counts come back because the two zero cases are different faults; see
// unverifiableKeyslotError.
func keyslotDigestCounts(keyslotID string, digests map[string]*Digest) (applicable, usable int) {
	for _, digest := range digests {
		if !digestCovers(digest, keyslotID) {
			continue
		}
		applicable++
		expected, _, err := screenDigest(digest)
		clearBytes(expected)
		if err == nil {
			usable++
		}
	}
	return applicable, usable
}

// unverifiableKeyslotError says why no digest can authenticate this keyslot.
//
// ONE function because the condition is reached from two places -- this screen,
// before any derivation, and verifyMasterKey, after trying -- and they must
// describe it identically. An operator who hits it early and one who hits it
// late are looking at the same header, and a reader comparing two wordings
// should not have to work out that they are the same fault.
//
// It distinguishes the two zero cases because the remedies differ: a keyslot no
// digest names is a header missing an association; a keyslot whose digests all
// fail to be evaluated is a header whose digest objects are damaged. It names
// the keyslot and the COUNT, and deliberately not which digest failed how --
// see the threat model on verifyMasterKey's branch, which is why every other
// exit there folds into one error.
func unverifiableKeyslotError(keyslotID string, applicable int) error {
	if applicable == 0 {
		return fmt.Errorf("%w: no digest in the header authenticates keyslot %s, so a key recovered from it cannot be verified",
			ErrInvalidHeader, keyslotID)
	}
	return fmt.Errorf("%w: all %d digests that authenticate keyslot %s are unusable, so a key recovered from it could not be compared against any of them",
		ErrInvalidHeader, applicable, keyslotID)
}

// keyslotCanOpenVolume reports whether a keyslot could actually yield the master
// key. It is the removal guard's predicate, and it is DERIVED from the unlock
// path rather than maintained alongside it -- see the file comment for why that
// distinction is the whole point.
//
// It is deliberately stricter than getMasterKey's ITERATION set. Being tried is
// not the same as being able to succeed: a "luks2" slot with damaged metadata is
// tried, fails, and is REPORTED, and that report is the diagnostic that tells an
// operator "at least one keyslot is unusable: <cause>" instead of a bare
// wrong-passphrase verdict. Narrowing the loop to match this predicate would fix
// the guard and destroy that diagnostic in the same edit, because the loop would
// no longer SEE the damaged slot. Two different questions need two different
// predicates; the fix for a guard that counts too much is a stricter guard, not
// a narrower loop.
func keyslotCanOpenVolume(f *os.File, id string, keyslot *Keyslot, digests map[string]*Digest) bool {
	plan, err := screenKeyslot(id, keyslot, digests)
	if err != nil {
		return false
	}
	return checkAreaWithinDevice(f, plan.areaOffset, plan.areaSize) == nil
}

// deviceSizeFromFile measures the device or file behind an open descriptor.
//
// BLKGETSIZE64 first, because a BLOCK DEVICE reports size 0 through Stat -- and
// this package exists to operate on block devices, so Stat alone measures
// exactly the case that does not matter and skips the one that does. Stat is
// the fallback, for the regular files used as containers and in tests.
//
// It is the same measurement getBlockDeviceSize performs for the data segment,
// and it is this function that performs it there too. One implementation: a
// second one would be free to disagree about the size of the device a
// destructive operation is about to write to.
func deviceSizeFromFile(f *os.File) (int64, error) {
	var size int64
	// #nosec G103 -- unsafe.Pointer required for ioctl syscall
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.BLKGETSIZE64, uintptr(unsafe.Pointer(&size)))
	if errno == 0 {
		return size, nil
	}

	stat, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("failed to get device/file size: %w", err)
	}
	return stat.Size(), nil
}

// measureDeviceSize is deviceSizeFromFile, reached through a variable so a test
// can present what a real block device reports without needing one -- the same
// seam as dm, devDir, nodeRdev and removeFile elsewhere in this package.
//
// The case that matters cannot be built in a unit test any other way: a block
// device answers Stat with 0, and the defect this guards was precisely that a 0
// was read as "no bound to check" rather than as "no measurement".
var measureDeviceSize = deviceSizeFromFile

// checkAreaWithinDevice reports whether a keyslot area lies inside the device,
// and FAILS CLOSED when it cannot tell.
//
// # What this used to do, and why that was a fail-open
//
// It measured with Stat alone and treated a size of 0 as "nothing to compare
// against", returning nil. A regular file reports its real size, so the check
// worked in tests and on file-backed containers -- and a BLOCK DEVICE, which is
// what this package is built for, reports 0. So on real hardware the bound was
// not merely approximate: it was skipped, and keyslotCanOpenVolume counted a
// keyslot whose area lies past the end of the device as a survivor. Removing the
// last keyslot that actually worked was then permitted, on the production path
// only. Raised by Codex review of fb29c6d.
//
// Measuring properly closes most of it. What remains is a device whose size
// neither the ioctl nor Stat can establish, and that is REFUSED rather than
// waved through: the callers are a survivor count and a wipe, both destructive
// or authorizing destruction, and "I could not measure it" is not evidence that
// a keyslot is inside the device. A guard that cannot verify its condition must
// not report success -- that is the same swallow-the-unknown defect the
// integration entrypoint's host check was fixed for.
//
// Failing closed here is safe in both directions: an unmeasurable device makes
// keyslotCanOpenVolume count nothing, so every removal is refused, and it makes
// a wipe refuse outright. Neither loses data.
func checkAreaWithinDevice(f *os.File, offset, size int64) error {
	deviceSize, err := measureDeviceSize(f)
	if err != nil {
		return fmt.Errorf("%w: the size of this device could not be measured, so a keyslot area cannot be proved to lie inside it: %w",
			ErrInvalidKeyslot, err)
	}

	if deviceSize <= 0 {
		return fmt.Errorf("%w: this device reports a size of %d, so a keyslot area at %d..%d cannot be proved to lie inside it",
			ErrInvalidKeyslot, deviceSize, offset, offset+size)
	}

	if offset+size > deviceSize {
		return fmt.Errorf("%w: keyslot area %d..%d lies outside the %d byte device",
			ErrInvalidKeyslot, offset, offset+size, deviceSize)
	}

	return nil
}
