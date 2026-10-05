// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"fmt"
	"math"
	"os"
	"slices"
	"strings"
	"unsafe"

	"github.com/jeremyhahn/go-enclave"
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

	// areaKeySize is the length of the key that WRAPS the area: what the KDF
	// derives and what the area cipher is keyed with. It is area.key_size, not
	// the keyslot's key_size -- that one is the VOLUME key the AF merge
	// recovers, and cryptsetup --keyslot-key-size makes the two differ (#249,
	// A6).
	areaKeySize int

	// area is the transform area.encryption names, taken only after the
	// WHOLE spec -- algorithm, mode and IV generator -- matched one this
	// package runs ("aes-cbc-essiv:sha256" -> AES-CBC with an ESSIV IV;
	// "serpent-xts-plain64" -> refused).
	area areaTransform
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
//	area cipher, whole spec     parseKeyslotAreaEncryption (below; #106)
//	volume key size             validateVolumeKeySize    (keyslotarea.go)
//	area key size               areaTransform.validateKeySize (keyslotarea.go, shared with keyslotAreaSectors)
//	anti-forensic hash          getHashFunc              (antiforensic.go)
//	area holds its own AF split computed here, from bounds validateKeyslot established
//	a digest that can attest it keyslotDigestCounts     (over screenDigest, which
//	                            verifyMasterKey also consumes)
//
// Every one of those is a condition on which the unlock ALREADY fails. This
// function only moves the failure earlier -- before a KDF is paid for, and
// before a removal guard can mistake the keyslot for a survivor. No container
// that opened before this existed is refused by it -- with ONE deliberate
// exception, the whole-spec area cipher check (#106): a keyslot whose declared
// mode is not the one its material was encrypted with used to open here, and
// nowhere else, because only the algorithm was read. That is the defect the
// check exists to close, so it is a new refusal rather than a moved one.
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
		return plan, &InvalidKeyslotError{Keyslot: id, Reason: "is null"}
	}
	if keyslot.Type != "luks2" {
		return plan, &InvalidKeyslotError{Keyslot: id,
			Reason: fmt.Sprintf("type %q cannot be opened; only luks2 keyslots hold a passphrase-wrapped volume key", keyslot.Type)}
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
		return plan, &InvalidKeyslotError{Keyslot: id, Reason: "declares a KDF cost this package refuses", Err: err}
	}

	// What the KDF would REFUSE, as opposed to what it would cost.
	if err := screenKDFParameters(keyslot.KDF); err != nil {
		return plan, &InvalidKeyslotError{Keyslot: id, Reason: "declares KDF parameters the derivation refuses", Err: err}
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
		return plan, &InvalidKeyslotError{Keyslot: id,
			Reason: fmt.Sprintf("declares an area offset %q that is not a number", keyslot.Area.Offset), Err: err}
	}
	plan.areaSize, err = parseSize(keyslot.Area.Size)
	if err != nil {
		return plan, &InvalidKeyslotError{Keyslot: id,
			Reason: fmt.Sprintf("declares an area size %q that is not a number", keyslot.Area.Size), Err: err}
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
		return plan, &InvalidKeyslotError{Keyslot: id,
			Reason: fmt.Sprintf("area of %d bytes is not a whole number of %d-byte sectors and cannot hold the %d bytes of AF material this keyslot declares",
				plan.areaSize, keyslotSectorSize, plan.afSplitSize)}
	}

	// The area cipher is read WHOLE -- algorithm, mode and IV generator -- and
	// refused unless it is a spec this package actually decrypts (#106). It used
	// to be cut down to its algorithm, so a keyslot declaring CBC over XTS
	// material opened here and nowhere else; the declared transform is now the
	// one run.
	//
	// The VOLUME key's size (keyslot.KeySize) is not the area cipher's
	// business: it is what the data segment's cipher takes -- 16 bytes for a
	// 128-bit aes-cbc-essiv volume, 64 for the default AES-XTS. It is held to
	// the sizes an AES data cipher can be keyed with, so a keyslot declaring
	// any other cannot be counted as a survivor by the removal guard: its AF
	// merge yields a key no segment this package maps can use.
	plan.area, err = parseKeyslotAreaEncryption(keyslot.Area.Encryption)
	if err != nil {
		return plan, &UnsupportedKeyslotCipherError{Keyslot: id, Spec: keyslot.Area.Encryption}
	}
	if err := validateVolumeKeySize(keyslot.KeySize); err != nil {
		return plan, &InvalidKeyslotError{Keyslot: id, Reason: "declares a volume key size no AES data cipher can use", Err: err}
	}
	// The AREA's key size is what the KDF derives and the area cipher is keyed
	// with (#249, A6). It used to be ignored and keyslot.KeySize used in its
	// place, which is the same number only until a keyslot is written with
	// cryptsetup --keyslot-key-size. Missing (0) is refused like any other size
	// the area cipher cannot use: cryptsetup requires the member, and so did
	// every version of this package's writer.
	plan.areaKeySize = keyslot.Area.KeySize
	if err := plan.area.validateKeySize(plan.areaKeySize); err != nil {
		return plan, &InvalidKeyslotError{Keyslot: id,
			Reason: fmt.Sprintf("declares an area key size of %d bytes, which its %s area cipher cannot use", plan.areaKeySize, keyslot.Area.Encryption), Err: err}
	}

	// The anti-forensic merge resolves this name and fails if it cannot. SHA-1
	// resolves (#236): it is what a converted LUKS1 volume carries.
	if err := afHashReadable(keyslot.AF.Hash); err != nil {
		return plan, &InvalidKeyslotError{Keyslot: id, Reason: "declares an anti-forensic hash nothing implements", Err: err}
	}
	// The FIPS 140-3 gate on it, after the structural check so a refusal here
	// is a well-formed keyslot this process may not run -- which is what
	// keyslotRefusedByFIPS depends on to call it an import, not damage.
	if err := requireFIPSApprovedAFHash(keyslot.AF.Hash); err != nil {
		return plan, &InvalidKeyslotError{Keyslot: id, Reason: "declares an anti-forensic hash the merge refuses", Err: err}
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
		return &detailError{Detail: "no KDF object"}
	}

	if err := requireFIPSApprovedKDF(kdf.Type); err != nil {
		return err
	}

	if err := screenKDFStructure(kdf); err != nil {
		return err
	}

	// The second FIPS gate, and the last check: PBKDF2 over SHA-1. Its name
	// has already resolved in screenKDFStructure, so the only thing this can
	// still refuse is the policy.
	if kdf.Type == KDFTypePBKDF2 {
		if _, err := getPBKDF2HashFunc(kdf.Hash); err != nil {
			return err
		}
	}

	return nil
}

// screenKDFStructure is screenKDFParameters without its two FIPS 140-3 gates:
// whether the KDF is well formed, as opposed to whether this process may run it.
//
// It is split out for one reader besides screenKDFParameters, which is the
// question "was this keyslot refused ONLY because the process is in FIPS
// mode?" (keyslotRefusedByFIPS). Answering that with a separate list of
// structural checks would be a second copy of the screen, which is the drift
// this file exists to remove; answering it with the screen minus its gates is
// the same checks by construction.
func screenKDFStructure(kdf *KDF) error {
	if kdf == nil {
		return &detailError{Detail: "no KDF object"}
	}

	if _, err := decodeBase64(kdf.Salt); err != nil {
		return &detailError{Detail: "invalid salt", Err: err}
	}

	switch kdf.Type {
	case KDFTypePBKDF2:
		if _, err := pbkdf2Hash(kdf.Hash); err != nil {
			return err
		}
	case KDFTypeArgon2i, KDFTypeArgon2id:
		// Nothing further is decidable without the passphrase: cost is
		// validateKDFCost's, and argon2 has no algorithm name to resolve.
	default:
		return &detailError{Detail: "unsupported KDF type: " + kdf.Type}
	}

	return nil
}

// parseKeyslotAreaEncryption reads a keyslot's area.encryption as the full
// cipher spec it is -- "<algorithm>-<mode>-<iv>" -- and returns the transform
// it names, or ErrUnsupportedKeyslotCipher if this package cannot run it.
//
// # The mode is consumed, not discarded (#106)
//
// This used to be a Split that kept the algorithm and threw the rest away, and
// the transform then ran AES-XTS whatever the header said. A keyslot declaring
// "aes-cbc-essiv:sha256" over XTS material therefore opened perfectly HERE and
// in no conforming implementation. Honoring the mode on read is what makes a
// wrong declaration a test failure instead of a container only this library
// can open: such a keyslot is now decrypted as the CBC it claims, fails its
// digest as it does in cryptsetup, and a genuine CBC keyslot opens.
//
// # The accepted set is exact and closed
//
// It is an enumeration of the area transforms cryptsetup writes for AES, not a
// grammar:
//
//	aes-xts-plain64       the default of this package and of cryptsetup
//	aes-xts-plain         --keyslot-cipher, and carried over from LUKS1
//	aes-cbc-essiv:sha256  LUKS1's long-time default, kept by `cryptsetup
//	                      convert`, and what cryptsetup writes for a volume
//	                      formatted with that data cipher
//	aes-cbc-plain64       --keyslot-cipher, or a data cipher of that name
//	aes-cbc-plain
//
// "plain" truncates the sector index to 32 bits, "plain64" does not; the two
// differ only for a sector index of 2^32 or more, and a keyslot area's
// decrypted length is bounded at about 4 MiB (validateKeyslot), so for every
// keyslot the screen admits they name the same bytes.
//
// Everything else is refused: another algorithm, another mode or IV generator
// (ecb, lrw, benbi, plain64be, null, essiv over XTS), a spec with the mode
// missing, and any other casing or decoration. Matching is exact because the
// kernel's crypto API names are case-sensitive and cryptsetup passes them
// through unchanged.
//
// It is a function rather than an inline comparison so the unlock path and the
// removal guard cannot come to read the spec differently -- both reach it only
// through screenKeyslot.
func parseKeyslotAreaEncryption(spec string) (areaTransform, error) {
	t, ok := keyslotAreaTransforms[spec]
	if !ok {
		return areaTransform{}, &UnsupportedKeyslotCipherError{Spec: spec}
	}
	return t, nil
}

// The area.encryption spellings parseKeyslotAreaEncryption accepts.
const (
	keyslotAreaSpecPlain64    = DefaultCipher + "-xts-plain64"
	keyslotAreaSpecPlain      = DefaultCipher + "-xts-plain"
	keyslotAreaSpecCBCESSIV   = DefaultCipher + "-cbc-essiv:sha256"
	keyslotAreaSpecCBCPlain64 = DefaultCipher + "-cbc-plain64"
	keyslotAreaSpecCBCPlain   = DefaultCipher + "-cbc-plain"
)

// keyslotAreaTransforms maps each accepted spec to what it runs.
var keyslotAreaTransforms = map[string]areaTransform{
	keyslotAreaSpecPlain64:    {mode: areaModeXTS, iv: areaIVPlain64},
	keyslotAreaSpecPlain:      {mode: areaModeXTS, iv: areaIVPlain},
	keyslotAreaSpecCBCESSIV:   {mode: areaModeCBC, iv: areaIVESSIVSHA256},
	keyslotAreaSpecCBCPlain64: {mode: areaModeCBC, iv: areaIVPlain64},
	keyslotAreaSpecCBCPlain:   {mode: areaModeCBC, iv: areaIVPlain},
}

// keyslotAreaSpecs lists the accepted specs, for messages.
func keyslotAreaSpecs() string {
	return strings.Join([]string{keyslotAreaSpecPlain64, keyslotAreaSpecPlain,
		keyslotAreaSpecCBCESSIV, keyslotAreaSpecCBCPlain64, keyslotAreaSpecCBCPlain}, ", ")
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
	expected, kdf, err := screenDigestStructure(digest)
	if err != nil {
		return expected, nil, err
	}

	// The FIPS 140-3 gates run LAST, after every structural check has passed,
	// so a digest refused here is a well-formed digest this process may not
	// evaluate -- never a damaged one. keyslotRefusedByFIPS depends on that.
	if err := screenKDFParameters(kdf); err != nil {
		return expected, nil, err
	}

	return expected, kdf, nil
}

// argon2DigestLen is the length an Argon2 digest that declares no hash is
// derived to.
//
// LUKS2 defines digests over PBKDF2 only, and the length of one follows from
// its hash. A digest declaring Argon2 is a foreign header's invention -- #84
// requires this package to evaluate and migrate one rather than assume it
// never meets one -- and such a digest may declare no hash at all. Its length
// is then pinned to one value rather than taken from the header, for the
// reason legacyDigestLen gives: a length off an untrusted device is a
// whitelist, never a range. 32 bytes is the digest length of every
// cryptsetup-written sha256 volume.
const argon2DigestLen = 32

// screenDigestStructure is screenDigest without the FIPS 140-3 gates: every
// check that the digest is well formed, and the KDF the derivation will run.
// The caller owns `expected` exactly as screenDigest's does.
//
// An Argon2 digest carries its cost the way an Argon2 keyslot KDF does, in
// time, memory and cpus members, and is bounded by the same validateKDFCost.
func screenDigestStructure(digest *Digest) ([]byte, *KDF, error) {
	if digest == nil {
		return nil, nil, &detailError{Detail: "digest is null"}
	}

	expected, err := decodeBase64(digest.Digest)
	if err != nil {
		return nil, nil, &detailError{Detail: "digest value is not base64", Err: err}
	}

	// Which lengths are derived to is a whitelist, not a range: the length the
	// declared hash implies, plus legacyDigestLen for containers an earlier
	// version of this package wrote and luks1DigestLen for converted LUKS1
	// containers. See legacyDigestLen. Resolved WITHOUT the
	// FIPS gate, which screenKDFParameters applies afterwards.
	argon2 := digest.Type == KDFTypeArgon2i || digest.Type == KDFTypeArgon2id
	wantLen := argon2DigestLen
	if !argon2 || digest.Hash != "" {
		h, err := pbkdf2Hash(digest.Hash)
		if err != nil {
			return expected, nil, err
		}
		wantLen = h.Size()
	}
	if len(expected) != wantLen && len(expected) != legacyDigestLen && len(expected) != luks1DigestLen {
		return expected, nil, &detailError{Detail: fmt.Sprintf(
			"digest is %d bytes, which agrees with neither %s nor a legacy carve-out", len(expected), digest.Hash)}
	}

	kdf := &KDF{
		Type:       digest.Type,
		Hash:       digest.Hash,
		Salt:       digest.Salt,
		Iterations: &digest.Iterations,
		Time:       digest.Time,
		Memory:     digest.Memory,
		CPUs:       digest.CPUs,
	}

	// The digest's KDF is header-supplied too, and it is the one that is easy to
	// miss: it is not the keyslot's.
	if err := validateKDFCost(kdf); err != nil {
		return expected, nil, err
	}
	if err := screenKDFStructure(kdf); err != nil {
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

// keyslotBoundToSegment reports whether the header DECLARES that keyslot
// keyslotID holds the key of data segment segmentID: the static half of "does
// this keyslot hold the volume key", answered without a passphrase.
//
// # Why "attests the keyslot" is not enough
//
// A LUKS2 header may carry keys that decrypt nothing: `cryptsetup luksAddKey
// --unbound` writes a keyslot whose digest names no segment, and a container
// mid-reencryption has a digest per segment. A digest's "segments" array is what
// says which data a key decrypts, and cryptsetup consults it -- both when it
// activates a segment and when it decides that a keyslot is the last one. A
// predicate that asks only whether some digest attests the keyslot treats an
// unbound key as a volume key: the removal guard then counts it as a survivor
// and authorizes destroying the only keyslot that holds the real key (#249,
// A1), and an unlock maps a key that decrypts garbage (Lane C, C1).
//
// # A declaration, strictly read
//
// It is true only when
//
//   - the segment exists in the header, and
//   - at least one digest attests the keyslot, and
//   - EVERY digest that attests the keyslot names the segment.
//
// The last condition is what keeps a crafted header from passing: a keyslot
// attested both by a digest bound to the segment and by an unbound one is a
// header cryptsetup refuses outright ("Keyslot N is not assigned to exactly 1
// digest"), and nothing static can say which of the two keys the keyslot really
// holds. Counting it would be counting a survivor on a guess; refusing it costs
// only a spurious refusal, and THE INVARIANT on the file comment says which of
// those two errors this package is allowed to make.
//
// Whether the attesting digests can actually be EVALUATED is deliberately not
// asked here: that is screenKeyslot's question (keyslotDigestCounts), it
// already refuses a keyslot no usable digest attests, and it reports it as the
// header fault it is. Asking it twice would turn "this keyslot's digest is
// damaged" into "no keyslot holds the volume key" -- the same refusal with the
// wrong diagnosis.
//
// It is a pure function of the metadata. Lane C's unlock (C1) and the removal
// guard below ask the same question through it, so the two cannot come to
// disagree about which keyslots hold the volume key.
func keyslotBoundToSegment(metadata *LUKS2Metadata, keyslotID, segmentID string) bool {
	if metadata == nil || metadata.Segments[segmentID] == nil {
		return false
	}
	attesting := 0
	for _, digest := range metadata.Digests {
		if !digestCovers(digest, keyslotID) {
			continue
		}
		if !slices.Contains(digest.Segments, segmentID) {
			return false
		}
		attesting++
	}
	return attesting > 0
}

// keyslotBoundToDataSegments is keyslotBoundToSegment for EVERY data segment
// the header declares: the keyslot holds the key the whole volume is encrypted
// with. A header that declares no segment has no volume key to hold, and is
// answered false rather than vacuously true -- a removal guard must not find a
// survivor in a header that describes nothing to survive for.
func keyslotBoundToDataSegments(metadata *LUKS2Metadata, keyslotID string) bool {
	if metadata == nil {
		return false
	}
	segments := dataSegmentIDs(metadata)
	if len(segments) == 0 {
		return false
	}
	for _, segment := range segments {
		if !keyslotBoundToSegment(metadata, keyslotID, segment) {
			return false
		}
	}
	return true
}

// recoveredKeyBoundToSegment is the DYNAMIC half: whether key, recovered from
// keyslot keyslotID, is attested for segment segmentID by a digest that both
// names that keyslot and that segment and actually matches key.
//
// keyslotBoundToSegment says what the header declares; this says what the key in
// hand satisfies, through evaluateDigest -- the comparison the unlock itself
// makes. An activation must use this one before it maps a key: a declaration is
// not proof, and the key decides which digest it matches. It derives once per
// candidate digest, so it is called once, after the key is recovered.
func recoveredKeyBoundToSegment(metadata *LUKS2Metadata, keyslotID, segmentID string, key *enclave.MemoryEnclave) bool {
	if metadata == nil || key == nil || metadata.Segments[segmentID] == nil {
		return false
	}
	for _, id := range sortedDigestIDs(metadata.Digests) {
		digest := metadata.Digests[id]
		if !digestCovers(digest, keyslotID) || !slices.Contains(digest.Segments, segmentID) {
			continue
		}
		if _, matched := evaluateDigest(key, digest); matched {
			return true
		}
	}
	return false
}

// keyslotCanOpenVolume reports whether a keyslot could actually yield the VOLUME
// key: the key the data segments are encrypted with. It is the removal guard's
// predicate, and it is DERIVED from the unlock path rather than maintained
// alongside it -- see the file comment for why that distinction is the whole
// point.
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
//
// On top of what the unlock screens, a survivor must
//
//   - sit at an id cryptsetup can address (canonicalKeyslotID; A9),
//   - be BOUND to every data segment (keyslotBoundToDataSegments; A1) -- an
//     unbound key opens its keyslot and decrypts nothing, so counting it let the
//     only keyslot holding the volume key be destroyed beside a `cryptsetup
//     luksAddKey --unbound` one, and
//   - lie inside the container's keyslots area and clear of every data segment
//     (checkKeyslotAreaConfined; A2) -- an area reaching into the header or the
//     payload is one the next header write or data write destroys, and one
//     cryptsetup refuses the whole header over.
func keyslotCanOpenVolume(f *os.File, hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata, id string) bool {
	if _, ok := canonicalKeyslotID(id); !ok {
		return false
	}
	if !keyslotHoldsKeyMaterial(f, id, metadata.Keyslots[id], metadata.Digests) {
		return false
	}
	if !keyslotBoundToDataSegments(metadata, id) {
		return false
	}
	return checkKeyslotAreaConfined(hdr, metadata, id) == nil
}

// keyslotHoldsKeyMaterial reports whether a keyslot's area holds key material
// some passphrase could open -- to ANY key, bound to the data or not. It is the
// set the overlap check protects (keyslotAreaDisjointFrom), and it is
// deliberately WIDER than keyslotCanOpenVolume: an unbound keyslot is not a
// survivor for the purposes of the last-keyslot guard, but its key is still
// somebody's key, and a wipe aimed at another keyslot must not destroy it. For
// the overlap check, protecting more is the safe direction.
func keyslotHoldsKeyMaterial(f *os.File, id string, keyslot *Keyslot, digests map[string]*Digest) bool {
	plan, err := screenKeyslot(id, keyslot, digests)
	if err != nil {
		return false
	}
	return checkAreaWithinDevice(f, plan.areaOffset, plan.areaSize) == nil
}

// checkKeyslotAreaConfined refuses a keyslot whose area is not wholly inside the
// container's reserved keyslots area (keyslotsAreaBounds), or that reaches into
// any data segment. See checkAreaConfined.
func checkKeyslotAreaConfined(hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata, id string) error {
	keyslot := metadata.Keyslots[id]
	if keyslot == nil {
		return &detailError{Kind: ErrInvalidKeyslot, Detail: "keyslot " + id + " declares no area, so what removing it would wipe is unknown"}
	}
	return checkAreaConfined(hdr, metadata, id, keyslot.Area)
}

// checkAreaConfined refuses a keyslot area -- named by id for the message --
// that is not wholly inside the container's reserved keyslots area, or that
// reaches into any data segment: an area this package would otherwise READ
// outside keyslot space when it unlocks or scans the keyslot, or OVERWRITE when
// it removes it (#249, A2).
//
// It takes the area rather than the id because the bytes a wipe destroys are not
// always the area the metadata now describes: ChangeKey relocates a keyslot and
// then wipes the area it USED to occupy.
//
// # Why every wipe needs it
//
// checkKeyslotRemovable refuses a wipe that would reach a SURVIVING keyslot's
// area, and checkAreaWithinDevice one past the end of the device. Neither asks
// whether the area is keyslot space at all. A keyslot -- a `reencrypt` one, a
// damaged one, one written by a hostile header -- declaring its area at the
// data offset, or at 0, had RemoveKey, KillSlot, KillKeyslot, ChangeKey's
// cleanup and WipeKeyslot overwrite up to 128 MiB of encrypted payload, or both
// header copies, with a crash before the rewrite losing the volume. It was
// enforced only on the FIPS migration's path. cryptsetup refuses such a header
// outright, so confining every wipe refuses nothing cryptsetup opens.
//
// Both boundaries are read from the container, never assumed.
func checkAreaConfined(hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata, id string, area *KeyslotArea) error {
	start, limit, err := keyslotsAreaBounds(hdr, metadata)
	if err != nil {
		return err
	}
	return confineArea(start, limit, metadata, id, area)
}

// checkKeyslotAreaConfinedByMetadata is checkKeyslotAreaConfined for the one
// reader that has no binary header in hand: the unlock scan. The keyslots area
// starts after both header copies, and their size is config.json_size plus the
// binary header -- the relation cryptsetup itself validates (hdr_size =
// json_size + 4096), so a header whose two disagree is one cryptsetup refuses.
func checkKeyslotAreaConfinedByMetadata(metadata *LUKS2Metadata, id string) error {
	keyslot := metadata.Keyslots[id]
	if keyslot == nil {
		return &detailError{Kind: ErrInvalidKeyslot, Detail: "keyslot " + id + " is null"}
	}
	if metadata.Config == nil {
		return &detailError{Kind: ErrInvalidHeader, Detail: "header has no config object, so the keyslots area is undefined"}
	}
	jsonSize, err := parseSize(metadata.Config.JSONSize)
	if err != nil || jsonSize <= 0 || jsonSize > LUKS2HeaderMaxSize-LUKS2HeaderSize {
		return &detailError{Kind: ErrInvalidHeader, Detail: fmt.Sprintf(
			"config.json_size %q does not describe a LUKS2 header area, so where the keyslots area starts is unknown", metadata.Config.JSONSize)}
	}
	start, limit, err := keyslotsAreaFrom(2*(jsonSize+LUKS2HeaderSize), metadata)
	if err != nil {
		return err
	}
	return confineArea(start, limit, metadata, id, keyslot.Area)
}

// dataOnAnotherDevice reports whether a data segment at offset is a detached
// header's: offset 0 means the data lives on another device (cryptsetup
// --header), so nothing in the header's own keyslots area can overlap it.
// cryptsetup exempts it from the same checks (json_segments_get_minimal_offset
// returning 0; see minimalSegmentOffset). Activation refuses such a header on
// its own terms (cryptTableParams).
func dataOnAnotherDevice(segmentOffset int64) bool {
	return segmentOffset == 0
}

// confineArea is the check itself, against a keyslots area [start, limit).
func confineArea(start, limit int64, metadata *LUKS2Metadata, id string, area *KeyslotArea) error {
	if area == nil {
		return &detailError{Kind: ErrInvalidKeyslot, Detail: "keyslot " + id + " declares no area, so what removing it would wipe is unknown"}
	}
	offset, offErr := parseSize(area.Offset)
	size, sizeErr := parseSize(area.Size)
	if offErr != nil || sizeErr != nil || offset < 0 || size <= 0 || offset > math.MaxInt64-size {
		return &detailError{Kind: ErrInvalidKeyslot, Detail: fmt.Sprintf(
			"keyslot %s declares an area at offset %q of size %q, which is not a byte range", id, area.Offset, area.Size)}
	}
	end := offset + size

	if offset < start || end > limit {
		return &detailError{Kind: ErrKeyslotAreaOverlap, Detail: fmt.Sprintf(
			"keyslot %s declares its area at [%d,%d), outside the container's keyslots area [%d,%d); "+
				"reading or wiping it would touch bytes that are not keyslot material", id, offset, end, start, limit)}
	}

	for _, segmentID := range dataSegmentIDs(metadata) {
		segment := metadata.Segments[segmentID]
		segmentStart, err := parseSize(segment.Offset)
		if err != nil || segmentStart < 0 {
			return &detailError{Kind: ErrInvalidHeader, Detail: fmt.Sprintf(
				"data segment %s declares an offset of %q, so whether keyslot %s's area overlaps it cannot be decided",
				segmentID, segment.Offset, id)}
		}
		if dataOnAnotherDevice(segmentStart) {
			continue
		}
		segmentEnd := int64(math.MaxInt64)
		if segment.Size != "dynamic" {
			segmentSize, err := parseSize(segment.Size)
			if err != nil || segmentSize < 0 || segmentStart > math.MaxInt64-segmentSize {
				return &detailError{Kind: ErrInvalidHeader, Detail: fmt.Sprintf(
					"data segment %s declares a size of %q, so whether keyslot %s's area overlaps it cannot be decided",
					segmentID, segment.Size, id)}
			}
			segmentEnd = segmentStart + segmentSize
		}
		if offset < segmentEnd && segmentStart < end {
			return &detailError{Kind: ErrKeyslotAreaOverlap, Detail: fmt.Sprintf(
				"keyslot %s declares its area at [%d,%d), which overlaps data segment %s starting at %d; "+
					"reading or wiping it would touch the encrypted data", id, offset, end, segmentID, segmentStart)}
		}
	}
	return nil
}

// deviceSizeFromFile measures the device or file behind an open descriptor.
//
// BLKGETSIZE64 first, because a BLOCK DEVICE reports size 0 through Stat -- and
// this package exists to operate on block devices, so Stat alone measures
// exactly the case that does not matter and skips the one that does. Stat is
// the fallback, for the regular files used as containers and in tests.
//
// It is the same measurement Unlock performs for the data segment,
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
