// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"
	"fmt"
	"github.com/jeremyhahn/go-luks2/internal/fips"
	"io"
	"os"
	"slices"

	"github.com/jeremyhahn/go-enclave"
	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/af"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// validateVolumeKey rejects a volume key that cannot be one, before the device
// is read. It checks the SHAPE only; whether the key opens this volume is the
// digest's question, answered by verifyVolumeKeyForSegment.
func validateVolumeKey(volumeKey enclave.ByteAccess) error {
	if volumeKey == nil {
		return &errs.Error{Kind: ErrInvalidCredential, Detail: "check the volume key: no enclave was given"}
	}
	if err := secret.Locked("check the volume key", volumeKey); err != nil {
		return err
	}
	if !volumeKey.IsAlive() {
		return &errs.Error{Kind: ErrInvalidCredential, Detail: "check the volume key: the enclave has been destroyed"}
	}
	if size := volumeKey.Size(); size <= 0 || size > header.MaxKeyslotKeySize {
		return &errs.Error{Kind: ErrInvalidCredential, Detail: fmt.Sprintf(
			"check the volume key: a %d-byte key is outside the 1..%d bytes this package supports", size, header.MaxKeyslotKeySize)}
	}
	return nil
}

// blockDeviceOf reports the device number of the block device f is open on,
// and refuses anything else: dm-crypt maps a block device, so a regular file
// has to be attached to a loop device first. A seam so the unit tests, which
// cannot create block devices, can map a regular-file image through a fake.
func statBlockDeviceOf(f *os.File) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return 0, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFBLK {
		return 0, ErrInvalidArgument
	}
	return uint64(st.Rdev), nil //nolint:unconvert // Rdev is not uint64 on every GOARCH
}

// activationSegment returns the one segment a mapping is built from.
//
// A header activates only when it declares EXACTLY ONE segment and that
// segment is a crypt segment. It used to take the first crypt segment in
// sorted id order whatever else the header declared, and a container left
// mid-reencryption declares five: the first is the part already under the NEW
// key, sized to the progress so far, so mapping it with the old key -- which is
// what the keyslot scan found first -- produced garbage over a truncated
// device (#250, C2). Such a container is normally refused earlier by its
// requirements flag; this refuses any other multi-segment header outright
// rather than guessing which part to map.
//
// It is one function because two things must agree on the answer: the mapping,
// and the digest the key is verified against. A key attested for one segment
// and mapped over another would be exactly the wrong-key failure that
// verification exists to prevent.
func activationSegment(metadata *header.Metadata) (string, *header.Segment, error) {
	if len(metadata.Segments) != 1 {
		return "", nil, &errs.Error{Kind: ErrUnsupported,
			Detail: fmt.Sprintf("select the segment to activate: the header declares %d segments; activation maps exactly one crypt segment", len(metadata.Segments))}
	}
	for id, segment := range metadata.Segments {
		if segment == nil || segment.Type != "crypt" {
			continue
		}
		// A segment with an integrity member sits on dm-integrity: its
		// sectors interleave with integrity tags and a journal, and its
		// volume key is the cipher key and the integrity key together.
		// Mapping dm-crypt straight over the device, which is all this
		// package does, reads garbage, and every write through the mapping
		// destroys the tags cryptsetup would check. It is refused before any
		// key is derived; the container's keyslots stay manageable.
		if segment.HasIntegrity() {
			return "", nil, &errs.Error{Kind: ErrUnsupported,
				Detail: "select the segment to activate: " + segmentLabel(id) + " is authenticated by dm-integrity (cryptsetup --integrity), which this package does not implement; open it with cryptsetup"}
		}
		return id, segment, nil
	}
	return "", nil, &errs.Error{Kind: errs.ErrInvalidHeader,
		Detail: "select the segment to activate: the header declares no crypt segment, so there is nothing to map"}
}

// unlockKeyslot attempts to unlock a keyslot with the given passphrase and
// returns the master key HELD IN PROTECTED MEMORY.
//
// keyslotID is the key this keyslot has in the header's keyslots object, and it
// is not decoration: it selects which digests are allowed to authenticate the
// recovered key. See verifyMasterKey.
//
// Everything derived along the way that is or reveals the master key -- the
// passphrase-derived key, the decrypted AF stripes, the merged key itself --
// lives in an enclave and is destroyed on every path out, success or failure.
// What is deliberately not enclaved is the ciphertext read off the device,
// which is already on the device; see areacipher.Transform.DecryptEnclave.
func unlockKeyslot(ctx context.Context, device string, keyslotID string, passphrase []byte, keyslot *header.Keyslot, digests map[string]*header.Digest, sys volumeSys) (enclave.ByteAccess, error) {
	f, err := openDevice("read the keyslot area", device, os.O_RDONLY, sys)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	return unlockKeyslotFrom(ctx, f, keyslotID, passphrase, keyslot, digests, sys)
}

// unlockKeyslotFrom is unlockKeyslot reading the keyslot area through dev, a
// descriptor the caller already holds -- the locked one, for a keyslot operation
// pinned to the device it locked (#249, A10).
func unlockKeyslotFrom(ctx context.Context, dev io.ReaderAt, keyslotID string, passphrase []byte, keyslot *header.Keyslot, digests map[string]*header.Digest, sys volumeSys) (enclave.ByteAccess, error) {
	// THE GATE, and it is one call rather than a prefix of checks written here.
	//
	// screenKeyslot performs every rejection this function can make WITHOUT the
	// passphrase -- the type, the geometry, the KDF's cost and its parameters,
	// the area cipher, the volume key size, the anti-forensic hash, whether the
	// area can hold its own split, and whether any digest attests the slot at
	// all -- and hands back the values the rest of this function needs.
	//
	// That is the whole of #45. The removal guard has to answer the same
	// question off metadata alone, and while these checks lived here it answered
	// it with a hand-maintained copy that was wrong three times and cost the
	// volume each time. The guard now calls screenKeyslot too. Consuming what it
	// returns is what makes the coupling mechanical: this function cannot skip
	// the screen and still work, so a rejection added there is inherited by the
	// guard and cannot be forgotten. See keyslotscreen.go.
	//
	// It is applied here as well as at the header read because this function is
	// also reachable with a keyslot a caller CONSTRUCTED rather than read.
	plan, err := screenKeyslot(keyslotID, keyslot, digests, sys.fipsMode)
	if err != nil {
		return nil, err
	}

	// Derive the key that WRAPS the area, to the AREA's key size -- which is
	// not the volume key's (#249, A6). cryptsetup --keyslot-key-size writes
	// them differently, and deriving to keyslot.KeySize decrypted such a
	// keyslot with the wrong key. Through passphraseKDF so the injected-key
	// path's tests can prove it never gets here; see UnlockWithVolumeKey.
	passphraseKey, err := sys.passphraseKDF(ctx, passphrase, keyslot.KDF, plan.areaKeySize)
	if err != nil {
		return nil, err
	}
	defer custody.Release(passphraseKey)

	return recoverKeyslotKey(ctx, dev, keyslotID, keyslot, plan, passphraseKey, digests, sys)
}

// recoverKeyslotKey is unlockKeyslotFrom past the derivation: it reads the area
// the screen bounded, decrypts it under the area key, merges the stripes and
// verifies the result against the digests that attest the keyslot.
//
// It is split out so a keyslot just WRITTEN can be read back through exactly
// this path with the area key its writer already holds (verifyWrittenKeyslot):
// the read-back then proves what the next unlock will see without paying the
// KDF a second time.
func recoverKeyslotKey(ctx context.Context, dev io.ReaderAt, keyslotID string, keyslot *header.Keyslot, plan keyslotPlan,
	passphraseKey enclave.ByteAccess, digests map[string]*header.Digest, sys volumeSys) (enclave.ByteAccess, error) {
	// The area bounds come from the screen, which parsed and bounded them --
	// see screenKeyslot.
	encryptedKeyMaterial := make([]byte, plan.areaSize)
	defer clearBytes(encryptedKeyMaterial)
	if _, err := dev.ReadAt(encryptedKeyMaterial, plan.areaOffset); err != nil {
		return nil, err
	}

	// Merge anti-forensic split.
	//
	// The keyslot area is 4 KiB-aligned and so is usually LARGER than the
	// keySize*stripes the merge consumes. Only plan.decryptLen is decrypted:
	// the stripes rounded UP to a whole sector. XTS tweaks on the sector index,
	// so decrypting a whole-sector prefix yields byte-identical plaintext to
	// decrypting the area and truncating, while the locked region needed shrinks
	// to the stripes themselves. Rounding up rather than down matters -- a short
	// final sector would be zero-padded by the transform and decrypt to
	// something else entirely.
	//
	// The screen computed all of it, including that the rounded length fits the
	// area; nothing here recomputes or re-checks any of it.
	decryptedKeyMaterial, err := plan.area.WithFIPS(sys.fipsMode()).DecryptEnclave(custody, encryptedKeyMaterial[:plan.decryptLen], passphraseKey)
	if err != nil {
		return nil, err
	}
	defer custody.Release(decryptedKeyMaterial)

	if decryptedKeyMaterial.Size() < plan.afSplitSize {
		return nil, &errs.Error{Kind: ErrKeyslotNotFound,
			Detail: fmt.Sprintf("decrypt keyslot %s: decrypted data too small: got %d, need %d", keyslotID, decryptedKeyMaterial.Size(), plan.afSplitSize)}
	}

	masterKey, err := afCodec(sys).Merge(decryptedKeyMaterial, keyslot.KeySize, af.Params{Stripes: keyslot.AF.Stripes, Hash: keyslot.AF.Hash})
	if err != nil {
		return nil, err
	}

	// Verify master key using the digests that authenticate THIS keyslot
	if err := verifyMasterKeyWithFIPS(ctx, masterKey, keyslotID, digests, sys.fipsMode); err != nil {
		custody.Release(masterKey)
		return nil, err
	}

	return masterKey, nil
}

// verifyMasterKey verifies a key recovered from keyslot keyslotID against the
// digests the header says authenticate THAT keyslot.
//
// # Only the digests that name this keyslot are consulted
//
// A LUKS2 digest carries a "keyslots" array naming the keyslots it
// authenticates, and it is not advisory: a container can hold more than one
// volume key -- that is the ordinary state of a container mid-reencryption --
// and each digest attests one of them. Trying EVERY digest against a key
// recovered from ONE keyslot accepts that key on the strength of an attestation
// made about a different keyslot. The unlock then treats it as authenticated
// for this keyslot's segments, and KillSlot authorizes a destructive operation
// through an association the header never made.
//
// So the digest set is filtered to those whose Keyslots contains keyslotID, and
// a keyslot no digest names cannot be authenticated at all -- reported as
// ErrInvalidHeader, because a keyslot with no digest is a broken header rather
// than a failed credential. A header with no digests at all lands in the same
// place for the same reason.
//
// # Among the digests that DO name it, every one is tried
//
// A digest that ERRORS is skipped exactly like a digest that mismatches. That
// symmetry is the fix for #58: the mismatch path already continued, but the
// derive and decode paths returned, so one unusable digest hid every usable one
// behind it. Under GODEBUG=fips140=only a PBKDF2-HMAC-SHA1 digest is refused,
// which made whether a volume opened depend on Go's randomized map iteration
// order -- the same header opening or not opening from run to run.
//
// The failure returned once the set is exhausted is deliberately identical
// whether the cause was a mismatch, an unsupported KDF, a corrupt salt or a
// digest of implausible length: the caller learns that this key did not verify
// and nothing about which digest rejected it or why.
func verifyMasterKey(ctx context.Context, masterKey enclave.ByteAccess, keyslotID string, digests map[string]*header.Digest) error {
	return verifyMasterKeyWithFIPS(ctx, masterKey, keyslotID, digests, fips.Probe)
}

// verifyMasterKeyWithFIPS is verifyMasterKey with an injectable FIPS policy,
// so recoverKeyslotKey can honor sys.fipsMode: a digest whose KDF the policy
// refuses must be classified as a FIPS refusal (keyslotRefusedByFIPS depends
// on that), not folded into ErrWrongKey by deriving against it anyway.
func verifyMasterKeyWithFIPS(ctx context.Context, masterKey enclave.ByteAccess, keyslotID string, digests map[string]*header.Digest, fipsMode func() fips.Mode) error {
	return verifyKeyAgainstDigests(ctx, masterKey, digests,
		func(digest *header.Digest) bool { return digestCovers(digest, keyslotID) },
		func(applicable int) error { return unverifiableKeyslotError(keyslotID, applicable) }, fipsMode)
}

// verifyVolumeKeyForSegment verifies a volume key the CALLER supplied against
// the digests the header says authenticate the crypt segment being mapped.
//
// There is no keyslot on this path, so the keyslot association verifyMasterKey
// filters on does not exist. The association that does is the digest's
// "segments" array, and it is the one cryptsetup consults when it activates a
// volume by volume key: the key must be attested FOR THE SEGMENT IT WILL
// DECRYPT. Everything else -- which digests are usable, that an error folds
// into the same verdict as a mismatch, when a header fault may be named -- is
// verifyMasterKey's reasoning unchanged, because it is the same loop.
//
// # The key's LENGTH is checked separately, because the digest cannot check it
//
// The digest is PBKDF2-HMAC over the key, and HMAC zero-pads a key shorter than
// the hash's block size before using it. So a key and the same key with zero
// bytes appended -- up to the block size, 128 bytes for sha512 -- produce the
// SAME digest. On the passphrase path that cannot matter: the key comes out of
// a keyslot at exactly that keyslot's key_size. Here the caller chooses the
// length, and a 32-byte volume key padded with 32 zeros would verify and then
// be handed to dm-crypt as a 64-byte aes-xts key, mapping garbage as plaintext.
//
// The length is therefore required to equal the key_size recorded by a keyslot
// the attesting digest names, and a digest is only consulted if it names one of
// that size -- which is cryptsetup's rule too: it takes the volume key size
// from the keyslots and refuses a volume key of any other. A volume whose
// digest names no keyslot records no key size and cannot be checked, so it is
// refused as a header fault. The format seam never produces one: a volume
// formatted around an injected key always carries its recovery keyslot.
func verifyVolumeKeyForSegment(ctx context.Context, volumeKey enclave.ByteAccess, segmentID string, metadata *header.Metadata) error {
	size := volumeKey.Size()

	coversSegment := func(digest *header.Digest) bool {
		return digest != nil && slices.Contains(digest.Segments, segmentID)
	}
	namesKeyslotOfSize := func(digest *header.Digest) bool {
		return slices.ContainsFunc(digest.Keyslots, func(id string) bool {
			keyslot := metadata.Keyslots[id]
			return keyslot != nil && keyslot.KeySize == size
		})
	}

	// Whether the header records ANY key size for this segment, and whether
	// this key's is one of them. Both come off cleartext header fields, so
	// saying so tells a reader nothing the device does not.
	recorded, matches := false, false
	for _, digest := range metadata.Digests {
		if !coversSegment(digest) {
			continue
		}
		for _, id := range digest.Keyslots {
			if keyslot := metadata.Keyslots[id]; keyslot != nil && keyslot.KeySize > 0 {
				recorded = true
				matches = matches || keyslot.KeySize == size
			}
		}
	}
	if !recorded {
		return &errs.Error{Kind: errs.ErrInvalidHeader,
			Detail: fmt.Sprintf("verify the volume key: no keyslot named by a digest of segment %s records the volume key size, so a supplied volume key cannot be checked", segmentID)}
	}
	if !matches {
		return &errs.Error{Kind: ErrWrongKey,
			Detail: fmt.Sprintf("verify the volume key: the supplied key is %d bytes, which no keyslot of segment %s records as the volume key size", size, segmentID)}
	}

	// Each digest is derived at most once here, and the header carries at most
	// MaxKeyslots of them (validateObjectCounts), so this is within the
	// operation budget by construction (#26).
	return verifyKeyAgainstDigests(ctx, volumeKey, metadata.Digests,
		func(digest *header.Digest) bool { return coversSegment(digest) && namesKeyslotOfSize(digest) },
		func(applicable int) error {
			return &errs.Error{Kind: errs.ErrInvalidHeader,
				Detail: fmt.Sprintf("verify the volume key: all %d digests that authenticate segment %s are unusable, so a supplied volume key could not be compared against any of them", applicable, segmentID)}
		}, fips.Probe)
}

// verifyKeyAgainstDigests is the comparison loop both verifications share. It
// tries every digest `covers` selects, and reports through `unverifiable` the
// two header faults in which no comparison ran; see verifyMasterKey for why
// those, and only those, are distinguished.
func verifyKeyAgainstDigests(ctx context.Context, masterKey enclave.ByteAccess, digests map[string]*header.Digest,
	covers func(*header.Digest) bool, unverifiable func(applicable int) error, fipsMode func() fips.Mode) error {
	// applicable counts the digests that ATTEST this keyslot; evaluated counts
	// the ones that got as far as a comparison. They differ by exactly the
	// digests that were unusable, and the difference is what separates a header
	// fault from a credential verdict at the bottom of this function.
	applicable := 0
	evaluated := 0

	for _, digest := range digests {
		// The association is checked BEFORE any derivation, so a digest that
		// does not attest this keyslot costs nothing and cannot influence the
		// outcome by any route.
		if !covers(digest) {
			continue
		}
		applicable++

		// Checked between digests: each digest check derives
		// a key, and a cancellation observed here stops trying further digests
		// rather than running the whole remaining set.
		if err := ctx.Err(); err != nil {
			return err
		}

		// The screen, the derivation and the comparison are evaluateDigest's;
		// see it for why each is done the way it is.
		//
		// A digest that fails any of it is SKIPPED, not fatal -- the symmetry
		// #58 established -- so one unusable digest cannot hide a usable one
		// behind it.
		ok, matched := evaluateDigest(masterKey, digest, fipsMode)
		if !ok {
			continue // unusable digest -- try the next one (#58)
		}
		evaluated++
		if matched {
			return nil // Verification successful
		}
	}

	// No digest in the header attests this keyslot. That is a header defect, not
	// a credential verdict, and it must not be reported as one: an operator told
	// their passphrase failed would go looking at the passphrase, while the
	// actual state is that the container declares a keyslot nothing can verify.
	if applicable == 0 {
		return unverifiable(applicable)
	}

	// Digests attest this keyslot and NOT ONE OF THEM COULD BE EVALUATED, so no
	// comparison ever ran. That is a header fault, and reporting it as a
	// verification verdict says a key was judged when nothing judged it (#41).
	//
	// # Why this case may be distinguished when the ones above it may not
	//
	// Every other exit from this function folds into ErrWrongKey
	// on purpose, and that must not be "tidied up" into per-cause errors. The
	// reason is a real attacker: someone holding the device can craft a header,
	// and an error distinguishing "digest 2 uses a KDF I refuse" from "digest 2
	// did not match" tells them WHICH keyslot to work on and how this
	// implementation reads the header. Any error derived from the OUTCOME OF A
	// COMPARISON carries that information, so all of them say one thing.
	//
	// This branch is the one place where no comparison happened. evaluated == 0
	// means every applicable digest fell out before EqualTo was reached, so
	// there is no comparison outcome in existence to leak, and the statement
	// being made is about the SHAPE OF THE HEADER -- which the attacker wrote,
	// and which anyone holding the device can read in cleartext. It leaks
	// nothing they do not already have.
	//
	// That is also why it stops here. The message names the keyslot and the
	// count and NOT the cause, even though the causes are header facts too:
	// naming them here would make naming them in the mixed case look like the
	// obvious next step, and in the mixed case a comparison DID run. The
	// boundary is easier to hold at "did a comparison happen" than at a
	// per-field judgement of what each cause reveals.
	//
	// The applicable == 0 branch above is the same distinction already being
	// drawn for the case where the header names no digest at all; this extends
	// it to the case where it names digests that cannot be used.
	if evaluated == 0 {
		return unverifiable(applicable)
	}

	return ErrWrongKey
}

// evaluateDigest compares masterKey against ONE digest. evaluated is false when
// the digest could not be used at all -- it failed screenDigest, or its
// derivation was refused -- and in that case matched is false too and no
// comparison ran. verifyMasterKey counts the two outcomes separately; see its
// comments for why that difference is the line between a header fault and a
// credential verdict.
//
// It is the body of verifyMasterKey's loop, split out so MigrateToFIPS can ask
// "does this particular digest attest this key" before it replaces the digest,
// through the same screen and the same comparison the unlock uses.
func evaluateDigest(masterKey enclave.ByteAccess, digest *header.Digest, fipsMode func() fips.Mode) (evaluated, matched bool) {
	// EVERY pre-derivation check lives in screenDigest, which the removal
	// guard also consumes -- see keyslotHasUsableDigest. This function used
	// to carry them inline, and the guard therefore had no way to ask the
	// question they answer: it settled for "is a digest ASSOCIATED with this
	// keyslot", counted a keyslot whose only digest could never be
	// evaluated, and authorized destroying the one that worked.
	//
	// It is consumed rather than repeated: `expected` and `kdf` are values
	// this function cannot obtain any other way, so the screen cannot be
	// skipped and a check added to it cannot fail to reach the guard.
	//
	// Deriving to the length ACTUALLY STORED, which screenDigest establishes,
	// is what cryptsetup does and is the only choice correct in both
	// directions. A cryptsetup-written sha512 volume stores 64 bytes and
	// needs 64 derived, which a hardcoded 32 could never produce (#73). A
	// volume written by an earlier version of THIS library stores 32 bytes
	// under a "sha512" label; deriving to the hash's natural 64 would render
	// every such volume unopenable.
	expected, kdf, err := screenDigest(digest, fipsMode)
	defer clearBytes(expected)
	if err != nil {
		return false, false
	}

	// The derivation borrows the master key in place; this package makes
	// no copy of it.
	//
	// It does leave protected memory once inside the KDF, though: pbkdf2
	// stringifies its password argument, so every digest tried here puts
	// the master key into an unwipeable Go string. See exposure 2 in
	// internal/secret. Trying N digests materializes it N times.
	//
	// context.Background(), not the caller's ctx: a digest check decides
	// WHICH key a keyslot holds and must always run to completion, exactly
	// like createDigest. Only the slow, cancellable passphrase KDF observes
	// ctx, and only before it starts: a derivation in flight is never
	// interrupted.
	derived, err := deriveKeySecretIn(context.Background(), masterKey, kdf, len(expected), fipsMode())
	if err != nil {
		return false, false // e.g. non-approved KDF in FIPS mode (#58)
	}

	// Compare using constant-time comparison to prevent timing attacks.
	// Memory.EqualTo does exactly that, under the enclave's own read
	// lock, so the derived digest is never copied out to be compared. The
	// stored digest is a cleartext header field and is cleared anyway; the
	// derived one is destroyed before returning, so a caller trying several
	// digests never holds more than one locked region for them at a time.
	matched, err = derived.EqualTo(expected)
	custody.Release(derived)
	if err != nil {
		return false, false // the derived digest could not be compared: unusable, like a refused KDF
	}
	return true, matched
}
