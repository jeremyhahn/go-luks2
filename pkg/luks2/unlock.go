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

// blockDeviceOf returns the device number of the block device f is open on and refuses anything else; a seam for unit tests.
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

// activationSegment returns the one segment a mapping is built from; a header activates only with exactly one segment, a crypt segment.
func activationSegment(metadata *header.Metadata) (string, *header.Segment, error) {
	if len(metadata.Segments) != 1 {
		return "", nil, &errs.Error{Kind: ErrUnsupported,
			Detail: fmt.Sprintf("select the segment to activate: the header declares %d segments; activation maps exactly one crypt segment", len(metadata.Segments))}
	}
	for id, segment := range metadata.Segments {
		if segment == nil || segment.Type != "crypt" {
			continue
		}
		// A segment on dm-integrity is refused before any key is derived; its keyslots stay manageable.
		if segment.HasIntegrity() {
			return "", nil, &errs.Error{Kind: ErrUnsupported,
				Detail: "select the segment to activate: " + segmentLabel(id) + " is authenticated by dm-integrity (cryptsetup --integrity), which this package does not implement; open it with cryptsetup"}
		}
		return id, segment, nil
	}
	return "", nil, &errs.Error{Kind: errs.ErrInvalidHeader,
		Detail: "select the segment to activate: the header declares no crypt segment, so there is nothing to map"}
}

// unlockKeyslot unlocks keyslotID with the passphrase and returns the master key in protected memory; every intermediate secret is destroyed on every path.
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
	// screenKeyslot makes every passphrase-free rejection, shared with the removal guard; applied here too for constructed keyslots.
	plan, err := screenKeyslot(keyslotID, keyslot, digests, sys.fipsMode)
	if err != nil {
		return nil, err
	}

	// Derive the area key to the area's key size, through passphraseKDF.
	passphraseKey, err := sys.passphraseKDF(ctx, passphrase, keyslot.KDF, plan.areaKeySize)
	if err != nil {
		return nil, err
	}
	defer custody.Release(passphraseKey)

	return recoverKeyslotKey(ctx, dev, keyslotID, keyslot, plan, passphraseKey, digests, sys)
}

// recoverKeyslotKey reads and decrypts the screened area, merges the stripes and verifies the key; also used to read back a just-written keyslot.
func recoverKeyslotKey(ctx context.Context, dev io.ReaderAt, keyslotID string, keyslot *header.Keyslot, plan keyslotPlan,
	passphraseKey enclave.ByteAccess, digests map[string]*header.Digest, sys volumeSys) (enclave.ByteAccess, error) {
	// The area bounds come from the screen, which parsed and bounded them --
	// see screenKeyslot.
	encryptedKeyMaterial := make([]byte, plan.areaSize)
	defer clearBytes(encryptedKeyMaterial)
	if _, err := dev.ReadAt(encryptedKeyMaterial, plan.areaOffset); err != nil {
		return nil, err
	}

	// Merge the anti-forensic split, decrypting only plan.decryptLen: the stripes rounded up to a whole sector.
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

	// Verify the master key using the digests that authenticate this keyslot.
	if err := verifyMasterKeyWithFIPS(ctx, masterKey, keyslotID, digests, sys.fipsMode); err != nil {
		custody.Release(masterKey)
		return nil, err
	}

	return masterKey, nil
}

// verifyMasterKey verifies a key from keyslotID against the digests naming that keyslot, trying each and skipping errors like mismatches; no naming digest is ErrInvalidHeader, and every failure looks the same.
func verifyMasterKey(ctx context.Context, masterKey enclave.ByteAccess, keyslotID string, digests map[string]*header.Digest) error {
	return verifyMasterKeyWithFIPS(ctx, masterKey, keyslotID, digests, fips.Probe)
}

// verifyMasterKeyWithFIPS is verifyMasterKey with an injectable FIPS policy, so a refused digest KDF is classified as a FIPS refusal.
func verifyMasterKeyWithFIPS(ctx context.Context, masterKey enclave.ByteAccess, keyslotID string, digests map[string]*header.Digest, fipsMode func() fips.Mode) error {
	return verifyKeyAgainstDigests(ctx, masterKey, digests,
		func(digest *header.Digest) bool { return digestCovers(digest, keyslotID) },
		func(applicable int) error { return unverifiableKeyslotError(keyslotID, applicable) }, fipsMode)
}

// verifyVolumeKeyForSegment verifies a caller-supplied volume key against the digests naming the crypt segment, and requires its length to equal a named keyslot's key_size, as cryptsetup does.
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

	// At most MaxKeyslots digests, each derived at most once.
	return verifyKeyAgainstDigests(ctx, volumeKey, metadata.Digests,
		func(digest *header.Digest) bool { return coversSegment(digest) && namesKeyslotOfSize(digest) },
		func(applicable int) error {
			return &errs.Error{Kind: errs.ErrInvalidHeader,
				Detail: fmt.Sprintf("verify the volume key: all %d digests that authenticate segment %s are unusable, so a supplied volume key could not be compared against any of them", applicable, segmentID)}
		}, fips.Probe)
}

// verifyKeyAgainstDigests is the comparison loop both verifications share; unverifiable reports the header faults where no comparison ran.
func verifyKeyAgainstDigests(ctx context.Context, masterKey enclave.ByteAccess, digests map[string]*header.Digest,
	covers func(*header.Digest) bool, unverifiable func(applicable int) error, fipsMode func() fips.Mode) error {
	// applicable counts digests attesting this keyslot, evaluated those that reached a comparison.
	applicable := 0
	evaluated := 0

	for _, digest := range digests {
		// The association is checked before any derivation.
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

		// evaluateDigest screens, derives and compares; a digest failing any step is skipped, not fatal.
		ok, matched := evaluateDigest(masterKey, digest, fipsMode)
		if !ok {
			continue // unusable digest -- try the next one
		}
		evaluated++
		if matched {
			return nil // Verification successful
		}
	}

	// No digest attests this keyslot: a header defect, not a credential verdict.
	if applicable == 0 {
		return unverifiable(applicable)
	}

	// Digests attest this keyslot but none could be evaluated: a header fault, safe to distinguish because no comparison ran; the message names the keyslot and count, not the cause.
	if evaluated == 0 {
		return unverifiable(applicable)
	}

	return ErrWrongKey
}

// evaluateDigest compares masterKey against one digest; evaluated is false when the digest could not be used and no comparison ran. Also used by MigrateToFIPS.
func evaluateDigest(masterKey enclave.ByteAccess, digest *header.Digest, fipsMode func() fips.Mode) (evaluated, matched bool) {
	// screenDigest holds every pre-derivation check, shared with the removal guard; derive to the stored length, as cryptsetup does.
	expected, kdf, err := screenDigest(digest, fipsMode)
	defer clearBytes(expected)
	if err != nil {
		return false, false
	}

	// The derivation borrows the master key in place, though pbkdf2 copies it into a string (exposure 2 in internal/secret); context.Background() so it always completes.
	derived, err := deriveKeySecretIn(context.Background(), masterKey, kdf, len(expected), fipsMode())
	if err != nil {
		return false, false // e.g. non-approved KDF in FIPS mode
	}

	// Constant-time comparison via Memory.EqualTo under the enclave's read lock; the derived digest is destroyed before returning.
	matched, err = derived.EqualTo(expected)
	custody.Release(derived)
	if err != nil {
		return false, false // the derived digest could not be compared: unusable, like a refused KDF
	}
	return true, matched
}
