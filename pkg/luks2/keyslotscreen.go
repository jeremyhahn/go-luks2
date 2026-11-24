// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"fmt"
	"math"
	"os"
	"slices"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/af"
	"github.com/jeremyhahn/go-luks2/internal/areacipher"
	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// screenKeyslot is the one passphrase-free answer to whether a keyslot can open the volume; unlock and the removal guard both consume it, and the guard may count fewer keyslots than unlock tries, never more.

// keyslotSectorSize is the sector size the keyslot area's XTS transform tweaks
// on. It is a property of the LUKS2 format -- key material is always processed
// in 512-byte sectors, independent of the data segment's sector size.
const keyslotSectorSize = areacipher.SectorSize

// keyslotPlan holds every value derived from a screened keyslot's metadata that the unlock path needs.
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

	// areaKeySize is area.key_size, the key that wraps the area; the keyslot's key_size is the volume key.
	areaKeySize int

	// area is the transform the whole area.encryption spec names.
	area areacipher.Transform
}

// screenKeyslot makes every rejection unlockKeyslot can make without the passphrase, through the same validators, and returns the plan; failures keep their sentinels.
func screenKeyslot(id string, keyslot *header.Keyslot, digests map[string]*header.Digest, fipsMode func() fips.Mode) (keyslotPlan, error) {
	var plan keyslotPlan

	// A LUKS2 "reencrypt" keyslot has no kdf object and its area is a checksum
	// region rather than key material, so it holds no passphrase-wrapped volume
	// key. It is valid metadata that cannot open anything.
	if keyslot == nil {
		return plan, &errs.Error{Kind: ErrKeyslotNotFound, Detail: fmt.Sprintf("luks2 keyslot %q: is null", id)}
	}
	if keyslot.Type != "luks2" {
		return plan, &errs.Error{Kind: ErrKeyslotNotFound,
			Detail: fmt.Sprintf("luks2 keyslot %q: type %q cannot be opened; only luks2 keyslots hold a passphrase-wrapped volume key", id, keyslot.Type)}
	}

	// The gate: everything below trusts the keyslot's declared geometry.
	if err := header.ValidateKeyslot(id, keyslot); err != nil {
		return plan, err
	}

	// The KDF cost, checked before any of it is spent (header.ValidateKDFCost).
	if err := header.ValidateKDFCost(keyslot.KDF); err != nil {
		return plan, &errs.Error{Kind: ErrKeyslotNotFound, Detail: fmt.Sprintf("luks2 keyslot %q: declares a KDF cost this package refuses", id), Err: err}
	}

	// What the KDF would REFUSE, as opposed to what it would cost.
	if err := screenKDFParameters(keyslot.KDF, fipsMode); err != nil {
		return plan, &errs.Error{Kind: ErrKeyslotNotFound, Detail: fmt.Sprintf("luks2 keyslot %q: declares KDF parameters the derivation refuses", id), Err: err}
	}

	// From here the order mirrors unlockKeyslot's, so the same cause is reported first.
	var err error
	plan.areaOffset, err = parseSize(keyslot.Area.Offset)
	if err != nil {
		return plan, &errs.Error{Kind: ErrKeyslotNotFound,
			Detail: fmt.Sprintf("luks2 keyslot %q: declares an area offset %q that is not a number", id, keyslot.Area.Offset), Err: err}
	}
	plan.areaSize, err = parseSize(keyslot.Area.Size)
	if err != nil {
		return plan, &errs.Error{Kind: ErrKeyslotNotFound,
			Detail: fmt.Sprintf("luks2 keyslot %q: declares an area size %q that is not a number", id, keyslot.Area.Size), Err: err}
	}

	// header.ValidateKeyslot has already established that this product does not
	// overflow and fits the area, so it is computed rather than re-checked.
	plan.afSplitSize = keyslot.KeySize * keyslot.AF.Stripes
	plan.decryptLen = alignTo(int64(plan.afSplitSize), keyslotSectorSize)

	if plan.decryptLen > plan.areaSize {
		// An area not a whole number of sectors is refused, not clamped.
		return plan, &errs.Error{Kind: ErrKeyslotNotFound,
			Detail: fmt.Sprintf("luks2 keyslot %q: area of %d bytes is not a whole number of %d-byte sectors and cannot hold the %d bytes of AF material this keyslot declares",
				id, plan.areaSize, keyslotSectorSize, plan.afSplitSize)}
	}

	// The area cipher spec is read whole; the volume key size is held to AES data-cipher sizes.
	plan.area, err = parseKeyslotAreaEncryption(keyslot.Area.Encryption)
	if err != nil {
		return plan, &errs.Error{Kind: ErrUnsupported, Detail: fmt.Sprintf(
			"keyslot %s area encryption %q; the keyslot area transforms this package implements are %s",
			id, keyslot.Area.Encryption, areacipher.Specs()), Err: ErrKeyslotNotFound}
	}
	if err := areacipher.ValidateVolumeKeySize(keyslot.KeySize); err != nil {
		return plan, &errs.Error{Kind: ErrKeyslotNotFound, Detail: fmt.Sprintf("luks2 keyslot %q: declares a volume key size no AES data cipher can use", id), Err: err}
	}
	// The area key size is what the KDF derives; missing (0) is refused.
	plan.areaKeySize = keyslot.Area.KeySize
	if err := plan.area.ValidateKeySize(plan.areaKeySize); err != nil {
		return plan, &errs.Error{Kind: ErrKeyslotNotFound,
			Detail: fmt.Sprintf("luks2 keyslot %q: declares an area key size of %d bytes, which its %s area cipher cannot use", id, plan.areaKeySize, keyslot.Area.Encryption), Err: err}
	}

	// The AF merge resolves this hash; SHA-1 resolves for converted LUKS1 volumes.
	if err := af.ValidateReadHash(keyslot.AF.Hash); err != nil {
		return plan, &errs.Error{Kind: ErrKeyslotNotFound, Detail: fmt.Sprintf("luks2 keyslot %q: declares an anti-forensic hash nothing implements", id), Err: err}
	}
	// The FIPS 140-3 gate on it, after the structural check so a refusal here
	// is a well-formed keyslot this process may not run -- which is what
	// keyslotRefusedByFIPS depends on to call it an import, not damage.
	if err := af.RequireApprovedHash(fipsMode(), keyslot.AF.Hash); err != nil {
		return plan, &errs.Error{Kind: ErrKeyslotNotFound, Detail: fmt.Sprintf("luks2 keyslot %q: declares an anti-forensic hash the merge refuses", id), Err: err}
	}

	// A keyslot no digest attests is refused with verifyMasterKey's ErrInvalidHeader and wording (unverifiableKeyslotError).
	applicable, usable := keyslotDigestCounts(id, digests, fipsMode)
	if usable == 0 {
		return plan, unverifiableKeyslotError(id, applicable)
	}

	return plan, nil
}

// screenKDFParameters rejects a KDF deriveKeyEnclave would refuse, through the same helpers; structural checks before FIPS gates, type matched raw.
func screenKDFParameters(kdf *header.KDF, fipsMode func() fips.Mode) error {
	if kdf == nil {
		return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "no KDF object"}
	}

	if err := screenKDFStructure(kdf); err != nil {
		return err
	}

	if err := fipsMode().RequireKDF(kdf.Type); err != nil {
		return err
	}

	// The second FIPS gate, and the last check: PBKDF2 over SHA-1. Its name
	// has already resolved in screenKDFStructure, so the only thing this can
	// still refuse is the policy.
	if kdf.Type == kdfTypePBKDF2 {
		if _, err := getPBKDF2HashFunc(kdf.Hash, fipsMode); err != nil {
			return err
		}
	}

	return nil
}

// screenKDFStructure is screenKDFParameters without its FIPS gates, for keyslotRefusedByFIPS.
func screenKDFStructure(kdf *header.KDF) error {
	if kdf == nil {
		return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "no KDF object"}
	}

	if _, err := decodeBase64(kdf.Salt); err != nil {
		return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "invalid salt", Err: err}
	}

	switch kdf.Type {
	case kdfTypePBKDF2:
		if _, err := pbkdf2Hash(kdf.Hash); err != nil {
			return err
		}
	case kdfTypeArgon2i, kdfTypeArgon2id:
		// Nothing further is decidable without the passphrase: cost is
		// header.ValidateKDFCost's, and argon2 has no algorithm name to resolve.
	default:
		return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "unsupported KDF type: " + kdf.Type}
	}

	return nil
}

// parseKeyslotAreaEncryption returns the transform area.encryption names, or ErrUnsupported; the accepted set is areacipher.Parse's.
func parseKeyslotAreaEncryption(spec string) (areacipher.Transform, error) {
	t, ok := areacipher.Parse(spec)
	if !ok {
		return areacipher.Transform{}, &errs.Error{Kind: ErrUnsupported, Detail: fmt.Sprintf(
			"area encryption %q; the keyslot area transforms this package implements are %s",
			spec, areacipher.Specs()), Err: ErrKeyslotNotFound}
	}
	return t, nil
}

// digestCovers reports whether a digest attests the named keyslot.
func digestCovers(digest *header.Digest, keyslotID string) bool {
	return digest != nil && slices.Contains(digest.Keyslots, keyslotID)
}

// screenDigest makes every check verifyMasterKey makes before deriving and returns what the derivation needs; the caller must clearBytes expected on every path.
func screenDigest(digest *header.Digest, fipsMode func() fips.Mode) ([]byte, *header.KDF, error) {
	expected, kdf, err := screenDigestStructure(digest)
	if err != nil {
		return expected, nil, err
	}

	// The FIPS gates run last, so a refusal here is never damage.
	if err := screenKDFParameters(kdf, fipsMode); err != nil {
		return expected, nil, err
	}

	return expected, kdf, nil
}

// argon2DigestLen is the length an Argon2 digest that declares no hash is derived to.
const argon2DigestLen = 32

// screenDigestStructure is screenDigest without the FIPS gates; the caller owns expected.
func screenDigestStructure(digest *header.Digest) ([]byte, *header.KDF, error) {
	if digest == nil {
		return nil, nil, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "digest is null"}
	}

	expected, err := decodeBase64(digest.Digest)
	if err != nil {
		return nil, nil, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "digest value is not base64", Err: err}
	}

	// Derived lengths are a whitelist: the declared hash's, legacyDigestLen and luks1DigestLen.
	argon2 := digest.Type == kdfTypeArgon2i || digest.Type == kdfTypeArgon2id
	wantLen := argon2DigestLen
	if !argon2 || digest.Hash != "" {
		h, err := pbkdf2Hash(digest.Hash)
		if err != nil {
			return expected, nil, err
		}
		wantLen = h.Size()
	}
	if len(expected) != wantLen && len(expected) != legacyDigestLen && len(expected) != luks1DigestLen {
		return expected, nil, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: fmt.Sprintf(
			"digest is %d bytes, which agrees with neither %s nor a legacy carve-out", len(expected), digest.Hash)}
	}

	kdf := &header.KDF{
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
	if err := header.ValidateKDFCost(kdf); err != nil {
		return expected, nil, err
	}
	if err := screenKDFStructure(kdf); err != nil {
		return expected, nil, err
	}

	return expected, kdf, nil
}

// keyslotDigestCounts reports how many digests attest this keyslot and how many can be evaluated; any usable one suffices.
func keyslotDigestCounts(keyslotID string, digests map[string]*header.Digest, fipsMode func() fips.Mode) (applicable, usable int) {
	for _, digest := range digests {
		if !digestCovers(digest, keyslotID) {
			continue
		}
		applicable++
		expected, _, err := screenDigest(digest, fipsMode)
		clearBytes(expected)
		if err == nil {
			usable++
		}
	}
	return applicable, usable
}

// unverifiableKeyslotError says why no digest can authenticate this keyslot, worded the same from the screen and verifyMasterKey.
func unverifiableKeyslotError(keyslotID string, applicable int) error {
	if applicable == 0 {
		return &errs.Error{
			Kind: ErrInvalidHeader,
			Detail: fmt.Sprintf("no digest in the header authenticates keyslot %s, so a key recovered from it cannot be verified",
				keyslotID),
		}
	}
	return &errs.Error{
		Kind: ErrInvalidHeader,
		Detail: fmt.Sprintf("all %d digests that authenticate keyslot %s are unusable, so a key recovered from it could not be compared against any of them",
			applicable, keyslotID),
	}
}

// keyslotBoundToSegment reports whether the header declares keyslotID holds segmentID's key: the segment exists and every attesting digest names it.
func keyslotBoundToSegment(metadata *header.Metadata, keyslotID, segmentID string) bool {
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

// keyslotBoundToDataSegments is keyslotBoundToSegment for every data segment; false when there are none.
func keyslotBoundToDataSegments(metadata *header.Metadata, keyslotID string) bool {
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

// recoveredKeyBoundToSegment reports whether key matches a digest naming both keyslotID and segmentID.
func recoveredKeyBoundToSegment(metadata *header.Metadata, keyslotID, segmentID string, key enclave.ByteAccess) bool {
	if metadata == nil || key == nil || metadata.Segments[segmentID] == nil {
		return false
	}
	for _, id := range sortedDigestIDs(metadata.Digests) {
		digest := metadata.Digests[id]
		if !digestCovers(digest, keyslotID) || !slices.Contains(digest.Segments, segmentID) {
			continue
		}
		if _, matched := evaluateDigest(key, digest, fips.Probe); matched {
			return true
		}
	}
	return false
}

// keyslotCanOpenVolume reports whether a keyslot could yield the volume key: screened, at a canonical id, bound to every segment, and confined to the keyslots area.
func keyslotCanOpenVolume(f *os.File, hdr *header.BinaryHeader, metadata *header.Metadata, id string, measureDeviceSize func(*os.File) (int64, error)) bool {
	if _, ok := header.CanonicalKeyslotID(id); !ok {
		return false
	}
	if !keyslotHoldsKeyMaterial(f, id, metadata.Keyslots[id], metadata.Digests, measureDeviceSize) {
		return false
	}
	if !keyslotBoundToDataSegments(metadata, id) {
		return false
	}
	return checkKeyslotAreaConfined(hdr, metadata, id) == nil
}

// keyslotHoldsKeyMaterial reports whether a keyslot's area holds key material some passphrase could open, bound or not.
func keyslotHoldsKeyMaterial(f *os.File, id string, keyslot *header.Keyslot, digests map[string]*header.Digest, measureDeviceSize func(*os.File) (int64, error)) bool {
	plan, err := screenKeyslot(id, keyslot, digests, fips.Probe)
	if err != nil {
		return false
	}
	return checkAreaWithinDevice(f, plan.areaOffset, plan.areaSize, measureDeviceSize) == nil
}

// checkKeyslotAreaConfined refuses a keyslot whose area is not wholly inside the
// container's reserved keyslots area (keyslotsAreaBounds), or that reaches into
// any data segment. See checkAreaConfined.
func checkKeyslotAreaConfined(hdr *header.BinaryHeader, metadata *header.Metadata, id string) error {
	keyslot := metadata.Keyslots[id]
	if keyslot == nil {
		return &errs.Error{Kind: ErrKeyslotNotFound, Detail: "keyslot " + id + " declares no area, so what removing it would wipe is unknown"}
	}
	return checkAreaConfined(hdr, metadata, id, keyslot.Area)
}

// checkAreaConfined refuses a keyslot area outside the reserved keyslots area or reaching any data segment.
func checkAreaConfined(hdr *header.BinaryHeader, metadata *header.Metadata, id string, area *header.KeyslotArea) error {
	start, limit, err := keyslotsAreaBounds(hdr, metadata)
	if err != nil {
		return err
	}
	return confineArea(start, limit, metadata, id, area)
}

// checkKeyslotAreaConfinedByMetadata is checkKeyslotAreaConfined from metadata alone (header size = json_size + 4096).
func checkKeyslotAreaConfinedByMetadata(metadata *header.Metadata, id string) error {
	keyslot := metadata.Keyslots[id]
	if keyslot == nil {
		return &errs.Error{Kind: ErrKeyslotNotFound, Detail: "keyslot " + id + " is null"}
	}
	if metadata.Config == nil {
		return &errs.Error{Kind: ErrInvalidHeader, Detail: "header has no config object, so the keyslots area is undefined"}
	}
	jsonSize, err := parseSize(metadata.Config.JSONSize)
	if err != nil || jsonSize <= 0 || jsonSize > header.HeaderMaxSize-header.HeaderSize {
		return &errs.Error{Kind: ErrInvalidHeader, Detail: fmt.Sprintf(
			"config.json_size %q does not describe a LUKS2 header area, so where the keyslots area starts is unknown", metadata.Config.JSONSize)}
	}
	start, limit, err := keyslotsAreaFrom(2*(jsonSize+header.HeaderSize), metadata)
	if err != nil {
		return err
	}
	return confineArea(start, limit, metadata, id, keyslot.Area)
}

// dataOnAnotherDevice reports whether a data segment at offset 0 is a detached header's, as cryptsetup treats it.
func dataOnAnotherDevice(segmentOffset int64) bool {
	return segmentOffset == 0
}

// confineArea is the check itself, against a keyslots area [start, limit).
func confineArea(start, limit int64, metadata *header.Metadata, id string, area *header.KeyslotArea) error {
	if area == nil {
		return &errs.Error{Kind: ErrKeyslotNotFound, Detail: "keyslot " + id + " declares no area, so what removing it would wipe is unknown"}
	}
	offset, offErr := parseSize(area.Offset)
	size, sizeErr := parseSize(area.Size)
	if offErr != nil || sizeErr != nil || offset < 0 || size <= 0 || offset > math.MaxInt64-size {
		return &errs.Error{Kind: ErrKeyslotNotFound, Detail: fmt.Sprintf(
			"keyslot %s declares an area at offset %q of size %q, which is not a byte range", id, area.Offset, area.Size)}
	}
	end := offset + size

	if offset < start || end > limit {
		return &errs.Error{Kind: ErrKeyslotAreaOverlap, Detail: fmt.Sprintf(
			"keyslot %s declares its area at [%d,%d), outside the container's keyslots area [%d,%d); "+
				"reading or wiping it would touch bytes that are not keyslot material", id, offset, end, start, limit)}
	}

	for _, segmentID := range dataSegmentIDs(metadata) {
		segment := metadata.Segments[segmentID]
		segmentStart, err := parseSize(segment.Offset)
		if err != nil || segmentStart < 0 {
			return &errs.Error{Kind: ErrInvalidHeader, Detail: fmt.Sprintf(
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
				return &errs.Error{Kind: ErrInvalidHeader, Detail: fmt.Sprintf(
					"data segment %s declares a size of %q, so whether keyslot %s's area overlaps it cannot be decided",
					segmentID, segment.Size, id)}
			}
			segmentEnd = segmentStart + segmentSize
		}
		if offset < segmentEnd && segmentStart < end {
			return &errs.Error{Kind: ErrKeyslotAreaOverlap, Detail: fmt.Sprintf(
				"keyslot %s declares its area at [%d,%d), which overlaps data segment %s starting at %d; "+
					"reading or wiping it would touch the encrypted data", id, offset, end, segmentID, segmentStart)}
		}
	}
	return nil
}

// deviceSizeFromFile measures the device behind an open descriptor: BLKGETSIZE64, then Stat.
func deviceSizeFromFile(f *os.File) (int64, error) {
	return device.Size(f)
}

// measureDeviceSize (volumeSys.measureDeviceSize) is deviceSizeFromFile; tests override it.

// checkAreaWithinDevice reports whether a keyslot area lies inside the device, and refuses when the size cannot be measured.
func checkAreaWithinDevice(f *os.File, offset, size int64, measureDeviceSize func(*os.File) (int64, error)) error {
	deviceSize, err := measureDeviceSize(f)
	if err != nil {
		return &errs.Error{
			Kind:   ErrKeyslotNotFound,
			Detail: "the size of this device could not be measured, so a keyslot area cannot be proved to lie inside it",
			Err:    err,
		}
	}

	if deviceSize <= 0 {
		return &errs.Error{
			Kind: ErrKeyslotNotFound,
			Detail: fmt.Sprintf("this device reports a size of %d, so a keyslot area at %d..%d cannot be proved to lie inside it",
				deviceSize, offset, offset+size),
		}
	}

	if offset+size > deviceSize {
		return &errs.Error{
			Kind: ErrKeyslotNotFound,
			Detail: fmt.Sprintf("keyslot area %d..%d lies outside the %d byte device",
				offset, offset+size, deviceSize),
		}
	}

	return nil
}
