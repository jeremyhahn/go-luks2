// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"github.com/jeremyhahn/go-luks2/internal/fips"
	"io"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/af"
	"github.com/jeremyhahn/go-luks2/internal/areacipher"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// LUKS2 keyslot constants
const (
	// MaxKeyslots is the maximum number of keyslots in LUKS2
	MaxKeyslots = 32

	// keyslotAreaAlignment is the alignment for keyslot areas
	keyslotAreaAlignment = 4096
)

// LUKS2 keyslot priorities; an absent member means normal, and the larger value is tried first.
const (
	// keyslotPriorityIgnore marks a keyslot a scan does not try; only naming
	// it opens it.
	keyslotPriorityIgnore = 0

	// keyslotPriorityNormal is the default and the meaning of an absent member.
	keyslotPriorityNormal = 1

	// keyslotPriorityPrefer marks a keyslot to try first.
	keyslotPriorityPrefer = 2
)

// Priority is a keyslot's try-order preference; the zero value PriorityDefault means not asked for, and values are the on-disk encoding plus one.
type Priority int

const (
	PriorityDefault Priority = iota
	PriorityIgnore
	PriorityNormal
	PriorityPrefer
)

// valid reports whether p is one of the declared values.
func (p Priority) valid() bool {
	return p >= PriorityDefault && p <= PriorityPrefer
}

// priorityFromDisk reads a keyslot's priority member: absent is
// PriorityNormal, the LUKS2 default; a present value v is Priority(v+1).
func priorityFromDisk(v *int) Priority {
	if v == nil {
		return PriorityNormal
	}
	return Priority(*v + 1)
}

// errInvalidPriority refuses a Priority outside the declared values instead
// of writing it.
func errInvalidPriority(p Priority) error {
	return &errs.Error{Kind: errs.ErrInvalidArgument, Detail: fmt.Sprintf("invalid keyslot priority %d", int(p))}
}

// keyslotInfoFromMetadata builds a KeyslotInfo for keyslot id, refusing an unparseable on-disk KDF type.
func keyslotInfoFromMetadata(id int, ks *header.Keyslot) (KeyslotInfo, error) {
	info := KeyslotInfo{ID: id, Type: ks.Type, KeySize: ks.KeySize, Priority: priorityFromDisk(ks.Priority)}
	if ks.Area != nil {
		info.Encryption = ks.Area.Encryption
	}
	if ks.KDF != nil {
		kdf, err := kdfParamsFromDisk(ks.KDF)
		if err != nil {
			return KeyslotInfo{}, err
		}
		info.KDF = kdf
	}
	return info, nil
}

// addKeyOptionsForTest contains options for adding a new key
type addKeyOptionsForTest struct {
	// header.Keyslot specifies which keyslot to use (nil = auto-select)
	Keyslot *int

	// KDFType is "pbkdf2" (or a hash alias), "argon2i" or "argon2id"; empty means DefaultKDFSpec, or Argon2id when an Argon2 cost is set.
	KDFType string

	// Hash specifies the hash algorithm for PBKDF2. Empty means the hash the
	// KDF type names (sha512 for "pbkdf2-sha512"), or sha256 for a type that
	// names none. It is only used when the KDF is PBKDF2.
	Hash string

	// Argon2 parameters (optional, uses defaults if not specified)
	Argon2Time     int
	Argon2Memory   int
	Argon2Parallel int

	// PBKDF2 parameters (for pbkdf2 KDF type)
	PBKDFIterTime int

	// InheritedArgon2Cost is set by AddKey to the Argon2 cost taken from the container, and nil otherwise.
	InheritedArgon2Cost *header.KDF

	// PBKDFIterations is an exact PBKDF2 count, overriding PBKDFIterTime; below the hash's floor it is refused with ErrPBKDFIterationsTooLow.
	PBKDFIterations int

	// No key-size or cipher option: the keyslot key size must equal the volume key length.
}

// KeyslotParams configures AddKeyslot and ChangeKeyslot.
type KeyslotParams struct {
	// Slot is the keyslot id to use. Nil picks the lowest free one.
	// ChangeKeyslot ignores it: the slot it rewrites is the one the caller's
	// *Key came from.
	Slot *int

	// Priority is the try-order preference; PriorityDefault gives normal on add and keeps the existing priority on ChangeKeyslot.
	Priority Priority

	// KDF is the new keyslot's cost; zero resolves to the default KDF or the container's inherited Argon2 cost.
	KDF KDFParams
}

// toAddKeyOptions carries p's KDF choice into the shape addKeyslotWithMasterKey
// and the ChangeKey core already consume. It does not set header.Keyslot or
// InheritedArgon2Cost: AddKeyslot and ChangeKeyslot fill those in themselves.
func (p KeyslotParams) toAddKeyOptions() *addKeyOptionsForTest {
	opts := &addKeyOptionsForTest{}
	if p.KDF.Type != "" {
		opts.KDFType = string(p.KDF.Type)
	}
	if p.KDF.Hash != 0 {
		opts.Hash = hashAlgoName(p.KDF.Hash)
	}
	opts.Argon2Time = p.KDF.Time
	opts.Argon2Memory = p.KDF.MemoryKiB
	opts.Argon2Parallel = p.KDF.Parallel
	if p.KDF.IterTime != 0 {
		opts.PBKDFIterTime = int(p.KDF.IterTime / time.Millisecond)
	}
	opts.PBKDFIterations = p.KDF.Iterations
	return opts
}

// addKeyFormatOptions maps add-key options onto format options; zero means unset and any other value, even out of range, is passed on to be refused.
func addKeyFormatOptions(opts *addKeyOptionsForTest, metadata *header.Metadata, fipsMode func() fips.Mode) (formatOptionsForTest, *header.KDF) {
	formatOpts := baseAddKeyFormatOptionsWith(opts, fipsMode)

	// Inherit the container's Argon2 cost exactly when the caller chose none, unclamped, so the owning hardware can derive it.
	if !isArgon2Type(formatOpts.KDFType) || callerChoseArgon2Cost(opts) {
		return formatOpts, nil
	}
	inherited := containerArgon2Cost(metadata)
	if inherited == nil {
		return formatOpts, nil
	}

	formatOpts.Argon2Time = *inherited.Time
	formatOpts.Argon2Parallel = *inherited.CPUs
	formatOpts.Argon2Memory = *inherited.Memory
	return formatOpts, inherited
}

// callerArgon2Options returns only the Argon2 costs the caller supplied.
func callerArgon2Options(opts *addKeyOptionsForTest) formatOptionsForTest {
	if opts == nil {
		return formatOptionsForTest{}
	}
	// All three costs, so a negative parallelism reaches validateArgon2CreateCost.
	return formatOptionsForTest{
		KDFType:        baseAddKeyFormatOptions(opts).KDFType,
		Argon2Time:     opts.Argon2Time,
		Argon2Memory:   opts.Argon2Memory,
		Argon2Parallel: opts.Argon2Parallel,
	}
}

// callerChoseArgon2Cost reports whether the caller supplied any Argon2 cost, including a negative one.
func callerChoseArgon2Cost(opts *addKeyOptionsForTest) bool {
	return opts != nil && (opts.Argon2Time != 0 || opts.Argon2Memory != 0 || opts.Argon2Parallel != 0)
}

func isArgon2Type(kdfType string) bool {
	return kdfType == kdfTypeArgon2id || kdfType == kdfTypeArgon2i
}

// containerArgon2Cost returns the Argon2 cost of the first keyslot in scan order that carries a complete one, or nil.
func containerArgon2Cost(metadata *header.Metadata) *header.KDF {
	if metadata == nil {
		return nil
	}
	for _, id := range header.KeyslotIDsInScanOrder(metadata.Keyslots) {
		kdf := metadata.Keyslots[id].KDF
		if kdf == nil || !isArgon2Type(kdf.Type) {
			continue
		}
		if kdf.Time == nil || kdf.Memory == nil || kdf.CPUs == nil {
			continue
		}
		return kdf
	}
	return nil
}

// baseAddKeyFormatOptions maps add-key options onto format options; HashAlgo is the caller's Hash or the hash the resolved type names.
func baseAddKeyFormatOptions(opts *addKeyOptionsForTest) formatOptionsForTest {
	return baseAddKeyFormatOptionsWith(opts, fips.Probe)
}

func baseAddKeyFormatOptionsWith(opts *addKeyOptionsForTest, fipsMode func() fips.Mode) formatOptionsForTest {
	formatOpts := formatOptionsForTest{
		KDFType:        resolveKDFTypeFor("", callerChoseArgon2Cost(opts), fipsMode()),
		Argon2Time:     4,
		Argon2Memory:   1048576,
		Argon2Parallel: 4,
	}

	var callerHash string
	if opts != nil {
		if opts.KDFType != "" {
			formatOpts.KDFType = opts.KDFType
		}
		callerHash = opts.Hash
	}
	formatOpts.HashAlgo = getHashAlgoForKDFType(normalizeKDFType(formatOpts.KDFType), callerHash)

	if opts == nil {
		return formatOpts
	}

	if opts.Argon2Time != 0 {
		formatOpts.Argon2Time = opts.Argon2Time
	}
	if opts.Argon2Memory != 0 {
		formatOpts.Argon2Memory = opts.Argon2Memory
	}
	if opts.Argon2Parallel != 0 {
		formatOpts.Argon2Parallel = opts.Argon2Parallel
	}
	if opts.PBKDFIterTime != 0 {
		formatOpts.PBKDFIterTime = opts.PBKDFIterTime
	}
	// Zero means unset, so an out-of-range count reaches forcedPBKDF2Iterations.
	if opts.PBKDFIterations != 0 {
		formatOpts.PBKDFIterations = opts.PBKDFIterations
	}

	return formatOpts
}

func testKeyForTest(device string, passphrase []byte) error {
	return testKeyForTestWithSys(device, passphrase, defaultVolumeSys())
}

// testKeyForTestWithSys is testKeyForTest, parameterized by sys so this
// package's own tests can inject a seam this test-only helper's fixed
// signature has no room for.
func testKeyForTestWithSys(device string, passphrase []byte, sys volumeSys) error {
	// An existing credential is judged by what can open a keyslot.
	if err := validateDevicePath(device); err != nil {
		return err
	}
	if err := validateExistingCredential(passphrase); err != nil {
		return err
	}

	// One descriptor for the header and every keyslot read (#249, A10).
	f, err := openDevice("read the LUKS2 header", device, os.O_RDONLY, sys)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	_, metadata, err := readHeaderCopyFrom(f, header.PrimaryHeaderOffset)
	if err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to read header", Err: err}
	}

	// The passphrase must open a keyslot holding the volume key.
	masterKey, _, err := getVolumeKey(context.Background(), f, device, passphrase, metadata, sys)
	if err != nil {
		// No verdict on the credential: the container may have no usable keyslot.
		return &errs.Error{Kind: errs.KindOf(err, ErrWrongKey), Detail: "could not open " + device + " with this passphrase", Err: err}
	}
	// The key is recovered only to prove the passphrase opens a slot; it is
	// released immediately rather than at the end of a scope that does nothing
	// else with it.
	custody.Release(masterKey)

	return nil
}

// addKeyWithPolicy is AddKey with an explicit keyslot cost policy; only AddRecoveryKey uses the relaxed one (see keyslotCostPolicy).
func addKeyWithPolicy(ctx context.Context, device string, existingPassphrase, newPassphrase []byte, opts *addKeyOptionsForTest, policy keyslotCostPolicy, sys volumeSys) (int, error) {
	if err := addKeyPreflight(device, existingPassphrase, newPassphrase, opts, sys.fipsMode()); err != nil {
		return -1, err
	}

	// Lock the device and keep the locked descriptor for everything below
	// (#249, A10).
	lock, dev, err := lockKeyslotDevice(ctx, device, sys)
	if err != nil {
		return -1, err
	}
	defer func() { _ = lock.Release() }()

	hdr, metadata, err := dev.readHeader()
	if err != nil {
		return -1, &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to read header", Err: err}
	}

	// Recover the volume key; an unbound keyslot proves nothing.
	masterKey, _, err := getVolumeKey(ctx, dev.reader(), device, existingPassphrase, metadata, sys)
	if err != nil {
		return -1, &errs.Error{Kind: errs.KindOf(err, ErrWrongKey), Detail: "failed to unlock with existing passphrase", Err: err}
	}
	defer custody.Release(masterKey)

	return addKeyslotWithMasterKey(ctx, dev, hdr, metadata, masterKey, newPassphrase, opts, policy)
}

// addKeyPreflight is every check addKeyWithPolicy makes before the lock, shared with enrollWithToken.
func addKeyPreflight(device string, existingPassphrase, newPassphrase []byte, opts *addKeyOptionsForTest, mode fips.Mode) error {
	// The existing credential is judged by what can open a keyslot, the new one by the creation policy.
	if err := validateDevicePath(device); err != nil {
		return err
	}
	if err := validateExistingCredential(existingPassphrase); err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrInvalidCredential), Detail: "invalid existing passphrase", Err: err}
	}
	if err := validatePassphraseBytes(newPassphrase); err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrInvalidCredential), Detail: "invalid new passphrase", Err: err}
	}
	// No SHA-1 keyslot, refused before the existing keyslot is unlocked --
	// which costs a full KDF derivation -- and before anything is written.
	if opts != nil {
		if err := refuseSHA1ForCreation(opts.KDFType, opts.Hash, mode); err != nil {
			return err
		}
	}

	// A caller-supplied Argon2 cost meets Format's floor, checked before the lock and the unlock.
	if err := validateArgon2CreateCost(callerArgon2Options(opts)); err != nil {
		return err
	}

	return nil
}

// addKeyslotWithMasterKey wraps masterKey under newPassphrase in a new keyslot and commits the header, under the caller's lock.
func addKeyslotWithMasterKey(ctx context.Context, dev *keyslotDevice, hdr *header.BinaryHeader, metadata *header.Metadata, masterKey enclave.ByteAccess,
	newPassphrase []byte, opts *addKeyOptionsForTest, policy keyslotCostPolicy) (int, error) {
	return addKeyslotWithMasterKeyAndPriority(ctx, dev, hdr, metadata, masterKey, newPassphrase, opts, policy, nil)
}

// addKeyslotWithMasterKeyAndPriority is addKeyslotWithMasterKey with an explicit on-disk priority; nil writes none.
func addKeyslotWithMasterKeyAndPriority(ctx context.Context, dev *keyslotDevice, hdr *header.BinaryHeader, metadata *header.Metadata, masterKey enclave.ByteAccess,
	newPassphrase []byte, opts *addKeyOptionsForTest, policy keyslotCostPolicy, priority *int) (int, error) {
	if priority != nil && (*priority < keyslotPriorityIgnore || *priority > keyslotPriorityPrefer) {
		return -1, errInvalidPriority(priorityFromDisk(priority))
	}

	// Find available keyslot
	targetSlot, err := findAvailableKeyslot(metadata, opts)
	if err != nil {
		return -1, err
	}

	// The ONE digest the new keyslot joins, chosen before anything is written.
	attestingDigest, err := digestAttestingKey(metadata, masterKey)
	if err != nil {
		return -1, err
	}

	// targetSlot is decided here under the lock; every failure returns -1.

	// No template keyslot: the key size comes from the volume key and the area cipher is a constant.

	// The keyslot key size is the volume key's length; the area key is that length for AES-XTS volume keys and AES-256-XTS otherwise, as cryptsetup does.
	newKeySize := masterKey.Size()
	areaKeySize := areacipher.WritableAreaKeySize(newKeySize)

	// Read the container's reserved keyslots area out of its own header rather
	// than assuming this library's default geometry.
	keyslotsStart, keyslotsEnd, err := keyslotsAreaBounds(hdr, metadata)
	if err != nil {
		return -1, err
	}

	// Calculate new keyslot area offset
	newOffset, err := calculateNextKeyslotOffset(metadata, keyslotsStart)
	if err != nil {
		return -1, err
	}

	// The size is the recovered volume key's; addKeyFormatOptions carries only the KDF choices.
	formatOpts, inherited := addKeyFormatOptions(opts, metadata, dev.sys.fipsMode)
	if inherited != nil && opts != nil {
		// Reported at the point of decision, the same way targetSlot is above,
		// rather than left to be inferred from the header afterwards.
		opts.InheritedArgon2Cost = inherited
	}

	kdf, err := createKDF(formatOpts, areaKeySize, policy, dev.sys.fipsMode, dev.sys.calibratedCountFloor, dev.sys.cryptoRand)
	if err != nil {
		return -1, &errs.Error{Kind: errs.KindOf(err, errs.ErrInvalidArgument), Detail: "failed to create KDF", Err: err}
	}

	// Derive the area key from the new passphrase
	passphraseKey, err := dev.sys.passphraseKDF(ctx, newPassphrase, kdf, areaKeySize)
	if err != nil {
		return -1, &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to derive key", Err: err}
	}
	defer custody.Release(passphraseKey)

	// Apply anti-forensic split to master key
	afData, err := afCodec(dev.sys).Split(masterKey, af.Params{Stripes: header.AFStripes, Hash: defaultHashAlgo})
	if err != nil {
		return -1, &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to apply AF split", Err: err}
	}
	defer custody.Release(afData)

	// Encrypt AF-split key material with new passphrase-derived key
	encryptedKeyMaterial, err := areacipher.Default().WithFIPS(dev.sys.fipsMode()).EncryptEnclave(custody, afData, passphraseKey)
	if err != nil {
		return -1, &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to encrypt key material", Err: err}
	}
	defer clearBytes(encryptedKeyMaterial)

	// Calculate aligned size
	alignedSize := alignTo(int64(len(encryptedKeyMaterial)), keyslotAreaAlignment)

	newKeyslotsEnd := newOffset + alignedSize

	// First boundary: the keyslot must fit inside config.keyslots_size.
	if newKeyslotsEnd > keyslotsEnd {
		return -1, &errs.Error{Kind: ErrNoSpace, Detail: fmt.Sprintf("a new keyslot would end at offset %d but the container's keyslots area is %d..%d (config.keyslots_size %s); reformat with a larger keyslots area",
			newKeyslotsEnd, keyslotsStart, keyslotsEnd, metadata.Config.KeyslotsSize)}
	}

	// Second boundary: the keyslot must not reach the encrypted data.
	for id, segment := range metadata.Segments {
		// An unparseable segment offset is refused: nothing upstream validates it.
		segmentOffset, err := parseSize(segment.Offset)
		if err != nil {
			return -1, &errs.Error{Kind: ErrInvalidHeader, Detail: fmt.Sprintf("data segment %s declares an offset of %q, which is not a valid size, so the "+
				"bound protecting the encrypted data from a new keyslot cannot be computed",
				id, segment.Offset)}
		}
		if !dataOnAnotherDevice(segmentOffset) && newKeyslotsEnd > segmentOffset {
			return -1, &errs.Error{Kind: ErrNoSpace, Detail: fmt.Sprintf("a new keyslot would end at offset %d but the data segment starts at %d; reformat with a larger header",
				newKeyslotsEnd, segmentOffset)}
		}
	}

	// Create the keyslot metadata with no priority member, which means normal.
	newKeyslot := &header.Keyslot{
		Type:     "luks2",
		KeySize:  newKeySize,
		Priority: priority,
		Area: &header.KeyslotArea{
			Type:    "raw",
			KeySize: areaKeySize,
			Offset:  formatSize(newOffset),
			Size:    formatSize(alignedSize),
			// The material is encrypted with areacipher.Default (XTS).
			Encryption: keyslotAreaEncryption,
		},
		KDF: kdf,
		AF: &header.AntiForensic{
			Type:    "luks1",
			Stripes: header.AFStripes,
			Hash:    defaultHashAlgo,
		},
	}

	// Add keyslot to metadata
	slotIDStr := strconv.Itoa(targetSlot)
	metadata.Keyslots[slotIDStr] = newKeyslot

	// The new keyslot joins only the digest attesting the key it wraps.
	if digest := metadata.Digests[attestingDigest]; !slices.Contains(digest.Keyslots, slotIDStr) {
		digest.Keyslots = append(digest.Keyslots, slotIDStr)
	}

	// config.keyslots_size is the reserved area's fixed size and is not changed here.

	// Check the header is writable before writing material, so a refusal strands no key copy.
	if err := checkHeaderWritable(hdr, metadata); err != nil {
		removeKeyslotFromMetadata(metadata, slotIDStr)
		return -1, err
	}

	// Increment sequence ID
	hdr.SequenceID++

	// Write the material, padded to the area, and make it durable before the header names it.
	if err := dev.writeArea(ctx, "write the keyslot area", newOffset, encryptedKeyMaterial, alignedSize); err != nil {
		return -1, err
	}

	// From here ctx is not consulted until the next consistent state; a read-back failure still rolls the keyslot out.
	ctx = context.WithoutCancel(ctx)

	// Write updated headers
	if err := dev.writeHeader(ctx, hdr, metadata); err != nil {
		return -1, &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to write header", Err: err}
	}

	// Read the keyslot back through the committed header; if it does not unwrap the volume key, roll it out.
	if err := verifyWrittenKeyslot(ctx, dev, slotIDStr, kdf, passphraseKey, masterKey); err != nil {
		return -1, rollBackAddedKeyslot(ctx, dev, slotIDStr, newKeyslot, err)
	}

	return targetSlot, nil
}

// changeKeyWithSys changes the passphrase for a specific keyslot, parameterized by sys so this package's
// tests can inject a seam the wrapper has no room for.
func changeKeyWithSys(device string, oldPassphrase, newPassphrase []byte, keyslot int, sys volumeSys) error {
	ctx := context.Background()
	// Validate inputs
	if err := validateDevicePath(device); err != nil {
		return err
	}
	if err := validateExistingCredential(oldPassphrase); err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrInvalidCredential), Detail: "invalid old passphrase", Err: err}
	}
	if err := validatePassphraseBytes(newPassphrase); err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrInvalidCredential), Detail: "invalid new passphrase", Err: err}
	}
	if keyslot < 0 || keyslot >= MaxKeyslots {
		return &errs.Error{Kind: ErrKeyslotNotFound, Detail: fmt.Sprintf("%d (must be 0-%d)", keyslot, MaxKeyslots-1)}
	}

	// Lock the device and keep the locked descriptor for everything below:
	// this used to resolve the path six times and write the new material
	// through a raw os.OpenFile (#249, A10).
	lock, dev, err := lockKeyslotDevice(ctx, device, sys)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()

	// Read existing header and metadata
	hdr, metadata, err := dev.readHeader()
	if err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to read header", Err: err}
	}

	// Check that keyslot exists
	slotIDStr := strconv.Itoa(keyslot)
	targetKeyslot, exists := metadata.Keyslots[slotIDStr]
	if !exists {
		return &errs.Error{Kind: ErrKeyslotNotFound, Detail: fmt.Sprintf("keyslot %d does not exist", keyslot)}
	}

	// Unlock with old passphrase to get master key
	masterKey, err := unlockKeyslotFrom(ctx, dev.reader(), slotIDStr, oldPassphrase, targetKeyslot, metadata.Digests, sys)
	if err != nil {
		return &errs.Error{Kind: errs.KindOf(err, ErrWrongKey), Detail: fmt.Sprintf("old passphrase does not match keyslot %d", keyslot), Err: err}
	}
	defer custody.Release(masterKey)

	return changeKeyslotCore(ctx, dev, hdr, metadata, slotIDStr, keyslot, targetKeyslot, masterKey, newPassphrase, nil)
}

// changeKeyslotCore is ChangeKey's write path once the master key is held; recost nil keeps the keyslot's KDF and cost.
func changeKeyslotCore(ctx context.Context, dev *keyslotDevice, hdr *header.BinaryHeader, metadata *header.Metadata, slotIDStr string, keyslot int, targetKeyslot *header.Keyslot, masterKey enclave.ByteAccess, newPassphrase []byte, recost *addKeyOptionsForTest) error {
	// The key must be this volume's, checked before anything is derived or written.
	if _, err := digestAttestingKey(metadata, masterKey); err != nil {
		return err
	}

	// The keyslot as it stands, kept whole: if the rewritten keyslot cannot be
	// proved to open, this is what the header is put back to. Its area and af
	// objects are copied because both are rewritten below.
	original := *targetKeyslot
	originalArea := *targetKeyslot.Area
	originalAF := *targetKeyslot.AF
	original.Area = &originalArea
	original.AF = &originalAF

	// Keep the area key length (area.key_size), except a CBC area is rewritten as aes-xts-plain64 with this package's XTS area key.
	areaKeySize := targetKeyslot.Area.KeySize
	areaEncryption := targetKeyslot.Area.Encryption
	if area, err := parseKeyslotAreaEncryption(areaEncryption); err != nil || !area.XTS() {
		areaEncryption = keyslotAreaEncryption
		areaKeySize = areacipher.WritableAreaKeySize(targetKeyslot.KeySize)
	}

	// The old area to be wiped must be keyslot space and disjoint from every surviving keyslot, checked before anything is written.
	oldArea := originalArea
	if err := checkAreaConfined(hdr, metadata, slotIDStr, &oldArea); err != nil {
		return err
	}
	if err := checkKeyslotAreaDisjointFromOthers(dev, metadata, slotIDStr, &oldArea); err != nil {
		return err
	}

	// The new KDF is the keyslot's own cost unless the caller named one, resolved as AddKeyslot does.
	var formatOpts formatOptionsForTest
	if recost != nil {
		formatOpts, _ = addKeyFormatOptions(recost, metadata, dev.sys.fipsMode)
	} else {
		var err error
		formatOpts, err = inheritedKeyslotFormatOptions(dev, targetKeyslot, areaKeySize)
		if err != nil {
			return err
		}
	}

	kdf, err := createKDF(formatOpts, areaKeySize, callerSuppliedCredential, dev.sys.fipsMode, dev.sys.calibratedCountFloor, dev.sys.cryptoRand)
	if err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrInvalidArgument), Detail: "failed to create KDF", Err: err}
	}

	// Derive the area key from the new passphrase, to the area's key size.
	passphraseKey, err := dev.sys.passphraseKDF(ctx, newPassphrase, kdf, areaKeySize)
	if err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to derive key", Err: err}
	}
	defer custody.Release(passphraseKey)

	// A SHA-1 anti-forensic hash is rewritten with the default; SHA-1 keyslots are read, never written.
	if targetKeyslot.AF.Hash == "sha1" {
		targetKeyslot.AF.Hash = defaultHashAlgo
	}

	// AF-split into the LUKS2 stripe count, and declare that count.
	afData, err := afCodec(dev.sys).Split(masterKey, af.Params{Stripes: header.AFStripes, Hash: targetKeyslot.AF.Hash})
	if err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to apply AF split", Err: err}
	}
	defer custody.Release(afData)
	targetKeyslot.AF.Stripes = header.AFStripes

	// Encrypt AF-split key material with new passphrase-derived key
	encryptedKeyMaterial, err := areacipher.Default().WithFIPS(dev.sys.fipsMode()).EncryptEnclave(custody, afData, passphraseKey)
	if err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to encrypt key material", Err: err}
	}
	defer clearBytes(encryptedKeyMaterial)

	// The area is at least the existing size, larger when the 4000-stripe material needs it.
	existingSize, err := parseSize(targetKeyslot.Area.Size)
	if err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrInvalidHeader), Detail: "failed to parse keyslot size", Err: err}
	}
	newSize := max(existingSize, alignTo(int64(len(encryptedKeyMaterial)), keyslotAreaAlignment))

	// Write new material into a free area, re-point the header, wipe the old area last: every crash state opens with the old or new passphrase.
	newOffset, err := findFreeKeyslotArea(hdr, metadata, newSize)
	if err != nil {
		return &errs.Error{Kind: ErrNoSpace, Detail: fmt.Sprintf("cannot rewrite keyslot %d safely (add a new key and remove this slot instead)", keyslot), Err: err}
	}

	// Prove the header writable before any device write.
	targetKeyslot.KDF = kdf
	targetKeyslot.Area.Offset = formatSize(newOffset)
	targetKeyslot.Area.Size = formatSize(newSize)
	targetKeyslot.Area.KeySize = areaKeySize
	targetKeyslot.Area.Encryption = areaEncryption
	hdr.SequenceID++
	if err := checkHeaderWritable(hdr, metadata); err != nil {
		return err
	}

	// Write the new material into the free area and make it durable before the header names it.
	if err := dev.writeArea(ctx, "write the keyslot area", newOffset, encryptedKeyMaterial, newSize); err != nil {
		return err
	}

	// From here the rewrite runs to its next consistent state, as AddKey's does.
	ctx = context.WithoutCancel(ctx)

	// The commit point. After this the new passphrase opens the volume.
	if err := dev.writeHeader(ctx, hdr, metadata); err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to write header", Err: err}
	}

	// Read the keyslot back; if it does not unwrap the old key, restore the old keyslot and report the failure.
	if err := verifyWrittenKeyslot(ctx, dev, slotIDStr, kdf, passphraseKey, masterKey); err != nil {
		return rollBackChangedKeyslot(ctx, dev, hdr, metadata, slotIDStr, &original, targetKeyslot, err)
	}

	// Only now is the old material wiped; a failure here leaves the new passphrase working.
	if err := wipeKeyslotArea(ctx, dev, hdr, metadata, slotIDStr, &original); err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: fmt.Sprintf("the new passphrase is live in keyslot %d, but the old key material could not be destroyed", keyslot), Err: err}
	}

	return nil
}

// inheritedKeyslotFormatOptions is the KDF a passphrase change writes when the caller names none: the keyslot's existing cost and hash.
func inheritedKeyslotFormatOptions(dev *keyslotDevice, targetKeyslot *header.Keyslot, areaKeySize int) (formatOptionsForTest, error) {
	kdfType := targetKeyslot.KDF.Type
	formatOpts := formatOptionsForTest{
		KDFType:  kdfType,
		HashAlgo: defaultHashAlgo,
	}
	if targetKeyslot.KDF.Hash != "" {
		formatOpts.HashAlgo = targetKeyslot.KDF.Hash
	}
	// Except SHA-1: rewritten as PBKDF2-SHA256 with a converted count (sha256IterationsForSHA1).
	rewritingSHA1 := strings.EqualFold(formatOpts.HashAlgo, "sha1")
	if rewritingSHA1 {
		formatOpts.HashAlgo = defaultHashAlgo
	}

	// Preserve the inherited Argon2 cost unraised, so the owning hardware can still derive it.
	if kdfType == "argon2id" || kdfType == "argon2i" {
		formatOpts.Argon2Time = 4
		formatOpts.Argon2Memory = 1048576
		formatOpts.Argon2Parallel = 4
		if targetKeyslot.KDF.Time != nil {
			formatOpts.Argon2Time = *targetKeyslot.KDF.Time
		}
		if targetKeyslot.KDF.Memory != nil {
			formatOpts.Argon2Memory = *targetKeyslot.KDF.Memory
		}
		if targetKeyslot.KDF.CPUs != nil {
			formatOpts.Argon2Parallel = *targetKeyslot.KDF.CPUs
		}
	}

	// Preserve the PBKDF2 count, raised to pbkdf2IterationFloor if below it.
	if isPBKDF2Type(normalizeKDFType(kdfType)) && targetKeyslot.KDF.Iterations != nil {
		preserved := *targetKeyslot.KDF.Iterations
		if rewritingSHA1 {
			converted, err := sha256IterationsForSHA1(preserved, areaKeySize, dev.sys)
			if err != nil {
				return formatOptionsForTest{}, &errs.Error{Kind: errs.KindOf(err, errs.ErrInvalidArgument), Detail: "failed to carry the PBKDF2-SHA1 keyslot's cost over to PBKDF2-SHA256", Err: err}
			}
			preserved = converted
		}
		if floor := int(math.Ceil(pbkdf2IterationFloor(formatOpts.HashAlgo, pbkdf2ReferenceTargetMs))); preserved < floor {
			preserved = floor
		}
		formatOpts.PBKDFIterations = preserved
	}
	return formatOpts, nil
}

// removeKeyslotCore is (*Volume).RemoveKeyslot's write path, factored out so
// it can be reused by call sites that have already read the header.
func removeKeyslotCore(ctx context.Context, dev *keyslotDevice, hdr *header.BinaryHeader, metadata *header.Metadata, slotIDStr string, targetKeyslot *header.Keyslot) error {
	// The removal gate; with no passphrase it alone protects the last volume key.
	if err := checkKeyslotRemovable(dev, hdr, metadata, slotIDStr); err != nil {
		return err
	}

	// Nothing is destroyed until the resulting header is proved writable.
	removeKeyslotFromMetadata(metadata, slotIDStr)
	hdr.SequenceID++
	if err := checkHeaderWritable(hdr, metadata); err != nil {
		return err
	}

	// From here the operation is destructive.
	if err := wipeKeyslotArea(ctx, dev, hdr, metadata, slotIDStr, targetKeyslot); err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to wipe keyslot area", Err: err}
	}

	// Write updated headers
	if err := dev.writeHeader(ctx, hdr, metadata); err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to write header", Err: err}
	}

	return nil
}

// listKeyslotsForTest returns information about all active keyslots
func listKeyslotsForTest(device string) ([]KeyslotInfo, error) {
	if err := validateDevicePath(device); err != nil {
		return nil, err
	}

	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		return nil, &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to read header", Err: err}
	}

	return listKeyslotsFrom(metadata)
}

func listKeyslotsFrom(metadata *header.Metadata) ([]KeyslotInfo, error) {
	var slots []KeyslotInfo
	// Scan order: the order unlock tries the keyslots.
	for _, idStr := range header.KeyslotIDsInScanOrder(metadata.Keyslots) {
		ks := metadata.Keyslots[idStr]
		// A key cryptsetup cannot address (not 0-31 in canonical form) is omitted from the listing, not refused.
		id, ok := header.CanonicalKeyslotID(idStr)
		if !ok {
			continue
		}

		slots = append(slots, keyslotInfoFromEntry(id, ks))
	}

	return slots, nil
}

// keyslotInfoFromEntry builds the KeyslotInfo for one on-disk keyslot; an absent priority is normal, and kdf and area may be absent.
func keyslotInfoFromEntry(id int, ks *header.Keyslot) KeyslotInfo {
	info := KeyslotInfo{
		ID:       id,
		Type:     ks.Type,
		KeySize:  ks.KeySize,
		Priority: priorityFromDisk(ks.Priority),
	}
	if ks.KDF != nil {
		// kdfParamsFromHeaderKDF reads through the pointers rather than
		// copying the KDF, so a caller cannot reach the header's own
		// structure through a listing and mutate it.
		info.KDF = kdfParamsFromHeaderKDF(ks.KDF)
	}
	if ks.Area != nil {
		info.Encryption = ks.Area.Encryption
	}
	return info
}

// KeyslotInfo contains information about a keyslot.
type KeyslotInfo struct {
	ID         int
	Type       string
	KeySize    int
	Priority   Priority
	Encryption string

	// KDF reports the cost written, including an inherited Argon2 cost; a zero Type means the keyslot has no KDF.
	KDF KDFParams
}

// getMasterKey returns the master key in protected memory, which the caller must Destroy; a keyslot that could not be tried is reported over a verification failure, and FIPS-only refusals as FIPSImportRequiredError.
func getMasterKey(device string, passphrase []byte, metadata *header.Metadata, sys volumeSys) (enclave.ByteAccess, error) {
	f, err := openDevice("read the keyslot area", device, os.O_RDONLY, sys)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	masterKey, _, err := getMasterKeySlot(context.Background(), f, device, passphrase, metadata, header.VolumeKeyScanOrder(metadata), sys)
	return masterKey, err
}

// getVolumeKey scans only keyslots bound to the data segments, verified against digests binding every segment, by priority; ErrNoKeyslots if none may be tried.
func getVolumeKey(ctx context.Context, f io.ReaderAt, device string, passphrase []byte, metadata *header.Metadata, sys volumeSys) (enclave.ByteAccess, string, error) {
	var bound []string
	for _, id := range header.KeyslotIDsInScanOrder(metadata.Keyslots) {
		if keyslotBoundToDataSegments(metadata, id) {
			bound = append(bound, id)
		}
	}
	preferred, normal, ignored := keyslotsByPriority(metadata, bound)
	order := slices.Concat(preferred, normal)
	if len(order) == 0 {
		if len(metadata.Keyslots) == 0 {
			return nil, "", &errs.Error{Kind: ErrNoKeyslots, Detail: "the header declares no keyslots"}
		}
		if len(ignored) > 0 {
			return nil, "", &errs.Error{Kind: ErrNoKeyslots, Detail: fmt.Sprintf(
				"every keyslot holding the volume key (%s) has priority ignore, which a scan never tries; name the keyslot to unlock it",
				strings.Join(ignored, ", "))}
		}
		return nil, "", &errs.Error{Kind: ErrNoKeyslots, Detail: fmt.Sprintf(
			"none of the header's %d keyslot(s) is attested by a digest binding every data segment (%s), so none holds the volume key",
			len(metadata.Keyslots), strings.Join(dataSegmentIDs(metadata), ", "))}
	}
	masterKey, id, err := getMasterKeySlot(ctx, f, device, passphrase, header.VolumeKeyDigestsView(metadata), order, sys)
	// The scan sees only the digests binding every data segment. An import
	// request is judged against the whole header, as MigrateToFIPS judges
	// it: a malformed digest the view leaves out is still damage.
	if errors.Is(err, ErrFIPSImportRequired) {
		if herr := malformedDigestError(metadata.Digests); herr != nil {
			return nil, "", herr
		}
	}
	return masterKey, id, err
}

// keyslotsByPriority splits ids into prefer, normal and ignore groups, keeping order; a null keyslot goes with normal.
func keyslotsByPriority(metadata *header.Metadata, ids []string) (preferred, normal, ignored []string) {
	for _, id := range ids {
		ks := metadata.Keyslots[id]
		switch {
		case ks == nil:
			normal = append(normal, id)
		case priorityFromDisk(ks.Priority) == PriorityIgnore:
			ignored = append(ignored, id)
		case priorityFromDisk(ks.Priority) == PriorityPrefer:
			preferred = append(preferred, id)
		default:
			normal = append(normal, id)
		}
	}
	return preferred, normal, ignored
}

// getMasterKeySlot is getMasterKey with a caller-supplied scan order, returning the id of the keyslot that opened.
func getMasterKeySlot(ctx context.Context, dev io.ReaderAt, device string, passphrase []byte, metadata *header.Metadata, order []string, sys volumeSys) (enclave.ByteAccess, string, error) {
	// Price the whole scan before its first derivation.
	if err := checkKDFBudget("open a keyslot", planKeyslotScan(metadata, order)); err != nil {
		return nil, "", err
	}

	// The first reason a keyslot could not be tried, in case nothing verifies.
	var untried error

	// How many keyslots the scan actually reached the unlock with. Counted
	// rather than derived from len(metadata.Keyslots), which counts entries the
	// unlock path skips.
	tried := 0

	// fipsBlocked names keyslots refused only by FIPS mode; otherBlocked records any other refusal.
	var fipsBlocked []string
	otherBlocked := false

	for _, id := range order {
		// Checked between keyslots in a scan: a cancellation
		// stops the scan before the next keyslot's derivation starts.
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}

		keyslot := metadata.Keyslots[id]
		if keyslot == nil || keyslot.Type != "luks2" {
			continue
		}
		// An id cryptsetup cannot address -- "01", "32", "abc" -- is not a
		// keyslot any LUKS2 implementation opens (see listKeyslotsFrom for the
		// measurements), so it is not one this scan opens either (#249, A9).
		if _, ok := header.CanonicalKeyslotID(id); !ok {
			continue
		}
		tried++

		// The area must be keyslot space before it is read.
		masterKey, err := func() (enclave.ByteAccess, error) {
			if err := checkKeyslotAreaConfinedByMetadata(metadata, id); err != nil {
				return nil, &errs.Error{Kind: ErrKeyslotNotFound, Detail: fmt.Sprintf("luks2 keyslot %q: declares an area outside keyslot space", id), Err: err}
			}
			return unlockKeyslotFrom(ctx, dev, id, passphrase, keyslot, metadata.Digests, sys)
		}()
		if err == nil {
			return masterKey, id, nil
		}

		// Protected memory is fail-closed: abort rather than try the remaining keyslots.
		if errors.Is(err, ErrProtectedMemory) {
			return nil, "", err
		}

		if errors.Is(err, ErrWrongKey) {
			// Tried, and did not verify. Try the next keyslot.
			continue
		}

		if keyslotRefusedByFIPS(id, keyslot, metadata.Digests, sys.fipsMode, err) {
			fipsBlocked = append(fipsBlocked, id)
		} else {
			otherBlocked = true
		}

		if untried == nil {
			// A malformed attesting digest is reported as header damage even when the KDF is also refused.
			if !errors.Is(err, errs.ErrInvalidHeader) {
				if structural := coveringDigestStructureError(id, metadata.Digests); structural != nil {
					err = structural
				}
			}
			untried = &errs.Error{Kind: errs.KindOf(err, errs.ErrInvalidHeader), Detail: "keyslot " + id + " could not be tried", Err: err}
		}
	}

	if len(fipsBlocked) > 0 && !otherBlocked {
		// A malformed digest anywhere is damage MigrateToFIPS refuses, so report it.
		if err := malformedDigestError(metadata.Digests); err != nil {
			return nil, "", err
		}
		return nil, "", newFIPSImportRequiredError(device, metadata, fipsBlocked)
	}

	if untried != nil {
		return nil, "", untried
	}

	// Nothing was tried, so nothing was judged: there is no credential verdict
	// to report, only a header that offers no way in.
	if tried == 0 {
		if len(metadata.Keyslots) == 0 {
			return nil, "", &errs.Error{Kind: ErrNoKeyslots, Detail: "the header declares no keyslots"}
		}
		return nil, "", &errs.Error{Kind: ErrNoKeyslots, Detail: fmt.Sprintf("the header declares %d keyslot(s), none of them a luks2 keyslot at an id cryptsetup can address",
			len(metadata.Keyslots))}
	}

	return nil, "", ErrWrongKey
}

// digestAttestingKey returns the digest masterKey matches, preferring one binding data segments; no match is refused.
func digestAttestingKey(metadata *header.Metadata, masterKey enclave.ByteAccess) (string, error) {
	// Prefer a digest binding every data segment, then some, then none.
	full := header.VolumeKeyDigestsView(metadata).Digests
	var other string
	for _, id := range sortedDigestIDs(metadata.Digests) {
		digest := metadata.Digests[id]
		if digest == nil {
			continue
		}
		if _, matched := evaluateDigest(masterKey, digest, fips.Probe); !matched {
			continue
		}
		if full[id] != nil {
			return id, nil
		}
		if other == "" || (len(metadata.Digests[other].Segments) == 0 && len(digest.Segments) > 0) {
			other = id
		}
	}
	if other != "" {
		return other, nil
	}
	return "", &errs.Error{Kind: ErrWrongKey,
		Detail: "no digest in the header attests the key the new keyslot would hold"}
}

// findAvailableKeyslot finds the next available keyslot number
func findAvailableKeyslot(metadata *header.Metadata, opts *addKeyOptionsForTest) (int, error) {
	// If specific keyslot requested, verify it's available
	if opts != nil && opts.Keyslot != nil {
		slot := *opts.Keyslot
		if slot < 0 || slot >= MaxKeyslots {
			return 0, &errs.Error{Kind: ErrKeyslotNotFound, Detail: fmt.Sprintf("%d (must be 0-%d)", slot, MaxKeyslots-1)}
		}
		slotIDStr := strconv.Itoa(slot)
		if _, exists := metadata.Keyslots[slotIDStr]; exists {
			return 0, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: fmt.Sprintf("keyslot %d already in use", slot)}
		}
		return slot, nil
	}

	// Find first available keyslot
	for i := 0; i < MaxKeyslots; i++ {
		slotIDStr := strconv.Itoa(i)
		if _, exists := metadata.Keyslots[slotIDStr]; !exists {
			return i, nil
		}
	}

	return 0, &errs.Error{Kind: ErrNoSpace, Detail: "no available keyslots"}
}

// keyslotsAreaBounds returns the reserved keyslots area [start, end): twice the header area size, for config.keyslots_size bytes.
func keyslotsAreaBounds(hdr *header.BinaryHeader, metadata *header.Metadata) (int64, int64, error) {
	area, err := header.HeaderAreaSize(hdr)
	if err != nil {
		return 0, 0, err
	}
	return keyslotsAreaFrom(2*int64(area), metadata)
}

// keyslotsAreaFrom is the keyslots area that starts at start and runs for
// config.keyslots_size bytes.
func keyslotsAreaFrom(start int64, metadata *header.Metadata) (int64, int64, error) {
	if metadata.Config == nil {
		return 0, 0, &errs.Error{Kind: ErrInvalidHeader, Detail: "header has no config object, so the keyslots area is undefined"}
	}
	size, err := parseSize(metadata.Config.KeyslotsSize)
	if err != nil {
		return 0, 0, &errs.Error{Kind: ErrInvalidHeader, Detail: fmt.Sprintf("config.keyslots_size %q is not a size", metadata.Config.KeyslotsSize), Err: err}
	}
	if size <= 0 || size > math.MaxInt64-start {
		return 0, 0, &errs.Error{Kind: ErrInvalidHeader, Detail: fmt.Sprintf("config.keyslots_size %d does not describe a keyslots area", size)}
	}

	return start, start + size, nil
}

// calculateNextKeyslotOffset calculates the offset for the next keyslot area from keyslotsStart.
func calculateNextKeyslotOffset(metadata *header.Metadata, keyslotsStart int64) (int64, error) {
	maxEnd := keyslotsStart

	// A keyslot whose extent cannot be read is refused, not skipped: this is the only guard on where AddKey writes.
	for id, ks := range metadata.Keyslots {
		// No area object at all is a different thing from an unreadable one:
		// there is no extent to exclude because the keyslot declares none, and
		// the declared-bounds check in AddKey does cover that case.
		if ks == nil || ks.Area == nil {
			continue
		}
		offset, err := parseSize(ks.Area.Offset)
		if err != nil {
			return 0, &errs.Error{
				Kind: ErrInvalidHeader,
				Detail: fmt.Sprintf("keyslot %s declares an area offset of %q, which is not a valid size; a new "+
					"keyslot cannot be placed without knowing where this one ends",
					id, ks.Area.Offset),
			}
		}
		size, err := parseSize(ks.Area.Size)
		if err != nil {
			return 0, &errs.Error{
				Kind: ErrInvalidHeader,
				Detail: fmt.Sprintf("keyslot %s declares an area size of %q, which is not a valid size; a new "+
					"keyslot cannot be placed without knowing where this one ends",
					id, ks.Area.Size),
			}
		}
		end := offset + size
		if end > maxEnd {
			maxEnd = end
		}
	}

	// Align to 4KB boundary
	return alignTo(maxEnd, keyslotAreaAlignment), nil
}

// wipeKeyslotArea overwrites a keyslot area, screening the keyslot itself since KillKeyslot reaches it without a passphrase.
func wipeKeyslotArea(ctx context.Context, dev *keyslotDevice, hdr *header.BinaryHeader, metadata *header.Metadata, id string, keyslot *header.Keyslot) error {
	if err := header.ValidateKeyslot(id, keyslot); err != nil {
		return err
	}

	// The bytes to be overwritten must be keyslot bytes, checked again at the write.
	if err := checkAreaConfined(hdr, metadata, id, keyslot.Area); err != nil {
		return err
	}

	offset, err := parseSize(keyslot.Area.Offset)
	if err != nil {
		return err
	}

	size, err := parseSize(keyslot.Area.Size)
	if err != nil {
		return err
	}

	if err := dev.sys.keyslotWriteStep(ctx, dev, "wipe the keyslot area"); err != nil {
		return err
	}
	f := dev.file

	if err := checkAreaWithinDevice(f, offset, size, dev.sys.measureDeviceSize); err != nil {
		return err
	}

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return err
	}

	// Overwrite with random, in fixed-size chunks, so a destroyed area looks like a live or unused one.
	if err := writeRandom(ctx, f, size, dev.sys.cryptoRand); err != nil {
		return err
	}

	return f.Sync()
}

// removeKeyslotFromMetadata removes a keyslot and every reference to its id, tokens included.
func removeKeyslotFromMetadata(metadata *header.Metadata, id string) {
	delete(metadata.Keyslots, id)
	header.ForgetKeyslotID(metadata, id)
}

// usableKeyslotsAfterRemoving reports how many keyslots could still open the volume if id were removed.
func usableKeyslotsAfterRemoving(f *os.File, hdr *header.BinaryHeader, metadata *header.Metadata, id string, measureDeviceSize func(*os.File) (int64, error)) int {
	remaining := 0
	for _, other := range header.KeyslotIDsInScanOrder(metadata.Keyslots) {
		if other == id {
			continue
		}
		if keyslotCanOpenVolume(f, hdr, metadata, other, measureDeviceSize) {
			remaining++
		}
	}
	return remaining
}

// keyslotAreaDisjointFrom refuses a wipe of area that overlaps a keyslot that can still open the volume.
func keyslotAreaDisjointFrom(f *os.File, metadata *header.Metadata, id string, area *header.KeyslotArea, measureDeviceSize func(*os.File) (int64, error)) error {
	if area == nil {
		// No target geometry: header.ValidateKeyslot refuses downstream before any write.
		return nil
	}
	targetOffset, offErr := parseSize(area.Offset)
	targetSize, sizeErr := parseSize(area.Size)
	if offErr != nil || sizeErr != nil || targetOffset < 0 || targetSize <= 0 {
		return nil // same reasoning as above
	}
	targetEnd := targetOffset + targetSize

	for _, other := range header.KeyslotIDsInScanOrder(metadata.Keyslots) {
		if other == id {
			continue
		}
		survivor := metadata.Keyslots[other]
		// Protect every keyslot holding key material, bound or not.
		if !keyslotHoldsKeyMaterial(f, other, survivor, metadata.Digests, measureDeviceSize) {
			continue
		}

		// Already validated by keyslotHoldsKeyMaterial; the error is still checked.
		otherOffset, err := parseSize(survivor.Area.Offset)
		if err != nil {
			return &errs.Error{Kind: ErrKeyslotNotFound, Detail: "keyslot " + other + " has an unreadable area offset"}
		}
		otherSize, err := parseSize(survivor.Area.Size)
		if err != nil {
			return &errs.Error{Kind: ErrKeyslotNotFound, Detail: "keyslot " + other + " has an unreadable area size"}
		}

		if targetOffset < otherOffset+otherSize && otherOffset < targetEnd {
			return &errs.Error{Kind: ErrKeyslotAreaOverlap, Detail: fmt.Sprintf(
				"zeroing [%d,%d) for keyslot %s would also zero keyslot %s at [%d,%d), which still holds a key",
				targetOffset, targetEnd, id, other, otherOffset, otherOffset+otherSize)}
		}
	}

	return nil
}

// checkKeyslotAreaDisjointFromOthers is the byte-level check alone, for ChangeKey, which wipes an area without removing the keyslot.
func checkKeyslotAreaDisjointFromOthers(dev *keyslotDevice, metadata *header.Metadata, id string, area *header.KeyslotArea) error {
	return keyslotAreaDisjointFrom(dev.file, metadata, id, area, dev.sys.measureDeviceSize)
}

// findFreeKeyslotArea returns a first-fit offset for size bytes inside the keyslots area, clear of every keyslot and the data.
func findFreeKeyslotArea(hdr *header.BinaryHeader, metadata *header.Metadata, size int64) (int64, error) {
	if size <= 0 {
		return 0, &errs.Error{Kind: ErrInvalidArgument, Detail: fmt.Sprintf("a keyslot area of %d bytes", size)}
	}

	start, end, err := keyslotsAreaBounds(hdr, metadata)
	if err != nil {
		return 0, err
	}
	// A segment offset that will not parse is refused, not skipped.
	for id, segment := range metadata.Segments {
		segmentOffset, err := parseSize(segment.Offset)
		if err != nil {
			return 0, &errs.Error{
				Kind: ErrInvalidHeader,
				Detail: fmt.Sprintf("data segment %s declares an offset of %q, which is not a valid size, so the "+
					"search for free keyslot space cannot be stopped before the encrypted data",
					id, segment.Offset),
			}
		}
		if !dataOnAnotherDevice(segmentOffset) && segmentOffset < end {
			end = segmentOffset
		}
	}

	// A keyslot extent that will not parse is refused, so the gap never overlaps it.
	type extent struct{ from, to int64 }
	used := make([]extent, 0, len(metadata.Keyslots))
	for id, ks := range metadata.Keyslots {
		if ks == nil || ks.Area == nil {
			continue
		}
		offset, err := parseSize(ks.Area.Offset)
		if err != nil {
			return 0, &errs.Error{
				Kind: ErrInvalidHeader,
				Detail: fmt.Sprintf("keyslot %s declares an area offset of %q, which is not a valid size; free "+
					"space cannot be chosen without knowing which bytes this keyslot occupies",
					id, ks.Area.Offset),
			}
		}
		areaSize, err := parseSize(ks.Area.Size)
		if err != nil {
			return 0, &errs.Error{
				Kind: ErrInvalidHeader,
				Detail: fmt.Sprintf("keyslot %s declares an area size of %q, which is not a valid size; free "+
					"space cannot be chosen without knowing which bytes this keyslot occupies",
					id, ks.Area.Size),
			}
		}
		// A non-positive size is a declared empty extent.
		if areaSize <= 0 {
			continue
		}
		used = append(used, extent{offset, offset + areaSize})
	}
	slices.SortFunc(used, func(a, b extent) int { return cmp.Compare(a.from, b.from) })

	cursor := alignTo(start, keyslotAreaAlignment)
	for _, in := range used {
		if in.to <= cursor {
			continue
		}
		if in.from-cursor >= size {
			break
		}
		cursor = alignTo(in.to, keyslotAreaAlignment)
	}

	if cursor+size > end {
		return 0, &errs.Error{
			Kind: ErrNoSpace,
			Detail: fmt.Sprintf("%d bytes are needed and the keyslots area %d..%d has no gap that large",
				size, start, end),
		}
	}
	return cursor, nil
}

// checkKeyslotRemovable is the single gate every keyslot removal passes: something must still open the volume, by entries and by bytes.
func checkKeyslotRemovable(dev *keyslotDevice, hdr *header.BinaryHeader, metadata *header.Metadata, id string) error {
	// The bytes to be overwritten must be keyslot bytes; checked first.
	if err := checkKeyslotAreaConfined(hdr, metadata, id); err != nil {
		return err
	}

	f := dev.file
	if usableKeyslotsAfterRemoving(f, hdr, metadata, id, dev.sys.measureDeviceSize) == 0 {
		return &errs.Error{Kind: ErrLastKeyslot, Detail: "removing keyslot " + id +
			" would leave no keyslot holding the volume key: none of the others is a keyslot the volume's data segments are bound to that could open it"}
	}
	return keyslotAreaDisjointFrom(f, metadata, id, areaOfKeyslot(metadata.Keyslots[id]), dev.sys.measureDeviceSize)
}

// verifyWrittenKeyslot proves keyslot id, as the committed header describes it, opens to want, using the writer's area key.
func verifyWrittenKeyslot(ctx context.Context, dev *keyslotDevice, id string, kdf *header.KDF, areaKey, want enclave.ByteAccess) error {
	_, metadata, err := dev.readHeader()
	if err != nil {
		return &errs.Error{Kind: ErrWrongKey, Detail: "the header could not be read back to verify keyslot " + id, Err: err}
	}
	keyslot := metadata.Keyslots[id]
	plan, err := screenKeyslot(id, keyslot, metadata.Digests, fips.Probe)
	if err != nil {
		return &errs.Error{Kind: ErrWrongKey, Detail: "keyslot " + id + " as written is not one the unlock path opens", Err: err}
	}
	if !sameKDF(keyslot.KDF, kdf) || plan.areaKeySize != areaKey.Size() {
		return &errs.Error{Kind: ErrWrongKey, Detail: "keyslot " + id + " as written does not declare the KDF and area key it was written with"}
	}

	got, err := recoverKeyslotKey(ctx, dev.reader(), id, keyslot, plan, areaKey, metadata.Digests, dev.sys)
	if err != nil {
		return &errs.Error{Kind: ErrWrongKey, Detail: "keyslot " + id + " as written does not open", Err: err}
	}
	defer custody.Release(got)

	if !sameSecret(got, want) {
		return &errs.Error{Kind: ErrWrongKey, Detail: "keyslot " + id + " as written opens to a different key"}
	}
	return nil
}

// sameKDF reports whether two KDF objects declare the same derivation: every
// parameter that decides the derived key.
func sameKDF(a, b *header.KDF) bool {
	if a == nil || b == nil {
		return false
	}
	eq := func(x, y *int) bool { return (x == nil && y == nil) || (x != nil && y != nil && *x == *y) }
	return a.Type == b.Type && a.Hash == b.Hash && a.Salt == b.Salt &&
		eq(a.Iterations, b.Iterations) && eq(a.Time, b.Time) && eq(a.Memory, b.Memory) && eq(a.CPUs, b.CPUs)
}

// sameSecret compares two keys held in protected memory, in constant time,
// without copying either out.
func sameSecret(a, b enclave.ByteAccess) bool {
	if a == nil || b == nil || a.Size() != b.Size() {
		return false
	}
	equal := false
	if err := secret.Borrow("compare keys", a, func(raw []byte) error {
		var err error
		equal, err = b.EqualTo(raw)
		return err
	}); err != nil {
		return false
	}
	return equal
}

// rollBackAddedKeyslot removes keyslot id and destroys its area after it failed to open, uncancellably; the result carries cause.
func rollBackAddedKeyslot(ctx context.Context, dev *keyslotDevice, id string, written *header.Keyslot, cause error) error {
	ctx = context.WithoutCancel(ctx)
	hdr, metadata, err := dev.readHeader()
	if err == nil {
		if _, present := metadata.Keyslots[id]; present {
			removeKeyslotFromMetadata(metadata, id)
			hdr.SequenceID++
			err = dev.writeHeader(ctx, hdr, metadata)
		}
	}
	if err == nil {
		err = wipeKeyslotArea(ctx, dev, hdr, metadata, id, written)
	}
	if err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "keyslot " + id + " was written and could not be verified, and taking it back out failed too; " +
			"check the header and remove that keyslot", Err: errors.Join(cause, err)}
	}
	return &errs.Error{Kind: errs.KindOf(cause, errs.ErrIO), Detail: "keyslot " + id + " was written and could not be verified, so it was taken back out", Err: cause}
}

// rollBackChangedKeyslot restores keyslot id to original and destroys the rewritten area, uncancellably; the result carries cause.
func rollBackChangedKeyslot(ctx context.Context, dev *keyslotDevice, hdr *header.BinaryHeader, metadata *header.Metadata, id string,
	original, rewritten *header.Keyslot, cause error) error {
	ctx = context.WithoutCancel(ctx)
	metadata.Keyslots[id] = original
	hdr.SequenceID++
	err := dev.writeHeader(ctx, hdr, metadata)
	if err == nil {
		err = wipeKeyslotArea(ctx, dev, hdr, metadata, id, rewritten)
	}
	if err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "the rewritten keyslot " + id + " could not be verified, and restoring the old one failed too; " +
			"the old passphrase's key material is still on the device -- check the header before doing anything else", Err: errors.Join(cause, err)}
	}
	return &errs.Error{Kind: errs.KindOf(cause, errs.ErrIO), Detail: "the rewritten keyslot " + id + " could not be verified, so the old one was restored and the old passphrase still opens it", Err: cause}
}

// areaOfKeyslot returns a keyslot's area, or nil if it has none.
func areaOfKeyslot(keyslot *header.Keyslot) *header.KeyslotArea {
	if keyslot == nil {
		return nil
	}
	return keyslot.Area
}
