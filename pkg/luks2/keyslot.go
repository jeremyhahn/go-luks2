// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"strconv"

	"github.com/jeremyhahn/go-enclave"
)

// LUKS2 keyslot constants
const (
	// MaxKeyslots is the maximum number of keyslots in LUKS2
	MaxKeyslots = 32

	// KeyslotAreaAlignment is the alignment for keyslot areas
	KeyslotAreaAlignment = 4096
)

// LUKS2 keyslot priorities. The member is OPTIONAL and its default is NORMAL,
// so a keyslot with no priority is a normal one -- not an ignored one, which is
// what reading the absent member as the zero value would say.
//
// The names exist because the numbers read backwards: the value that sorts
// higher means "try this first". A bare 2 under a comment saying "lower
// priority" is how addKey came to mark every added key as the preferred one.
const (
	// KeyslotPriorityIgnore marks a keyslot that should not be tried.
	KeyslotPriorityIgnore = 0

	// KeyslotPriorityNormal is the default, and the meaning of an ABSENT
	// priority member.
	KeyslotPriorityNormal = 1

	// KeyslotPriorityPrefer marks a keyslot that should be tried FIRST. It is
	// numerically the largest and semantically the highest.
	KeyslotPriorityPrefer = 2
)

// AddKeyOptions contains options for adding a new key
type AddKeyOptions struct {
	// Keyslot specifies which keyslot to use (nil = auto-select)
	Keyslot *int

	// KDFType specifies the KDF type (default: argon2id)
	// Valid values: "pbkdf2", "argon2i", "argon2id"
	KDFType string

	// Hash specifies the hash algorithm for PBKDF2 (default: sha256)
	// Valid values: "sha256", "sha512"
	// Note: This is only used when KDFType is "pbkdf2"
	Hash string

	// Argon2 parameters (optional, uses defaults if not specified)
	Argon2Time     int
	Argon2Memory   int
	Argon2Parallel int

	// PBKDF2 parameters (for pbkdf2 KDF type)
	PBKDFIterTime int

	// InheritedArgon2Cost is WRITTEN BY AddKey and never read by it. It carries
	// the Argon2 cost the new keyslot was given when that cost came FROM THE
	// CONTAINER rather than from this package's defaults, and is nil otherwise.
	//
	// It exists because the inherited value must not be silent. A volume
	// deliberately formatted at 512 MiB -- chosen so it stays openable from a
	// rescue USB or a small recovery box -- used to gain keyslots at this
	// package's hardcoded 1 GiB default, inconsistent with every neighbor and
	// precisely on the credential added for a recovery scenario. Inheriting
	// fixes that by construction; reporting it is what lets an operator SEE
	// which cost was used and that it was taken from the volume.
	//
	// A field rather than a log line, for the reason recorded on
	// forgetKeyslotID (header.go): a logger in a layer-0 primitive, or a write
	// to log/slog's process-global default, imposes a logging decision on every
	// embedding application. cmd/luks2 is the application that turns this into
	// something an operator reads.
	InheritedArgon2Cost *KDF

	// PBKDFIterations is an exact PBKDF2 iteration count. When it is non-zero
	// it is written as given and PBKDFIterTime is not consulted, so a keyslot
	// added to two machines from one specification carries identical cost
	// instead of whatever each machine's benchmark happened to measure.
	//
	// It does NOT bypass the iteration floor -- see forcedPBKDF2Iterations. A
	// count below the minimum for the chosen hash is refused with
	// ErrPBKDFIterationsTooLow rather than written.
	PBKDFIterations int

	// There is deliberately NO key-size or cipher option here, and #55 asked for
	// one. A keyslot's key size is not a preference: it is the length of the
	// VOLUME KEY the slot wraps, which was fixed when the container was
	// formatted. A caller-chosen 32 on a 64-byte volume derives a 32-byte
	// wrapping key, AF-splits the full 64-byte master key underneath it, and
	// declares a 32-byte keyslot -- so the unlock merges half the stripes,
	// recovers a 32-byte candidate, and no digest can ever verify it. AddKey
	// returns nil and the credential opens nothing. Measured, not reasoned
	// about, and it is the exact silent-catastrophic-failure shape the removal
	// guards in this package exist to prevent, so the option is not offered.
	//
	// What #55 actually reported -- that a heterogeneous container made AddKey
	// create a slot weaker than the one the caller authenticated with -- is
	// fixed at its source instead: the size comes from the recovered master key
	// rather than from a template keyslot. See addKey.
}

// TestKey verifies that a passphrase can unlock the LUKS volume.
// Returns nil if the passphrase opens a keyslot, error otherwise.
//
// A failure is NOT a statement that the passphrase is wrong. getMasterKey
// distinguishes a keyslot that judged the credential and rejected it from one
// that could not be tried and from a container with no usable keyslot at all
// (#30), and this wrapper carries that distinction through instead of
// flattening every outcome into a credential verdict. Match on the wrapped
// error -- ErrMasterKeyVerification, ErrInvalidKeyslot, ErrNoKeyslots -- rather
// than on the message.
// addKeyFormatOptions maps AddKeyOptions onto the FormatOptions that create the
// new keyslot's KDF, applying this package's defaults for anything the caller
// left unset.
//
// Zero means UNSET and anything else is the caller's choice -- including a value
// that is out of range. PBKDFIterTime used to be copied only when it was > 0,
// which silently discarded a negative and produced a keyslot at the 2000ms
// default instead. That was harmless before #52, when nothing validated the
// budget; it stopped being harmless the moment BenchmarkPBKDF2 began refusing an
// unusable one, because the same nonsense value then errored through
// FormatOptions and was quietly ignored through AddKeyOptions -- two contracts
// for one parameter, on adjacent APIs. Propagating it is what makes the refusal
// reach every caller.
//
// The Argon2 costs use != 0 for the same reason (#112). A caller that passes a
// negative gets a typed error instead of a silently-defaulted keyslot, which is
// the same contract PBKDFIterTime has on the adjacent API.
//
// PROPAGATING REQUIRED THE REFUSAL TO EXIST FIRST. deriveArgon2id/i bounded
// Time and CPUs but NOT Memory, so forwarding a negative memory cost would have
// turned a silent default into a ~4 TiB allocation -- strictly worse than the
// defect. The floor was added there in the same change; a producer must not be
// widened into a consumer that cannot refuse what it will now receive.
func addKeyFormatOptions(opts *AddKeyOptions, metadata *LUKS2Metadata) (FormatOptions, *KDF) {
	formatOpts := baseAddKeyFormatOptions(opts)

	// INHERIT THE CONTAINER'S ARGON2 COST EXACTLY when the caller did not
	// choose one.
	//
	// THE INVARIANT: every keyslot in a volume should be derivable by the
	// hardware that owns the volume. The container's existing cost is the only
	// evidence this package has about that hardware, and inheriting it exactly
	// is how the invariant is kept.
	//
	// The defaults above are this package's, not the volume's, and using them
	// unconditionally is what made AddKey write a 1 GiB keyslot onto a volume
	// deliberately formatted at 512 MiB. cryptsetup's luksAddKey re-benchmarks
	// instead of inheriting, which is the same mistake in a different
	// direction: the new slot's cost is then decided by whichever machine
	// happens to be running.
	//
	// NOT CLAMPED UP TO MinArgon2MemoryKB, and this is the case that makes the
	// distinction concrete. THE MACHINE ADDING THE KEY NEED NOT BE THE MACHINE
	// USING THE VOLUME. An operator adding a credential from a workstation with
	// plenty of RAM, for a volume that lives on a 32 MiB device, would clamp
	// successfully on the workstation and write a keyslot the target hardware
	// cannot derive at all -- discovered later, by whoever needed that
	// credential. On the small device itself the clamp at least fails loudly;
	// remotely it fails silently, which is worse.
	//
	// And the clamp buys nothing to pay for that. A volume's resistance is
	// bounded by its WEAKEST keyslot, and on a 32 MiB container the weak slots
	// already exist -- adding a 64 MiB slot beside them does not make the
	// volume harder to attack, because the attacker goes at a 32 MiB slot
	// exactly as before. A rule that costs derivability on the target hardware
	// and returns no security is not hardening.
	//
	// The floor still binds where there is no evidence to defer to: a cost the
	// CALLER supplies (checked in addKeyWithPolicy, before anything is written)
	// and a container with no complete Argon2 cost to inherit, which falls
	// through to the defaults above -- all of which are above the floor.
	// ChangeKey inherits on the same terms and for the same reason.
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

// callerArgon2Options returns ONLY the Argon2 costs the caller supplied, so the
// create floor judges the caller's request and nothing else. Defaults and
// inherited values are resolved later and are not the caller's to answer for.
func callerArgon2Options(opts *AddKeyOptions) FormatOptions {
	if opts == nil {
		return FormatOptions{}
	}
	// All THREE costs, not two. Argon2Parallel was missing, so a negative
	// parallelism never reached validateArgon2CreateCost and was refused one
	// layer later by deriveArgon2 instead -- see #176 and the parallelism
	// branch in validateArgon2CreateCost.
	return FormatOptions{
		KDFType:        baseAddKeyFormatOptions(opts).KDFType,
		Argon2Time:     opts.Argon2Time,
		Argon2Memory:   opts.Argon2Memory,
		Argon2Parallel: opts.Argon2Parallel,
	}
}

// callerChoseArgon2Cost reports whether the caller supplied ANY Argon2 cost,
// including a negative one. != 0 for the same reason addKeyFormatOptions uses
// it (#112): a negative is still a deliberate choice, and treating it as "no
// choice" would silently INHERIT the container's cost instead of reaching the
// refusal in addKeyWithPolicy, which checks the caller's request -- via
// callerArgon2Options -- before anything is written.
func callerChoseArgon2Cost(opts *AddKeyOptions) bool {
	return opts != nil && (opts.Argon2Time != 0 || opts.Argon2Memory != 0 || opts.Argon2Parallel != 0)
}

func isArgon2Type(kdfType string) bool {
	return kdfType == KDFTypeArgon2id || kdfType == KDFTypeArgon2i
}

// containerArgon2Cost returns the Argon2 cost of the first keyslot in scan
// order that carries a complete one, or nil.
//
// Scan order rather than map order, for the reason keyslotIDsInScanOrder
// exists: ranging the map would make the inherited cost depend on which entry
// Go happened to yield first, so two AddKey calls on one container could
// disagree.
func containerArgon2Cost(metadata *LUKS2Metadata) *KDF {
	if metadata == nil {
		return nil
	}
	for _, id := range keyslotIDsInScanOrder(metadata.Keyslots) {
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

func baseAddKeyFormatOptions(opts *AddKeyOptions) FormatOptions {
	formatOpts := FormatOptions{
		KDFType:        "argon2id",
		HashAlgo:       DefaultHashAlgo,
		Argon2Time:     4,
		Argon2Memory:   1048576,
		Argon2Parallel: 4,
	}

	if opts == nil {
		return formatOpts
	}

	if opts.KDFType != "" {
		formatOpts.KDFType = opts.KDFType
	}
	if opts.Hash != "" {
		formatOpts.HashAlgo = opts.Hash
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
	// Copied on the same "zero means unset" rule as PBKDFIterTime above, and
	// for the same reason: an out-of-range count must reach the refusal in
	// forcedPBKDF2Iterations rather than be dropped here, or AddKey and Format
	// would enforce different contracts for one parameter.
	if opts.PBKDFIterations != 0 {
		formatOpts.PBKDFIterations = opts.PBKDFIterations
	}

	return formatOpts
}

func TestKey(device string, passphrase []byte) error {
	// Validate inputs
	if err := ValidateDevicePath(device); err != nil {
		return err
	}
	if err := ValidatePassphrase(passphrase); err != nil {
		return err
	}

	// Read header and metadata
	_, metadata, err := ReadHeader(device)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Try to get master key with the passphrase
	masterKey, err := getMasterKey(device, passphrase, metadata)
	if err != nil {
		// Deliberately NOT "passphrase does not unlock any keyslot". That names
		// a verdict on the credential, and for a container with no usable
		// keyslot -- or one whose keyslot is too damaged to evaluate anything
		// -- no such verdict was ever reached. See #30.
		return fmt.Errorf("could not open %s with this passphrase: %w", device, err)
	}
	// The key is recovered only to prove the passphrase opens a slot; it is
	// released immediately rather than at the end of a scope that does nothing
	// else with it.
	masterKey.Destroy()

	return nil
}

// AddKey adds a new passphrase to an available keyslot and returns the number
// of the keyslot it used.
//
// existingPassphrase is used to unlock the volume and retrieve the master key;
// newPassphrase is the new passphrase to add.
//
// The keyslot is reported from where it is CHOSEN -- under the device lock, at
// the point of decision -- rather than left for the caller to infer from the
// header afterwards. Inferring it is how #42 destroyed the wrong credential:
// AddRecoveryKey assumed "the highest-numbered slot" while AddKey fills "the
// first free slot", and the two agree only while the active slots are
// contiguous from zero, which stops being true the moment any credential is
// revoked. A caller that does not need the number writes `_, err :=`; a caller
// that does can no longer get it wrong (#101).
//
// On error the returned slot is -1 and must not be acted on.
func AddKey(device string, existingPassphrase, newPassphrase []byte, opts *AddKeyOptions) (int, error) {
	// The default and the only policy any EXPORTED path can select. A
	// credential arriving through AddKey came from the caller, so nothing is
	// known about its entropy and the full floor applies.
	return addKeyWithPolicy(device, existingPassphrase, newPassphrase, opts, callerSuppliedCredential)
}

// addKeyWithPolicy is AddKey with the keyslot cost policy made explicit.
//
// It is unexported and takes an unexported type, which is the whole mechanism:
// the relaxed floor is reachable only from inside this package, and only from a
// caller that GENERATED the credential it is enrolling. AddRecoveryKey
// (recovery.go) is that caller, and today it is the only one: it passes
// libraryGeneratedCredential where every other path takes AddKey and the strict
// default.
//
// A second such caller is expected -- enrolling an external key provider's
// secret has the same shape, a 256-bit value this package drew or received
// rather than one a human chose -- but it does not exist in this package yet,
// and naming it here as though it did would describe a wiring that is not
// there. See keyslotCostPolicy (kdf.go) for what the exemption is, what it is
// not, and why it is not a field on AddKeyOptions.
func addKeyWithPolicy(device string, existingPassphrase, newPassphrase []byte, opts *AddKeyOptions, policy keyslotCostPolicy) (int, error) {
	// Validate inputs
	if err := ValidateDevicePath(device); err != nil {
		return -1, err
	}
	if err := ValidatePassphrase(existingPassphrase); err != nil {
		return -1, fmt.Errorf("invalid existing passphrase: %w", err)
	}
	if err := ValidatePassphrase(newPassphrase); err != nil {
		return -1, fmt.Errorf("invalid new passphrase: %w", err)
	}

	// A NEW KEYSLOT IS A KEYSLOT THIS PACKAGE CREATES, so a caller-supplied
	// Argon2 cost is bound by the same floor Format applies. It was not, and
	// the gap was reachable: AddKey with an explicit Argon2Memory of 32 wrote a
	// keyslot Format refuses outright, so the floor held on one entry point and
	// not the other.
	//
	// Checked HERE, before the lock and before the unlock, because a refusal
	// that arrives after seconds of key derivation has already spent what the
	// refusal was meant to save. Only the CALLER'S values are judged at this
	// point; an inherited cost is resolved later, once the container has been
	// read, and is clamped rather than refused.
	if err := validateArgon2CreateCost(callerArgon2Options(opts)); err != nil {
		return -1, err
	}

	// Acquire exclusive lock
	lock, err := AcquireFileLock(device)
	if err != nil {
		return -1, fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	// Read existing header and metadata
	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		return -1, fmt.Errorf("failed to read header: %w", err)
	}

	// Unlock with existing passphrase to get master key
	masterKey, err := getMasterKey(device, existingPassphrase, metadata)
	if err != nil {
		return -1, fmt.Errorf("failed to unlock with existing passphrase: %w", err)
	}
	defer masterKey.Destroy()

	// Find available keyslot
	targetSlot, err := findAvailableKeyslot(metadata, opts)
	if err != nil {
		return -1, err
	}

	// targetSlot is what the caller receives on success: decided HERE, under
	// the lock, rather than left to be inferred from the header afterwards
	// (#42). Every remaining failure path returns -1 with its error, so a
	// caller that sees success has the slot and a caller that sees an error
	// has nothing to act on.

	// Get existing keyslot for reference (cipher, key size, etc.).
	//
	// Its KeySize sizes the derivation and the AF split for the NEW keyslot, so
	// a damaged slot picked as the template would push its damage into a slot
	// that is about to be written. Slots are considered in scan order and the
	// first usable one wins, rather than whichever the map yielded first: with
	// a random pick, whether AddKey succeeded depended on which keyslot Go
	// happened to iterate to.
	// THERE IS NO TEMPLATE KEYSLOT ANY MORE, and that is the fix for a
	// regression this branch introduced.
	//
	// AddKey used to copy two things from an existing slot: the key size and the
	// area cipher. The key size now comes from the recovered master key, which
	// is the only value that can work (#55). The area cipher is a constant.
	// Nothing was left to template, and the scan that picked one was being
	// consulted for a value it should never have supplied.
	//
	// Removing it also repairs LEGACY CONTAINERS, which is what forced the
	// issue. Before this branch, Format wrote the container's DATA cipher into
	// the keyslot area -- so a volume created with, say,
	// `CipherMode: "cbc-essiv:sha256"` carries AES-XTS key material under an
	// "aes-cbc-essiv:sha256" label. Those volumes still OPEN here, because the
	// read path consults only the algorithm. Screening the template against what
	// this writer produces therefore rejected every keyslot of every such
	// container, and AddKey refused to add a credential to a volume it could
	// perfectly well unlock: a correctness fix producing a data-availability
	// regression, on exactly the containers least able to afford one.
	//
	// Writing the constant beats both inheriting and refusing. The new keyslot
	// declares what its material actually is, no wrong label is propagated, and
	// no container is turned away. The legacy slot's own label is left alone
	// rather than silently rewritten -- this call is authoring one keyslot, not
	// repairing someone else's.
	//
	// Raised by the local Codex review of e975ed5.

	// THE NEW KEYSLOT'S KEY SIZE COMES FROM THE MASTER KEY, NOT FROM A TEMPLATE.
	//
	// This is #55's fix, and it is a derivation rather than a choice. The slot
	// about to be written wraps the master key recovered above; its declared
	// key_size is what the unlock will merge the AF stripes back down to, so the
	// only value that can ever work is the length of that key. Any other value
	// produces a keyslot that is written successfully, reported successfully,
	// and opens nothing -- the unlock merges the wrong number of stripes and no
	// digest verifies the result.
	//
	// It used to come from a template keyslot, which is right only while every
	// slot agrees. A header whose keyslots DISAGREE is accepted by this package
	// and by cryptsetup without complaint, so any container this library did not
	// create may carry one slot at 64 bytes and another at 32 -- and AddKey then
	// inherited whichever the template rule picked and wrote a dead slot, or a
	// weaker live one, silently either way. Making the pick deterministic
	// narrowed that and did not close it: if the first slot in scan order is the
	// odd one, every added key inherits it, every time.
	//
	// Deriving removes the question. There is nothing for the new slot to be
	// weaker than and nothing for it to disagree with, because the master key is
	// the thing it has to match. Its length is already known to be a legal
	// AES-XTS key: it came out of a keyslot that passed screenKeyslot.
	newKeySize := masterKey.Size()
	if err := validateXTSKeySize(newKeySize); err != nil {
		return -1, fmt.Errorf("%w: the recovered volume key is unusable as a keyslot key: %w", ErrInvalidKeyslot, err)
	}

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

	// main's extraction (#102), with THIS branch's key size. The size is the
	// recovered volume key's, not the template keyslot's -- see the derivation
	// above and #55; addKeyFormatOptions carries only the KDF choices, which are
	// genuinely the caller's.
	formatOpts, inherited := addKeyFormatOptions(opts, metadata)
	if inherited != nil && opts != nil {
		// Reported at the point of decision, the same way targetSlot is above,
		// rather than left to be inferred from the header afterwards.
		opts.InheritedArgon2Cost = inherited
	}

	kdf, err := createKDF(formatOpts, newKeySize, policy)
	if err != nil {
		return -1, fmt.Errorf("failed to create KDF: %w", err)
	}

	// Derive key from new passphrase
	passphraseKey, err := DeriveKeyEnclave(newPassphrase, kdf, newKeySize)
	if err != nil {
		return -1, fmt.Errorf("failed to derive key: %w", err)
	}
	defer passphraseKey.Destroy()

	// Apply anti-forensic split to master key
	afData, err := afSplitEnclave(masterKey, AFStripes, DefaultHashAlgo)
	if err != nil {
		return -1, fmt.Errorf("failed to apply AF split: %w", err)
	}
	defer afData.Destroy()

	// Encrypt AF-split key material with new passphrase-derived key
	encryptedKeyMaterial, err := encryptKeyMaterialEnclave(afData, passphraseKey, DefaultCipher)
	if err != nil {
		return -1, fmt.Errorf("failed to encrypt key material: %w", err)
	}
	defer clearBytes(encryptedKeyMaterial)

	// Calculate aligned size
	alignedSize := alignTo(int64(len(encryptedKeyMaterial)), KeyslotAreaAlignment)

	newKeyslotsEnd := newOffset + alignedSize

	// CRITICAL, and two separate boundaries.
	//
	// The first is the container's DECLARED geometry: config.keyslots_size. A
	// keyslot beyond it is outside the area the container says it reserved for
	// keyslots, even when nothing is physically overwritten, and another LUKS2
	// implementation is entitled to refuse the result. Only the data-segment
	// check existed before, which on a conformant container whose data offset
	// sits past the keyslots area let a new keyslot be placed in the gap
	// between the two.
	if newKeyslotsEnd > keyslotsEnd {
		return -1, fmt.Errorf("%w: a new keyslot would end at offset %d but the container's keyslots area is %d..%d (config.keyslots_size %s); reformat with a larger keyslots area",
			ErrKeyslotsAreaFull, newKeyslotsEnd, keyslotsStart, keyslotsEnd, metadata.Config.KeyslotsSize)
	}

	// The second is PHYSICAL: the encrypted data itself. It is kept even though
	// the declared bound is normally tighter, because a container whose
	// config.keyslots_size overstates the space available would otherwise let a
	// keyslot be written over user data.
	for id, segment := range metadata.Segments {
		// A SEGMENT WHOSE OFFSET WILL NOT PARSE DISABLES THIS CHECK, and this
		// check is the last thing standing between a new keyslot and the
		// encrypted data. Skipping the segment was silent: the declared bound
		// above had already passed (that is the case this exists for -- a
		// config.keyslots_size that overstates the space), so the write went
		// ahead against a segment whose real position nobody knew.
		//
		// Nothing upstream validates segment.Offset: validateSegment checks
		// SectorSize, IVTweak and Encryption and never touches it, so such a
		// header reaches here through a clean ReadHeader.
		segmentOffset, err := parseSize(segment.Offset)
		if err != nil {
			return -1, fmt.Errorf("%w: data segment %s declares an offset of %q, which is not a valid size, so the "+
				"bound protecting the encrypted data from a new keyslot cannot be computed",
				ErrInvalidHeader, id, segment.Offset)
		}
		if newKeyslotsEnd > segmentOffset {
			return -1, fmt.Errorf("%w: a new keyslot would end at offset %d but the data segment starts at %d; reformat with a larger header",
				ErrKeyslotsAreaFull, newKeyslotsEnd, segmentOffset)
		}
	}

	// Create new keyslot metadata.
	//
	// NO PRIORITY IS WRITTEN, and what was here before was wrong in both halves
	// at once: `priority := 2` under the comment "Lower priority than original
	// keyslot". In LUKS2, 2 is PREFER -- HIGHER, tried first -- so every key
	// this package added was marked as the one to try before the original,
	// which is the opposite of the stated intent. MEASURED against cryptsetup
	// 2.7.0: `config --priority prefer` writes 2, `--priority normal` deletes
	// the member, and luksAddKey writes none.
	//
	// The intent -- a newly added key gets no special treatment -- IS the
	// absent member, because absent means normal. Expressing it by omission
	// makes the value and the meaning impossible to disagree again. See
	// createMetadata (format.go) for the same decision on the format path.
	newKeyslot := &Keyslot{
		Type:    "luks2",
		KeySize: newKeySize,
		Area: &KeyslotArea{
			Type:    "raw",
			KeySize: newKeySize,
			Offset:  formatSize(newOffset),
			Size:    formatSize(alignedSize),
			// What this call actually encrypts the material with, stated
			// rather than copied from a neighbor. encryptKeyMaterialEnclave
			// uses DefaultCipher and xtsSectors runs XTS; there is no other
			// truthful value here, and a wrong one is a keyslot only this
			// package can open -- with our own suite staying green, because
			// the read path discards the mode.
			Encryption: KeyslotAreaEncryption,
		},
		KDF: kdf,
		AF: &AntiForensic{
			Type:    "luks1",
			Stripes: AFStripes,
			Hash:    DefaultHashAlgo,
		},
	}

	// Add keyslot to metadata
	slotIDStr := strconv.Itoa(targetSlot)
	metadata.Keyslots[slotIDStr] = newKeyslot

	// Update digest to include new keyslot
	for _, digest := range metadata.Digests {
		found := false
		for _, ks := range digest.Keyslots {
			if ks == slotIDStr {
				found = true
				break
			}
		}
		if !found {
			digest.Keyslots = append(digest.Keyslots, slotIDStr)
		}
	}

	// config.keyslots_size is deliberately NOT touched here.
	//
	// It is the size of the RESERVED keyslots area, fixed when the container was
	// formatted, and not a high-water mark of the slots in use. Writing
	// newKeyslotsEnd -- an absolute end offset -- into it was the same defect as
	// the one Format carried (#28): it stored an offset where the spec wants a
	// size, and on top of that it SHRANK the reserved area down to the end of the
	// newly added slot, so a conformant container stopped being one as soon as a
	// second passphrase was added.
	//
	// Nothing needs to grow either: the overlap check above already refuses a slot
	// that would run past the data segment, which is the boundary the reserved
	// area was sized against.

	// Increment sequence ID
	hdr.SequenceID++

	// Write encrypted key material to device
	f, err := os.OpenFile(device, os.O_RDWR, 0600) // #nosec G304 -- device path validated by caller
	if err != nil {
		return -1, fmt.Errorf("failed to open device: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := f.Seek(newOffset, 0); err != nil {
		return -1, fmt.Errorf("failed to seek to keyslot area: %w", err)
	}

	if _, err := f.Write(encryptedKeyMaterial); err != nil {
		return -1, fmt.Errorf("failed to write key material: %w", err)
	}

	// Pad to aligned size
	padding := make([]byte, alignedSize-int64(len(encryptedKeyMaterial)))
	if _, err := f.Write(padding); err != nil {
		return -1, fmt.Errorf("failed to write padding: %w", err)
	}

	if err := f.Sync(); err != nil {
		return -1, fmt.Errorf("failed to sync: %w", err)
	}

	// Write updated headers
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		return -1, fmt.Errorf("failed to write header: %w", err)
	}

	return targetSlot, nil
}

// RemoveKey removes a passphrase from a keyslot
// The passphrase must match the key in the specified slot
func RemoveKey(device string, passphrase []byte, keyslot int) error {
	// Validate inputs
	if err := ValidateDevicePath(device); err != nil {
		return err
	}
	if err := ValidatePassphrase(passphrase); err != nil {
		return err
	}
	if keyslot < 0 || keyslot >= MaxKeyslots {
		return fmt.Errorf("invalid keyslot: %d (must be 0-%d)", keyslot, MaxKeyslots-1)
	}

	// Acquire exclusive lock
	lock, err := AcquireFileLock(device)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	// Read existing header and metadata
	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Check that keyslot exists
	slotIDStr := strconv.Itoa(keyslot)
	targetKeyslot, exists := metadata.Keyslots[slotIDStr]
	if !exists {
		return fmt.Errorf("keyslot %d does not exist", keyslot)
	}

	// Verify passphrase unlocks this specific keyslot. The recovered key is
	// wanted only as proof, so it is released at once instead of being held for
	// the rest of the removal.
	verified, err := unlockKeyslot(device, slotIDStr, passphrase, targetKeyslot, metadata.Digests)
	if err != nil {
		return fmt.Errorf("passphrase does not match keyslot %d: %w", keyslot, err)
	}
	verified.Destroy()

	// THE GATE. Every removal path passes through checkKeyslotRemovable, which
	// asks the one question all of them need answered: after this removal, can
	// anything still open the volume?
	//
	// It replaces `len(metadata.Keyslots) <= 1`, which counted MAP ENTRIES. A
	// `reencrypt` slot, a slot with no anti-forensic object, a slot whose cipher
	// nothing implements -- each reads as a keyslot to len() and opens nothing,
	// so the guard reported a survivor and the only working credential was
	// destroyed (#37, #71). It also checks the BYTES: the wipe below zeroes a
	// range, and that range can belong to a keyslot that must survive (#38).
	if err := checkKeyslotRemovable(device, metadata, slotIDStr); err != nil {
		return err
	}

	// NOTHING IS DESTROYED UNTIL THE RESULTING HEADER IS PROVED WRITABLE.
	//
	// The metadata is brought to its post-removal state and run through the
	// write path's own encoder first. This used to wipe and then discover the
	// header would not fit, so a failure that could have been a clean refusal
	// instead cost a keyslot (#50). Removal only shrinks metadata, so this is
	// unreachable for a container this library wrote -- and reachable for one it
	// did not, whose JSON area already exceeds what the writer will accept.
	removeKeyslotFromMetadata(metadata, slotIDStr)
	hdr.SequenceID++
	if err := checkHeaderWritable(hdr, metadata); err != nil {
		return err
	}

	// From here the operation is destructive.
	if err := wipeKeyslotArea(device, targetKeyslot); err != nil {
		return fmt.Errorf("failed to wipe keyslot area: %w", err)
	}

	// Write updated headers
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	return nil
}

// KillSlot removes a keyslot from a LUKS device after authenticating with any valid passphrase.
// This is equivalent to "cryptsetup luksKillSlot --key-file keyfile device slot".
// Unlike RemoveKey, the authentication passphrase does NOT need to be from the slot being removed.
//
// Parameters:
//   - device: Path to the LUKS device
//   - authPassphrase: A valid passphrase from ANY keyslot (for authentication)
//   - targetSlot: The keyslot number to remove (0-31)
func KillSlot(device string, authPassphrase []byte, targetSlot int) error {
	// Validate inputs
	if err := ValidateDevicePath(device); err != nil {
		return err
	}
	if err := ValidatePassphrase(authPassphrase); err != nil {
		return err
	}
	if targetSlot < 0 || targetSlot >= MaxKeyslots {
		return fmt.Errorf("invalid keyslot: %d (must be 0-%d)", targetSlot, MaxKeyslots-1)
	}

	// Acquire exclusive lock
	lock, err := AcquireFileLock(device)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	// Read existing header and metadata
	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Authenticate through getMasterKey, which is the ONE implementation of the
	// keyslot scan.
	//
	// This used to carry its own copy -- no keyslot-type filter, no distinction
	// between a slot that rejected the credential and one that could not be
	// tried, and a single "passphrase does not match any keyslot" for every
	// outcome including a container with no usable keyslots at all. That is the
	// misattribution #30 is about, reproduced in a second place, and the answer
	// is one scan rather than two agreeing scans.
	//
	// The in-loop "removing the only keyslot we can authenticate with" guard
	// went with it, and nothing is lost: it fired only when the container had
	// exactly one keyslot and it was the target, which the len(...) <= 1 refusal
	// below rejects anyway, with the same message.
	//
	// Authentication only -- the key is not wanted past this point.
	candidate, err := getMasterKey(device, authPassphrase, metadata)
	if err != nil {
		// "authentication failed" was the old wording and it asserted a verdict
		// this call may never have reached -- a container with no usable
		// keyslot judged nothing. The operation is named; the outcome comes
		// from the wrapped error.
		return fmt.Errorf("could not authenticate against %s: %w", device, err)
	}
	candidate.Destroy()

	// Check that target keyslot exists
	slotIDStr := strconv.Itoa(targetSlot)
	targetKeyslot, exists := metadata.Keyslots[slotIDStr]
	if !exists {
		return fmt.Errorf("keyslot %d does not exist", targetSlot)
	}

	// THE GATE. Every removal path passes through checkKeyslotRemovable, which
	// asks the one question all of them need answered: after this removal, can
	// anything still open the volume?
	//
	// It replaces `len(metadata.Keyslots) <= 1`, which counted MAP ENTRIES. A
	// `reencrypt` slot, a slot with no anti-forensic object, a slot whose cipher
	// nothing implements -- each reads as a keyslot to len() and opens nothing,
	// so the guard reported a survivor and the only working credential was
	// destroyed (#37, #71). It also checks the BYTES: the wipe below zeroes a
	// range, and that range can belong to a keyslot that must survive (#38).
	if err := checkKeyslotRemovable(device, metadata, slotIDStr); err != nil {
		return err
	}

	// NOTHING IS DESTROYED UNTIL THE RESULTING HEADER IS PROVED WRITABLE.
	//
	// The metadata is brought to its post-removal state and run through the
	// write path's own encoder first. This used to wipe and then discover the
	// header would not fit, so a failure that could have been a clean refusal
	// instead cost a keyslot (#50). Removal only shrinks metadata, so this is
	// unreachable for a container this library wrote -- and reachable for one it
	// did not, whose JSON area already exceeds what the writer will accept.
	removeKeyslotFromMetadata(metadata, slotIDStr)
	hdr.SequenceID++
	if err := checkHeaderWritable(hdr, metadata); err != nil {
		return err
	}

	// From here the operation is destructive.
	if err := wipeKeyslotArea(device, targetKeyslot); err != nil {
		return fmt.Errorf("failed to wipe keyslot area: %w", err)
	}

	// Write updated headers
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	return nil
}

// ChangeKey changes the passphrase for a specific keyslot
func ChangeKey(device string, oldPassphrase, newPassphrase []byte, keyslot int) error {
	// Validate inputs
	if err := ValidateDevicePath(device); err != nil {
		return err
	}
	if err := ValidatePassphrase(oldPassphrase); err != nil {
		return fmt.Errorf("invalid old passphrase: %w", err)
	}
	if err := ValidatePassphrase(newPassphrase); err != nil {
		return fmt.Errorf("invalid new passphrase: %w", err)
	}
	if keyslot < 0 || keyslot >= MaxKeyslots {
		return fmt.Errorf("invalid keyslot: %d (must be 0-%d)", keyslot, MaxKeyslots-1)
	}

	// Acquire exclusive lock
	lock, err := AcquireFileLock(device)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	// Read existing header and metadata
	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Check that keyslot exists
	slotIDStr := strconv.Itoa(keyslot)
	targetKeyslot, exists := metadata.Keyslots[slotIDStr]
	if !exists {
		return fmt.Errorf("keyslot %d does not exist", keyslot)
	}

	// Unlock with old passphrase to get master key
	masterKey, err := unlockKeyslot(device, slotIDStr, oldPassphrase, targetKeyslot, metadata.Digests)
	if err != nil {
		return fmt.Errorf("old passphrase does not match keyslot %d: %w", keyslot, err)
	}
	defer masterKey.Destroy()

	// Create the new KDF WITH THE COST THE KEYSLOT ALREADY HAD.
	//
	// A passphrase change is not a request to re-cost the keyslot. The argon2
	// branch below always understood that; the pbkdf2 side did not, and left
	// both its cost and its hash to be re-decided:
	//
	//	iterations  recalibrated against the 2000ms default budget
	//	hash        replaced with DefaultHashAlgo -- sha256, whatever it was
	//
	// So an operator who deliberately configured a cost had it discarded by an
	// unrelated passphrase change, silently and in both directions. MEASURED: a
	// single ChangeKey on a container formatted with --pbkdf-force-iterations
	// 1000 took ~6.3 seconds and left the keyslot at several million
	// iterations. The volume still opened, which is why nothing caught it.
	kdfType := targetKeyslot.KDF.Type
	formatOpts := FormatOptions{
		KDFType:  kdfType,
		HashAlgo: DefaultHashAlgo,
	}
	if targetKeyslot.KDF.Hash != "" {
		formatOpts.HashAlgo = targetKeyslot.KDF.Hash
	}

	// Copy existing Argon2 parameters or set defaults.
	//
	// AN INHERITED ARGON2 MEMORY COST IS PRESERVED, NOT RAISED TO
	// MinArgon2MemoryKB, and this is the one place the create floor deliberately
	// does not reach.
	//
	// THE INVARIANT, the same one AddKey keeps: every keyslot in a volume should
	// be derivable by the hardware that owns the volume. A cost read out of the
	// container is the only evidence this package has about that hardware --
	// a volume formatted at 32 MiB was formatted by something that had 32 MiB --
	// so raising it produces a keyslot that cannot be derived at all on the only
	// hardware that uses the volume. Preserving makes nothing weaker than it
	// already was: the operator is changing the credential, not the cost, and
	// the volume's resistance is bounded by its weakest slot either way.
	//
	// It is the opposite of the PBKDF2 rule below, which DOES raise an inherited
	// count to the floor, and the asymmetry is PHYSICAL rather than a
	// preference: PBKDF2 iterations cost time, which any machine can spend;
	// Argon2 memory costs RAM, which it may simply not have.
	//
	// The floor still binds where the cost is the CALLER's -- Format and AddKey
	// -- because there is no container to take evidence from. See
	// MinArgon2MemoryKB.
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

	// The pbkdf2 equivalent, with one asymmetry that is not an oversight: the
	// preserved count is RAISED TO THIS PACKAGE'S FLOOR if it sits below it.
	//
	// Argon2 has no such floor, so preserving there is unconditional. PBKDF2
	// does (pbkdf2IterationFloor), and a container written elsewhere may
	// legitimately carry a count under it -- cryptsetup's
	// --pbkdf-force-iterations will write 1000. Preserving that exactly would
	// mean forcedPBKDF2Iterations refusing the write, so an imported container
	// could never have its passphrase changed at all; that is a worse outcome
	// than a keyslot stronger than the one asked for, and it would be this
	// package refusing to let an operator rotate a credential.
	//
	// Raising is also CLOSER to the old behavior than refusing: recalibration
	// already replaced a low count with a much larger one. What changes is that
	// the increase now stops at the floor instead of at whatever this machine
	// benchmarks.
	if isPBKDF2Type(normalizeKDFType(kdfType)) && targetKeyslot.KDF.Iterations != nil {
		preserved := *targetKeyslot.KDF.Iterations
		if floor := int(math.Ceil(pbkdf2IterationFloor(formatOpts.HashAlgo, pbkdf2ReferenceTargetMs))); preserved < floor {
			preserved = floor
		}
		formatOpts.PBKDFIterations = preserved
	}

	kdf, err := CreateKDF(formatOpts, targetKeyslot.KeySize)
	if err != nil {
		return fmt.Errorf("failed to create KDF: %w", err)
	}

	// Derive key from new passphrase
	passphraseKey, err := DeriveKeyEnclave(newPassphrase, kdf, targetKeyslot.KeySize)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}
	defer passphraseKey.Destroy()

	// Apply anti-forensic split to master key
	afData, err := afSplitEnclave(masterKey, AFStripes, targetKeyslot.AF.Hash)
	if err != nil {
		return fmt.Errorf("failed to apply AF split: %w", err)
	}
	defer afData.Destroy()

	// Encrypt AF-split key material with new passphrase-derived key
	encryptedKeyMaterial, err := encryptKeyMaterialEnclave(afData, passphraseKey, DefaultCipher)
	if err != nil {
		return fmt.Errorf("failed to encrypt key material: %w", err)
	}
	defer clearBytes(encryptedKeyMaterial)

	// Get existing keyslot size. Its OFFSET is not needed here any more: the
	// new material is written elsewhere and the old area is described by
	// oldArea below, which is what the final wipe acts on.
	existingSize, err := parseSize(targetKeyslot.Area.Size)
	if err != nil {
		return fmt.Errorf("failed to parse keyslot size: %w", err)
	}

	// Verify new key material fits in existing area
	if int64(len(encryptedKeyMaterial)) > existingSize {
		return fmt.Errorf("new key material too large for existing keyslot area")
	}

	// THE NEW MATERIAL GOES SOMEWHERE ELSE, AND THE OLD AREA IS WIPED LAST.
	//
	// This used to wipe the existing area, write the new material into it, and
	// only then make the new KDF durable. Between the material write and the
	// header write the on-disk state was: material derived from the NEW
	// passphrase, under the OLD salt and iteration count. Neither passphrase
	// derives the key that decrypts that material, so on a single-keyslot volume
	// an ordinary power failure in that window was permanent data loss -- no
	// attacker required. The wipe also destroyed the old material before
	// anything replacing it existed, so a failure in the WRITE alone was already
	// unrecoverable (#39).
	//
	// Writing into a free area and re-pointing the header removes the window
	// rather than narrowing it. Every intermediate state is openable:
	//
	//	crash before the header write   old area intact, header still names it
	//	                                -> the OLD passphrase opens the volume
	//	crash after the header write    header names the new area, material there
	//	                                -> the NEW passphrase opens the volume
	//
	// The keyslot keeps its id and its area SIZE; only the offset moves, which
	// is ordinary LUKS2 -- keyslot areas are not required to be contiguous, and
	// the area freed here is reclaimed by the next relocation.
	newOffset, err := findFreeKeyslotArea(hdr, metadata, existingSize)
	if err != nil {
		return fmt.Errorf("cannot rewrite keyslot %d safely: %w; add a new key and remove this slot instead", keyslot, err)
	}

	// The area this call will eventually ZERO is checked here, up front, against
	// the keyslots that must survive (#38). A keyslot's area can overlap
	// another's, and ChangeKey destroys an area exactly as a removal does -- so
	// on such a container it would take a healthy keyslot's key material with it.
	//
	// It is checked BEFORE anything is written rather than beside the wipe at the
	// end, and the difference is the whole value of the check: by the time the
	// wipe runs the new passphrase is already live, so a refusal there would be a
	// half-completed operation reported as a failure. Refusing now costs nothing
	// -- the volume is untouched and both the old passphrase and the overlapping
	// keyslot still work.
	//
	// ChangeKey deliberately does NOT take the entry-level half of the removal
	// gate: changing the passphrase on a single-keyslot volume is exactly what
	// this function is for.
	oldArea := *targetKeyslot.Area
	if err := checkKeyslotAreaDisjointFromOthers(device, metadata, slotIDStr, &oldArea); err != nil {
		return err
	}

	// The header is proved writable and the metadata brought to its final state
	// BEFORE any device write, so a refusal costs nothing.
	targetKeyslot.KDF = kdf
	targetKeyslot.Area.Offset = formatSize(newOffset)
	hdr.SequenceID++
	if err := checkHeaderWritable(hdr, metadata); err != nil {
		return err
	}

	// Write new encrypted key material into the free area. Nothing depends on
	// these bytes until the header points at them, so a failure here leaves the
	// volume exactly as it was.
	f, err := os.OpenFile(device, os.O_RDWR, 0600) // #nosec G304 -- device path validated by caller
	if err != nil {
		return fmt.Errorf("failed to open device: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := f.Seek(newOffset, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to keyslot area: %w", err)
	}

	if _, err := f.Write(encryptedKeyMaterial); err != nil {
		return fmt.Errorf("failed to write key material: %w", err)
	}

	// Pad remaining area
	remaining := existingSize - int64(len(encryptedKeyMaterial))
	if remaining > 0 {
		padding := make([]byte, remaining)
		if _, err := f.Write(padding); err != nil {
			return fmt.Errorf("failed to write padding: %w", err)
		}
	}

	// THE MATERIAL IS DURABLE BEFORE THE HEADER NAMES IT. Reversing these two
	// would recreate the window in a new place: a header pointing at an area
	// whose contents had not reached the device.
	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync: %w", err)
	}

	// The commit point. After this the new passphrase opens the volume.
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Only now is the old material destroyed. That the wipe is SAFE was
	// established before any of this began -- see the overlap check above -- so
	// what can fail here is I/O, not a refusal, and a failure leaves the volume
	// openable by the new passphrase with the old material still on the device.
	old := *targetKeyslot
	old.Area = &oldArea
	if err := wipeKeyslotArea(device, &old); err != nil {
		return fmt.Errorf("the new passphrase is live in keyslot %d, but the old key material could not be destroyed: %w", keyslot, err)
	}

	return nil
}

// KillKeyslot removes a keyslot without requiring the passphrase
// WARNING: This is a destructive operation - the keyslot cannot be recovered
func KillKeyslot(device string, keyslot int) error {
	// Validate inputs
	if err := ValidateDevicePath(device); err != nil {
		return err
	}
	if keyslot < 0 || keyslot >= MaxKeyslots {
		return fmt.Errorf("invalid keyslot: %d (must be 0-%d)", keyslot, MaxKeyslots-1)
	}

	// Acquire exclusive lock
	lock, err := AcquireFileLock(device)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	// Read existing header and metadata
	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Check that keyslot exists
	slotIDStr := strconv.Itoa(keyslot)
	targetKeyslot, exists := metadata.Keyslots[slotIDStr]
	if !exists {
		return fmt.Errorf("keyslot %d does not exist", keyslot)
	}

	// THE GATE. Every removal path passes through checkKeyslotRemovable, which
	// asks the one question all of them need answered: after this removal, can
	// anything still open the volume?
	//
	// It replaces `len(metadata.Keyslots) <= 1`, which counted MAP ENTRIES. A
	// `reencrypt` slot, a slot with no anti-forensic object, a slot whose cipher
	// nothing implements -- each reads as a keyslot to len() and opens nothing,
	// so the guard reported a survivor and the only working credential was
	// destroyed (#37, #71). It also checks the BYTES: the wipe below zeroes a
	// range, and that range can belong to a keyslot that must survive (#38).
	if err := checkKeyslotRemovable(device, metadata, slotIDStr); err != nil {
		return err
	}

	// NOTHING IS DESTROYED UNTIL THE RESULTING HEADER IS PROVED WRITABLE.
	//
	// The metadata is brought to its post-removal state and run through the
	// write path's own encoder first. This used to wipe and then discover the
	// header would not fit, so a failure that could have been a clean refusal
	// instead cost a keyslot (#50). Removal only shrinks metadata, so this is
	// unreachable for a container this library wrote -- and reachable for one it
	// did not, whose JSON area already exceeds what the writer will accept.
	removeKeyslotFromMetadata(metadata, slotIDStr)
	hdr.SequenceID++
	if err := checkHeaderWritable(hdr, metadata); err != nil {
		return err
	}

	// From here the operation is destructive.
	if err := wipeKeyslotArea(device, targetKeyslot); err != nil {
		return fmt.Errorf("failed to wipe keyslot area: %w", err)
	}

	// Write updated headers
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	return nil
}

// ListKeyslots returns information about all active keyslots
func ListKeyslots(device string) ([]KeyslotInfo, error) {
	if err := ValidateDevicePath(device); err != nil {
		return nil, err
	}

	_, metadata, err := ReadHeader(device)
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	return listKeyslotsFrom(metadata)
}

func listKeyslotsFrom(metadata *LUKS2Metadata) ([]KeyslotInfo, error) {
	var slots []KeyslotInfo
	// Scan order, not map order: ranging the map returned the listing in a
	// different order on every call for an unchanged device (#57). This is the
	// same order unlock attempts the slots in, so an operator reading the
	// listing is reading the order the volume is actually tried in.
	for _, idStr := range keyslotIDsInScanOrder(metadata.Keyslots) {
		ks := metadata.Keyslots[idStr]
		// AN UNADDRESSABLE KEY IS IGNORED, for the reasons #35 established for
		// tokens and MEASURED again here against cryptsetup 2.7.0, on headers
		// crafted for this question with a numeric control through the same
		// rewrite path:
		//
		//	keyslots {"7": k}    luksDump exit 0, shows "7: luks2"   <- control
		//	keyslots {"31": k}   luksDump exit 0, shows "31: luks2"  <- bound
		//	keyslots {"32": k}   luksDump exit 0, "Keyslots:" EMPTY
		//	keyslots {"1000": k} luksDump exit 0, "Keyslots:" EMPTY
		//	keyslots {"007": k}  luksDump exit 1, "is not a valid LUKS device"
		//	keyslots {"+3": k}   luksDump exit 1, "is not a valid LUKS device"
		//	keyslots {"-1": k}   luksDump exit 1, "is not a valid LUKS device"
		//	keyslots {"reencrypt-in-progress": k}
		//	                     luksDump exit 1, "is not a valid LUKS device"
		//
		// So a key cryptsetup cannot address is not a working keyslot that
		// omitting would strand -- no LUKS2 implementation reaches it -- and
		// the header is still readable HERE on purpose, because an operator has
		// to be able to inspect a container cryptsetup will not open. Refusing
		// the listing is the BRICKING DIRECTION the tokens-are-tolerated ruling
		// exists to avoid, and it was briefly implemented here before these
		// measurements were taken.
		//
		// cryptsetup is STRICTER about keyslot keys than token keys: "01" is a
		// tolerated-but-unreachable token and an invalid DEVICE as a keyslot.
		// This function does not reproduce that asymmetry, because tolerating
		// more than cryptsetup only ever costs an entry in a listing, while
		// tolerating less would hide a keyslot from an operator inspecting a
		// container that still opens.
		id, ok := canonicalKeyslotID(idStr)
		if !ok {
			continue
		}

		// AN ABSENT PRIORITY IS NORMAL (1), NOT IGNORE (0).
		//
		// This defaulted to 0 and that is the wrong end of the scale: LUKS2
		// gives priority the values 0 ignore, 1 normal, 2 prefer, and defines
		// the member as OPTIONAL WITH A DEFAULT OF NORMAL. cryptsetup omits it
		// for a normal keyslot -- MEASURED: `cryptsetup config --priority
		// normal` deletes the member rather than writing 1 -- so essentially
		// every keyslot in every cryptsetup-created container arrives here with
		// no priority at all, and every one of them was being listed as
		// "ignore": a slot an operator is told to skip, and that a
		// priority-aware unlock would skip.
		//
		// It was already wrong for foreign containers before this package
		// stopped emitting the default; now it would be wrong for our own too.
		priority := KeyslotPriorityNormal
		if ks.Priority != nil {
			priority = *ks.Priority
		}

		// kdf and area are OPTIONAL as far as this function is concerned. A
		// luks2 keyslot always has both and the header reader enforces that,
		// but a "reencrypt" keyslot has no kdf at all, and listing keyslots is
		// an inspection operation -- the one thing an operator does when a
		// container is in a state nothing else can handle. It must report what
		// is there rather than crash on what is not.
		info := KeyslotInfo{
			ID:       id,
			Type:     ks.Type,
			KeySize:  ks.KeySize,
			Priority: priority,
		}
		if ks.KDF != nil {
			info.KDFType = ks.KDF.Type
			// Read through the pointers rather than copying the KDF, so a
			// caller cannot reach the header's own structure through a
			// listing and mutate it.
			if ks.KDF.Iterations != nil {
				info.PBKDF2Iterations = *ks.KDF.Iterations
			}
			if ks.KDF.Time != nil {
				info.Argon2Time = *ks.KDF.Time
			}
			if ks.KDF.Memory != nil {
				info.Argon2MemoryKB = *ks.KDF.Memory
			}
			if ks.KDF.CPUs != nil {
				info.Argon2Parallel = *ks.KDF.CPUs
			}
		}
		if ks.Area != nil {
			info.Encryption = ks.Area.Encryption
		}

		slots = append(slots, info)
	}

	return slots, nil
}

// KeyslotInfo contains information about a keyslot
type KeyslotInfo struct {
	ID         int
	Type       string
	KeySize    int
	Priority   int
	KDFType    string
	Encryption string

	// The keyslot's KDF COST, which is what an operator needs to see and could
	// not get from this package without parsing the header themselves.
	//
	// It matters most where the costs on one volume DIFFER. ChangeKey preserves
	// a slot's existing Argon2 memory cost even when it sits below
	// MinArgon2MemoryKB -- deliberately, because raising it would ask the
	// formatting hardware for RAM it may not have (see ChangeKey) -- so a
	// rotated slot can legitimately read below what Format would ever write.
	// That is the one thing about the decision an operator has to be able to
	// observe, and a listing is where they would look.
	//
	// Zero where the KDF does not carry the parameter: a pbkdf2 slot has no
	// Argon2 costs and an argon2 slot has no iteration count.
	PBKDF2Iterations int
	Argon2Time       int
	Argon2MemoryKB   int
	Argon2Parallel   int
}

// canonicalKeyslotID reports the slot number a keyslot key addresses, and
// whether any LUKS2 implementation can reach it.
//
// It mirrors canonicalTokenID exactly, and deliberately: the two questions are
// the same question about two maps in the same header, and answering them
// differently is how a listing comes to disagree with what can be retrieved.
//
// SPELLING, then RANGE. strconv.Atoi accepts "007", "+1" and " 1" and returns
// the same number for each, so parsing alone does not answer whether a key
// addresses a slot; the round trip through strconv.Itoa does. Range then bounds
// it to the 0..LUKS2MaxKeyslots-1 that cryptsetup addresses -- the 31/32 pair in
// the measurements above pins that boundary rather than assuming it.
func canonicalKeyslotID(key string) (int, bool) {
	id, err := strconv.Atoi(key)
	if err != nil || strconv.Itoa(id) != key {
		return 0, false
	}
	if id < 0 || id >= LUKS2MaxKeyslots {
		return 0, false
	}
	return id, true
}

// keyslotIDsInScanOrder returns every keyslot ID in the order unlock attempts
// are made: ascending numeric ID, with any ID that does not parse with
// strconv.Atoi after those, in lexical order. That tail is not only
// non-numeric spellings -- a decimal string too large for an int lands there
// too, because Atoi reports it as an error.
//
// Ranging over the keyslot map directly leaves the order to Go's randomized map
// iteration, which costs twice. Every attempt is a full derivation -- a failed
// one costs exactly as much as a successful one, because the digest comparison
// is the only rejection point -- and the credential in use is almost always in
// the lowest-numbered slot, so a random start pays O(n/2) derivations where
// ascending order pays one. It also makes the time to open a volume differ on
// every call for reasons the caller cannot see or control.
//
// The ordering is TOTAL: every key in the map is returned exactly once. An ID
// that does not parse as a number is still returned rather than skipped,
// because dropping it would make its keyslot unreachable, and an unreachable
// keyslot is a credential that can no longer open the volume.
//
// Keyslot priority is deliberately not consulted here. No unlock path reads
// that field -- ListKeyslots reads it, but only to report it -- and honoring it
// would change WHICH keyslots are tried rather than merely the order, which is
// a different decision from this one. See #56: the values written for it are
// inverted with respect to LUKS2, so it must not be wired up as it stands.
func keyslotIDsInScanOrder(keyslots map[string]*Keyslot) []string {
	ids := make([]string, 0, len(keyslots))
	for id := range keyslots {
		ids = append(ids, id)
	}

	slices.SortFunc(ids, func(a, b string) int {
		na, errA := strconv.Atoi(a)
		nb, errB := strconv.Atoi(b)
		switch {
		case errA == nil && errB == nil:
			// Two spellings of one number ("7" and "007") parse equal. Ties
			// must break on the raw string: slices.SortFunc is not stable and
			// the input order comes from the map, so leaving them equal would
			// hand exactly this header back to the randomness the ordering
			// exists to remove.
			if c := cmp.Compare(na, nb); c != 0 {
				return c
			}
			return cmp.Compare(a, b)
		case errA == nil:
			return -1
		case errB == nil:
			return 1
		default:
			return cmp.Compare(a, b)
		}
	})

	return ids
}

// getMasterKey unlocks the volume and returns the master key HELD IN PROTECTED
// MEMORY. The caller owns the returned enclave and must Destroy it.
//
// Keyslots are tried in the order given by keyslotIDsInScanOrder; every slot is
// tried before the attempt is reported as having failed.
//
// # Failing to VERIFY and failing to TRY are different facts
//
// This used to collapse every failure into a bare "incorrect passphrase", which
// made a damaged volume indistinguishable from a wrong credential all the way
// up to VerifyRecoveryKey -- where an operator is told to discard a recovery key
// that in fact works (#72).
//
// So a keyslot that was tried and whose digest did not match is separated from
// one that could not be tried at all. If NO keyslot verified and at least one
// could not be tried, the reason it could not be tried is what comes back: the
// volume's state is the thing the caller can act on, and claiming a credential
// verdict that was never actually reached is the failure being fixed.
//
// # What this deliberately does NOT claim
//
// It does not report a wrong-passphrase verdict for a digest mismatch, and
// since #70 there is no sentinel left that could state one. Three causes
// arrive at that comparison indistinguishably -- a wrong credential, the RIGHT
// credential over damaged key material, and a semantically wrong digest -- so
// naming it after one of them would be a false statement of exactly the kind
// this change exists to remove. What a non-verifying keyslot set should be
// called is an open design question (#68), left untyped here rather than
// guessed at; ErrMasterKeyVerification says what happened without saying why.
//
// # A volume with NO usable keyslot is not a wrong passphrase either
//
// If the scan tries nothing at all, ErrNoKeyslots comes back rather than a
// verification verdict (#30). A wrong-passphrase verdict is the one answer an
// operator will assume is their own fault, and reporting it here sends someone
// whose header carries no openable keyslot to retype a credential that was
// never the problem and that no passphrase would replace.
// The state is reachable without anything exotic -- a keyslots object that is
// empty or absent, or one whose every entry has a type the unlock path will not
// try, such as a container left mid-reencryption. A `reencrypt`-only volume
// even looks populated in ListKeyslots, which deliberately keeps a broader
// view, while being unopenable here.
//
// The message names which of the two it was, because the remedies differ: an
// empty keyslots object is a lost or truncated header, while keyslots present
// but untryable is a container in a state this path does not handle.
func getMasterKey(device string, passphrase []byte, metadata *LUKS2Metadata) (*enclave.MemoryEnclave, error) {
	// The first reason a keyslot could not be TRIED, kept in case nothing
	// verifies. The first rather than the last, because scan order is
	// deterministic and the lowest-numbered damaged slot is the one an operator
	// will look at first.
	var untried error

	// How many keyslots the scan actually reached the unlock with. Counted
	// rather than derived from len(metadata.Keyslots), which counts entries the
	// unlock path skips.
	tried := 0

	for _, id := range keyslotIDsInScanOrder(metadata.Keyslots) {
		keyslot := metadata.Keyslots[id]
		if keyslot.Type != "luks2" {
			continue
		}
		tried++

		masterKey, err := unlockKeyslot(device, id, passphrase, keyslot, metadata.Digests)
		if err == nil {
			return masterKey, nil
		}

		// Protected memory is FAIL-CLOSED, so this aborts rather than moving on:
		// every remaining keyslot needs the same locked pages and would fail the
		// same way, and continuing would bury an operator-fixable RLIMIT_MEMLOCK
		// condition under a credential verdict.
		if errors.Is(err, ErrProtectedMemory) {
			return nil, err
		}

		if errors.Is(err, ErrMasterKeyVerification) {
			// Tried, and did not verify. Try the next keyslot.
			continue
		}

		if untried == nil {
			untried = fmt.Errorf("keyslot %s could not be tried: %w", id, err)
		}
	}

	if untried != nil {
		return nil, untried
	}

	// Nothing was tried, so nothing was judged: there is no credential verdict
	// to report, only a header that offers no way in.
	if tried == 0 {
		if len(metadata.Keyslots) == 0 {
			return nil, fmt.Errorf("%w: the header declares no keyslots", ErrNoKeyslots)
		}
		return nil, fmt.Errorf("%w: the header declares %d keyslot(s), none of them of a type the unlock path can try",
			ErrNoKeyslots, len(metadata.Keyslots))
	}

	return nil, ErrMasterKeyVerification
}

// findAvailableKeyslot finds the next available keyslot number
func findAvailableKeyslot(metadata *LUKS2Metadata, opts *AddKeyOptions) (int, error) {
	// If specific keyslot requested, verify it's available
	if opts != nil && opts.Keyslot != nil {
		slot := *opts.Keyslot
		if slot < 0 || slot >= MaxKeyslots {
			return 0, fmt.Errorf("invalid keyslot: %d (must be 0-%d)", slot, MaxKeyslots-1)
		}
		slotIDStr := strconv.Itoa(slot)
		if _, exists := metadata.Keyslots[slotIDStr]; exists {
			return 0, fmt.Errorf("keyslot %d already in use", slot)
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

	return 0, fmt.Errorf("no available keyslots")
}

// keyslotsAreaBounds returns the half-open [start, end) byte range of the
// container's reserved keyslots area.
//
// Both ends are READ FROM THE CONTAINER; neither is assumed. The area starts at
// twice the header area size, because the two header copies tile the front of
// the device, and it runs for config.keyslots_size bytes. Hardcoding the start
// at 0x8000 is correct only for the 16 KiB metadata area this library formats
// with -- a container with a 32 KiB area starts its keyslots at 0x10000 -- and
// it is the same "geometry as a constant" mistake that put the secondary header
// at a fixed offset.
//
// The data segment is NOT the end of this area. On a conformant container the
// data offset may sit well past it, and the gap between the two is space that
// belongs to neither: a keyslot placed there passes a segment-overlap check
// while falling outside the geometry the container declares about itself.
func keyslotsAreaBounds(hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata) (int64, int64, error) {
	area, err := headerAreaSize(hdr)
	if err != nil {
		return 0, 0, err
	}
	start := 2 * int64(area)

	if metadata.Config == nil {
		return 0, 0, fmt.Errorf("%w: header has no config object, so the keyslots area is undefined",
			ErrInvalidHeader)
	}
	size, err := parseSize(metadata.Config.KeyslotsSize)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: config.keyslots_size %q is not a size: %v",
			ErrInvalidHeader, metadata.Config.KeyslotsSize, err)
	}
	if size <= 0 {
		return 0, 0, fmt.Errorf("%w: config.keyslots_size %d leaves no room for any keyslot",
			ErrInvalidHeader, size)
	}

	return start, start + size, nil
}

// calculateNextKeyslotOffset calculates the offset for the next keyslot area.
//
// keyslotsStart is where the container's keyslots area begins -- see
// keyslotsAreaBounds. It is a parameter rather than a constant because it is a
// property of the container, not of this library.
func calculateNextKeyslotOffset(metadata *LUKS2Metadata, keyslotsStart int64) (int64, error) {
	maxEnd := keyslotsStart

	// THE COMMENT THAT USED TO BE HERE PROMISED A GUARD THAT DOES NOT EXIST.
	//
	// It said a damaged keyslot could be skipped because "the overlap checks in
	// AddKey are what refuse that". There are no such checks on the ADD path:
	// keyslotAreaDisjointFrom has exactly two call sites, ChangeKey on the OLD
	// area it is about to wipe, and the removal path. Nothing validates the new
	// offset this function returns.
	//
	// So a sibling dropped from maxEnd was not merely unaccounted for -- it was
	// unprotected. This function is the ONLY thing choosing where AddKey writes,
	// and a keyslot whose area.offset or area.size did not parse silently
	// lowered the maximum, letting the new slot land inside that keyslot's real
	// bytes and destroy another credential's key material, with AddKey
	// reporting success.
	//
	// A keyslot whose extent cannot be read is therefore a refusal, not a skip.
	for id, ks := range metadata.Keyslots {
		// No area object at all is a different thing from an unreadable one:
		// there is no extent to exclude because the keyslot declares none, and
		// the declared-bounds check in AddKey does cover that case.
		if ks == nil || ks.Area == nil {
			continue
		}
		offset, err := parseSize(ks.Area.Offset)
		if err != nil {
			return 0, fmt.Errorf("%w: keyslot %s declares an area offset of %q, which is not a valid size; a new "+
				"keyslot cannot be placed without knowing where this one ends",
				ErrInvalidHeader, id, ks.Area.Offset)
		}
		size, err := parseSize(ks.Area.Size)
		if err != nil {
			return 0, fmt.Errorf("%w: keyslot %s declares an area size of %q, which is not a valid size; a new "+
				"keyslot cannot be placed without knowing where this one ends",
				ErrInvalidHeader, id, ks.Area.Size)
		}
		end := offset + size
		if end > maxEnd {
			maxEnd = end
		}
	}

	// Align to 4KB boundary
	return alignTo(maxEnd, KeyslotAreaAlignment), nil
}

// wipeKeyslotArea securely wipes a keyslot area.
//
// It screens the keyslot itself because KillKeyslot reaches it with NO
// passphrase and therefore never passes through unlockKeyslot's check. That
// makes this the one path where a crafted keyslot's declared offset and size
// decide where zeros get written, and where a missing area object dereferences
// nil.
func wipeKeyslotArea(device string, keyslot *Keyslot) error {
	if err := validateKeyslot("", keyslot); err != nil {
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

	f, err := os.OpenFile(device, os.O_RDWR, 0600) // #nosec G304 -- device path validated by caller
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	if err := checkAreaWithinDevice(f, offset, size); err != nil {
		return err
	}

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return err
	}

	// OVERWRITTEN WITH RANDOM, NOT ZEROED.
	//
	// Both destroy the key material equally well -- that is not what is at
	// stake. What differs is what the destroyed area then LOOKS LIKE. A live
	// keyslot's area holds AF-split material under a passphrase-derived key,
	// which is indistinguishable from random; a zeroed area is
	// distinguishable from every one of them at a glance. So zeroing published
	// the one fact the removal was meant to end: that a key USED to be here and
	// was revoked. Anyone holding the drive afterwards learns the container's
	// key-management history -- how many credentials existed, which were
	// destroyed and when relative to each other -- from the pattern alone.
	//
	// cryptsetup leaves a freed area random for this reason, and Format now
	// fills the whole unallocated keyslots region the same way (format.go), so
	// a slot that was never used and a slot that was destroyed are
	// indistinguishable from each other as well as from a live one.
	//
	// In fixed-size chunks: size came out of a header this process did not
	// write, and even bounded there is no reason to let it choose an
	// allocation. WipeKeyslot (wipe.go) still zeroes, with its own write loop
	// and its own contract -- it is a destructive operator command, not part of
	// a removal.
	if err := writeRandom(f, size); err != nil {
		return err
	}

	return f.Sync()
}

// removeKeyslotFromMetadata removes a keyslot and every stored reference to its
// id, in one call.
//
// The three removal paths used to open-code this, and each open-coding deleted
// the map entry and filtered the digests -- and none of them touched the tokens,
// so a token could outlive the keyslot it named on every route. That is the
// hand-written-cleanup failure recorded on forgetKeyslotID (header.go), reached
// from the other direction: the header READ already had to forget a dropped
// keyslot's references, so the code existed and the removal paths simply did not
// call it.
//
// One function owning the whole removal is what stops the next author having to
// know that "holds a keyslot id" is a different relation from "is a keyslot".
func removeKeyslotFromMetadata(metadata *LUKS2Metadata, id string) {
	delete(metadata.Keyslots, id)
	forgetKeyslotID(metadata, id)
}

// usableKeyslotsAfterRemoving reports how many keyslots would still be able to
// open the volume if id were removed.
//
// This is the question every last-keyslot guard actually needs to ask, and both
// simpler spellings of it are wrong in opposite directions:
//
//   - len(metadata.Keyslots) counts entries that cannot open anything -- a
//     `reencrypt` slot, a slot whose af object is missing, a slot whose cipher
//     nothing implements. That is what the guards counted, and it authorized
//     removing the last real keyslot and left the volume permanently unopenable
//     (#37, #71).
//   - counting the slots the unlock loop would TRY is right only when the target
//     is itself usable. When it is not, the count does not change on removal, so
//     a volume with one usable slot and one stale reencrypt slot would refuse to
//     delete the STALE one -- one damaged slot costing the volume its mutability,
//     which is the same class of failure from the other side.
//
// Phrasing it as "what remains afterwards" collapses both cases, so RemoveKey
// (whose target is provably usable, having just been unlocked) and the kill
// paths (whose target may not be) share one predicate and neither needs to know
// which situation it is in.
func usableKeyslotsAfterRemoving(f *os.File, metadata *LUKS2Metadata, id string) int {
	remaining := 0
	for _, other := range keyslotIDsInScanOrder(metadata.Keyslots) {
		if other == id {
			continue
		}
		if keyslotCanOpenVolume(f, other, metadata.Keyslots[other], metadata.Digests) {
			remaining++
		}
	}
	return remaining
}

// keyslotAreaDisjointFrom refuses a wipe that would land on key material another
// keyslot still needs.
//
// wipeKeyslotArea validates the target's own geometry and then zeroes it.
// Nothing checked it against the areas of the slots that must SURVIVE, so the
// guard and the wipe disagreed about what the removal destroys: the guard
// reasoned over keyslot ENTRIES, the wipe acted on BYTES. Two shape-valid slots
// sharing an area were enough (#38) -- removing either destroyed the other's key
// material while the guard counted a survivor, and the volume then reported
// "invalid passphrase" for a passphrase that was correct.
//
// The area is passed in rather than read from metadata.Keyslots[id], because
// the range about to be zeroed is not always the one the metadata now describes:
// ChangeKey relocates the keyslot first and then destroys the area it used to
// occupy. Asking about the wrong range is how a check like this passes while the
// wipe lands somewhere else entirely.
//
// Only slots that can still open the volume are protected. An area belonging to
// a slot that could never yield a key is not worth refusing a removal over, and
// protecting those would turn every damaged slot into a reason the volume cannot
// be repaired -- the failure this package spends most of its guards avoiding.
func keyslotAreaDisjointFrom(f *os.File, metadata *LUKS2Metadata, id string, area *KeyslotArea) error {
	if area == nil {
		// No target geometry, so no overlap can be computed -- and none needs
		// to be. Every wipe path reaches validateKeyslot before writing a byte
		// and refuses there, with a message about the geometry rather than the
		// less informative one this function could offer. Failing closed is
		// already the downstream behavior; returning nil here does not open it.
		return nil
	}
	targetOffset, offErr := parseSize(area.Offset)
	targetSize, sizeErr := parseSize(area.Size)
	if offErr != nil || sizeErr != nil || targetOffset < 0 || targetSize <= 0 {
		return nil // same reasoning as above
	}
	targetEnd := targetOffset + targetSize

	for _, other := range keyslotIDsInScanOrder(metadata.Keyslots) {
		if other == id {
			continue
		}
		survivor := metadata.Keyslots[other]
		if !keyslotCanOpenVolume(f, other, survivor, metadata.Digests) {
			continue
		}

		// keyslotCanOpenVolume has already required these to parse and to be
		// non-negative and non-overflowing (validateKeyslot); the error is
		// consumed rather than ignored so that a future loosening of the
		// predicate cannot silently skip a survivor.
		otherOffset, err := parseSize(survivor.Area.Offset)
		if err != nil {
			return fmt.Errorf("%w: keyslot %s has an unreadable area offset", ErrInvalidKeyslot, other)
		}
		otherSize, err := parseSize(survivor.Area.Size)
		if err != nil {
			return fmt.Errorf("%w: keyslot %s has an unreadable area size", ErrInvalidKeyslot, other)
		}

		if targetOffset < otherOffset+otherSize && otherOffset < targetEnd {
			return fmt.Errorf("%w: zeroing [%d,%d) for keyslot %s would also zero keyslot %s at [%d,%d), which can still open this volume",
				ErrKeyslotAreaOverlap, targetOffset, targetEnd, id, other, otherOffset, otherOffset+otherSize)
		}
	}

	return nil
}

// checkKeyslotAreaDisjointFromOthers is the BYTE-level half on its own, for the
// caller that zeroes a keyslot area without removing the keyslot.
//
// ChangeKey must NOT take the entry-level half -- changing the passphrase on a
// single-keyslot volume is exactly what that function is for, and the
// last-keyslot guard would refuse it. It must take this half, because the bytes
// it overwrites can belong to another keyslot just as easily as a removal's can.
//
// The enumeration that produced the seam was "removal paths", and it misses this
// site, because ChangeKey is not a removal. The set the OVERLAP invariant ranges
// over is the paths that ZERO A KEYSLOT'S AREA, and there are five:
//
//	RemoveKey, KillSlot, ChangeKey, KillKeyslot   via wipeKeyslotArea
//	WipeKeyslot                                   with its own write loop
//
// Two counts live near each other here and they are NOT the same number, which
// is its own small lesson about writing one down: wipeKeyslotArea has four
// callers, while five paths zero a keyslot area, because WipeKeyslot does not go
// through it. wipeHeaders is deliberately outside both -- it destroys the header
// on purpose.
func checkKeyslotAreaDisjointFromOthers(device string, metadata *LUKS2Metadata, id string, area *KeyslotArea) error {
	f, err := os.Open(device) // #nosec G304 -- device path validated by caller
	if err != nil {
		return &DeviceError{Device: device, Op: "open", Err: err}
	}
	defer func() { _ = f.Close() }()

	return keyslotAreaDisjointFrom(f, metadata, id, area)
}

// findFreeKeyslotArea returns an offset inside the container's keyslots area at
// which `size` bytes can be written without touching any existing keyslot's
// area or the encrypted data.
//
// It is a first-fit search over the GAPS between the areas in use, not a bump
// allocator. calculateNextKeyslotOffset -- which AddKey uses to place a brand
// new slot -- takes the maximum end and rounds up, and that is right there,
// because every existing slot is in use. It is wrong here: ChangeKey frees the
// area it relocated out of, and a bump allocator would march up the keyslots
// area until it ran out, making the number of times a passphrase can be changed
// a function of how much room the container was formatted with.
//
// Both bounds are read from the container. The declared keyslots area is the
// primary one; the data segment is kept as a second, physical ceiling for a
// container whose config.keyslots_size overstates the space it actually has --
// the same pair of boundaries AddKey enforces, for the same reason.
func findFreeKeyslotArea(hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata, size int64) (int64, error) {
	if size <= 0 {
		return 0, fmt.Errorf("%w: a keyslot area of %d bytes", ErrInvalidSize, size)
	}

	start, end, err := keyslotsAreaBounds(hdr, metadata)
	if err != nil {
		return 0, err
	}
	// This loop narrows the search so it cannot run into the encrypted data. A
	// segment whose offset would not parse was skipped, which WIDENS the
	// search -- the opposite of what an unreadable bound should do.
	for id, segment := range metadata.Segments {
		segmentOffset, err := parseSize(segment.Offset)
		if err != nil {
			return 0, fmt.Errorf("%w: data segment %s declares an offset of %q, which is not a valid size, so the "+
				"search for free keyslot space cannot be stopped before the encrypted data",
				ErrInvalidHeader, id, segment.Offset)
		}
		if segmentOffset < end {
			end = segmentOffset
		}
	}

	// And this one is what keeps the chosen gap off every OTHER keyslot's
	// bytes. ChangeKey disjointness-checks only the OLD area it is about to
	// wipe (keyslot.go, checkKeyslotAreaDisjointFromOthers) and never re-checks
	// the new offset chosen here, so a sibling dropped from `used` because its
	// extent would not parse could be written straight over -- destroying that
	// credential during what looks like a routine passphrase change.
	type extent struct{ from, to int64 }
	used := make([]extent, 0, len(metadata.Keyslots))
	for id, ks := range metadata.Keyslots {
		if ks == nil || ks.Area == nil {
			continue
		}
		offset, err := parseSize(ks.Area.Offset)
		if err != nil {
			return 0, fmt.Errorf("%w: keyslot %s declares an area offset of %q, which is not a valid size; free "+
				"space cannot be chosen without knowing which bytes this keyslot occupies",
				ErrInvalidHeader, id, ks.Area.Offset)
		}
		areaSize, err := parseSize(ks.Area.Size)
		if err != nil {
			return 0, fmt.Errorf("%w: keyslot %s declares an area size of %q, which is not a valid size; free "+
				"space cannot be chosen without knowing which bytes this keyslot occupies",
				ErrInvalidHeader, id, ks.Area.Size)
		}
		// A non-positive size is a DECLARED empty extent rather than an
		// unreadable one: it parsed, and it occupies nothing to avoid.
		if areaSize <= 0 {
			continue
		}
		used = append(used, extent{offset, offset + areaSize})
	}
	slices.SortFunc(used, func(a, b extent) int { return cmp.Compare(a.from, b.from) })

	cursor := alignTo(start, KeyslotAreaAlignment)
	for _, in := range used {
		if in.to <= cursor {
			continue
		}
		if in.from-cursor >= size {
			break
		}
		cursor = alignTo(in.to, KeyslotAreaAlignment)
	}

	if cursor+size > end {
		return 0, fmt.Errorf("%w: %d bytes are needed and the keyslots area %d..%d has no gap that large",
			ErrKeyslotsAreaFull, size, start, end)
	}
	return cursor, nil
}

// checkKeyslotRemovable is the SINGLE gate every keyslot removal passes through.
//
// It exists as one function rather than as a check each caller performs because
// this package has already paid for the other arrangement twice: the
// last-keyslot guard was applied to the paths enumerated from a review finding
// and missed WipeKeyslot entirely, and the digest cleanup was open-coded at
// three sites and cleaned tokens at none. Five call sites that each remember to
// run two checks is the same defect waiting for its sixth path.
//
// The two conditions are ONE question asked about entries and about bytes:
// after this removal, can anything still open the volume? A guard that only
// counts surviving ENTRIES answers it for the metadata and not for the key
// material those entries point at.
//
// Both refusals are REFUSALS, not warnings. A removal that leaves a volume
// unopenable succeeds, reports success, and is discovered at the next unlock --
// the definition of a silent catastrophic failure, and the reason this is a
// guard rather than a documented caveat.
func checkKeyslotRemovable(device string, metadata *LUKS2Metadata, id string) error {
	f, err := os.Open(device) // #nosec G304 -- device path validated by caller
	if err != nil {
		return &DeviceError{Device: device, Op: "open", Err: err}
	}
	defer func() { _ = f.Close() }()

	if usableKeyslotsAfterRemoving(f, metadata, id) == 0 {
		return fmt.Errorf("%w: removing keyslot %s would leave no keyslot that can open this volume",
			ErrLastKeyslot, id)
	}
	return keyslotAreaDisjointFrom(f, metadata, id, areaOfKeyslot(metadata.Keyslots[id]))
}

// areaOfKeyslot returns a keyslot's area, or nil if it has none. It exists so
// the removal gate can ask about "the area this keyslot occupies" without a nil
// dereference on a keyslot that declares no area at all -- which is a shape the
// wipe paths refuse downstream, in a message about the geometry.
func areaOfKeyslot(keyslot *Keyslot) *KeyslotArea {
	if keyslot == nil {
		return nil
	}
	return keyslot.Area
}
