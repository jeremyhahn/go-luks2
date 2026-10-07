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

// LUKS2 keyslot priorities. The member is OPTIONAL and its default is NORMAL,
// so a keyslot with no priority is a normal one -- not an ignored one, which is
// what reading the absent member as the zero value would say.
//
// The names exist because the numbers read backwards: the value that sorts
// higher means "try this first". A bare 2 under a comment saying "lower
// priority" is how addKey came to mark every added key as the preferred one.
const (
	// keyslotPriorityIgnore marks a keyslot that should not be tried.
	keyslotPriorityIgnore = 0

	// keyslotPriorityNormal is the default, and the meaning of an ABSENT
	// priority member.
	keyslotPriorityNormal = 1

	// keyslotPriorityPrefer marks a keyslot that should be tried FIRST. It is
	// numerically the largest and semantically the highest.
	keyslotPriorityPrefer = 2
)

// Priority is a keyslot's try-order preference (DESIGN.md §B.2). Its values
// mirror keyslotPriorityIgnore/Normal/Prefer exactly -- the on-disk LUKS2
// encoding this package already reads and writes -- under the typed name the
// new read model and KeyslotParams use.
type Priority int

const (
	PriorityIgnore Priority = iota
	PriorityNormal
	PriorityPrefer
)

// keyslotInfoFromMetadata builds a KeyslotInfo for keyslot id from its
// on-disk metadata, as written by addKeyslotWithMasterKey. Equivalent to
// keyslotInfoFromEntry, except that it refuses an unparseable on-disk KDF
// type (via kdfParamsFromDisk) instead of defaulting it; Enrollment callers
// (recovery.go) use this one so a write they just made is read back exactly
// or reported as broken, never silently misreported.
func keyslotInfoFromMetadata(id int, ks *header.Keyslot) (KeyslotInfo, error) {
	info := KeyslotInfo{ID: id, Type: ks.Type, KeySize: ks.KeySize, Priority: PriorityNormal}
	if ks.Priority != nil {
		info.Priority = Priority(*ks.Priority)
	}
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

	// KDFType specifies the KDF type: "pbkdf2" (or an alias naming the hash,
	// such as "pbkdf2-sha512"), "argon2i" or "argon2id". Empty means
	// DefaultKDFSpec -- PBKDF2-SHA512 in FIPS 140-3 mode, Argon2id otherwise
	// (#237) -- or Argon2id when an Argon2 cost is set.
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
	InheritedArgon2Cost *rawKDF

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

// KeyslotParams configures AddKeyslot and ChangeKeyslot (DESIGN.md §B.2).
type KeyslotParams struct {
	// Slot is the keyslot id to use. Nil picks the lowest free one.
	// ChangeKeyslot ignores it: the slot it rewrites is the one the caller's
	// *Key came from.
	Slot *int

	// Priority is the keyslot's try-order preference, written explicitly for
	// PriorityIgnore and PriorityPrefer and omitted (the on-disk default,
	// read back as PriorityNormal) for PriorityNormal -- the same contract
	// listKeyslotsFrom already reads. ChangeKeyslot keeps the slot's existing
	// priority when Priority is left at its zero value, and rewrites it only
	// for an explicit PriorityNormal or PriorityPrefer.
	Priority Priority

	// KDF is the new keyslot's key-derivation cost. A zero KDFParams resolves
	// through the same policy AddKeyOptions already does: the library's
	// default KDF, or an inherited Argon2 cost when the container already
	// has one and the caller named neither a type nor a cost.
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

// TestKey verifies that a passphrase can unlock the LUKS volume.
// Returns nil if the passphrase opens a keyslot, error otherwise.
//
// A failure is NOT a statement that the passphrase is wrong. getMasterKey
// distinguishes a keyslot that judged the credential and rejected it from one
// that could not be tried and from a container with no usable keyslot at all
// (#30), and this wrapper carries that distinction through instead of
// flattening every outcome into a credential verdict. Match on the wrapped
// error -- ErrWrongKey, ErrInvalidKeyslot, ErrNoKeyslots -- rather
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
func addKeyFormatOptions(opts *addKeyOptionsForTest, metadata *header.Metadata, fipsMode func() fips.Mode) (formatOptionsForTest, *rawKDF) {
	formatOpts := baseAddKeyFormatOptionsWith(opts, fipsMode)

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
func callerArgon2Options(opts *addKeyOptionsForTest) formatOptionsForTest {
	if opts == nil {
		return formatOptionsForTest{}
	}
	// All THREE costs, not two. Argon2Parallel was missing, so a negative
	// parallelism never reached validateArgon2CreateCost and was refused one
	// layer later by deriveArgon2 instead -- see #176 and the parallelism
	// branch in validateArgon2CreateCost.
	return formatOptionsForTest{
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
func callerChoseArgon2Cost(opts *addKeyOptionsForTest) bool {
	return opts != nil && (opts.Argon2Time != 0 || opts.Argon2Memory != 0 || opts.Argon2Parallel != 0)
}

func isArgon2Type(kdfType string) bool {
	return kdfType == kdfTypeArgon2id || kdfType == kdfTypeArgon2i
}

// containerArgon2Cost returns the Argon2 cost of the first keyslot in scan
// order that carries a complete one, or nil.
//
// Scan order rather than map order, for the reason keyslotIDsInScanOrder
// exists: ranging the map would make the inherited cost depend on which entry
// Go happened to yield first, so two AddKey calls on one container could
// disagree.
func containerArgon2Cost(metadata *header.Metadata) *rawKDF {
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

// baseAddKeyFormatOptions maps the caller's AddKeyOptions onto FormatOptions,
// with this package's defaults for whatever the caller left unset.
//
// The KDF type resolves through resolveKDFType, so a caller that names none
// gets DefaultKDFSpec -- PBKDF2-SHA512 in FIPS mode, Argon2id otherwise (#237)
// -- unless it supplied an Argon2 cost, which selects Argon2id.
//
// HashAlgo is the caller's Hash when it gave one and otherwise the hash the
// resolved type names: "sha512" for "pbkdf2-sha512", and DefaultHashAlgo for a
// type that names none. It was DefaultHashAlgo unconditionally, and since
// HashAlgo overrides the hash a KDF alias names, that wrote every
// "pbkdf2-sha512" keyslot -- the FIPS-mode default among them -- as
// PBKDF2-SHA256.
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
	// Copied on the same "zero means unset" rule as PBKDFIterTime above, and
	// for the same reason: an out-of-range count must reach the refusal in
	// forcedPBKDF2Iterations rather than be dropped here, or AddKey and Format
	// would enforce different contracts for one parameter.
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
	// Validate inputs. An EXISTING credential is judged by what can open a
	// keyslot, not by the policy for new ones (#249, A7).
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

	// The passphrase must open a keyslot holding the VOLUME key, as cryptsetup
	// --test-passphrase requires: an unbound keyslot opening is not the
	// volume opening (#249, A1).
	masterKey, _, err := getVolumeKey(context.Background(), f, device, passphrase, metadata, sys)
	if err != nil {
		// Deliberately NOT "passphrase does not unlock any keyslot". That names
		// a verdict on the credential, and for a container with no usable
		// keyslot -- or one whose keyslot is too damaged to evaluate anything
		// -- no such verdict was ever reached. See #30.
		return &errs.Error{Kind: errs.KindOf(err, ErrWrongKey), Detail: "could not open " + device + " with this passphrase", Err: err}
	}
	// The key is recovered only to prove the passphrase opens a slot; it is
	// released immediately rather than at the end of a scope that does nothing
	// else with it.
	custody.Release(masterKey)

	return nil
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
func addKeyWithPolicy(ctx context.Context, device string, existingPassphrase, newPassphrase []byte, opts *addKeyOptionsForTest, policy keyslotCostPolicy, sys volumeSys) (int, error) {
	if err := addKeyPreflight(device, existingPassphrase, newPassphrase, opts); err != nil {
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

	// Unlock with the existing passphrase to get the VOLUME key. A credential
	// that opens only an unbound keyslot proves nothing about the volume and
	// would enroll another keyslot that decrypts nothing (#249, A1).
	masterKey, _, err := getVolumeKey(ctx, dev.reader(), device, existingPassphrase, metadata, sys)
	if err != nil {
		return -1, &errs.Error{Kind: errs.KindOf(err, ErrWrongKey), Detail: "failed to unlock with existing passphrase", Err: err}
	}
	defer custody.Release(masterKey)

	return addKeyslotWithMasterKey(ctx, dev, hdr, metadata, masterKey, newPassphrase, opts, policy)
}

// addKeyPreflight is every check addKeyWithPolicy makes before it takes the
// device lock. It is separate so that enrollWithToken (keyprovider.go), which
// must hold ONE lock across the keyslot and the token it writes, makes exactly
// the same checks rather than a copy of them.
func addKeyPreflight(device string, existingPassphrase, newPassphrase []byte, opts *addKeyOptionsForTest) error {
	// Validate inputs. The existing credential is judged by what can open a
	// keyslot -- a cryptsetup keyfile of up to 8 MiB, a short legacy
	// passphrase -- and the NEW one by the policy for credentials this package
	// creates (#249, A7).
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
		if err := refuseSHA1ForCreation(opts.KDFType, opts.Hash); err != nil {
			return err
		}
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
		return err
	}

	return nil
}

// addKeyslotWithMasterKey is the half of AddKey that runs once the volume key is
// in hand: it wraps masterKey under newPassphrase in a new keyslot, writes the
// key material, and commits the header. hdr and metadata are the container's
// current header, read under the device lock the CALLER holds, and are mutated
// into the state that is written.
//
// It is split out so an operation that already holds the lock and has already
// recovered the volume key -- MigrateToFIPS (fipsmigrate.go) -- adds its keyslot
// through the same code AddKey does rather than through a copy of it. The lock
// is not reentrant (flock on a second descriptor waits on the first), so that
// caller cannot go through AddKey itself without releasing the lock between its
// steps.
func addKeyslotWithMasterKey(ctx context.Context, dev *keyslotDevice, hdr *header.BinaryHeader, metadata *header.Metadata, masterKey *enclave.MemoryEnclave,
	newPassphrase []byte, opts *addKeyOptionsForTest, policy keyslotCostPolicy) (int, error) {
	return addKeyslotWithMasterKeyAndPriority(ctx, dev, hdr, metadata, masterKey, newPassphrase, opts, policy, nil)
}

// addKeyslotWithMasterKeyAndPriority is addKeyslotWithMasterKey, extended with
// an explicit on-disk priority for AddKeyslot (DESIGN.md §B.2): nil writes no
// priority member at all, same as every existing caller through
// addKeyslotWithMasterKey, and cryptsetup's own convention for a normal
// keyslot (see the no-priority-written comment below).
func addKeyslotWithMasterKeyAndPriority(ctx context.Context, dev *keyslotDevice, hdr *header.BinaryHeader, metadata *header.Metadata, masterKey *enclave.MemoryEnclave,
	newPassphrase []byte, opts *addKeyOptionsForTest, policy keyslotCostPolicy, priority *int) (int, error) {
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
	// LEGACY CONTAINERS are what forced the issue. Before this branch, Format wrote the container's DATA cipher into
	// the keyslot area -- so a volume created with, say,
	// `CipherMode: "cbc-essiv:sha256"` carries AES-XTS key material under an
	// "aes-cbc-essiv:sha256" label. Those volumes used to OPEN here, because the
	// read path consulted only the algorithm, and screening the template against
	// what this writer produces rejected every keyslot of every such container.
	//
	// #106 has since made the READ path honor the declared mode (owner ruling
	// 2026-09-25), so a mislabeled keyslot is now refused by getMasterKey above,
	// with ErrUnsupported, before this point is reached: it opens
	// nowhere, including here. What remains true is that a template's label has
	// nothing to contribute to a new keyslot.
	//
	// Writing the constant beats inheriting. The new keyslot declares what its
	// material actually is and no wrong label is propagated. Any other slot's
	// label is left alone rather than silently rewritten -- this call is
	// authoring one keyslot, not repairing someone else's.
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
	// the thing it has to match.
	//
	// The AREA key -- what the passphrase derives and AES-XTS wraps the
	// stripes with -- is the volume key's length when that keys AES-XTS, and
	// AES-256-XTS otherwise, as cryptsetup does: a volume key is whatever the
	// data cipher takes (16 bytes for 128-bit aes-cbc-essiv, 96 for
	// --integrity hmac-sha256), and that is not the keyslot cipher's concern.
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

	// main's extraction (#102), with THIS branch's key size. The size is the
	// recovered volume key's, not the template keyslot's -- see the derivation
	// above and #55; addKeyFormatOptions carries only the KDF choices, which are
	// genuinely the caller's.
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
		return -1, &errs.Error{Kind: ErrNoSpace, Detail: fmt.Sprintf("a new keyslot would end at offset %d but the container's keyslots area is %d..%d (config.keyslots_size %s); reformat with a larger keyslots area",
			newKeyslotsEnd, keyslotsStart, keyslotsEnd, metadata.Config.KeyslotsSize)}
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
			return -1, &errs.Error{Kind: ErrInvalidHeader, Detail: fmt.Sprintf("data segment %s declares an offset of %q, which is not a valid size, so the "+
				"bound protecting the encrypted data from a new keyslot cannot be computed",
				id, segment.Offset)}
		}
		if !dataOnAnotherDevice(segmentOffset) && newKeyslotsEnd > segmentOffset {
			return -1, &errs.Error{Kind: ErrNoSpace, Detail: fmt.Sprintf("a new keyslot would end at offset %d but the data segment starts at %d; reformat with a larger header",
				newKeyslotsEnd, segmentOffset)}
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
	newKeyslot := &header.Keyslot{
		Type:     "luks2",
		KeySize:  newKeySize,
		Priority: priority,
		Area: &header.KeyslotArea{
			Type:    "raw",
			KeySize: areaKeySize,
			Offset:  formatSize(newOffset),
			Size:    formatSize(alignedSize),
			// What this call actually encrypts the material with, stated
			// rather than copied from a neighbor. The material is encrypted
			// with areacipher.Default, which runs XTS; there is no other
			// truthful value here, and a wrong one is a keyslot only this
			// package can open -- with our own suite staying green, because
			// the read path discards the mode.
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

	// The new keyslot joins exactly the digest that attests the key it wraps.
	// It used to be appended to EVERY digest, which on a header carrying an
	// unbound key beside the volume key claimed the new keyslot for both keys:
	// cryptsetup refuses such a header outright ("header.Keyslot N is not assigned to
	// exactly 1 digest"), so adding a passphrase made the volume unreadable to
	// every other LUKS2 implementation.
	if digest := metadata.Digests[attestingDigest]; !slices.Contains(digest.Keyslots, slotIDStr) {
		digest.Keyslots = append(digest.Keyslots, slotIDStr)
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

	// THE HEADER THAT WILL NAME THE KEYSLOT IS CHECKED BEFORE THE MATERIAL IS
	// WRITTEN (#248). Every header write is held to cryptsetup's structural
	// rules, so a header carrying damage elsewhere -- a token naming a missing
	// keyslot, an out-of-area keyslot -- refuses the write below. Found only
	// then, the new keyslot's material would already sit in a free area: a
	// passphrase-wrapped copy of the volume key that nothing names and nothing
	// wipes. Asked first, the refusal costs nothing, and the metadata is put
	// back as it was for a caller that keeps using it.
	if err := checkHeaderWritable(hdr, metadata); err != nil {
		removeKeyslotFromMetadata(metadata, slotIDStr)
		return -1, err
	}

	// Increment sequence ID
	hdr.SequenceID++

	// Write the encrypted key material, padded to the aligned area, and make it
	// durable BEFORE the header names it. Through the device the caller locked
	// (#249, A10); for MigrateToFIPS's unpinned device that is still openDevice,
	// the seam its crash suite counts write steps through.
	if err := dev.writeArea(ctx, "write the keyslot area", newOffset, encryptedKeyMaterial, alignedSize); err != nil {
		return -1, err
	}

	// FROM HERE THE TRANSACTION RUNS TO ITS NEXT CONSISTENT STATE (DESIGN.md
	// §D.2). The caller's context was honored up to the first write; a
	// cancellation now would stop between the area write and the header write
	// and strand a passphrase-wrapped copy of the volume key in an area no
	// header names and nothing wipes. So the header write and the read-back
	// run regardless -- and a read-back failure still rolls the keyslot out.
	ctx = context.WithoutCancel(ctx)

	// Write updated headers
	if err := dev.writeHeader(ctx, hdr, metadata); err != nil {
		return -1, &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to write header", Err: err}
	}

	// PROVE IT OPENS, from the header as committed (#249, A3). AddKey used to
	// report success on the strength of having written something; a keyslot
	// whose parameters and material disagree -- the shape ChangeKey's stripe
	// count produced -- reported success the same way and opened nothing. The
	// new keyslot is read back through the header on the device and must
	// unwrap exactly the volume key it was written from. If it does not, it is
	// taken out again rather than left as a credential that silently fails.
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

	return changeKeyslotCore(ctx, dev, hdr, metadata, slotIDStr, keyslot, targetKeyslot, masterKey, newPassphrase)
}

// changeKeyslotCore is ChangeKey's write path, factored out so
// (*Volume).ChangeKeyslot can share it: everything ChangeKey does once it
// already holds the master key, keyed by keyslot/slotIDStr rather than
// re-deriving either. targetKeyslot is the container's own keyslot object
// (metadata.Keyslots[slotIDStr]), mutated and then written in place.
func changeKeyslotCore(ctx context.Context, dev *keyslotDevice, hdr *header.BinaryHeader, metadata *header.Metadata, slotIDStr string, keyslot int, targetKeyslot *header.Keyslot, masterKey *enclave.MemoryEnclave, newPassphrase []byte) error {
	// THE KEY MUST BE THIS VOLUME'S, established before anything is derived
	// or written -- the check AddKey makes. A key from another volume would
	// otherwise be wrapped, committed under the header and only caught by the
	// read-back below; a crash inside that window leaves the slot naming
	// material that unwraps to nothing this volume's digests accept.
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

	// The key that WRAPS the area is area.key_size long, which need not be the
	// volume key's length (cryptsetup --keyslot-key-size; #249, A6). It is
	// kept: a passphrase change re-wraps the same key under the same area
	// cipher, it does not re-choose either -- unless the area was CBC: the
	// new material is always wrapped with AES-XTS, so the rewritten keyslot
	// declares aes-xts-plain64, which is what its material is, with the area
	// key this package writes for that volume key (a CBC key of 16 to 32
	// bytes may not key XTS).
	areaKeySize := targetKeyslot.Area.KeySize
	areaEncryption := targetKeyslot.Area.Encryption
	if area, err := parseKeyslotAreaEncryption(areaEncryption); err != nil || !area.XTS() {
		areaEncryption = keyslotAreaEncryption
		areaKeySize = areacipher.WritableAreaKeySize(targetKeyslot.KeySize)
	}

	// The area this call will eventually ZERO is checked here, up front, against
	// the keyslots that must survive (#38). A keyslot's area can overlap
	// another's, and ChangeKey destroys an area exactly as a removal does -- so
	// on such a container it would take a healthy keyslot's key material with it.
	//
	// It is checked BEFORE anything is written, and before the new KDF is paid
	// for, rather than beside the wipe at the end, and the difference is the whole value of the check: by the time the
	// wipe runs the new passphrase is already live, so a refusal there would be a
	// half-completed operation reported as a failure. Refusing now costs nothing
	// -- the volume is untouched and both the old passphrase and the overlapping
	// keyslot still work.
	//
	// ChangeKey deliberately does NOT take the entry-level half of the removal
	// gate: changing the passphrase on a single-keyslot volume is exactly what
	// this function is for.
	//
	// And it must be KEYSLOT space at all (#249, A2): an old area declared over
	// the header or the payload is refused here, while refusing still costs
	// nothing.
	oldArea := originalArea
	if err := checkAreaConfined(hdr, metadata, slotIDStr, &oldArea); err != nil {
		return err
	}
	if err := checkKeyslotAreaDisjointFromOthers(dev, metadata, slotIDStr, &oldArea); err != nil {
		return err
	}

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
	formatOpts := formatOptionsForTest{
		KDFType:  kdfType,
		HashAlgo: defaultHashAlgo,
	}
	if targetKeyslot.KDF.Hash != "" {
		formatOpts.HashAlgo = targetKeyslot.KDF.Hash
	}
	// EXCEPT SHA-1, which is never written (#239). A PBKDF2-SHA1 keyslot -- a
	// converted LUKS1 one -- is rewritten as PBKDF2-SHA256, and its iteration
	// count is CONVERTED from what it cost, not copied: see
	// sha256IterationsForSHA1 for why a copied count can halve the work.
	rewritingSHA1 := strings.EqualFold(formatOpts.HashAlgo, "sha1")
	if rewritingSHA1 {
		formatOpts.HashAlgo = defaultHashAlgo
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
		if rewritingSHA1 {
			converted, err := sha256IterationsForSHA1(preserved, areaKeySize, dev.sys)
			if err != nil {
				return &errs.Error{Kind: errs.KindOf(err, errs.ErrInvalidArgument), Detail: "failed to carry the PBKDF2-SHA1 keyslot's cost over to PBKDF2-SHA256", Err: err}
			}
			preserved = converted
		}
		if floor := int(math.Ceil(pbkdf2IterationFloor(formatOpts.HashAlgo, pbkdf2ReferenceTargetMs))); preserved < floor {
			preserved = floor
		}
		formatOpts.PBKDFIterations = preserved
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

	// A keyslot read with SHA-1 anti-forensic hashing -- a converted LUKS1
	// keyslot -- is REWRITTEN with the default: this package reads SHA-1
	// keyslots and never writes one (#236). The area holds the same bytes
	// either way, keySize x stripes, so nothing else moves.
	if targetKeyslot.AF.Hash == "sha1" {
		targetKeyslot.AF.Hash = defaultHashAlgo
	}

	// Apply anti-forensic split to master key, with the stripe count LUKS2
	// writes -- and the keyslot is made to SAY so below. It used to split into
	// 4000 stripes and keep whatever af.stripes the keyslot declared, so a
	// foreign keyslot written with 2000 was rewritten as 4000 stripes of
	// material under a header that merges 2000: a keyslot that opens nothing,
	// and the old area wiped behind it (#249, A3).
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

	// The area the rewritten keyslot needs. It is at least the existing area's
	// size, so a keyslot never shrinks under a passphrase change, and LARGER
	// when the material outgrows it -- which a foreign keyslot with fewer
	// stripes than LUKS2 writes does, now that the stripes are rewritten as
	// 4000. Refusing there would make that keyslot's passphrase unchangeable.
	existingSize, err := parseSize(targetKeyslot.Area.Size)
	if err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrInvalidHeader), Detail: "failed to parse keyslot size", Err: err}
	}
	newSize := max(existingSize, alignTo(int64(len(encryptedKeyMaterial)), keyslotAreaAlignment))

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
	newOffset, err := findFreeKeyslotArea(hdr, metadata, newSize)
	if err != nil {
		return &errs.Error{Kind: ErrNoSpace, Detail: fmt.Sprintf("cannot rewrite keyslot %d safely (add a new key and remove this slot instead)", keyslot), Err: err}
	}

	// The header is proved writable and the metadata brought to its final state
	// BEFORE any device write, so a refusal costs nothing.
	targetKeyslot.KDF = kdf
	targetKeyslot.Area.Offset = formatSize(newOffset)
	targetKeyslot.Area.Size = formatSize(newSize)
	targetKeyslot.Area.KeySize = areaKeySize
	targetKeyslot.Area.Encryption = areaEncryption
	hdr.SequenceID++
	if err := checkHeaderWritable(hdr, metadata); err != nil {
		return err
	}

	// Write new encrypted key material into the free area, through the locked
	// descriptor, and make it durable. Nothing depends on these bytes until
	// the header points at them, so a failure here leaves the volume exactly
	// as it was. THE MATERIAL IS DURABLE BEFORE THE HEADER NAMES IT: reversing
	// the two would recreate the window in a new place, a header pointing at
	// an area whose contents had not reached the device.
	if err := dev.writeArea(ctx, "write the keyslot area", newOffset, encryptedKeyMaterial, newSize); err != nil {
		return err
	}

	// From here the rewrite runs to its next consistent state (DESIGN.md
	// §D.2), exactly as AddKey's does: the caller's context was honored up to
	// the first write, and a cancellation now would leave the new material in
	// an area no header names, or the old passphrase's material unwiped behind
	// a committed header.
	ctx = context.WithoutCancel(ctx)

	// The commit point. After this the new passphrase opens the volume.
	if err := dev.writeHeader(ctx, hdr, metadata); err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to write header", Err: err}
	}

	// PROVE IT, before anything old is destroyed (#249, A3). The keyslot is
	// read back through the header as committed and must unwrap exactly the
	// key the old one held. If it does not, the header is put back to the old
	// keyslot -- whose area has not been touched -- so the OLD passphrase
	// still opens the volume, and the operation reports the failure instead of
	// wiping the only working copy of the key.
	if err := verifyWrittenKeyslot(ctx, dev, slotIDStr, kdf, passphraseKey, masterKey); err != nil {
		return rollBackChangedKeyslot(ctx, dev, hdr, metadata, slotIDStr, &original, targetKeyslot, err)
	}

	// Only now is the old material destroyed. That the wipe is SAFE was
	// established before any of this began -- see the overlap check above -- so
	// what can fail here is I/O, not a refusal, and a failure leaves the volume
	// openable by the new passphrase with the old material still on the device.
	if err := wipeKeyslotArea(ctx, dev, hdr, metadata, slotIDStr, &original); err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: fmt.Sprintf("the new passphrase is live in keyslot %d, but the old key material could not be destroyed", keyslot), Err: err}
	}

	return nil
}

// removeKeyslotCore is (*Volume).RemoveKeyslot's write path, factored out so
// it can be reused by call sites that have already read the header.
func removeKeyslotCore(ctx context.Context, dev *keyslotDevice, hdr *header.BinaryHeader, metadata *header.Metadata, slotIDStr string, targetKeyslot *header.Keyslot) error {
	// THE GATE; see RemoveKey and checkKeyslotRemovable. With no passphrase it
	// is the ONLY thing standing between this call and the last volume key.
	if err := checkKeyslotRemovable(dev, hdr, metadata, slotIDStr); err != nil {
		return err
	}

	// NOTHING IS DESTROYED UNTIL THE RESULTING HEADER IS PROVED WRITABLE (#50).
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

		slots = append(slots, keyslotInfoFromEntry(id, ks))
	}

	return slots, nil
}

// keyslotInfoFromEntry builds the KeyslotInfo a listing or Enroll
// (provider.go) reports for one on-disk keyslot.
//
// AN ABSENT PRIORITY IS NORMAL (1), NOT IGNORE (0).
//
// This defaulted to 0 and that is the wrong end of the scale: LUKS2 gives
// priority the values 0 ignore, 1 normal, 2 prefer, and defines the member as
// OPTIONAL WITH A DEFAULT OF NORMAL. cryptsetup omits it for a normal keyslot
// -- MEASURED: `cryptsetup config --priority normal` deletes the member
// rather than writing 1 -- so essentially every keyslot in every
// cryptsetup-created container arrives here with no priority at all, and
// every one of them was being listed as "ignore": a slot an operator is told
// to skip, and that a priority-aware unlock would skip.
//
// It was already wrong for foreign containers before this package stopped
// emitting the default; now it would be wrong for our own too.
//
// kdf and area are OPTIONAL as far as this function is concerned. A luks2
// keyslot always has both and the header reader enforces that, but a
// "reencrypt" keyslot has no kdf at all, and listing keyslots is an
// inspection operation -- the one thing an operator does when a container is
// in a state nothing else can handle. It must report what is there rather
// than crash on what is not.
func keyslotInfoFromEntry(id int, ks *header.Keyslot) KeyslotInfo {
	priority := keyslotPriorityNormal
	if ks.Priority != nil {
		priority = *ks.Priority
	}

	info := KeyslotInfo{
		ID:       id,
		Type:     ks.Type,
		KeySize:  ks.KeySize,
		Priority: Priority(priority),
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

	// KDF reports the cost actually written, including an inherited Argon2
	// cost (was the AddKeyOptions.InheritedArgon2Cost out-parameter).
	//
	// It matters most where the costs on one volume DIFFER. ChangeKeyslot
	// preserves a slot's existing Argon2 memory cost even when it sits below
	// MinArgon2MemoryKB -- deliberately, because raising it would ask the
	// formatting hardware for RAM it may not have -- so a rotated slot can
	// legitimately read below what AddKeyslot would ever write. A zero
	// KDFParams.Type means the keyslot has no KDF at all (a "reencrypt"
	// keyslot in progress), not that the KDF failed to parse.
	KDF KDFParams
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
// guessed at; ErrWrongKey says what happened without saying why.
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
//
// # A FIPS refusal is not damage, and is not reported as damage
//
// In a FIPS 140-3 process an Argon2 keyslot -- cryptsetup's default -- cannot be
// tried at all, and neither can a keyslot whose only digests are refused. That
// used to surface as the first untried keyslot's error, "invalid keyslot:
// argon2id: algorithm not approved", which reads as corruption to anyone who
// does not know LUKS2 internals. When every keyslot that could not be tried was
// refused for exactly that reason, and none verified, the scan instead returns
// a FIPSImportRequiredError: it says the refusal is a policy one, names the
// keyslots and digests involved, and names MigrateToFIPS as the remedy.
func getMasterKey(device string, passphrase []byte, metadata *header.Metadata, sys volumeSys) (*enclave.MemoryEnclave, error) {
	f, err := openDevice("read the keyslot area", device, os.O_RDONLY, sys)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	masterKey, _, err := getMasterKeySlot(context.Background(), f, device, passphrase, metadata, volumeKeyScanOrder(metadata), sys)
	return masterKey, err
}

// getVolumeKey is the keyslot scan for an operation that needs the VOLUME key
// -- the key the data segments are encrypted with -- rather than whatever key
// the passphrase happens to open (#249, A1; Lane C's C1 is the same question for
// Unlock).
//
// A LUKS2 header may carry unbound keys (`cryptsetup luksAddKey --unbound`).
// One the same passphrase opens is a perfectly good keyslot and no evidence at
// all about the volume: AddKey would wrap it into a new keyslot that decrypts
// nothing, and KillSlot would accept it as authority to destroy a keyslot that
// does. cryptsetup scans only the keyslots assigned to the segment it acts on,
// and so does this.
//
// It is enforced twice, statically and on the key:
//
//   - only keyslots keyslotBoundToDataSegments declares bound are tried, and
//   - they are verified against only the digests that bind every data segment
//     (volumeKeyDigestsView), so a key that verifies IS one a digest attests
//     for the data -- with no derivation beyond the scan's own.
//
// A passphrase that opens only an unbound keyslot is therefore reported exactly
// as cryptsetup reports it, as a credential that opens nothing here:
// ErrWrongKey.
func getVolumeKey(ctx context.Context, f io.ReaderAt, device string, passphrase []byte, metadata *header.Metadata, sys volumeSys) (*enclave.MemoryEnclave, string, error) {
	var order []string
	for _, id := range keyslotIDsInScanOrder(metadata.Keyslots) {
		if keyslotBoundToDataSegments(metadata, id) {
			order = append(order, id)
		}
	}
	if len(order) == 0 {
		if len(metadata.Keyslots) == 0 {
			return nil, "", &errs.Error{Kind: ErrNoKeyslots, Detail: "the header declares no keyslots"}
		}
		return nil, "", &errs.Error{Kind: ErrNoKeyslots, Detail: fmt.Sprintf(
			"none of the header's %d keyslot(s) is attested by a digest binding every data segment (%s), so none holds the volume key",
			len(metadata.Keyslots), strings.Join(dataSegmentIDs(metadata), ", "))}
	}
	return getMasterKeySlot(ctx, f, device, passphrase, volumeKeyDigestsView(metadata), order, sys)
}

// getMasterKeySlot is getMasterKey with the scan order supplied by the caller
// and the id of the keyslot that opened reported back. order must name keyslots
// of metadata; getMasterKey passes volumeKeyScanOrder, and MigrateToFIPS
// passes the same order with FIPS-approved keyslots moved to the front so a
// credential that already has an approved keyslot is found there first, without
// running Argon2.
func getMasterKeySlot(ctx context.Context, dev io.ReaderAt, device string, passphrase []byte, metadata *header.Metadata, order []string, sys volumeSys) (*enclave.MemoryEnclave, string, error) {
	// The whole scan is priced before its first derivation (#26): a header
	// that would have it derive more than any cryptsetup header can, or hold
	// more locked memory than the allocator could ever admit, is refused here
	// rather than after the work.
	if err := checkKDFBudget("open a keyslot", planKeyslotScan(metadata, order)); err != nil {
		return nil, "", err
	}

	// The first reason a keyslot could not be TRIED, kept in case nothing
	// verifies. The first rather than the last, because scan order is
	// deterministic and the lowest-numbered damaged slot is the one an operator
	// will look at first.
	var untried error

	// How many keyslots the scan actually reached the unlock with. Counted
	// rather than derived from len(metadata.Keyslots), which counts entries the
	// unlock path skips.
	tried := 0

	// fipsBlocked names the keyslots that could not be tried ONLY because this
	// process runs in FIPS 140-3 mode; otherBlocked records whether anything
	// could not be tried for any other reason. The typed FIPS error is returned
	// only when the first is non-empty and the second is false, so a volume that
	// is also damaged is still reported as damaged.
	var fipsBlocked []string
	otherBlocked := false

	for _, id := range order {
		// Checked between keyslots in a scan (DESIGN.md §D.2): a cancellation
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
		if _, ok := canonicalKeyslotID(id); !ok {
			continue
		}
		tried++

		// Its area must be keyslot space before a byte of it is read: inside
		// the keyslots area and clear of the header copies and every data
		// segment (#249, A2). cryptsetup refuses such a header outright; here
		// it costs that keyslot and nothing else.
		masterKey, err := func() (*enclave.MemoryEnclave, error) {
			if err := checkKeyslotAreaConfinedByMetadata(metadata, id); err != nil {
				return nil, &errs.Error{Kind: ErrKeyslotNotFound, Detail: fmt.Sprintf("luks2 keyslot %q: declares an area outside keyslot space", id), Err: err}
			}
			return unlockKeyslotFrom(ctx, dev, id, passphrase, keyslot, metadata.Digests, sys)
		}()
		if err == nil {
			return masterKey, id, nil
		}

		// Protected memory is FAIL-CLOSED, so this aborts rather than moving on:
		// every remaining keyslot needs the same locked pages and would fail the
		// same way, and continuing would bury an operator-fixable RLIMIT_MEMLOCK
		// condition under a credential verdict.
		if errors.Is(err, ErrProtectedMemory) {
			return nil, "", err
		}

		if errors.Is(err, ErrWrongKey) {
			// Tried, and did not verify. Try the next keyslot.
			continue
		}

		if keyslotRefusedByFIPS(id, keyslot, metadata.Digests, sys.fipsMode) {
			fipsBlocked = append(fipsBlocked, id)
		} else {
			otherBlocked = true
		}

		if untried == nil {
			untried = &errs.Error{Kind: errs.KindOf(err, errs.ErrInvalidHeader), Detail: "keyslot " + id + " could not be tried", Err: err}
		}
	}

	if len(fipsBlocked) > 0 && !otherBlocked {
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

// digestAttestingKey returns the id of the digest a keyslot wrapping masterKey
// must be assigned to: the digests masterKey actually matches, evaluated in
// sorted id order, preferring one that binds data segments over an unbound one.
// LUKS2 assigns every keyslot to exactly one digest, and the key the keyslot
// holds is what decides which -- not which digests happen to exist.
//
// Matching no digest is refused rather than guessed: the key came from a
// keyslot a digest just verified, so no match means the header changed under
// the caller or the key is not the one it claims to be, and a keyslot joined to
// a digest its key does not satisfy never opens.
func digestAttestingKey(metadata *header.Metadata, masterKey *enclave.MemoryEnclave) (string, error) {
	// A digest binding EVERY data segment is preferred to one binding some of
	// them, and either to an unbound one (#249): the keyslot joins the digest
	// that makes it a volume-key credential whenever the key has one, not a
	// stale or partial one that happens to sort first.
	full := volumeKeyDigestsView(metadata).Digests
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
func keyslotsAreaBounds(hdr *header.BinaryHeader, metadata *header.Metadata) (int64, int64, error) {
	area, err := headerAreaSize(hdr)
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

// calculateNextKeyslotOffset calculates the offset for the next keyslot area.
//
// keyslotsStart is where the container's keyslots area begins -- see
// keyslotsAreaBounds. It is a parameter rather than a constant because it is a
// property of the container, not of this library.
func calculateNextKeyslotOffset(metadata *header.Metadata, keyslotsStart int64) (int64, error) {
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

// wipeKeyslotArea securely wipes a keyslot area.
//
// It screens the keyslot itself because KillKeyslot reaches it with NO
// passphrase and therefore never passes through unlockKeyslot's check. That
// makes this the one path where a crafted keyslot's declared offset and size
// decide where zeros get written, and where a missing area object dereferences
// nil.
func wipeKeyslotArea(ctx context.Context, dev *keyslotDevice, hdr *header.BinaryHeader, metadata *header.Metadata, id string, keyslot *header.Keyslot) error {
	if err := validateKeyslot(id, keyslot); err != nil {
		return err
	}

	// The bytes about to be overwritten must be KEYSLOT bytes (#249, A2). The
	// gate checked this already; it is checked again here, at the write,
	// because this is the function that decides where random lands and a wipe
	// must not depend on every caller having remembered.
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

	// OVERWRITTEN WITH RANDOM, NOT ZEROED.
	//
	// Both destroy the key material equally well -- that is not what is at
	// stake. What differs is what the destroyed area then LOOKS LIKE. A live
	// keyslot's area holds AF-split material under a passphrase-derived key,
	// which is indistinguishable from random; a zeroed area is
	// distinguishable from every one of them at a glance. So zeroing published
	// the one fact the removal was meant to end: that a key USED to be here and
	// was revoked.
	//
	// cryptsetup leaves a freed area random for this reason, and Format now
	// fills the whole unallocated keyslots region the same way (format.go), so
	// a slot that was never used and a slot that was destroyed are
	// indistinguishable from each other as well as from a live one.
	//
	// In fixed-size chunks: size came out of a header this process did not
	// write, and even bounded there is no reason to let it choose an
	// allocation.
	if err := writeRandom(ctx, f, size, dev.sys.cryptoRand); err != nil {
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
func removeKeyslotFromMetadata(metadata *header.Metadata, id string) {
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
func usableKeyslotsAfterRemoving(f *os.File, hdr *header.BinaryHeader, metadata *header.Metadata, id string, measureDeviceSize func(*os.File) (int64, error)) int {
	remaining := 0
	for _, other := range keyslotIDsInScanOrder(metadata.Keyslots) {
		if other == id {
			continue
		}
		if keyslotCanOpenVolume(f, hdr, metadata, other, measureDeviceSize) {
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
func keyslotAreaDisjointFrom(f *os.File, metadata *header.Metadata, id string, area *header.KeyslotArea, measureDeviceSize func(*os.File) (int64, error)) error {
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
		// The protected set is every keyslot holding key material some
		// passphrase opens -- bound to the data OR NOT. It is deliberately
		// wider than the last-keyslot guard's survivors: an unbound key is not
		// a volume key, but it is still somebody's key, and a wipe aimed at a
		// different keyslot has no business destroying it. Protecting more is
		// the safe direction here; see keyslotHoldsKeyMaterial.
		if !keyslotHoldsKeyMaterial(f, other, survivor, metadata.Digests, measureDeviceSize) {
			continue
		}

		// keyslotHoldsKeyMaterial has already required these to parse and to be
		// non-negative and non-overflowing (validateKeyslot); the error is
		// consumed rather than ignored so that a future loosening of the
		// predicate cannot silently skip a survivor.
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
func checkKeyslotAreaDisjointFromOthers(dev *keyslotDevice, metadata *header.Metadata, id string, area *header.KeyslotArea) error {
	return keyslotAreaDisjointFrom(dev.file, metadata, id, area, dev.sys.measureDeviceSize)
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
func findFreeKeyslotArea(hdr *header.BinaryHeader, metadata *header.Metadata, size int64) (int64, error) {
	if size <= 0 {
		return 0, &errs.Error{Kind: ErrInvalidArgument, Detail: fmt.Sprintf("a keyslot area of %d bytes", size)}
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
		// A non-positive size is a DECLARED empty extent rather than an
		// unreadable one: it parsed, and it occupies nothing to avoid.
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
func checkKeyslotRemovable(dev *keyslotDevice, hdr *header.BinaryHeader, metadata *header.Metadata, id string) error {
	// The bytes this removal will overwrite must be keyslot bytes (#249, A2):
	// inside the keyslots area and clear of the header copies and every data
	// segment. Asked FIRST, because it is a question about the target alone.
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

// verifyWrittenKeyslot proves that keyslot id, as the header on the device now
// describes it, opens to exactly want (#249, A3).
//
// It reads the header BACK rather than trusting the metadata in hand: what
// matters is what the next unlock will see, and that is the committed header.
// The keyslot is then put through the unlock path itself -- screenKeyslot, and
// recoverKeyslotKey's read, decrypt, merge and digest verification -- with one
// difference: the area key is the one the writer derived, not a second
// derivation of the passphrase. That is sound because a KDF is deterministic:
// the header is required to carry exactly the KDF the area key was derived
// under, so the next unlock derives the same key. It is also what keeps the
// read-back from doubling the cost of every keyslot this package writes.
func verifyWrittenKeyslot(ctx context.Context, dev *keyslotDevice, id string, kdf *rawKDF, areaKey, want *enclave.MemoryEnclave) error {
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
func sameKDF(a, b *rawKDF) bool {
	if a == nil || b == nil {
		return false
	}
	eq := func(x, y *int) bool { return (x == nil && y == nil) || (x != nil && y != nil && *x == *y) }
	return a.Type == b.Type && a.Hash == b.Hash && a.Salt == b.Salt &&
		eq(a.Iterations, b.Iterations) && eq(a.Time, b.Time) && eq(a.Memory, b.Memory) && eq(a.CPUs, b.CPUs)
}

// sameSecret compares two keys held in protected memory, in constant time,
// without copying either out.
func sameSecret(a, b *enclave.MemoryEnclave) bool {
	if a == nil || b == nil || a.Size() != b.Size() {
		return false
	}
	equal := false
	if err := secret.Borrow("compare keys", a, func(raw []byte) error {
		equal = b.EqualTo(raw)
		return nil
	}); err != nil {
		return false
	}
	return equal
}

// rollBackAddedKeyslot takes keyslot id back out of the header after it was
// written and could not be proved to open, and destroys its area: the material
// there wraps the volume key under the new passphrase, and a keyslot nothing
// names must not be left holding it. cause is why; the result always carries
// it, and names a rollback that did not complete so an operator knows what is
// on the device.
// rollBackAddedKeyslot runs under context.WithoutCancel(ctx): a keyslot
// already written must be taken back out whether or not the ctx that started
// the operation is still live, the same rule DESIGN.md §D.2 states for dm
// rollback after a failed or canceled Activate.
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

// rollBackChangedKeyslot restores keyslot id to original after ChangeKey's
// rewrite could not be proved to open. original's area was never touched, so
// the restored header opens the volume with the OLD passphrase exactly as
// before; the rewritten area is then destroyed. cause is why.
// rollBackChangedKeyslot runs under context.WithoutCancel(ctx); see
// rollBackAddedKeyslot.
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

// areaOfKeyslot returns a keyslot's area, or nil if it has none. It exists so
// the removal gate can ask about "the area this keyslot occupies" without a nil
// dereference on a keyslot that declares no area at all -- which is a shape the
// wipe paths refuse downstream, in a message about the geometry.
func areaOfKeyslot(keyslot *header.Keyslot) *header.KeyslotArea {
	if keyslot == nil {
		return nil
	}
	return keyslot.Area
}
