// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/internal/kdf"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// Common errors that can be checked using errors.Is()
var (
	// ErrInvalidHeader indicates a LUKS header is invalid or corrupted
	ErrInvalidHeader = errs.ErrInvalidHeader

	// ErrInvalidArgument indicates a caller-supplied argument this package
	// refuses: out of range, malformed, or structurally wrong for the call.
	// Defined once, in internal/errs, and re-exported by value.
	ErrInvalidArgument = errs.ErrInvalidArgument

	// ErrInvalidCredential indicates a credential refused before any comparison: too short, too long, or empty.
	ErrInvalidCredential = errs.ErrInvalidCredential

	// ErrIO indicates a read, write or other I/O failure that is not itself
	// classified (not found, not permitted, in use, ...).
	ErrIO = errs.ErrIO

	// ErrUnsupported indicates an algorithm, cipher, KDF, hash, checksum or layout this package does not implement, or a device it cannot read past the page cache.
	ErrUnsupported = device.ErrUnsupported

	// ErrNoSpace indicates no room for a new keyslot, metadata or token; the area is fixed at format time.
	ErrNoSpace = errors.New("luks2: no space")

	// ErrDeviceNotFound indicates the device path doesn't exist. Defined
	// once, in internal/device, and re-exported by value.
	ErrDeviceNotFound = device.ErrNotFound

	// ErrKeyslotNotFound indicates the keyslot is invalid or unavailable
	ErrKeyslotNotFound = errs.ErrInvalidKeyslot

	// ErrUnsupportedRequirement indicates an unimplemented mandatory requirement: the container is readable but must not be modified.
	ErrUnsupportedRequirement = header.ErrUnsupportedRequirement

	// ErrNoKeyslots indicates no valid keyslots are available, distinct from ErrWrongKey: no credential was tried.
	ErrNoKeyslots = errors.New("luks2: no valid keyslots")

	// ErrInvalidSize folded into ErrInvalidArgument: a
	// size parameter -- key, sector, metadata or otherwise -- is invalid,
	// with Detail naming which one and the accepted range.

	// ErrPermissionDenied indicates the process lacks access to the device; it wraps the *fs.PathError, so os.ErrPermission still matches.
	ErrPermissionDenied = device.ErrPermissionDenied

	// ErrWrongKey indicates a key was compared against at least one digest and matched none; one value for every cause, so nothing leaks.
	ErrWrongKey = errors.New("luks2: master key verification failed")

	// ErrLastKeyslot indicates a removal was refused because no keyslot that can yield the master key would remain.
	ErrLastKeyslot = errors.New("luks2: removal would leave no keyslot that can open the volume")

	// ErrKeyslotAreaOverlap indicates a removal was refused because its wipe would zero another usable keyslot's material.
	ErrKeyslotAreaOverlap = errors.New("luks2: keyslot area overlaps a keyslot that can still open the volume")

	// ErrFIPSNotApproved indicates the requested algorithm is not approved by
	// the Go Cryptographic Module and is refused while the process runs in
	// FIPS 140-3 mode. See docs/fips/engineering.md.
	ErrFIPSNotApproved = fips.ErrNotApproved

	// ErrFIPSImportRequired indicates a FIPS process met an intact volume whose KDF FIPS cannot execute; MigrateToFIPS from a non-FIPS process is the remedy.
	ErrFIPSImportRequired = errors.New("luks2: volume must be imported for FIPS 140-3 mode before a FIPS process can open it")

	// ErrFIPSMigration matches every FIPSMigrationError; Stage and MigrationStage say which stage failed.
	ErrFIPSMigration = errors.New("luks2: FIPS 140-3 migration failed")

	// errFIPSMigrationUnderFIPS indicates MigrateToFIPS was called in a FIPS 140-3 process; refused before the device is touched.
	errFIPSMigrationUnderFIPS = errors.New("the FIPS import must run in a process that is not in FIPS 140-3 mode")

	// errFIPSMigrationDigest indicates a non-approved digest that could not be evaluated or does not attest the recovered key; nothing is written.
	errFIPSMigrationDigest = errors.New("a digest that is not FIPS-approved does not attest the recovered volume key and cannot be migrated")

	// errFIPSMigrationVerification indicates MigrateToFIPS could not confirm its outcome through approved paths alone.
	errFIPSMigrationVerification = errors.New("the FIPS import could not verify that the volume opens through FIPS-approved KDFs only")

	// errFIPSMigrationUnboundKey indicates the passphrase does not open a keyslot holding the data segments' volume key; nothing is written.
	errFIPSMigrationUnboundKey = errors.New("the passphrase does not open a keyslot holding the key the data segments are encrypted with")

	// ErrDeviceCacheStale indicates bytes read through the page cache differ from the same bytes read past it.
	ErrDeviceCacheStale = device.ErrCacheStale

	// ErrKDFCalibration indicates a new keyslot's PBKDF2 count could not be calibrated and no keyslot was created; never a default.
	ErrKDFCalibration = kdf.ErrKDFCalibration

	// ErrPBKDFIterationsTooLow and ErrPBKDFIterationsTooHigh folded into
	// ErrInvalidArgument: a PBKDF2 iteration count outside
	// the floor-to-ceiling range is *KDFCostError, which Is ErrInvalidArgument.

	// ErrDeviceChanged indicates a device path resolved to a different file on reopen than when it was locked.
	ErrDeviceChanged = device.ErrChanged

	// ErrProtectedMemory indicates key material could not be placed in or read from protected memory (usually RLIMIT_MEMLOCK), so the operation was refused.
	ErrProtectedMemory = secret.ErrProtectedMemory

	// ErrNotLockedMemory indicates a handle reports a backend other than go-enclave locked memory; refused before it is read, not destroyed.
	ErrNotLockedMemory = secret.ErrNotLockedMemory

	// ErrLockContended indicates the device lock was held by another holder for the whole wait budget; retrying later is reasonable.
	ErrLockContended = device.ErrLockContended

	// ErrMetadataLockUnavailable indicates cryptsetup's lock directory (/run/cryptsetup) is missing, unusable or inaccessible; nothing was read or written.
	ErrMetadataLockUnavailable = device.ErrMetadataLockUnavailable
)

// Error is the module's one error shape, aliased so callers can use errors.As without importing internal/errs.
type Error = errs.Error

// A keyslot the unlock path refuses is an *errs.Error with Kind ErrKeyslotNotFound and Detail naming it.

// LockTimeoutError reports a device lock not taken within the wait budget, with the fields an operator needs.
type LockTimeoutError = device.LockTimeoutError

// NotLockedMemoryError is the reason behind ErrNotLockedMemory: Backend is the name the refused handle reported.
type NotLockedMemoryError = secret.NotLockedMemoryError

// An unlock refusal is an *errs.Error whose Kind is the classifying cause, if any, and whose Detail never carries key or passphrase content.

// KDFCalibrationError reports that BenchmarkPBKDF2 could not determine a count: an unusable budget, or a clock that does not advance.
type KDFCalibrationError = kdf.CalibrationError

// KDFCostError reports a refused Argon2 or PBKDF2 cost with the permitted range; always ErrInvalidArgument.
type KDFCostError struct {
	// Param is the cost that was refused: "memory", "time", "parallelism" or
	// "pbkdf2 iterations".
	Param string

	// Value is what the caller asked for. Argon2 memory is in KiB.
	Value int

	// Min is the smallest value that would have been accepted.
	Min int

	// Max is the largest value that would have been accepted: the ceiling
	// the read path applies, so a keyslot is never written that cannot be
	// opened. Zero when no ceiling was stated.
	Max int
}

func (e *KDFCostError) Error() string {
	if e.Max > 0 {
		return fmt.Sprintf("%s: requested %s %d, permitted range %d..%d", ErrInvalidArgument.Error(), e.Param, e.Value, e.Min, e.Max)
	}
	return fmt.Sprintf("%s: requested %s %d, minimum %d", ErrInvalidArgument.Error(), e.Param, e.Value, e.Min)
}

// Is reports every KDFCostError as ErrInvalidArgument, in the idiom of
// ErrProtectedMemory.
func (e *KDFCostError) Is(target error) bool {
	return target == ErrInvalidArgument
}

// NonApprovedKDF names one keyslot or digest whose KDF FIPS 140-3 mode cannot
// execute. ID is the header's own key for the object; Type and Hash are its KDF
// as declared ("argon2id" and "", or "pbkdf2" and "sha1").
type NonApprovedKDF struct {
	ID   int
	Type string
	Hash string

	// Reason is set when strict FIPS refuses a parameter or anti-forensic hash rather than the KDF algorithm itself.
	Reason string
}

// String renders the KDF the way an operator would name it: "argon2id",
// "pbkdf2-sha1", "pbkdf2-sha256 (salt shorter than 128 bits)".
func (k NonApprovedKDF) String() string {
	name := k.Type
	if k.Hash != "" {
		name += "-" + k.Hash
	}
	if k.Reason != "" {
		name += " (" + k.Reason + ")"
	}
	return name
}

// FIPSImportRequiredError is what a FIPS process gets for an intact volume whose KDF FIPS cannot execute; it matches ErrFIPSImportRequired and ErrFIPSNotApproved.
type FIPSImportRequiredError struct {
	// Device is the volume that was being opened.
	Device string

	// Keyslots are the keyslots whose own KDF is not approved.
	Keyslots []NonApprovedKDF

	// Digests are the digests attesting the refused keyslots whose KDF is not
	// approved. A volume can need these migrated even when every keyslot is
	// already PBKDF2, and the failure looks identical from outside.
	Digests []NonApprovedKDF
}

func (e *FIPSImportRequiredError) Error() string {
	var uses []string
	for _, k := range e.Keyslots {
		uses = append(uses, fmt.Sprintf("keyslot %d uses %s", k.ID, k))
	}
	for _, d := range e.Digests {
		uses = append(uses, fmt.Sprintf("digest %d uses %s", d.ID, d))
	}
	return fmt.Sprintf("%s: %s is intact, but this process runs in FIPS 140-3 mode and %s, which FIPS mode cannot execute; "+
		"no key was derived through them, so this is not a verdict on the volume or on the passphrase; "+
		"import it once with MigrateToFIPS from a process that is NOT in FIPS mode -- it rewraps the existing volume key "+
		"under PBKDF2 without re-encrypting any data -- and this process can then open it",
		ErrFIPSImportRequired.Error(), e.Device, strings.Join(uses, " and "))
}

// Unwrap reports a match for ErrFIPSImportRequired and ErrFIPSNotApproved.
func (e *FIPSImportRequiredError) Unwrap() []error {
	return []error{ErrFIPSImportRequired, ErrFIPSNotApproved}
}

// FIPSMigrationError reports an incomplete MigrateToFIPS: the stage, the cause, and the openable state the volume was left in.
type FIPSMigrationError struct {
	// Device is the volume being migrated.
	Device string

	// Stage is the step that failed: "precondition", "unlock", "plan",
	// "sync", "reconcile header copies", "add keyslot", "migrate digest",
	// "verify", "remove keyslot" or "final check".
	Stage string

	// State describes the volume as the failure left it.
	State string

	// Err is the cause, reachable through Unwrap.
	Err error
}

// Error renders the stage, the cause and the state.
func (e *FIPSMigrationError) Error() string {
	return fmt.Sprintf("at %s: %s; %s", e.Stage, strings.TrimPrefix(fmt.Sprint(e.Err), "luks2: "), e.State)
}

// Unwrap reports a FIPSMigrationError as both ErrFIPSMigration and the original failure.
func (e *FIPSMigrationError) Unwrap() []error { return []error{ErrFIPSMigration, e.Err} }

// MigrationStage maps e.Stage onto one of the five FIPSMigrationStage phases; an unrecognized Stage is StagePreflight.
func (e *FIPSMigrationError) MigrationStage() FIPSMigrationStage {
	switch e.Stage {
	case "unlock", "plan", "verify":
		return StageVerify
	case "reconcile header copies", "add keyslot", "migrate digest":
		return StageWrite
	case "remove keyslot":
		return StageRemove
	case "final check":
		return StageVerifyWritten
	default: // "precondition", "sync", and anything unrecognized
		return StagePreflight
	}
}

// unsupportedRequirementDetail returns the requirement and mandatory set an ErrUnsupportedRequirement error names; ok is false otherwise.
func unsupportedRequirementDetail(err error) (detail string, ok bool) {
	var req *header.UnsupportedRequirementError
	if !errors.As(err, &req) {
		return "", false
	}
	return fmt.Sprintf("the container declares the mandatory requirement %q, which this package does not implement (mandatory: %s)",
		req.Requirement, strings.Join(req.Mandatory, ", ")), true
}

// Out-of-range caller input is ErrInvalidArgument (or ErrInvalidCredential for a credential), with Detail naming the value.

// Format refuses an unwritable cipher combination as ErrUnsupported, and an oversized label or undersized device as ErrInvalidArgument.

// Wipe refusals.
var (
	// ErrDeviceInUse indicates a destructive operation refused a block device something else holds.
	ErrDeviceInUse = device.ErrInUse
)

// Recovery-key generation refusals are ErrInvalidArgument, with Detail naming the value.

// The causes a KDFCalibrationError carries.
var (
	// errCalibrationTargetInvalid is the cause reported when the requested
	// iteration time is not a usable number of milliseconds. The rejected value
	// itself is carried on the KDFCalibrationError.
	errCalibrationTargetInvalid = kdf.ErrCalibrationTargetInvalid

	// errCalibrationImmeasurable is the cause reported when no probe up to the
	// ceiling ran long enough to be timed.
	errCalibrationImmeasurable = kdf.ErrCalibrationImmeasurable
)

// The external-key sentinels raised by Volume.Enroll, Volume.UnlockWithProvider and importTokenLocked.
var (
	// ErrKeyProvider is matched only by an OrphanedKeyslotError, alongside ErrOrphanedKeyslot.
	ErrKeyProvider = errors.New("luks2: external key provider")

	// ErrNoKeyProvider folded into ErrInvalidArgument: an
	// operation was given no provider, or a token with nothing in it to
	// build one from.

	// ErrOrphanedKeyslot indicates a credential's keyslot was written, its token was not, and the keyslot could not be removed; it needs a human.
	ErrOrphanedKeyslot = errors.New("luks2: orphaned keyslot")
)

// ErrPrimaryHeaderCurrent indicates RestorePrimaryHeader was refused because
// the primary header copy is intact and at least as new as the secondary, so
// restoring would roll the volume back rather than repair it.
var ErrPrimaryHeaderCurrent = header.ErrPrimaryHeaderCurrent

// ErrTokenNotFound indicates the token was not found
var ErrTokenNotFound = errors.New("luks2: token not found")

// ErrNoFreeTokenSlot folded into ErrNoSpace: no free
// token slots are available.

// The following are sentinels the Volume API raises itself.
var (
	// ErrReadOnly indicates a mutating method was called on a Volume opened
	// with WithReadOnly.
	ErrReadOnly = errors.New("luks2: the volume was opened read-only")

	// ErrClosed indicates a method was called on a Volume after Close.
	ErrClosed = errors.New("luks2: the volume is closed")

	// ErrNotLUKS2 indicates a LUKS header whose version is not 2, not damage.
	ErrNotLUKS2 = header.ErrUnsupportedLUKSVersion
)
