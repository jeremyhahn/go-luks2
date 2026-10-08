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
	// Defined once, in internal/errs, and re-exported by value (§C.3).
	ErrInvalidArgument = errs.ErrInvalidArgument

	// ErrInvalidCredential indicates a caller-supplied passphrase, recovery
	// key or other credential this package refuses before it is ever
	// compared against a keyslot: too short, too long, or empty. It is
	// distinct from ErrWrongKey, which is a comparison that ran and matched
	// nothing.
	ErrInvalidCredential = errs.ErrInvalidCredential

	// ErrIO indicates a read, write or other I/O failure that is not itself
	// classified (not found, not permitted, in use, ...).
	ErrIO = errs.ErrIO

	// ErrUnsupported indicates a header, or a caller's options, names an
	// algorithm, cipher, KDF, hash, checksum or segment layout this package
	// does not implement for that use, or a device that cannot be read past
	// the page cache. It has no single owner below the public API --
	// internal/kdf, internal/header, internal/device and this package's own
	// area-cipher and segment checks each refuse a different kind of "not
	// implemented" -- so, like ErrInvalidArgument, it is this package's one
	// name for all of them (§C.3). Defined once, in internal/device, and
	// re-exported by value, exactly as the device-level sentinels below are.
	// A FIPS-refused algorithm is NOT this error -- that is
	// ErrFIPSNotApproved, because the algorithm is implemented and the mode
	// refuses it, which is a different thing for an operator to be told.
	ErrUnsupported = device.ErrUnsupported

	// ErrNoSpace indicates a container has no room left for what was asked
	// of it: a new keyslot outside the keyslots area, metadata that does not
	// fit the header area it was formatted with, or a token with no free
	// slot. The area is fixed at format time in every case, so this is a
	// refusal rather than a retryable condition.
	ErrNoSpace = errors.New("luks2: no space")

	// ErrDeviceNotFound indicates the device path doesn't exist. Defined
	// once, in internal/device, and re-exported by value.
	ErrDeviceNotFound = device.ErrNotFound

	// ErrVolumeAlreadyUnlocked moved to pkg/dmcrypt.ErrActive (#268):
	// adopting an in-use mapping name was Unlock's refusal, and Unlock is
	// pkg/dmcrypt.Activate now.

	// ErrUnsupportedKDF and ErrUnsupportedHash folded into ErrUnsupported
	// (DESIGN.md §C.3): raised where a KDF is DISPATCHED (kdf.go) or a hash
	// algorithm is resolved, with Detail naming what was refused.
	// header.ValidateKDFCost deliberately returns an unclassified error for the
	// same KDF condition, because only its caller knows whether an unusable
	// KDF condemns a keyslot or a digest.

	// ErrKeyslotNotFound indicates the keyslot is invalid or unavailable
	ErrKeyslotNotFound = errs.ErrInvalidKeyslot

	// ErrUnsupportedKeyslotCipher folded into ErrUnsupported (DESIGN.md
	// §C.3): a keyslot's area.encryption names a cipher spec -- algorithm,
	// mode AND IV generator -- this package cannot decrypt. The read path
	// honors the whole spec rather than only its algorithm (#106): a
	// keyslot declaring "aes-cbc-essiv:sha256" is refused here, never
	// decrypted as AES-XTS. A keyslot refused with it is also
	// ErrKeyslotNotFound, so the keyslot scan moves on to the next one.

	// ErrUnsupportedRequirement indicates the container declares a mandatory
	// requirement this package does not implement, so it must not be modified.
	// The container is still READABLE -- see Requirements (types.go).
	ErrUnsupportedRequirement = header.ErrUnsupportedRequirement

	// ErrNoKeyslots indicates no valid keyslots are available.
	//
	// It is deliberately distinct from ErrWrongKey: #30 is exactly the bug
	// that collapsing them would reintroduce. A container with no usable
	// keyslot and a container whose keyslot rejected a real passphrase are
	// different failures an operator acts on differently -- one says
	// retype nothing, the credential was never tried; the other says the
	// credential was tried and did not match -- and
	// TestAVolumeWithNoUsableKeyslotIsNotReportedAsAWrongPassphrase pins
	// the two apart on both sides. The disposition table (DESIGN.md §C.3)
	// now names this KEEP for that reason; see DECISIONS.md.
	ErrNoKeyslots = errors.New("luks2: no valid keyslots")

	// ErrInvalidSize folded into ErrInvalidArgument (DESIGN.md §C.3): a
	// size parameter -- key, sector, metadata or otherwise -- is invalid,
	// with Detail naming which one and the accepted range.

	// ErrPermissionDenied indicates that an operation could not open the device
	// because the process lacks access to it.
	//
	// It is raised by classifyDeviceOpen, which every open in this package's
	// header, format and unlock paths goes through, and it wraps the original
	// *fs.PathError -- so errors.Is(err, os.ErrPermission) stays true of the
	// same value and a caller that already branched on the standard library's
	// sentinel does not have to change.
	//
	// The message an operator sees was never the problem: "failed to open
	// device: open /dev/sdb1: permission denied" says what happened. What was
	// missing, until #31, was the TYPE. Consumers of this library build daemons
	// and provisioning flows, and errors.Is(err, ErrPermissionDenied) is the
	// difference between prompting for elevation and failing a deployment.
	//
	// Not every open in the package classifies yet: the keyslot rewrite paths
	// (keyslot.go), the wipe paths (wipe.go), loop-device setup (loopdev.go)
	// and the recovery-key file paths (recovery.go) still surface a bare
	// *fs.PathError. Every EXPORTED entry point that touches a device reaches
	// one of the classified opens first -- each of them reads the header, and
	// Format opens the device itself -- so the contract holds at the API
	// surface; the residue is stated here rather than left for the next reader
	// to discover.
	// Defined once, in internal/device, and re-exported by value.
	ErrPermissionDenied = device.ErrPermissionDenied

	// ErrWrongKey indicates that a candidate master key was
	// COMPARED against at least one digest in the header and matched none of
	// them.
	//
	// It is deliberately one value for every cause -- mismatch, an unsupported
	// or FIPS-refused digest KDF, a corrupt salt, a digest of implausible
	// length -- so that neither the message nor the number of digests tried
	// tells a caller which digest rejected the key. An attacker holding the
	// device can craft a header, and an error separating "digest 2 uses a KDF I
	// refuse" from "digest 2 did not match" would tell them which keyslot to
	// work on and how this implementation reads the header.
	//
	// The word COMPARED is load-bearing, and is the #41 fix. A keyslot whose
	// every attesting digest is unusable never reaches a comparison at all, and
	// that is reported as ErrInvalidHeader instead: there is no comparison
	// outcome to leak, and telling an operator their key failed verification
	// when nothing verified it sends them to the credential rather than to the
	// header. verifyMasterKey states the boundary and why it sits exactly
	// there.
	ErrWrongKey = errors.New("luks2: master key verification failed")

	// ErrInvalidVolumeKey folded into ErrInvalidCredential (DESIGN.md §C.3):
	// a volume key handed to UnlockWithVolumeKey that cannot be a volume key
	// at all -- a nil or destroyed enclave, or one whose size no keyslot of
	// this package could hold. It is the caller's argument that is wrong,
	// and it is reported before the device is read.
	//
	// A key of plausible shape that the header does not attest is NOT this
	// error; that is ErrWrongKey, exactly as for a passphrase
	// that recovers the wrong key, and for the same reason.

	// ErrMetadataTooLarge folded into ErrNoSpace (DESIGN.md §C.3): the JSON
	// metadata does not fit the header area the container was formatted
	// with. The area cannot be enlarged after the fact -- the keyslots and
	// data offsets on disk are already sized against it -- so this is a
	// refusal, not a retryable condition.

	// ErrLastKeyslot indicates a removal was REFUSED because it would leave the
	// container with no keyslot that can open it.
	//
	// The count behind it is of keyslots that could actually yield the master
	// key, not of map entries: a `reencrypt` slot, a slot with no anti-forensic
	// object, a slot whose cipher nothing implements all read as keyslots and
	// open nothing. Counting entries is what let the only working credential be
	// destroyed while the guard reported a survivor (#37, #71).
	//
	// It is a refusal rather than a warning by owner ruling. A removal that
	// leaves a volume unopenable otherwise succeeds, reports success, and is
	// discovered at the next unlock.
	ErrLastKeyslot = errors.New("luks2: removal would leave no keyslot that can open the volume")

	// ErrKeyslotAreaOverlap indicates a removal was REFUSED because zeroing the
	// target keyslot's area would also zero key material belonging to a keyslot
	// that can still open the volume.
	//
	// The guard and the wipe used to disagree about what a removal destroys --
	// the guard reasoned over keyslot entries, the wipe acted on bytes -- so two
	// entirely well-formed keyslots sharing an area were enough to reproduce
	// permanent data loss (#38).
	ErrKeyslotAreaOverlap = errors.New("luks2: keyslot area overlaps a keyslot that can still open the volume")

	// ErrKeyslotsAreaFull folded into ErrNoSpace (DESIGN.md §C.3): the
	// container has no room for another keyslot -- the new one would fall
	// outside the keyslots area the header declares, or past the start of
	// the encrypted data. Both are refusals rather than retryable
	// conditions -- the area is fixed at format time.

	// ErrFIPSNotApproved indicates the requested algorithm is not approved by
	// the Go Cryptographic Module and is refused while the process runs in
	// FIPS 140-3 mode. See docs/FIPS.md.
	ErrFIPSNotApproved = fips.ErrNotApproved

	// ErrFIPSImportRequired indicates that a FIPS 140-3 process met a volume
	// whose keyslots -- or the digests attesting them -- use a KDF FIPS mode
	// cannot execute, most often Argon2id, cryptsetup's default. The volume is
	// not damaged. The remedy is a one-time MigrateToFIPS from a process that
	// is NOT in FIPS mode. It is carried by FIPSImportRequiredError, which also
	// matches ErrFIPSNotApproved.
	ErrFIPSImportRequired = errors.New("luks2: volume must be imported for FIPS 140-3 mode before a FIPS process can open it")

	// ErrFIPSMigration matches every FIPSMigrationError regardless of which
	// stage failed -- a caller that only cares whether the migration
	// completed does not need to know the specific cause. FIPSMigrationError.
	// Stage (and MigrationStage) say which one, for a caller that does.
	ErrFIPSMigration = errors.New("luks2: FIPS 140-3 migration failed")

	// errFIPSMigrationUnderFIPS indicates MigrateToFIPS was called in a process
	// running in FIPS 140-3 mode. The migration has to unlock the volume through
	// its existing Argon2 keyslots, which FIPS mode cannot execute, so it is
	// refused before the device is touched rather than failing inside the
	// derivation.
	errFIPSMigrationUnderFIPS = errors.New("the FIPS import must run in a process that is not in FIPS 140-3 mode")

	// errFIPSMigrationDigest indicates a digest whose KDF is not FIPS-approved
	// could not be migrated, because it could not be evaluated or does not
	// attest the volume key the passphrase recovered. Rewriting it would
	// replace an attestation about some other key with one about this key, so
	// the migration refuses before writing anything.
	errFIPSMigrationDigest = errors.New("a digest that is not FIPS-approved does not attest the recovered volume key and cannot be migrated")

	// errFIPSMigrationVerification indicates MigrateToFIPS could not confirm
	// its own outcome: the migrated keyslot did not open the volume through a
	// FIPS-approved path to the same volume key, or a keyslot or digest that is
	// not FIPS-approved remained that the caller did not ask to keep. The
	// operation reports failure rather than a success nobody checked.
	errFIPSMigrationVerification = errors.New("the FIPS import could not verify that the volume opens through FIPS-approved KDFs only")

	// errFIPSMigrationUnboundKey indicates the passphrase handed to
	// MigrateToFIPS does not open a keyslot holding the volume key the data
	// segments are encrypted with. Migrating whatever key it does open -- an
	// unbound key a LUKS2 header may carry beside the volume key -- and then
	// removing the non-approved keyslots would erase the only way to the data
	// while the migrated keyslot still opened, so the migration refuses before
	// writing anything.
	errFIPSMigrationUnboundKey = errors.New("the passphrase does not open a keyslot holding the key the data segments are encrypted with")

	// ErrSHA1NotWritten folded into ErrInvalidArgument (DESIGN.md §C.3): a
	// request to WRITE SHA-1 into a keyslot or digest -- a PBKDF2-SHA1 KDF
	// (KDFTypePBKDF2SHA1, or a "sha1" hash for a new keyslot or a format) or
	// a SHA-1 anti-forensic split. SHA-1 is deprecated for key derivation
	// and not FIPS-approved for it, so this package reads it -- to open
	// volumes cryptsetup and LUKS1 wrote -- and never writes it (#236,
	// #239). Kind is ErrInvalidArgument and Err is ErrUnsupported, with
	// Detail naming whichever option -- the KDF type or the hash -- was
	// rejected (refuseSHA1ForCreation, kdf.go).

	// ErrDeviceCacheStale indicates that bytes read from the device through the
	// page cache differ from the same bytes read past it (O_DIRECT): another
	// process holds the device mapped, or an earlier write failed and left
	// bytes in the cache that never reached the medium. An operation that
	// would act on what it read refuses rather than act on what is not there.
	// Defined once, in internal/device, and re-exported by value.
	ErrDeviceCacheStale = device.ErrCacheStale

	// ErrDirectIOUnsupported folded into ErrUnsupported (DESIGN.md §C.3):
	// the device cannot be read past the page cache (O_DIRECT is refused)
	// and is not on a memory filesystem, where the cache would be the only
	// copy -- or the platform has no O_DIRECT at all. What is on the
	// medium therefore cannot be confirmed, and an operation that needs it
	// confirmed refuses.

	// ErrKDFCalibration indicates that the PBKDF2 iteration count for a NEW
	// keyslot could not be calibrated, and that no keyslot was created.
	//
	// It is a refusal and never a default. The iteration count is written into
	// the LUKS2 header at format time and is the entire cost an offline attacker
	// pays per passphrase guess, so a calibration that cannot be performed has
	// exactly one safe answer: fail. Returning a plausible-looking constant
	// instead -- which is what this package did until issue #52 -- produces a
	// header that is permanently weaker than the caller asked for, with a nil
	// error to say so. Nothing later can strengthen a header that is already on
	// disk. See KDFCalibrationError for what the failure carries.
	ErrKDFCalibration = kdf.ErrKDFCalibration

	// ErrPBKDFIterationsTooLow and ErrPBKDFIterationsTooHigh folded into
	// ErrInvalidArgument (DESIGN.md §B.6): a PBKDF2 iteration count outside
	// the floor-to-ceiling range is *KDFCostError, which Is ErrInvalidArgument.

	// ErrMappingStillLive and ErrMappingBusy moved to pkg/dmcrypt as
	// ErrStillLive and ErrBusy (#268): both were raised only by activation
	// code (Unlock's rollback, Lock), which no longer lives here.

	// ErrNotBlockDevice folded into ErrInvalidArgument (DESIGN.md §C.3):
	// Unlock was given something that is not a block device. dm-crypt maps
	// a block device by its major:minor, so a regular file must be
	// attached to a loop device first.

	// ErrUnsupportedSegmentLayout folded into ErrUnsupported (DESIGN.md
	// §C.3): a header whose segments are not exactly one crypt segment.
	// Activation maps one segment with one key, and any other layout
	// would map part of the device with the wrong key.

	// ErrUnsupportedHeaderChecksum folded into ErrUnsupported (DESIGN.md
	// §C.3): a binary header whose checksum algorithm field names anything
	// but sha256, the algorithm cryptsetup writes and the only one this
	// package verifies. Such a header is refused on read; the error also
	// matches ErrInvalidHeader.

	// ErrDeviceChanged indicates that a device path resolved to a different
	// file when it was opened again than when it was locked: a symlink
	// re-pointed in between. The operation is refused before it writes.
	// Defined once, in internal/device, and re-exported by value.
	ErrDeviceChanged = device.ErrChanged

	// ErrProtectedMemory indicates that key material could not be placed in, or
	// read back from, protected memory, and that the operation was therefore
	// REFUSED rather than completed with the material on the ordinary heap.
	//
	// It is almost always a deployment condition rather than a defect: the
	// process has hit RLIMIT_MEMLOCK. internal/secret documents the amount this
	// library needs and why the refusal is not negotiable.
	ErrProtectedMemory = secret.ErrProtectedMemory

	// ErrLockContended indicates that the exclusive lock on a device could not
	// be taken within the caller's wait budget, because another holder kept it
	// for the whole of that budget.
	//
	// IT IS NOT "THE DEVICE IS BUSY" AND IT IS NOT A DEFECT. The lock exists so
	// that two writers cannot interleave in a LUKS2 header, and contention for
	// it is the ORDINARY case whenever two operations address the same device
	// at once. What it means is that the wait was bounded and the bound was
	// reached -- so the caller is being told the operation did not start, and
	// that retrying later is reasonable, rather than being told something is
	// wrong with the volume.
	//
	// The distinction matters because the alternative to a bound is not
	// "success": it is a process that waits for a lock nothing will ever drop.
	// See LockTimeoutError for what was waited and for how to find the holder.
	// Defined once, in internal/device, and re-exported by value.
	ErrLockContended = device.ErrLockContended

	// ErrMetadataLockUnavailable indicates that cryptsetup's metadata lock for
	// a block device could not be taken at all: its directory
	// (/run/cryptsetup) is missing and cannot be created, is not a directory,
	// is a symlink, or does not admit the caller. Nothing was read or written.
	//
	// cryptsetup refuses the same device in the same state ("Failed to
	// acquire read lock"), for reads as well as writes, so this is not a
	// stricter rule than the one other tools obey. A non-root caller gets it
	// for a root-only lock directory; granting that caller's group write
	// access to the directory admits both tools (docs/COMPATIBILITY.md).
	//
	// Defined once, in internal/device, and re-exported by value (owner
	// ruling, 2026-08-23).
	ErrMetadataLockUnavailable = device.ErrMetadataLockUnavailable
)

// The keyring sentinel family (ErrKeyring, ErrKeyringUnavailable,
// ErrKeyringBlocked, ErrKeyringUnsupported, ErrKeyringQuotaExhausted,
// ErrKeyringFailed, ErrKeyringEntryExists, ErrKeyringKeyNotReleased) and
// KeyringUnavailableError moved to pkg/dmcrypt (#268), re-exported there
// from internal/keyring by value exactly as they were re-exported here:
// activation is pkg/dmcrypt's now, and this package no longer imports
// internal/keyring at all (DESIGN.md §A.2).

// A keyslot whose area.encryption names a cipher spec this package cannot
// decrypt (#106) is reported as an *errs.Error with Kind ErrUnsupported,
// Err set to ErrKeyslotNotFound so the scan still moves on to the
// keyslots that still open, and Detail naming the keyslot and the spec
// (parseKeyslotAreaEncryption, keyslotscreen.go).
//
// Error is the one error shape of this module (DESIGN.md §C.1), aliased
// here so a caller can match it with errors.As(&Error{}) without importing
// internal/errs.
type Error = errs.Error

// A keyslot the unlock path refuses on its own account -- its type, its
// geometry, its KDF or its anti-forensic parameters -- is reported as an
// *errs.Error with Kind ErrKeyslotNotFound and Detail naming the keyslot
// and the reason (screenKeyslot, keyslotscreen.go).

// LockTimeoutError reports that a device lock could not be taken within the
// wait budget, and carries what an operator needs to act: the three fields
// are the diagnostic. Defined once, in internal/device, and aliased here, so
// a caller's errors.As(&LockTimeoutError{}) is unaffected by where the
// classification happens to live.
type LockTimeoutError = device.LockTimeoutError

// An unlock refusal is an *errs.Error: Kind is the classifying cause when
// the keyslot scan has one -- ErrInvalidCredential, ErrWrongKey,
// ErrInvalidHeader -- and nil when the refusal has none; Detail names the
// step that refused and what was wrong with it, built from the caller's
// argument shape and cleartext header fields only, never key or passphrase
// content.

// KDFCalibrationError reports that BenchmarkPBKDF2 could not determine an
// iteration count for the requested time budget, and carries what the probe
// saw so the condition can be diagnosed without re-running it.
//
// Two causes reach here, and both are refusals:
//
//   - The requested budget is not a usable number of milliseconds -- zero,
//     negative, or so large that it is not an iteration time anyone meant.
//   - No probe up to the ceiling ran long enough to be timed. On real hardware
//     this cannot happen: a probe doubles until it clears a floor measured in
//     tens of milliseconds, and even the fastest machine reaches that within a
//     few million iterations. It means the clock is not advancing.
type KDFCalibrationError = kdf.CalibrationError

// KDFCostError reports that a KDF cost -- an Argon2 parameter or a PBKDF2
// iteration count -- was refused, and carries the permitted range so the
// caller can act without guessing what the floor or ceiling is.
//
// It unifies what used to be two types (Argon2CostError, PBKDFIterationsError,
// DESIGN.md §B.6): an Argon2 and a PBKDF2 refusal are both a CALLER-CHOSEN
// keyslot cost outside the range the read path would accept back, and an
// operator should not have to learn two vocabularies for one decision. It is
// always ErrInvalidArgument.
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

	// Reason is set when something other than the KDF algorithm is what
	// strict FIPS mode (GODEBUG=fips140=only) refuses: a parameter -- a salt
	// shorter than 128 bits, an output shorter than 112 bits -- or, for a
	// keyslot, its anti-forensic hash ("anti-forensic hash sha1", whatever its
	// KDF). Empty when the KDF algorithm alone is what is not approved.
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

// FIPSImportRequiredError is what a FIPS 140-3 process gets when it tries to
// open a volume it cannot open ONLY because the volume's keyslots or digests
// use a KDF FIPS mode cannot execute -- an Argon2 keyslot, as every volume from
// a default `cryptsetup luksFormat` has.
//
// Its message is written for someone who does not know LUKS2 internals, because
// the bare refusal it replaces ("invalid keyslot: argon2id: algorithm not
// approved") read as corruption. It says the volume is intact, what it uses,
// why this process cannot execute that, and that MigrateToFIPS is the remedy.
//
// It matches ErrFIPSImportRequired and ErrFIPSNotApproved with errors.Is, so a
// caller that already branched on the latter keeps working. It deliberately
// does NOT unwrap to the scan's ErrKeyslotNotFound or ErrInvalidHeader: those
// say the header is damaged, which is precisely the reading this error exists
// to correct.
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

// FIPSMigrationError reports a MigrateToFIPS that did not complete: which stage
// failed, why, and -- because a migration writes to the device in several steps
// -- what state the volume was left in. State is never left for the caller to
// infer; the migration is ordered so that every state it can stop in is
// openable, and State says by what.
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

// Error renders the stage, the cause and the state. It names neither the
// device nor ErrFIPSMigration, and drops the cause's own "luks2: " prefix:
// MigrateToFIPS returns it under the package's *errs.Error, whose head
// already says each of those once (DESIGN.md §C.2 rule 3).
func (e *FIPSMigrationError) Error() string {
	return fmt.Sprintf("at %s: %s; %s", e.Stage, strings.TrimPrefix(fmt.Sprint(e.Err), "luks2: "), e.State)
}

// Unwrap reports a FIPSMigrationError as both ErrFIPSMigration -- the one
// condition a caller may want to single out without naming a stage -- and
// the original failure, so errors.Is(err, ErrFIPSMigration) matches every
// stage and errors.Is(err, <the specific cause>) still reaches it too.
func (e *FIPSMigrationError) Unwrap() []error { return []error{ErrFIPSMigration, e.Err} }

// MigrationStage maps e.Stage's detailed string onto one of the five coarse
// phases FIPSMigrationStage names (DESIGN.md §B.2), so a caller can switch
// on where a migration failed without string-matching e.Stage. The mapping
// is not 1:1 -- ten Stage strings onto five phases -- and is recorded in
// DECISIONS.md's H9 train-merge entry:
//
//	"precondition", "sync"                                      -> StagePreflight
//	"unlock", "plan", "verify"                                  -> StageVerify
//	"reconcile header copies", "add keyslot", "migrate digest"  -> StageWrite
//	"remove keyslot"                                            -> StageRemove
//	"final check"                                               -> StageVerifyWritten
//
// "unlock"/"plan" and "verify" share StageVerify deliberately: the stage's
// own doc comment already groups unlocking and planning (before any write)
// with the post-write opens that prove the result, as the two halves of
// "making sure the migration is sound" that bracket the writes in StageWrite.
// An unrecognized Stage -- not reachable from this package's own
// migrateToFIPS, but not provably unreachable for any *FIPSMigrationError a
// caller could construct -- returns StagePreflight, the conservative choice
// since it implies nothing has been written yet.
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

// ErrInvalidPath, ErrPassphraseTooShort/Long, ErrCredentialEmpty/TooLong,
// ErrInvalidKeySize/SectorSize/MetadataSize, ErrIntegerOverflow and
// ErrInvalidArgon2Memory/Time/Parallel (DESIGN.md §B.6) all folded into
// ErrInvalidArgument or ErrInvalidCredential (DESIGN.md §C.3): a
// caller-supplied device path, size or count outside the accepted range is
// *errs.Error{Kind: ErrInvalidArgument} (or *KDFCostError, which Is it); a
// caller-supplied passphrase or credential outside the accepted length is
// *errs.Error{Kind: ErrInvalidCredential}. Both keep the original message
// in Detail.
//
// ErrInvalidMappingName indicates a device-mapper mapping name that this
// library will not create. See ValidateMappingName for what the name
// reaches and why the charset is a whitelist.

// Format and validateFormatOptionsForTest refuse before the device is
// touched (#248). ErrUnsupportedCipher (a Cipher/CipherMode/KeySize
// combination Format does not write), ErrInvalidLabel (a Label or
// Subsystem that does not fit the 48-byte header field) and ErrDeviceTooSmall
// (no room for the header copies, the keyslots area and at least one
// encryption sector) folded into ErrUnsupported and ErrInvalidArgument
// respectively (DESIGN.md §C.3), with the original message in Detail.

// Wipe refusals.
var (
	// ErrDeviceInUse indicates a destructive operation refused a block device
	// that something else holds: it is mounted, it backs a device-mapper
	// mapping or an md array, or another process opened it exclusively. The
	// kernel reports this when the device is opened with O_EXCL.
	// Defined once, in internal/device, and re-exported by value.
	ErrDeviceInUse = device.ErrInUse
)

// Recovery-key generation refusals (#249, A4). ErrRecoveryKeyTooShort (fewer
// than RecoveryKeyLength random bytes, or a rendering too long to be
// enrolled as a passphrase) and ErrInvalidRecoveryKeyFormat (a format other
// than hex, base64 or dashed) folded into ErrInvalidArgument (DESIGN.md
// §C.3), with the original message in Detail.

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

// The external-key vocabulary (keyprovider.go). The exec-helper vocabulary
// (ErrHelperNotConfigured, ErrHelperPathNotAbsolute, ErrNoFIDO2Device,
// ErrHelperFailed, ErrHelperOutput, ErrInvalidFIDO2Binding) moved to
// pkg/keyprovider with the code that raised it (#271); what is left here is
// raised only by Volume.Enroll, Volume.UnlockWithProvider and importTokenLocked,
// which stay (DECISIONS.md H10d).
var (
	// ErrKeyProvider is matched only by an OrphanedKeyslotError, alongside
	// ErrOrphanedKeyslot. Other external-key failures carry their own
	// sentinels: a provider's error passes through as the provider returned
	// it (pkg/keyprovider's ErrHelperFailed and the rest), and a refused
	// argument or keyslot is ErrInvalidArgument or ErrKeyslotNotFound.
	ErrKeyProvider = errors.New("luks2: external key provider")

	// ErrNoKeyProvider folded into ErrInvalidArgument (DESIGN.md §C.3): an
	// operation was given no provider, or a token with nothing in it to
	// build one from.

	// ErrOrphanedKeyslot indicates a credential was written to a keyslot, the
	// token identifying it could not be written, AND the keyslot could not be
	// removed again.
	//
	// This is the one outcome in this file that needs a human. The volume now
	// has a live credential that nothing on the device describes: it opens the
	// volume, it cannot be told apart from a credential still in use, and the
	// only record of which slot it is, is this error.
	ErrOrphanedKeyslot = errors.New("luks2: orphaned keyslot")
)

// ErrPrimaryHeaderCurrent indicates RestorePrimaryHeader was refused because
// the primary header copy is intact and at least as new as the secondary, so
// restoring would roll the volume back rather than repair it.
var ErrPrimaryHeaderCurrent = header.ErrPrimaryHeaderCurrent

// ErrTokenNotFound indicates the token was not found
var ErrTokenNotFound = errors.New("luks2: token not found")

// ErrNoFreeTokenSlot folded into ErrNoSpace (DESIGN.md §C.3): no free
// token slots are available.

// The following are the new pkg/luks2 API's (DESIGN.md §B.2, §C.3) own
// sentinels.
var (
	// ErrReadOnly indicates a mutating method was called on a Volume opened
	// with WithReadOnly.
	ErrReadOnly = errors.New("luks2: the volume was opened read-only")

	// ErrClosed indicates a method was called on a Volume after Close.
	ErrClosed = errors.New("luks2: the volume is closed")

	// ErrNotLUKS2 indicates a header copy whose magic is LUKS but whose
	// version is not 2 -- a LUKS1 container, most often. It is not damage,
	// and is not reported as ErrInvalidHeader. Defined once, in
	// internal/header (as ErrUnsupportedLUKSVersion), and re-exported by
	// value under the new API's name (§C.3).
	ErrNotLUKS2 = header.ErrUnsupportedLUKSVersion
)
