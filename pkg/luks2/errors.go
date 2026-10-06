// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-luks2/internal/areacipher"
	"github.com/jeremyhahn/go-luks2/internal/command"
	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/internal/kdf"
	keyringpkg "github.com/jeremyhahn/go-luks2/internal/keyring"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// Common errors that can be checked using errors.Is()
var (
	// ErrInvalidHeader indicates a LUKS header is invalid or corrupted
	ErrInvalidHeader = errs.ErrInvalidHeader

	// ErrDeviceNotFound indicates the device path doesn't exist. Defined
	// once, in internal/device, and re-exported by value.
	ErrDeviceNotFound = device.ErrNotFound

	// ErrVolumeNotUnlocked indicates that an operation needs a live
	// device-mapper mapping and there is none: Lock was asked to close a name
	// nothing has opened, or Mount was pointed at a volume that is not unlocked.
	ErrVolumeNotUnlocked = errors.New("volume not unlocked")

	// ErrVolumeAlreadyUnlocked indicates that the mapping name Unlock was given
	// is already in use.
	//
	// It is a REFUSAL and not a no-op: the existing target may be a mapping of a
	// different volume entirely, and adopting it would hand the caller a
	// plaintext device it did not open. The message names the command that
	// closes it.
	ErrVolumeAlreadyUnlocked = errors.New("volume already unlocked")

	// ErrNotMounted indicates that Unmount was given a path the KERNEL says is
	// not a mount point: it is raised on an EINVAL from umount2(2), never ahead
	// of the syscall.
	//
	// Reading that EINVAL this way is only sound because Unmount validates the
	// caller's flags first. umount2(2) documents three causes for EINVAL -- not
	// a mount point, MNT_EXPIRE combined with MNT_FORCE or MNT_DETACH, and an
	// undefined flag value -- and the last two are properties of the caller's
	// own argument, so refusing them up front leaves the first as the only
	// remaining reading. Bad flags are therefore refused BEFORE the syscall and
	// are NOT this error.
	//
	// An earlier draft answered the question itself, from /proc/mounts, ahead of
	// the syscall. It was wrong twice over: a check that duplicates a decision
	// the kernel already makes is a second source of truth, and /proc/mounts
	// escapes its fields, so it refused every mount point whose path contains a
	// space, tab, newline or backslash. See Unmount.
	ErrNotMounted = errors.New("not mounted")

	// ErrUnsupportedKDF indicates the KDF type named by a header, or by a
	// caller's options, is not one this package implements. It is raised where a
	// KDF is DISPATCHED (kdf.go); validateKDFCost deliberately returns an
	// unclassified error for the same condition, because only its caller knows
	// whether an unusable KDF condemns a keyslot or a digest.
	ErrUnsupportedKDF = kdf.ErrUnsupportedKDF

	// ErrUnsupportedHash indicates the hash algorithm named by a header, or by a
	// caller's options, is not one this package implements. A FIPS-refused
	// algorithm is NOT this error -- that is ErrFIPSNotApproved, because the
	// algorithm is implemented and the mode refuses it, which is a different
	// thing for an operator to be told.
	ErrUnsupportedHash = errs.ErrUnsupportedHash

	// ErrUnsupportedFilesystem indicates a filesystem type that is not in
	// SupportedFilesystems(). MakeFilesystemWithOptions and CheckFilesystem
	// raise it before touching a device. ext2 and ext3 are deliberately in
	// this category (#195); see FilesystemExt2 and FilesystemExt3.
	ErrUnsupportedFilesystem = errors.New("unsupported filesystem type")

	// ErrInvalidKeyslot indicates the keyslot is invalid or unavailable
	ErrInvalidKeyslot = errs.ErrInvalidKeyslot

	// ErrUnsupportedKeyslotCipher indicates a keyslot's area.encryption names a
	// cipher spec -- algorithm, mode AND IV generator -- this package cannot
	// decrypt. The read path honors the whole spec rather than only its
	// algorithm (#106): a keyslot declaring "aes-cbc-essiv:sha256" is refused
	// here, never decrypted as AES-XTS. A keyslot refused with it is also
	// ErrInvalidKeyslot, so the keyslot scan moves on to the next one.
	ErrUnsupportedKeyslotCipher = errors.New("unsupported keyslot area cipher")

	// ErrUnsupportedRequirement indicates the container declares a mandatory
	// requirement this package does not implement, so it must not be modified.
	// The container is still READABLE -- see Requirements (types.go).
	ErrUnsupportedRequirement = header.ErrUnsupportedRequirement

	// ErrNoKeyslots indicates no valid keyslots are available
	ErrNoKeyslots = errors.New("no valid keyslots")

	// ErrInvalidSize indicates a size parameter is invalid
	ErrInvalidSize = errors.New("invalid size")

	// ErrDetachIncomplete indicates a loop device was told to detach and the
	// kernel had not released it before the wait expired. It is deliberately
	// distinct from a failed detach: the request succeeded, and something else
	// still holds the device open. An operator who reads "detach failed" goes
	// looking at the detach; this one has to go looking at what else has the
	// device.
	ErrDetachIncomplete = errors.New("loop device detach did not become observable")

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

	// ErrMasterKeyVerification indicates that a candidate master key was
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
	ErrMasterKeyVerification = errors.New("master key verification failed")

	// ErrInvalidVolumeKey indicates a volume key handed to UnlockWithVolumeKey
	// that cannot be a volume key at all: a nil or destroyed enclave, or one
	// whose size no keyslot of this package could hold. It is the caller's
	// argument that is wrong, and it is reported before the device is read.
	//
	// A key of plausible shape that the header does not attest is NOT this
	// error; that is ErrMasterKeyVerification, exactly as for a passphrase
	// that recovers the wrong key, and for the same reason.
	ErrInvalidVolumeKey = errors.New("invalid volume key")

	// ErrMetadataTooLarge indicates the JSON metadata does not fit the header
	// area the container was formatted with. The area cannot be enlarged after
	// the fact -- the keyslots and data offsets on disk are already sized
	// against it -- so this is a refusal, not a retryable condition.
	ErrMetadataTooLarge = header.ErrMetadataTooLarge

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
	ErrLastKeyslot = errors.New("removal would leave no keyslot that can open the volume")

	// ErrKeyslotAreaOverlap indicates a removal was REFUSED because zeroing the
	// target keyslot's area would also zero key material belonging to a keyslot
	// that can still open the volume.
	//
	// The guard and the wipe used to disagree about what a removal destroys --
	// the guard reasoned over keyslot entries, the wipe acted on bytes -- so two
	// entirely well-formed keyslots sharing an area were enough to reproduce
	// permanent data loss (#38).
	ErrKeyslotAreaOverlap = errors.New("keyslot area overlaps a keyslot that can still open the volume")

	// ErrKeyslotsAreaFull indicates the container has no room for another
	// keyslot: the new one would fall outside the keyslots area the header
	// declares, or past the start of the encrypted data. Both are refusals
	// rather than retryable conditions -- the area is fixed at format time.
	ErrKeyslotsAreaFull = errors.New("no room in the keyslots area for another keyslot")

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
	ErrFIPSImportRequired = errors.New("volume must be imported for FIPS 140-3 mode before a FIPS process can open it")

	// ErrFIPSMigrationUnderFIPS indicates MigrateToFIPS was called in a process
	// running in FIPS 140-3 mode. The migration has to unlock the volume through
	// its existing Argon2 keyslots, which FIPS mode cannot execute, so it is
	// refused before the device is touched rather than failing inside the
	// derivation.
	ErrFIPSMigrationUnderFIPS = errors.New("the FIPS import must run in a process that is not in FIPS 140-3 mode")

	// ErrFIPSMigrationDigest indicates a digest whose KDF is not FIPS-approved
	// could not be migrated, because it could not be evaluated or does not
	// attest the volume key the passphrase recovered. Rewriting it would
	// replace an attestation about some other key with one about this key, so
	// the migration refuses before writing anything.
	ErrFIPSMigrationDigest = errors.New("a digest that is not FIPS-approved does not attest the recovered volume key and cannot be migrated")

	// ErrFIPSMigrationVerification indicates MigrateToFIPS could not confirm
	// its own outcome: the migrated keyslot did not open the volume through a
	// FIPS-approved path to the same volume key, or a keyslot or digest that is
	// not FIPS-approved remained that the caller did not ask to keep. The
	// operation reports failure rather than a success nobody checked.
	ErrFIPSMigrationVerification = errors.New("the FIPS import could not verify that the volume opens through FIPS-approved KDFs only")

	// ErrFIPSMigrationUnboundKey indicates the passphrase handed to
	// MigrateToFIPS does not open a keyslot holding the volume key the data
	// segments are encrypted with. Migrating whatever key it does open -- an
	// unbound key a LUKS2 header may carry beside the volume key -- and then
	// removing the non-approved keyslots would erase the only way to the data
	// while the migrated keyslot still opened, so the migration refuses before
	// writing anything.
	ErrFIPSMigrationUnboundKey = errors.New("the passphrase does not open a keyslot holding the key the data segments are encrypted with")

	// ErrSHA1NotWritten indicates a request to WRITE SHA-1 into a keyslot or
	// digest: a PBKDF2-SHA1 KDF (KDFTypePBKDF2SHA1, or a "sha1" hash for a new
	// keyslot or a format) or a SHA-1 anti-forensic split. SHA-1 is
	// deprecated for key derivation and not FIPS-approved for it, so this
	// package reads it -- to open volumes cryptsetup and LUKS1 wrote -- and
	// never writes it (#236, #239). It is carried alongside ErrUnsupportedHash
	// or ErrUnsupportedKDF, whichever the rejected option names.
	ErrSHA1NotWritten = errs.ErrSHA1NotWritten

	// ErrUnsupportedLUKSVersion indicates a header copy whose magic is LUKS
	// but whose version is not 2 -- a LUKS1 container, most often. It is not
	// damage, and is not reported as ErrInvalidHeader.
	ErrUnsupportedLUKSVersion = header.ErrUnsupportedLUKSVersion

	// ErrDeviceCacheStale indicates that bytes read from the device through the
	// page cache differ from the same bytes read past it (O_DIRECT): another
	// process holds the device mapped, or an earlier write failed and left
	// bytes in the cache that never reached the medium. An operation that
	// would act on what it read refuses rather than act on what is not there.
	// Defined once, in internal/device, and re-exported by value.
	ErrDeviceCacheStale = device.ErrCacheStale

	// ErrDirectIOUnsupported indicates the device cannot be read past the
	// page cache (O_DIRECT is refused) and is not on a memory filesystem,
	// where the cache would be the only copy -- or the platform has no
	// O_DIRECT at all. What is on the medium therefore cannot be confirmed,
	// and an operation that needs it confirmed refuses. Defined once, in
	// internal/device, and re-exported by value.
	ErrDirectIOUnsupported = device.ErrUnsupported

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

	// ErrPBKDFIterationsTooLow indicates a caller supplied an explicit PBKDF2
	// iteration count below the floor this package writes.
	//
	// It exists because FormatOptions.PBKDFIterations and
	// AddKeyOptions.PBKDFIterations bypass calibration, and calibration was
	// where the floor was applied. cryptsetup's own
	// --pbkdf-force-iterations bypasses ITS minimum; this package deliberately
	// does not copy that. A floor that any caller can argue its way around is
	// not a floor, and the keyslot outlives every reason anyone had for
	// lowering it.
	ErrPBKDFIterationsTooLow = kdf.ErrPBKDFIterationsTooLow

	// ErrPBKDFIterationsTooHigh indicates an explicit PBKDF2 iteration count
	// above maxKDFIterations, which is the ceiling validateKDFCost enforces
	// when a header is READ.
	//
	// It is a refusal rather than a clamp for the same reason the floor is a
	// refusal: writing the ceiling instead would produce a keyslot with less
	// work than the caller asked for and return nil to say it succeeded. It is
	// also the only outcome that keeps write and read consistent -- a count
	// above the ceiling makes a keyslot this package would refuse to open.
	ErrPBKDFIterationsTooHigh = kdf.ErrPBKDFIterationsTooHigh

	// ErrMappingStillLive indicates that Unlock failed AFTER the dm-crypt target
	// was already live, and that the target this call created may still be
	// present.
	//
	// It is the difference between "the volume did not open" and "the volume
	// did not open AND there is a decrypted device sitting there anyway". A
	// caller that sees a plain unlock failure is entitled to assume no
	// plaintext device exists and to do nothing further; a caller that sees
	// this one must not, and must treat the volume as partially open --
	// unmounting, releasing the backing device or reusing the name will all
	// fail while the mapping holds it.
	//
	// It is also returned when the state could not be CONFIRMED, not only when
	// removal is known to have failed. An unverifiable plaintext mapping is
	// reported rather than assumed away.
	ErrMappingStillLive = errors.New("plaintext device-mapper target may still be live after a failed unlock")

	// ErrMappingBusy indicates that a device-mapper target could not be removed
	// because something still holds it open, after the removal was retried to
	// its budget.
	//
	// It is the ORDINARY-CLOSE answer, raised by Lock. It is deliberately not
	// ErrMappingStillLive: that one means a plaintext target created by a
	// FAILED unlock may exist while the caller believes nothing does, and its
	// danger is silence. Here the caller asked for the close and is being told
	// it did not happen, so the fact is not silent -- only the cause is, which
	// is what this names.
	//
	// A transient hold is not this error. dmsetup(8) documents the same
	// condition and retries "for a few seconds" for the same reason; by the
	// time this is returned that window has been spent, so it means something
	// genuinely holds the device -- a mounted filesystem, an open descriptor, a
	// stacked target. The message carries how to find it, and the underlying
	// EBUSY stays reachable through the chain.
	ErrMappingBusy = errors.New("device-mapper target is held open and could not be removed")

	// ErrDeviceNodeUnverified indicates that no device node carries the device
	// number device-mapper reports for a mapping. A node is used only when its
	// rdev matches the mapping's dm DevNo, so a stale or planted
	// /dev/mapper/<name> is refused rather than handed to mount or mkfs.
	ErrDeviceNodeUnverified = errors.New("no device node verifiably names the device-mapper target")

	// ErrNotBlockDevice indicates that Unlock was given something that is not
	// a block device. dm-crypt maps a block device by its major:minor, so a
	// regular file must be attached to a loop device first.
	ErrNotBlockDevice = errors.New("not a block device")

	// ErrUnsupportedSegmentLayout indicates a header whose segments are not
	// exactly one crypt segment. Activation maps one segment with one key, and
	// any other layout would map part of the device with the wrong key.
	ErrUnsupportedSegmentLayout = errors.New("the header's segment layout cannot be activated")

	// ErrFilesystemTool indicates a filesystem program could not be found in
	// the fixed system directories this package runs tools from, or was found
	// but is writable by someone other than root or the current user.
	ErrFilesystemTool = command.ErrTool

	// ErrUnsupportedHeaderChecksum indicates a binary header whose checksum
	// algorithm field names anything but sha256, the algorithm cryptsetup
	// writes and the only one this package verifies. Such a header is refused
	// on read; the error also matches ErrInvalidHeader.
	ErrUnsupportedHeaderChecksum = header.ErrUnsupportedHeaderChecksum

	// ErrDeviceChanged indicates that a device path resolved to a different
	// file when it was opened again than when it was locked: a symlink
	// re-pointed in between. The operation is refused before it writes.
	// Defined once, in internal/device, and re-exported by value.
	ErrDeviceChanged = device.ErrChanged

	// ErrFilesystemNotDetected indicates that the filesystem on a device could
	// not be determined: blkid found no signature, more than one, or one that
	// is not a mountable filesystem. DetectFilesystem returns it, and so does
	// Mount when it is asked to detect the type, rather than guessing one.
	ErrFilesystemNotDetected = errors.New("the filesystem on the device could not be determined")

	// ErrInvalidFilesystemOption indicates a filesystem option (a ZFS pool,
	// dataset, feature or property name, for example) that could be read as
	// a command-line option or does not follow the tool's naming rules.
	ErrInvalidFilesystemOption = errors.New("invalid filesystem option")

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

	// ErrKDFBudgetExceeded indicates that a header would have one unlock,
	// verification or authorization derive more than the most expensive header
	// cryptsetup can write: LUKS2MaxKeyslots keyslots, one digest each, every
	// derivation at its ceiling. It is refused before the first derivation; see
	// KDFBudgetError. Every error matching it also matches ErrInvalidHeader.
	ErrKDFBudgetExceeded = errors.New("the header asks one operation for more key derivation than any cryptsetup header can")

	// ErrLoopNodeAbsent indicates that the kernel allocated a loop device but
	// no device node for it appeared under /dev within the wait budget.
	//
	// THE ALLOCATION SUCCEEDED. LOOP_CTL_GET_FREE reserves a minor number and
	// returns it; creating the node is a separate job belonging to devtmpfs or
	// to udev, and neither is guaranteed to have finished -- or to be running
	// at all. So this is not "no loop devices available", which is the reading
	// the bare ENOENT invited: it means the number is ours and the path to it
	// does not exist yet.
	//
	// It is invisible until allocation passes the PRE-CREATED range, typically
	// loop0-loop7, because those nodes exist from boot. That is why it presents
	// as "works for the first N, fails past them", with N depending on how many
	// loop devices the host already has in use.
	ErrLoopNodeAbsent = errors.New("kernel allocated a loop device but its /dev node did not appear")

	// ErrKeyring is the ROOT of every keyring condition in this package, and
	// the only sentinel that is safe to use as a catch-all. See
	// internal/keyring.ErrKeyring, which this re-exports by value (#265, H7).
	ErrKeyring = keyringpkg.ErrKeyring

	// ErrKeyringUnavailable indicates that the volume key could not be placed
	// in the kernel keyring, and that the operation was therefore REFUSED. See
	// internal/keyring.ErrUnavailable.
	ErrKeyringUnavailable = keyringpkg.ErrUnavailable

	// ErrKeyringBlocked indicates the kernel keyring syscalls are refused by
	// policy rather than being absent. See internal/keyring.ErrBlocked.
	ErrKeyringBlocked = keyringpkg.ErrBlocked

	// ErrKeyringUnsupported indicates the kernel does not implement the
	// keyring syscalls at all. See internal/keyring.ErrUnsupported.
	ErrKeyringUnsupported = keyringpkg.ErrUnsupported

	// ErrKeyringQuotaExhausted indicates the per-user kernel key quota is
	// full. See internal/keyring.ErrQuotaExhausted.
	ErrKeyringQuotaExhausted = keyringpkg.ErrQuotaExhausted

	// ErrKeyringFailed indicates the keyring syscalls are reachable and the
	// kernel refused the operation anyway. See internal/keyring.ErrFailed.
	ErrKeyringFailed = keyringpkg.ErrFailed

	// ErrKeyringEntryExists indicates a key was ALREADY present under the
	// description this unlock was about to use. See
	// internal/keyring.ErrEntryExists.
	ErrKeyringEntryExists = keyringpkg.ErrEntryExists

	// ErrKeyringKeyNotReleased indicates that a keyring entry holding a volume
	// key could not be revoked and unlinked after the activation that needed
	// it. See internal/keyring.ErrKeyNotReleased.
	ErrKeyringKeyNotReleased = keyringpkg.ErrKeyNotReleased
)

// KeyringUnavailableError reports that the kernel keyring could not hold the
// volume key, names the step that failed, and carries the REMEDY for the
// specific cause. It is an alias of internal/keyring.UnavailableError, whose
// Error/Unwrap/Is methods moved with it (#265, H7).
type KeyringUnavailableError = keyringpkg.UnavailableError

// UnsupportedKeyslotCipherError reports a keyslot whose area.encryption names a
// cipher spec this package cannot decrypt (#106), and carries which keyslot and
// which spec so an operator is told what the header actually declares.
//
// It is BOTH ErrUnsupportedKeyslotCipher and ErrInvalidKeyslot. The first says
// why; the second is what keeps getMasterKey's scan moving on to the keyslots
// that still open, rather than aborting the unlock on one it cannot read.
type UnsupportedKeyslotCipherError struct {
	// Keyslot is the keyslot's JSON id; empty when the spec was refused before
	// it was attributed to one.
	Keyslot string
	// Spec is the area.encryption value exactly as the header declares it.
	Spec string
}

func (e *UnsupportedKeyslotCipherError) Error() string {
	slot := ""
	if e.Keyslot != "" {
		slot = fmt.Sprintf("luks2 keyslot %q: ", e.Keyslot)
	}
	return fmt.Sprintf("%s: %s: %sarea encryption %q; the keyslot area transforms this package implements are %s",
		ErrInvalidKeyslot.Error(), ErrUnsupportedKeyslotCipher.Error(), slot, e.Spec, areacipher.Specs())
}

// Is reports the error as both sentinels it stands for, in the idiom of
// ErrProtectedMemory.
func (e *UnsupportedKeyslotCipherError) Is(target error) bool {
	return target == ErrUnsupportedKeyslotCipher || target == ErrInvalidKeyslot
}

// InvalidKeyslotError reports a keyslot the unlock path refuses on its own
// account -- its type, its geometry, its KDF or its anti-forensic parameters --
// and names which keyslot, so an operator is told where to look.
//
// It is always ErrInvalidKeyslot, which is what keeps getMasterKey's scan
// moving on to the keyslots that still open. Err, when set, is the underlying
// cause and stays reachable through errors.Is and errors.As.
type InvalidKeyslotError struct {
	// Keyslot is the keyslot's JSON id.
	Keyslot string
	// Reason says what about the keyslot is refused.
	Reason string
	// Err is the cause, or nil when Reason says everything.
	Err error
}

func (e *InvalidKeyslotError) Error() string {
	msg := fmt.Sprintf("%s: luks2 keyslot %q: %s", ErrInvalidKeyslot.Error(), e.Keyslot, e.Reason)
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap exposes the cause, so its own classification survives the wrap.
func (e *InvalidKeyslotError) Unwrap() error {
	return e.Err
}

// Is reports every InvalidKeyslotError as ErrInvalidKeyslot, in the idiom of
// ErrProtectedMemory.
func (e *InvalidKeyslotError) Is(target error) bool {
	return target == ErrInvalidKeyslot
}

// LockTimeoutError reports that a device lock could not be taken within the
// wait budget, and carries what an operator needs to act: the three fields
// are the diagnostic. Defined once, in internal/device, and aliased here, so
// a caller's errors.As(&LockTimeoutError{}) is unaffected by where the
// classification happens to live.
type LockTimeoutError = device.LockTimeoutError

// DeviceError represents an error related to a specific device. Defined
// once, in internal/device, and aliased here.
type DeviceError = device.Error

// VolumeError represents an error related to a volume operation
type VolumeError struct {
	Volume string
	Op     string
	Err    error
}

func (e *VolumeError) Error() string {
	return fmt.Sprintf("%s volume %s: %v", e.Op, e.Volume, e.Err)
}

func (e *VolumeError) Unwrap() error {
	return e.Err
}

// KeyslotError represents an error related to a keyslot operation
type KeyslotError struct {
	Keyslot int
	Op      string
	Err     error
}

func (e *KeyslotError) Error() string {
	return fmt.Sprintf("%s keyslot %d: %v", e.Op, e.Keyslot, e.Err)
}

func (e *KeyslotError) Unwrap() error {
	return e.Err
}

// CryptoError represents an error in cryptographic operations
type CryptoError struct {
	Op  string
	Err error
}

func (e *CryptoError) Error() string {
	return fmt.Sprintf("crypto %s: %v", e.Op, e.Err)
}

func (e *CryptoError) Unwrap() error {
	return e.Err
}

// UnlockError reports why an unlock refused, carrying the classifying cause
// in Err so errors.Is sees through it -- ErrInvalidVolumeKey,
// ErrMasterKeyVerification, ErrInvalidHeader, or whatever the keyslot scan
// returned. Err is nil when the refusal has no underlying cause to carry.
//
// Op names the step that refused and Detail says what was wrong with it. Both
// are built from the caller's argument shape and cleartext header fields only;
// neither ever carries key or passphrase content.
type UnlockError struct {
	Op     string
	Detail string
	Err    error
}

func (e *UnlockError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("%s: %s", e.Op, e.Detail)
	}
	if e.Detail == "" {
		return fmt.Sprintf("%s: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("%s: %v: %s", e.Op, e.Err, e.Detail)
}

func (e *UnlockError) Unwrap() error {
	return e.Err
}

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

// UnsupportedFilesystemError names the filesystem type that
// MakeFilesystemWithOptions or CheckFilesystem refused because it is not in
// SupportedFilesystems(). It unwraps to ErrUnsupportedFilesystem.
type UnsupportedFilesystemError struct {
	// Filesystem is the type the caller asked for.
	Filesystem FilesystemType
}

func (e *UnsupportedFilesystemError) Error() string {
	return fmt.Sprintf("%s: %q", ErrUnsupportedFilesystem.Error(), string(e.Filesystem))
}

func (e *UnsupportedFilesystemError) Unwrap() error { return ErrUnsupportedFilesystem }

// FilesystemCommandError reports that an external filesystem tool (a checker
// such as e2fsck or fsck.fat) exited unsuccessfully. It carries the tool's
// combined output so the cause can be read without re-running it, and keeps the
// exec error reachable through Unwrap.
type FilesystemCommandError struct {
	// Command is the program that was run.
	Command string

	// Device is the device path it was run against.
	Device string

	// Output is the program's combined stdout and stderr.
	Output string

	// Err is the error from running the program, typically an *exec.ExitError.
	Err error
}

func (e *FilesystemCommandError) Error() string {
	return fmt.Sprintf("%s %s failed: %v\nOutput: %s", e.Command, e.Device, e.Err, e.Output)
}

func (e *FilesystemCommandError) Unwrap() error { return e.Err }

// PBKDFIterationsError reports that an explicit PBKDF2 iteration count was
// refused, and carries both numbers so the caller can act without guessing what
// the floor is.
//
// The floor is a function of the HASH, not a single constant: it is the larger
// of this package's absolute minimum and OWASP's recommendation for that hash
// at the reference budget, so the same count is acceptable under sha512 and
// refused under sha256. Reporting only "too low" would leave a caller unable to
// tell which.
type PBKDFIterationsError = kdf.PBKDF2IterationsError

// Argon2CostError reports that an Argon2 cost a caller supplied was refused,
// and carries the permitted range so the caller can act without guessing.
//
// It is the Argon2 counterpart of PBKDFIterationsError and deliberately reads
// the same way: both are refusals of a CALLER-CHOSEN keyslot cost, and an
// operator should not have to learn two vocabularies for one decision.
//
// It wraps the existing sentinels rather than replacing them, so
// errors.Is(err, ErrInvalidArgon2Memory) stays true of the same value and
// callers that already branch on those do not change.
type Argon2CostError = kdf.Argon2CostError

// NonApprovedKDF names one keyslot or digest whose KDF FIPS 140-3 mode cannot
// execute. ID is the header's own key for the object; Type and Hash are its KDF
// as declared ("argon2id" and "", or "pbkdf2" and "sha1").
type NonApprovedKDF struct {
	ID   string
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
// does NOT unwrap to the scan's ErrInvalidKeyslot or ErrInvalidHeader: those
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
		uses = append(uses, fmt.Sprintf("keyslot %s uses %s", k.ID, k))
	}
	for _, d := range e.Digests {
		uses = append(uses, fmt.Sprintf("digest %s uses %s", d.ID, d))
	}
	return fmt.Sprintf("%s: %s is intact, but this process runs in FIPS 140-3 mode and %s, which FIPS mode cannot execute; "+
		"no key was derived through them, so this is not a verdict on the volume or on the passphrase; "+
		"import it once with MigrateToFIPS from a process that is NOT in FIPS mode -- it rewraps the existing volume key "+
		"under PBKDF2 without re-encrypting any data -- and this process can then open it",
		ErrFIPSImportRequired.Error(), e.Device, strings.Join(uses, " and "))
}

// Is reports a match for ErrFIPSImportRequired and ErrFIPSNotApproved.
func (e *FIPSImportRequiredError) Is(target error) bool {
	return target == ErrFIPSImportRequired || target == ErrFIPSNotApproved
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

func (e *FIPSMigrationError) Error() string {
	return fmt.Sprintf("FIPS import of %s failed at %s: %v; %s", e.Device, e.Stage, e.Err, e.State)
}

func (e *FIPSMigrationError) Unwrap() error { return e.Err }

// Validation errors: device paths, credentials and format parameters.
var (
	ErrInvalidPath        = errors.New("invalid device path")
	ErrPassphraseTooShort = errors.New("passphrase too short (minimum 8 bytes)")
	ErrPassphraseTooLong  = errors.New("passphrase too long (maximum 512 bytes)")

	// ErrCredentialEmpty and ErrCredentialTooLong bound an EXISTING
	// credential -- one presented to open a keyslot, not one being created.
	// See validateExistingCredential.
	ErrCredentialEmpty   = errors.New("credential is empty")
	ErrCredentialTooLong = errors.New("credential too long (maximum 8 MiB, cryptsetup's key file limit)")
	ErrInvalidKeySize    = errors.New("invalid key size (must be 256 or 512 bits)")
	ErrInvalidSectorSize = errors.New("invalid sector size (must be 512 or 4096)")
	//nolint:lll // the message states the accepted set, like its siblings above
	ErrInvalidMetadataSize = errors.New("invalid metadata size (must be 0 for the default, or a power of two from 16 KiB to 4 MiB)")
	ErrInvalidArgon2Memory = errors.New("invalid Argon2 memory (must be 65536..4194304 KB)")
	ErrInvalidArgon2Time   = errors.New("invalid Argon2 time cost (must be 1..10000)")
	//nolint:lll // the message states the bound, like its two siblings above
	ErrInvalidArgon2Parallel = errors.New("invalid Argon2 parallelism (must be 1..255)")
	ErrIntegerOverflow       = errors.New("integer overflow detected")

	// ErrInvalidMappingName indicates a device-mapper mapping name that this
	// library will not create. See ValidateMappingName for what the name
	// reaches and why the charset is a whitelist.
	ErrInvalidMappingName = errors.New("invalid device-mapper mapping name")
)

// Errors Format and ValidateFormatOptions refuse with before the device is
// touched (#248).
var (
	// ErrUnsupportedCipher indicates a Cipher, CipherMode and KeySize that are
	// not a combination Format writes: aes-xts-plain64 with a 256- or 512-bit
	// key, or aes-cbc-essiv:sha256 with a 256-bit key.
	ErrUnsupportedCipher = errors.New("unsupported cipher, mode and key size combination")

	// ErrInvalidLabel indicates a Label or Subsystem that does not fit the
	// 48-byte header field with its NUL terminator, or that contains a NUL.
	ErrInvalidLabel = errors.New("label must be at most 47 bytes and contain no NUL byte")

	// ErrDeviceTooSmall indicates a device with no room for the header copies,
	// the keyslots area and at least one encryption sector of data.
	ErrDeviceTooSmall = errors.New("device is too small for a LUKS2 container")
)

// Wipe refusals.
var (
	// ErrDeviceInUse indicates a destructive operation refused a block device
	// that something else holds: it is mounted, it backs a device-mapper
	// mapping or an md array, or another process opened it exclusively. The
	// kernel reports this when the device is opened with O_EXCL.
	// Defined once, in internal/device, and re-exported by value.
	ErrDeviceInUse = device.ErrInUse

	// ErrWipeVerification indicates that what was read back from the medium,
	// past the page cache, is not what the last wipe pass wrote.
	ErrWipeVerification = errors.New("wipe verification failed: the medium does not hold what the last pass wrote")
)

// Recovery-key generation refusals (#249, A4).
var (
	// ErrRecoveryKeyTooShort is returned for a recovery key of fewer than
	// RecoveryKeyLength random bytes, or one whose rendering is too long to be
	// enrolled as a passphrase.
	ErrRecoveryKeyTooShort = errors.New("recovery key length out of range (at least 32 random bytes, and a rendering no longer than 512 bytes)")

	// ErrInvalidRecoveryKeyFormat is returned for a format other than hex,
	// base64 or dashed.
	ErrInvalidRecoveryKeyFormat = errors.New("unknown recovery key format (hex, base64 or dashed)")
)

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

// The external-key vocabulary (keyprovider.go).
var (
	// ErrKeyProvider is the sentinel every external-key failure matches.
	ErrKeyProvider = errors.New("external key provider")

	// ErrNoKeyProvider indicates an operation was given no provider, or a token
	// with nothing in it to build one from.
	ErrNoKeyProvider = errors.New("no key provider")

	// ErrHelperNotConfigured indicates the provider has no command to run. It is
	// distinct from a helper that is missing on disk: nothing was named, so
	// nothing was looked for.
	ErrHelperNotConfigured = errors.New("no helper command configured")

	// ErrHelperPathNotAbsolute indicates a helper was named by a relative path
	// or a bare command name. It is refused rather than looked up on PATH,
	// whose contents belong to whoever invoked the process.
	ErrHelperPathNotAbsolute = errors.New("helper path is not absolute")

	// ErrNoFIDO2Device indicates a FIDO2 operation was given no authenticator
	// device. The libfido2 helpers require one, and an empty argument in its
	// place is not a default.
	ErrNoFIDO2Device = errors.New("no FIDO2 authenticator device named")

	// ErrHelperFailed indicates the helper ran and exited non-zero -- the
	// authenticator refused, the touch timed out, the PIN was wrong.
	ErrHelperFailed = errors.New("key helper failed")

	// ErrHelperOutput indicates the helper SUCCEEDED and produced something this
	// package cannot use: too few lines, an empty credential, output that is not
	// the expected encoding.
	//
	// It is deliberately separate from ErrHelperFailed. A helper that exits 0
	// and prints the wrong thing is a protocol mismatch -- a different helper
	// version, a changed output order -- and telling an operator "the
	// authenticator refused" would send them to look at the hardware.
	ErrHelperOutput = errors.New("unusable key helper output")

	// ErrUnsupportedTokenType indicates a token names a mechanism this package
	// cannot drive. The token is left alone: another implementation may well be
	// able to use it.
	ErrUnsupportedTokenType = errors.New("unsupported token type")

	// ErrInvalidFIDO2Binding indicates a FIDO2 binding is missing a field an
	// assertion needs, or carries one that does not decode.
	ErrInvalidFIDO2Binding = errors.New("invalid FIDO2 binding")

	// ErrOrphanedKeyslot indicates a credential was written to a keyslot, the
	// token identifying it could not be written, AND the keyslot could not be
	// removed again.
	//
	// This is the one outcome in this file that needs a human. The volume now
	// has a live credential that nothing on the device describes: it opens the
	// volume, it cannot be told apart from a credential still in use, and the
	// only record of which slot it is, is this error.
	ErrOrphanedKeyslot = errors.New("orphaned keyslot")
)

// ErrMetadataJSON indicates that a LUKS2 metadata object could not be
// converted to or from JSON.
//
// It is raised where the CONVERSION fails, and says nothing about whether the
// object is a valid LUKS2 object: a syntactically perfect keyslot with an
// impossible key size decodes cleanly and is refused elsewhere.
var ErrMetadataJSON = header.ErrMetadataJSON

// ErrAmbiguousJSONMember indicates a LUKS2 metadata object that names one
// member twice, or names a member this package models in a different case
// ("Keyslots" for "keyslots").
//
// Such an object reads differently to different implementations, so it is
// refused rather than interpreted (#248). encoding/json binds a member to a
// struct field CASE-INSENSITIVELY and lets the last duplicate win; json-c,
// which cryptsetup parses the header with, is case-sensitive. A digest
// carrying {"keyslots":["0"], "Keyslots":["1"]} attests keyslot 0 to
// cryptsetup and keyslot 1 to this package -- and the next header write by this
// package would have rewritten it to what this package saw.
var ErrAmbiguousJSONMember = header.ErrAmbiguousJSONMember

// ErrPrimaryHeaderCurrent indicates RestorePrimaryHeader was refused because
// the primary header copy is intact and at least as new as the secondary, so
// restoring would roll the volume back rather than repair it.
var ErrPrimaryHeaderCurrent = header.ErrPrimaryHeaderCurrent

// ErrTokenNotFound indicates the token was not found
var ErrTokenNotFound = errors.New("token not found")

// ErrNoFreeTokenSlot indicates no free token slots are available
var ErrNoFreeTokenSlot = errors.New("no free token slots available")
