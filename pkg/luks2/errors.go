// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"errors"
	"fmt"
)

// Common errors that can be checked using errors.Is()
var (
	// ErrInvalidHeader indicates a LUKS header is invalid or corrupted
	ErrInvalidHeader = errors.New("invalid LUKS header")

	// ErrDeviceNotFound indicates the device path doesn't exist
	ErrDeviceNotFound = errors.New("device not found")

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
	ErrUnsupportedKDF = errors.New("unsupported KDF type")

	// ErrUnsupportedHash indicates the hash algorithm named by a header, or by a
	// caller's options, is not one this package implements. A FIPS-refused
	// algorithm is NOT this error -- that is ErrFIPSNotApproved, because the
	// algorithm is implemented and the mode refuses it, which is a different
	// thing for an operator to be told.
	ErrUnsupportedHash = errors.New("unsupported hash algorithm")

	// ErrInvalidKeyslot indicates the keyslot is invalid or unavailable
	ErrInvalidKeyslot = errors.New("invalid keyslot")

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
	ErrPermissionDenied = errors.New("permission denied")

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

	// ErrMetadataTooLarge indicates the JSON metadata does not fit the header
	// area the container was formatted with. The area cannot be enlarged after
	// the fact -- the keyslots and data offsets on disk are already sized
	// against it -- so this is a refusal, not a retryable condition.
	ErrMetadataTooLarge = errors.New("metadata does not fit the header area")

	// ErrKeyslotsAreaFull indicates the container has no room for another
	// keyslot: the new one would fall outside the keyslots area the header
	// declares, or past the start of the encrypted data. Both are refusals
	// rather than retryable conditions -- the area is fixed at format time.
	ErrKeyslotsAreaFull = errors.New("no room in the keyslots area for another keyslot")

	// ErrFIPSNotApproved indicates the requested algorithm is not approved by
	// the Go Cryptographic Module and is refused while the process runs in
	// FIPS 140-3 mode. See docs/FIPS.md.
	ErrFIPSNotApproved = errors.New("algorithm not approved in FIPS 140-3 mode")

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

	// ErrProtectedMemory indicates that key material could not be placed in, or
	// read back from, protected memory, and that the operation was therefore
	// REFUSED rather than completed with the material on the ordinary heap.
	//
	// It is almost always a deployment condition rather than a defect: the
	// process has hit RLIMIT_MEMLOCK. See ProtectedMemoryError for the amount
	// this library needs and for why the refusal is not negotiable.
	ErrProtectedMemory = errors.New("key material could not be held in protected memory")

	// ErrKeyring is the ROOT of every keyring condition in this package, and
	// the only sentinel that is safe to use as a catch-all.
	//
	// It exists because ErrKeyringUnavailable is NOT one, and reading it as one
	// is a mistake with real consequences: ErrKeyringEntryExists and
	// ErrKeyringKeyNotReleased are anomalies rather than unavailability and do
	// not match it. A caller whose catch-all was ErrKeyringUnavailable would
	// silently miss both -- including the one that reports that a volume master
	// key may still be resident in the kernel. Every sentinel below matches
	// this one; TestKeyringSentinelsFormOneFamily pins that.
	ErrKeyring error = keyringSentinel("a kernel keyring operation failed")

	// ErrKeyringUnavailable indicates that the volume key could not be placed
	// in the kernel keyring, and that the operation was therefore REFUSED.
	//
	// There is no fallback. The only other way to give dm-crypt a key is INSIDE
	// the device-mapper table, where a third-party library hex-encodes it into
	// unwipeable Go strings and an uncleared ioctl buffer -- so a fallback would
	// silently trade the guarantee this library exists to provide for the
	// exposure it exists to close. Owner ruling 2026-08-31: fail closed, we do
	// not support legacy kernels that are insecure.
	//
	// It is the umbrella for UNAVAILABILITY specifically, and every
	// unavailability also matches exactly one of the four causes below, because
	// they are four different problems with four different fixes and a single
	// "unavailable" would be technically true and operationally useless.
	//
	// It is NOT the catch-all for everything keyring-shaped, and an earlier
	// version of this comment said it was. ErrKeyringEntryExists and
	// ErrKeyringKeyNotReleased do not match it. Use ErrKeyring for "any keyring
	// condition"; the preamble in enclave.go about an understated claim being
	// worse than the state it describes applies to this file too.
	//
	// Use CheckKeyringAvailable at startup so this is a configuration error
	// rather than an outage at first unlock.
	ErrKeyringUnavailable error = keyringSentinel("the volume key could not be placed in the kernel keyring")

	// ErrKeyringBlocked indicates the kernel keyring syscalls are refused by
	// policy rather than being absent -- almost always a container seccomp
	// profile. MEASURED 2026-08-31: Docker's default profile denies add_key,
	// keyctl and request_key, and --cap-add SYS_ADMIN does NOT lift it; only
	// relaxing seccomp does. The fix is a narrow custom profile, not
	// seccomp=unconfined.
	ErrKeyringBlocked error = keyringSentinel("the kernel keyring syscalls are blocked by policy")

	// ErrKeyringUnsupported indicates the kernel does not implement the keyring
	// syscalls at all -- built without CONFIG_KEYS. There is no configuration
	// that fixes this; the kernel cannot hold a volume key.
	ErrKeyringUnsupported error = keyringSentinel("this kernel does not implement the keyring syscalls")

	// ErrKeyringQuotaExhausted indicates the per-user kernel key quota is full.
	// It is a resource condition, recoverable by raising the quota or by
	// finding what is leaking keys.
	ErrKeyringQuotaExhausted error = keyringSentinel("the kernel key quota for this user is exhausted")

	// ErrKeyringFailed indicates the keyring syscalls are reachable and the
	// kernel refused the operation anyway, for a reason none of the other three
	// describe. It is the residual case and it names no remedy, because none
	// can be inferred.
	ErrKeyringFailed error = keyringSentinel("the kernel keyring refused the operation")

	// ErrKeyringEntryExists indicates a key was ALREADY present under the
	// description this unlock was about to use.
	//
	// It is an anomaly, not a routine condition, and it is refused rather than
	// resolved. add_key UPDATES a key of the same type and description in place
	// instead of failing, so proceeding would either overwrite key material
	// this process did not create or adopt a stale entry as though it were
	// ours -- both silently. The description is derived from the volume's
	// identity precisely so that a collision means something: a leftover from a
	// crashed process, a concurrent unlock of the same volume, or another
	// process of the same uid planting an entry.
	ErrKeyringEntryExists error = keyringSentinel("a kernel keyring entry already exists for this volume")

	// ErrKeyringKeyNotReleased indicates that a keyring entry holding a volume
	// key could not be revoked and unlinked after the activation that needed
	// it, and that the key MAY STILL BE PRESENT in the kernel keyring.
	//
	// It is reported rather than swallowed for the same reason
	// ErrMappingStillLive is: undestroyed key material nobody is told about is
	// worse than a failed operation. It is also raised when absence could not
	// be CONFIRMED, not only when removal is known to have failed -- release
	// verifies by searching rather than trusting the syscall return values. An
	// entry that was already gone is not this error.
	ErrKeyringKeyNotReleased error = keyringSentinel("a kernel keyring entry holding the volume key could not be released")
)

// keyringSentinel is the type every keyring sentinel above has, so that all of
// them report themselves as ErrKeyring while remaining distinct from each
// other.
//
// A plain errors.New value cannot do that -- errors.Is compares those by
// identity and there is nowhere to hang a second relationship -- and wrapping
// each sentinel in an ErrKeyring at every construction site would prefix every
// message with the root's text. The type is a string so two sentinels are
// distinct exactly when their messages differ, which is how they are declared.
type keyringSentinel string

func (e keyringSentinel) Error() string { return string(e) }

// Is reports every sentinel as the ErrKeyring root, so a caller can match "any
// keyring condition" with one target and still match the specific one it can
// act on. errors.Is has already tried equality by the time this is called, so
// this only ever adds the root.
func (e keyringSentinel) Is(target error) bool { return target == ErrKeyring }

// KeyringUnavailableError reports that the kernel keyring could not hold the
// volume key, names the step that failed, and carries the REMEDY for the
// specific cause.
//
// # Why the remedy is in the error and not only in the docs
//
// The overwhelmingly common cause is a container seccomp profile, and the
// operator who meets it is reading a log line, not this file. The message
// therefore names the three syscalls -- add_key, keyctl, request_key -- so a
// profile can be written from the error text alone, and says that
// --cap-add SYS_ADMIN does not help, because that is the first thing anyone
// tries and it is measurably wrong.
//
// # Why it is fatal and never a degradation
//
// Same reasoning as ProtectedMemoryError, and it is the owner's ruling
// (2026-08-31): the alternative is the volume master key in memory this library
// cannot wipe, for an unbounded time, and a caller that got a successful return
// would believe a guarantee that did not hold. The failure is recoverable by
// configuration; the leak is not recoverable at all.
type KeyringUnavailableError struct {
	// Op names the keyring step that failed, for example "add the volume key
	// to the session keyring". It never carries key content.
	Op string

	// Kind is the sentinel naming the cause: ErrKeyringBlocked,
	// ErrKeyringUnsupported, ErrKeyringQuotaExhausted or ErrKeyringFailed.
	Kind error

	// Err is the underlying errno, kept reachable through Unwrap so a caller
	// can match unix.EPERM, unix.EDQUOT or unix.ENOSYS directly.
	Err error
}

func (e *KeyringUnavailableError) Error() string {
	return fmt.Sprintf("%s: could not %s: %v. %s", e.kind().Error(), e.Op, e.Err, keyringRemedy(e.kind()))
}

// kind returns the classification, defaulting a zero value to ErrKeyringFailed.
// Nothing in this package constructs one without a Kind, but this type is
// exported and formatting an error is the worst possible moment to panic:
// Error() is what runs while something else is already going wrong.
func (e *KeyringUnavailableError) kind() error {
	if e.Kind == nil {
		return ErrKeyringFailed
	}
	return e.Kind
}

func (e *KeyringUnavailableError) Unwrap() error { return e.Err }

// Is reports every KeyringUnavailableError as its specific cause, as the
// ErrKeyringUnavailable umbrella and as the ErrKeyring root, so a caller can
// branch on the cause it can do something about and fall back to either
// umbrella for the rest, while errors.Is also still reaches the errno through
// Unwrap.
func (e *KeyringUnavailableError) Is(target error) bool {
	return target == ErrKeyring || target == ErrKeyringUnavailable || target == e.kind()
}

// keyringRemedy returns the operator guidance for a cause.
//
// Each one is a complete instruction rather than a hint. An operator should be
// able to act on it without reading the source, which is the whole point of
// putting it here instead of in a comment.
func keyringRemedy(kind error) string {
	switch kind {
	case ErrKeyringBlocked:
		return "This is almost always a container seccomp profile: Docker's DEFAULT profile denies the add_key, keyctl and request_key syscalls, and (measured) --cap-add SYS_ADMIN does NOT lift that -- only relaxing seccomp does. " +
			"Allow those three syscalls in a NARROW custom profile and run with --security-opt seccomp=<profile>.json; prefer that over --security-opt seccomp=unconfined, which also drops every other syscall restriction. " +
			"Under Kubernetes the equivalent is a localhost seccomp profile in securityContext.seccompProfile. " +
			"Call CheckKeyringAvailable at startup so this is found at boot rather than at the first unlock."
	case ErrKeyringUnsupported:
		return "The kernel was built without CONFIG_KEYS, so it cannot hold a volume key at all and no runtime configuration will change that. This library requires a kernel with keyring support; it does not fall back to putting the key in the device-mapper table."
	case ErrKeyringQuotaExhausted:
		return "Raise the per-user key quota (/proc/sys/kernel/keys/maxkeys and maxbytes, or root_maxkeys and root_maxbytes for uid 0), or find what is leaking keys with `keyctl show` -- this library releases every entry it creates as soon as the activation ioctl returns, so a growing key count is coming from elsewhere."
	default:
		return "The keyring syscalls are reachable and the operation was refused anyway; the cause reported above is the kernel's own answer."
	}
}

// ProtectedMemoryError reports that a piece of key material could not be held
// in protected memory, and names the operation that needed it.
//
// # Why this is fatal and never a degradation
//
// Every path in this package that meets one of these FAILS CLOSED: the
// operation is abandoned and no key material is placed on the ordinary heap
// instead. The reasoning is deliberate and worth stating, because failing an
// unlock has a real availability cost:
//
//   - A caller that gets a successful return believes the protected-memory
//     mandate held for that operation. A silent fallback makes that belief
//     wrong exactly when it matters -- on a machine already under memory
//     pressure, which is also where swapping is most likely.
//   - The failure is recoverable and the leak is not. An operator can raise
//     RLIMIT_MEMLOCK and retry; a master key that reached swap or a core dump
//     cannot be recalled, and nothing tells anyone it happened.
//   - This is disk encryption. The material at stake is the volume master key,
//     which is the entire secret -- not a session token that expires.
//
// # What an operator has to provide
//
// The locked memory a single operation needs is dominated by the anti-forensic
// stripes, which are key_size * stripes bytes, held alongside their decrypted
// counterpart.
//
// For a container THIS library wrote that is 256 KiB each, so roughly 512 KiB
// of RLIMIT_MEMLOCK headroom per operation in flight. That figure is the
// DEFAULT GEOMETRY, not the requirement, and an earlier version of this comment
// gave it as though it were the requirement -- which is wrong for exactly the
// case that matters, a header someone else wrote.
//
// The requirement is the ceiling the header bounds allow: key_size up to 1024
// bytes and stripes up to 4000, so about 4 MiB of stripes plus 4 MiB of
// decrypted keyslot material. Budget 8 MiB per concurrent operation for
// containers whose headers are not yours. See keyslotvalidation.go for where
// those bounds come from.
//
// 8 MiB is a typical host default exactly, and it is well ABOVE the 64 KiB some
// container runtimes still impose. A container that runs these operations must
// raise its memlock ulimit.
//
// # What is NOT bounded
//
// There is no AGGREGATE budget across an operation, and none can be inferred
// from the per-item bounds: an unlock derives once per keyslot and once per
// digest per keyslot, and the digest count is not bounded at parse. go-enclave
// ships an Allocator for exactly this -- a byte budget admitted against before
// anything is mapped -- and this package does not use one yet. Deliberately
// deferred rather than overlooked: the fix is a design choice with its own
// failure mode (a budget refuses a legitimately large honest container the same
// way it refuses a crafted one), and it is tracked with the aggregate KDF-cost
// problem in issue #26.
//
// Cause is go-enclave's error and matches enclave.ErrLockedMemoryUnavailable
// when the kernel refused the lock, so a caller can tell a resource limit from
// a use-after-destroy without depending on message text.
type ProtectedMemoryError struct {
	// Op names the material or step that needed protected memory, for example
	// "master key" or "af split". It never carries key content, and it never
	// carries a key LENGTH: a size in an error string is a fact about the
	// volume that the error path has no reason to publish.
	Op  string
	Err error
}

func (e *ProtectedMemoryError) Error() string {
	return fmt.Sprintf("%s: %s: %v", ErrProtectedMemory.Error(), e.Op, e.Err)
}

func (e *ProtectedMemoryError) Unwrap() error {
	return e.Err
}

// Is reports every ProtectedMemoryError as ErrProtectedMemory, so callers can
// match the sentinel without knowing this type, while errors.Is also still
// reaches the underlying go-enclave cause through Unwrap.
func (e *ProtectedMemoryError) Is(target error) bool {
	return target == ErrProtectedMemory
}

// DeviceError represents an error related to a specific device
type DeviceError struct {
	Device string
	Op     string
	Err    error
}

func (e *DeviceError) Error() string {
	return fmt.Sprintf("%s %s: %v", e.Op, e.Device, e.Err)
}

func (e *DeviceError) Unwrap() error {
	return e.Err
}

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
