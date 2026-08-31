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

	// ErrInvalidPassphrase indicates the passphrase is incorrect
	ErrInvalidPassphrase = errors.New("invalid passphrase")

	// ErrDeviceNotFound indicates the device path doesn't exist
	ErrDeviceNotFound = errors.New("device not found")

	// ErrVolumeNotUnlocked indicates the volume is not unlocked
	ErrVolumeNotUnlocked = errors.New("volume not unlocked")

	// ErrVolumeAlreadyUnlocked indicates the volume is already unlocked
	ErrVolumeAlreadyUnlocked = errors.New("volume already unlocked")

	// ErrNotMounted indicates the path is not mounted
	ErrNotMounted = errors.New("not mounted")

	// ErrAlreadyMounted indicates the path is already mounted
	ErrAlreadyMounted = errors.New("already mounted")

	// ErrUnsupportedKDF indicates the KDF type is not supported
	ErrUnsupportedKDF = errors.New("unsupported KDF type")

	// ErrUnsupportedHash indicates the hash algorithm is not supported
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

	// ErrPermissionDenied indicates insufficient permissions
	ErrPermissionDenied = errors.New("permission denied")

	// ErrMasterKeyVerification indicates that a candidate master key did not
	// match any digest in the header. It is deliberately one value for every
	// cause -- mismatch, an unsupported or FIPS-refused digest KDF, a corrupt
	// salt, a digest of implausible length -- so that neither the message nor
	// the number of digests tried tells a caller which digest rejected the key.
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
)

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
