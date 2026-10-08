// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/jeremyhahn/go-luks2/internal/clock"
	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/internal/kdf"
)

// Security constants
const (
	MinPassphraseLength = 8
	MaxPassphraseLength = 512
	minKeySize          = 256
	maxKeySize          = 512
	minSectorSize       = 512
	maxSectorSize       = 4096
	// digestIterationTargetMs is how long the master-key digest's PBKDF2 is
	// calibrated to take, and it replaces the DigestIterations constant that
	// used to fix the count at 600000.
	//
	// # WHAT THIS PARAMETER IS AND IS NOT
	//
	// It buys essentially NO SECURITY, and pretending otherwise is how it gets
	// mis-tuned. The digest verifies a candidate MASTER KEY -- 512 bits from a
	// CSPRNG -- so there is no guessable input for an iteration count to slow
	// down and no offline search for it to multiply. The count that does defend
	// a guessable secret is the KEYSLOT KDF's, whose floor
	// (pbkdf2RecommendedIterations, kdf.go) is non-negotiable and unrelated to
	// this. What this controls is unlock latency and behavioral parity with
	// cryptsetup. Nothing else.
	//
	// # WHY 100ms, MEASURED
	//
	// cryptsetup CALIBRATES the digest; it does not pin it. Across 14 default
	// containers on one host, converting each recorded count by this machine's
	// measured PBKDF2 rate:
	//
	//	--hash sha512   317750..328090 iterations   96.7..101.0 ms
	//	--hash sha256   493679..518071 iterations   47.1.. 49.5 ms
	//
	// The two hashes look like different targets and are not. cryptsetup
	// benchmarks a FIXED 64-BYTE derivation whatever the hash, and for sha256
	// that is two PBKDF2 blocks per iteration rather than one. Re-measuring at
	// 64 bytes collapses them: sha512 100.0ms, sha256 101.0ms. Hence
	// DigestCalibrationKeyLen below, and hence 100.
	//
	// The digest cost is also independent of the KEYSLOT budget -- measured at
	// --iter-time 500/2000/8000, the keyslot count scaled 16x while the digest
	// held between 452753 and 468951 -- which is why it needs its own target
	// rather than a share of the keyslot's.
	//
	// # THE MEASUREMENT TRAP
	//
	// A container formatted with --pbkdf-force-iterations reports a digest of
	// exactly the forced value, because that flag pins the DIGEST as well as
	// the keyslot. Measuring that way shows a digest of 1000 and invites the
	// conclusion that cryptsetup hardcodes it. That conclusion was drawn here,
	// acted on, and reverted: the flag was writing the number the measurement
	// then attributed to cryptsetup. Take this measurement on DEFAULT
	// containers or not at all.
	digestIterationTargetMs = kdf.DigestIterationTargetMs

	// digestCalibrationKeyLen is the derived-key length the digest calibration
	// benchmarks, fixed at 64 bytes REGARDLESS of the hash because that is what
	// cryptsetup does.
	//
	// It is deliberately not the digest's own output length. Deriving 64 bytes
	// costs one PBKDF2 block under sha512 and two under sha256, so calibrating
	// at the hash's own length would target 100ms of real work for every hash
	// and produce roughly twice cryptsetup's count for sha256. That is arguably
	// the more principled number and it is not the one the reference
	// implementation writes; parity is worth more here than tidiness, given the
	// parameter defends nothing. The practical effect is that a sha256 digest
	// costs ~50ms at unlock and a sha512 one ~100ms, exactly as cryptsetup's do.
	digestCalibrationKeyLen = kdf.DigestCalibrationKeyLen
)

// validateDevicePath validates a device path for security
func validateDevicePath(device string) error {
	if device == "" {
		return &errs.Error{Kind: ErrInvalidArgument, Detail: "device path is empty"}
	}

	// Clean the path. On an ABSOLUTE path Clean resolves every ".." element
	// lexically, so nothing that survives the IsAbs check below can climb
	// above the root. The substring check that used to follow refused nothing
	// that check does not, and refused legitimate names that merely contain
	// two dots, such as /dev/disk/by-label/a..b (#249, A10).
	cleaned := filepath.Clean(device)

	// Must be absolute path
	if !filepath.IsAbs(cleaned) {
		return &errs.Error{Kind: ErrInvalidArgument, Detail: "device path is not absolute"}
	}

	// Check that device exists
	info, err := os.Stat(cleaned)
	if err != nil {
		if os.IsNotExist(err) {
			return &errs.Error{Kind: ErrDeviceNotFound, Err: err}
		}
		return &errs.Error{Kind: ErrInvalidArgument, Detail: err.Error()}
	}

	// Must be a regular file or block device
	mode := info.Mode()
	if !mode.IsRegular() && (mode&os.ModeDevice == 0) {
		return &errs.Error{Kind: ErrInvalidArgument, Detail: "device path is neither a regular file nor a block device"}
	}

	return nil
}

// maxCredentialLength is the longest EXISTING credential this package will
// present to a keyslot: cryptsetup's key file limit (DEFAULT_KEYFILE_SIZE_MAXKB,
// 8 MiB). A keyslot cryptsetup enrolled from a key file can only be opened with
// the whole file.
const maxCredentialLength = 8 << 20

// validateExistingCredential bounds a credential presented to OPEN a keyslot --
// Unlock, TestKey, the existing passphrase of AddKey, ChangeKey's old one,
// RemoveKey, KillSlot and MigrateToFIPS -- as opposed to one being enrolled.
//
// # Why this is not ValidatePassphrase (#249, A7)
//
// ValidatePassphrase's 8..512 bytes is a POLICY for credentials this package
// creates, and it was applied to credentials that already exist. A keyslot does
// not record how long its passphrase was, and cryptsetup enrolls key files of
// up to 8 MiB -- `dd bs=4096 count=1` is the common recipe -- and passphrases
// shorter than 8 characters. Such a volume could never be unlocked, tested,
// rotated or used to authenticate through this package: the policy refused
// the one credential that opens it, before any keyslot was tried.
//
// Policy has no purchase on an existing credential: refusing it does not make
// the keyslot stronger, it only locks its owner out. So only what no keyslot
// can be opened with is refused -- nothing at all -- and what cryptsetup itself
// will not read past.
func validateExistingCredential(credential []byte) error {
	if len(credential) == 0 {
		return ErrInvalidCredential
	}
	if len(credential) > maxCredentialLength {
		return ErrInvalidCredential
	}
	return nil
}

// validatePassphraseBytes validates the length of a NEW passphrase: the policy for a
// credential this package enrolls (Format, AddKey's new passphrase, ChangeKey's
// new one). A credential presented to open an existing keyslot is bounded by
// validateExistingCredential instead.
func validatePassphraseBytes(passphrase []byte) error {
	if len(passphrase) < MinPassphraseLength {
		return ErrInvalidCredential
	}
	if len(passphrase) > MaxPassphraseLength {
		return ErrInvalidCredential
	}
	return nil
}

// minArgon2MemoryKB is the smallest Argon2 memory cost this package will WRITE
// when a caller chooses it.
//
// # A CREATE FLOOR, NOT AN ACCEPT FLOOR
//
// These are two different decisions and they were one code path. Refusing to
// CREATE a weak keyslot is this package's judgement to make. Refusing to TOUCH
// a container someone else created is not: cryptsetup has no such floor, a
// low-memory or embedded device has good reason to format below 64 MiB, and a
// library that will not open, rotate or remove a credential on a container the
// reference implementation considers valid has turned a hardening preference
// into an interop failure.
//
// So the accept side is deliberately far more liberal -- header.MinArgon2Memory in
// internal/header/keyslot.go is 8 KiB, below even cryptsetup's own 32 -- and every
// read path, RemoveKey and KillSlot go through that one instead. This bound
// applies only where a caller SUPPLIES a cost: Format and AddKey.
//
// ChangeKey is deliberately NOT bound by it. It inherits the cost of the slot
// it is rotating, which is a cost this package did not choose, on hardware that
// has already demonstrated it can afford that and nothing more. See ChangeKey.
const minArgon2MemoryKB = kdf.MinArgon2MemoryKB

// header.MinArgon2Time, in internal/header/keyslot.go, is the smallest Argon2 time cost
// this package will write. It is the format's own minimum; a zero or
// negative time cost is not a weak keyslot but a malformed one.
//
// header.MinArgon2Parallel, also there, is the smallest Argon2 parallelism this
// package will write, for the same reason: Argon2 parallelism is a uint8 in
// 1..255, so zero or negative is malformed, not weak. Its CEILING, like
// Time's and Memory's, is the read side's own (header.MaxArgon2Parallel,
// internal/header/keyslot.go), applied by validateArgon2CreateCost so nothing is
// written that the reader would refuse (#249, A5).

// validateArgon2CreateCost bounds the Argon2 costs a CALLER supplies.
//
// Split out of validateFormatOptionsForTest so AddKey can apply the identical bound
// without inheriting the rest of it -- device paths, passphrase lengths, sector
// sizes -- none of which AddKey is in a position to check. Before this, the
// bound existed on Format alone, so AddKey with an explicit Argon2Memory of 32
// wrote a keyslot Format would have refused: a floor reachable from one entry
// point and not the other, which is the shape of every bypass in this package's
// history.
//
// The KDF is judged as it RESOLVES, not as it is spelled: an empty KDFType
// with an Argon2 cost resolves to Argon2id (resolveKDFType), and the bound
// applies to it. Checking the spelling let FormatOptions{Argon2Memory: 32}
// past this floor because the type was left to the default (#237).
func validateArgon2CreateCost(opts formatOptionsForTest) error {
	if !isArgon2Type(resolveKDFType(normalizeKDFType(opts.KDFType), formatArgon2CostGiven(opts))) {
		return nil
	}
	// Each cost has a FLOOR -- what this package will write -- and a CEILING,
	// which is exactly what header.ValidateKDFCost refuses when the header is read
	// back (#249, A5). Without the ceiling, Format with Argon2Memory 8 GiB on a
	// host that had the RAM derived, wrote and reported success, and every
	// later unlock refused the keyslot: a volume nothing can open, created on
	// request. The read-side bounds are the ones used, not restated, so the
	// two can never disagree about what a keyslot may cost.
	if opts.Argon2Memory != 0 && (opts.Argon2Memory < minArgon2MemoryKB || opts.Argon2Memory > header.MaxArgon2Memory) {
		return &KDFCostError{
			Param: "memory",
			Value: opts.Argon2Memory,
			Min:   minArgon2MemoryKB,
			Max:   header.MaxArgon2Memory,
		}
	}
	if opts.Argon2Time != 0 && (opts.Argon2Time < header.MinArgon2Time || opts.Argon2Time > header.MaxArgon2Time) {
		return &KDFCostError{
			Param: "time",
			Value: opts.Argon2Time,
			Min:   header.MinArgon2Time,
			Max:   header.MaxArgon2Time,
		}
	}
	// Parallelism is checked HERE, with its siblings, rather than being left to
	// deriveArgon2 (#176). It was refused -- `cpus must be between 1 and 255`
	// -- but one layer later, after the pre-check had passed, and as a
	// CryptoError rather than the Argon2CostError the other two produce. Same
	// mistake by the caller, two different error shapes and two different
	// moments.
	if opts.Argon2Parallel != 0 && (opts.Argon2Parallel < header.MinArgon2Parallel || opts.Argon2Parallel > header.MaxArgon2Parallel) {
		return &KDFCostError{
			Param: "parallelism",
			Value: opts.Argon2Parallel,
			Min:   header.MinArgon2Parallel,
			Max:   header.MaxArgon2Parallel,
		}
	}
	return nil
}

// validateFormatOptionsForTest validates all format options
func validateFormatOptionsForTest(opts formatOptionsForTest) error {
	// Validate device path
	if err := validateDevicePath(opts.Device); err != nil {
		return err
	}

	// Validate passphrase
	if err := validatePassphraseBytes(opts.Passphrase); err != nil {
		return err
	}

	// Validate key size
	if opts.KeySize != 0 && opts.KeySize != 256 && opts.KeySize != 512 {
		return ErrInvalidArgument
	}

	// Validate sector size
	if opts.SectorSize != 0 && opts.SectorSize != 512 && opts.SectorSize != 4096 {
		return ErrInvalidArgument
	}

	if err := validateMetadataSize(opts.MetadataSize); err != nil {
		return err
	}

	// Cipher, mode and key size as a combination, and the two labels (#248).
	if err := validateFormatChoices(opts); err != nil {
		return err
	}

	// Validate Argon2 parameters if specified
	if err := validateArgon2CreateCost(opts); err != nil {
		return err
	}

	// Check for integer overflow in size calculations
	if opts.KeySize > 0 {
		keyBytes := opts.KeySize / 8
		afSize := keyBytes * header.AFStripes
		if afSize/header.AFStripes != keyBytes {
			return ErrInvalidArgument
		}
	}

	return nil
}

// validateMetadataSize checks FormatOptions.MetadataSize against exactly the
// set cryptsetup's --luks2-metadata-size accepts: zero for the default, or a
// power of two from header.HeaderMinSize to header.HeaderMaxSize. Measured against
// cryptsetup 2.7.0 on #47 -- 8k, 12288, 20k and 8m are all refused there with
// "Unsupported LUKS2 metadata size options".
func validateMetadataSize(size int) error {
	if size == 0 {
		return nil
	}
	if size < header.HeaderMinSize || size > header.HeaderMaxSize || !isPowerOf2(size) {
		return ErrInvalidArgument
	}
	return nil
}

// ConstantTimeEqual compares two byte slices in constant time
// checkOverflow checks if a*b would overflow
func checkOverflow(a, b int) error {
	if a > 0 && b > 0 && a > math.MaxInt/b {
		return ErrInvalidArgument
	}
	return nil
}

// openDevice is the ONE way this package opens a device -- a forward into
// internal/device.Open, through sys.openFile, which keeps the CLASSIFICATION
// of a failure in one place rather than at every call site.
//
// Every LUKS2 operation opens the device -- the header reader, the writer, the
// keyslot paths, the size probe -- and none of them used to look at WHY an open
// failed. The message an operator saw was accurate ("failed to open device:
// open /dev/sdb1: permission denied"); what was missing was the typed contract.
// A caller building a daemon or a provisioning flow cannot write
//
//	errors.Is(err, luks2.ErrPermissionDenied)
//
// to tell "you need privileges" from "this device is broken" unless something
// says so, and ErrPermissionDenied was declared and returned by nothing (#31).
func openDevice(op, path string, flag int, sys volumeSys) (*os.File, error) {
	return device.Open(context.Background(), op, path, flag, sys.openFile)
}

// classifyDeviceOpen adds the package's typed vocabulary to an open failure,
// and returns anything it cannot classify UNCHANGED. The real work is
// internal/device.ClassifyOpen.
func classifyDeviceOpen(op string, err error) error {
	return device.ClassifyOpen(op, err)
}

// deviceLock represents a file lock for concurrent access protection. It wraps
// internal/device's Pinned/Locked pair, which does the real locking: the node
// flock, then cryptsetup's own lock for a block device, excluding cryptsetup
// as well (internal/device's cryptsetuplock.go).
type deviceLock struct {
	locked *device.Locked
}

// DefaultLockWait is what acquireDeviceLock spends before giving up. It is a
// BOUND, not a target: an uncontended lock is taken on the first attempt and
// costs nothing, and the budget is consumed only when another holder has the
// device.
//
// 30s is chosen against the thing actually being waited for. The longest lock
// hold in this library is a format, whose cost is dominated by the KDF -- and
// the KDF is calibrated to a caller-supplied time, defaulting to 2000ms per
// derivation. A budget of 30s therefore absorbs a normal format several times
// over while still terminating a genuine deadlock in a time an operator will
// sit through. Below about 5s it would start refusing ordinary contention,
// which is the failure this replaces.
const DefaultLockWait = device.DefaultLockWait

// The backoff a device lock wait uses, as internal/device.Lock does it.
// Tests assert the acquisition's timing against these.
const (
	lockBackoffMin = device.LockBackoffMin
	lockBackoffMax = device.LockBackoffMax
)

// acquireDeviceLock acquires an exclusive lock on a device, waiting up to
// DefaultLockWait for a competing holder to release it.
//
// IT WAITS, AND THAT IS THE POINT. This call used to be LOCK_NB with no retry:
// the first caller won and every other caller failed IMMEDIATELY with a bare
// "resource temporarily unavailable". On a host-global device -- which is what
// the integration suite locks -- that turns ordinary concurrency into a
// failure, and one that presents inconsistently enough to be filed as
// flakiness rather than as contention (#107). Shortening the hold time hides
// it; bounding the wait fixes it.
func acquireDeviceLock(path string) (*deviceLock, error) {
	return acquireDeviceLockTimeout(path, DefaultLockWait)
}

// acquireDeviceLockTimeout is acquireDeviceLock with an explicit wait budget, for
// callers that know their own latency requirement -- and for tests, which need
// contention to resolve in milliseconds rather than in DefaultLockWait.
//
// A budget of zero or less makes exactly ONE attempt and returns immediately,
// which is the old non-blocking behavior, available deliberately rather than
// by accident.
//
// The wait is a POLL WITH BACKOFF rather than a blocking LOCK_EX. A blocking
// flock cannot be given a deadline without arranging for a signal to interrupt
// it, and a lock wait that cannot time out is the deadlock this is meant to
// terminate. Polling costs a syscall per attempt and can be bounded exactly.
func acquireDeviceLockTimeout(path string, wait time.Duration) (*deviceLock, error) {
	ctx := context.Background()
	return acquireFileLock(ctx, path, wait, clock.System{}, defaultVolumeSys())
}

// acquireFileLock is acquireDeviceLockTimeout on the given clock and sys.
func acquireFileLock(ctx context.Context, path string, wait time.Duration, clk clock.Clock, sys volumeSys) (*deviceLock, error) {
	pinned, err := device.OpenPinned(ctx, "lock the device", path, os.O_RDWR, sys.openFile)
	if err != nil {
		return nil, err
	}
	locked, err := pinned.Lock(ctx, device.LockExclusive, wait, clk, cryptsetupLockDir, device.DefaultOpenLockFile, sys.lockHeld)
	if err != nil {
		_ = pinned.Close()
		return nil, err
	}
	return &deviceLock{locked: locked}, nil
}

// Release releases the file lock
func (l *deviceLock) Release() error {
	if l.locked == nil {
		return nil
	}
	_ = l.locked.Unlock()
	return l.locked.File().Close()
}

// OpenFileSecure opens a file with proper permissions
// safeUint64ToInt64 converts uint64 to int64 safely, returning error on overflow
func safeUint64ToInt64(v uint64) (int64, error) {
	if v > math.MaxInt64 {
		return 0, ErrInvalidArgument
	}
	return int64(v), nil
}

// safeUint64ToInt converts uint64 to int safely, returning error on overflow
func safeUint64ToInt(v uint64) (int, error) {
	if v > uint64(math.MaxInt) {
		return 0, ErrInvalidArgument
	}
	return int(v), nil
}

// safeInt64ToUint64 converts int64 to uint64 safely, returning error on negative
func safeInt64ToUint64(v int64) (uint64, error) {
	if v < 0 {
		return 0, ErrInvalidArgument
	}
	return uint64(v), nil
}
