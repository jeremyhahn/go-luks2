// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Security constants
const (
	MinPassphraseLength = 8
	MaxPassphraseLength = 512
	MinKeySize          = 256
	MaxKeySize          = 512
	MinSectorSize       = 512
	MaxSectorSize       = 4096
	// DigestIterationTargetMs is how long the master-key digest's PBKDF2 is
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
	DigestIterationTargetMs = 100

	// DigestCalibrationKeyLen is the derived-key length the digest calibration
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
	DigestCalibrationKeyLen = 64
)

// Validation errors
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

// MaxMappingNameLength bounds a device-mapper name. The kernel's DM_NAME_LEN is
// 128 bytes INCLUDING the terminating NUL, and devmapper.go copies the name into
// that fixed-width ioctl field, so 127 is the largest value that cannot be
// truncated on the way in. A truncated name is not a cosmetic problem: the
// rollback identifies its own target by name, so two names that differ only past
// the cut would become the same target.
const MaxMappingNameLength = 127

// ValidateMappingName validates a device-mapper mapping name.
//
// # What the name reaches
//
// It is not just a label. The name becomes, in order: the dm ioctl's name
// field; the /dev/mapper/<name> path this package creates, stats and unlinks;
// part of the dm UUID used to prove a target belongs to this unlock; and --
// since #78 -- part of the identity the kernel-keyring description is derived
// from. A dm target's parameter string is SPACE-DELIMITED and positional
// (<cipher> <key> <iv_offset> <device> <start>), so a token carrying a space,
// a newline or a NUL shifts the fields after it.
//
// The keyring description is hashed before it reaches that grammar, which
// closes the parser-confusion route by construction rather than by charset --
// see keyringDescription. This validator is the other half: it stops a hostile
// or careless name from reaching the /dev/mapper path, the ioctl field, or the
// dm UUID in the first place, and it is a WHITELIST because enumerating what a
// path and a positional grammar both consider harmless is the kind of list
// that is always one character short.
//
// # Why it is checked here and not only at the callers
//
// Unlock validated the device path and the passphrase and never the name. That
// was survivable while the name only reached fixed-width ioctl fields, which
// are not grammar-parsed. It stopped being survivable when the name started
// contributing to a target-spec token.
func ValidateMappingName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: the name is empty", ErrInvalidMappingName)
	}
	if len(name) > MaxMappingNameLength {
		return fmt.Errorf("%w: %d bytes exceeds the %d the device-mapper ioctl can carry without truncation",
			ErrInvalidMappingName, len(name), MaxMappingNameLength)
	}

	// A leading dash would be read as an option by the command lines this
	// library's own error messages tell an operator to run, and "." and ".."
	// are directory entries rather than names.
	if name == "." || name == ".." {
		return fmt.Errorf("%w: %q is a directory entry, not a name", ErrInvalidMappingName, name)
	}
	// /dev/mapper/control is device-mapper's own control node. A mapping
	// called "control" would make /dev/mapper/<name> that node, and the node
	// repair after an unlock would replace it (#250).
	if name == "control" {
		return &detailError{Kind: ErrInvalidMappingName, Detail: `"control" names the device-mapper control node`}
	}
	if first := name[0]; !isMappingNameStart(first) {
		return fmt.Errorf("%w: %q must start with a letter or a digit", ErrInvalidMappingName, name)
	}

	for i := 0; i < len(name); i++ {
		if !isMappingNameByte(name[i]) {
			return fmt.Errorf("%w: byte %d of %q is not one of A-Z a-z 0-9 _ . + -; a device-mapper name reaches a /dev path and a space-delimited target specification, so the permitted set is a whitelist",
				ErrInvalidMappingName, i, name)
		}
	}

	return nil
}

func isMappingNameStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isMappingNameByte(c byte) bool {
	return isMappingNameStart(c) || c == '_' || c == '.' || c == '+' || c == '-'
}

// ValidateDevicePath validates a device path for security
func ValidateDevicePath(device string) error {
	if device == "" {
		return ErrInvalidPath
	}

	// Clean the path. On an ABSOLUTE path Clean resolves every ".." element
	// lexically, so nothing that survives the IsAbs check below can climb
	// above the root. The substring check that used to follow refused nothing
	// that check does not, and refused legitimate names that merely contain
	// two dots, such as /dev/disk/by-label/a..b (#249, A10).
	cleaned := filepath.Clean(device)

	// Must be absolute path
	if !filepath.IsAbs(cleaned) {
		return ErrInvalidPath
	}

	// Check that device exists
	info, err := os.Stat(cleaned)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrDeviceNotFound
		}
		return fmt.Errorf("%w: %v", ErrInvalidPath, err)
	}

	// Must be a regular file or block device
	mode := info.Mode()
	if !mode.IsRegular() && (mode&os.ModeDevice == 0) {
		return ErrInvalidPath
	}

	return nil
}

// MaxCredentialLength is the longest EXISTING credential this package will
// present to a keyslot: cryptsetup's key file limit (DEFAULT_KEYFILE_SIZE_MAXKB,
// 8 MiB). A keyslot cryptsetup enrolled from a key file can only be opened with
// the whole file.
const MaxCredentialLength = 8 << 20

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
		return ErrCredentialEmpty
	}
	if len(credential) > MaxCredentialLength {
		return ErrCredentialTooLong
	}
	return nil
}

// ValidatePassphrase validates the length of a NEW passphrase: the policy for a
// credential this package enrolls (Format, AddKey's new passphrase, ChangeKey's
// new one). A credential presented to open an existing keyslot is bounded by
// validateExistingCredential instead.
func ValidatePassphrase(passphrase []byte) error {
	if len(passphrase) < MinPassphraseLength {
		return ErrPassphraseTooShort
	}
	if len(passphrase) > MaxPassphraseLength {
		return ErrPassphraseTooLong
	}
	return nil
}

// MinArgon2MemoryKB is the smallest Argon2 memory cost this package will WRITE
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
// So the accept side is deliberately far more liberal -- minArgon2Memory in
// keyslotvalidation.go is 8 KiB, below even cryptsetup's own 32 -- and every
// read path, RemoveKey and KillSlot go through that one instead. This bound
// applies only where a caller SUPPLIES a cost: Format and AddKey.
//
// ChangeKey is deliberately NOT bound by it. It inherits the cost of the slot
// it is rotating, which is a cost this package did not choose, on hardware that
// has already demonstrated it can afford that and nothing more. See ChangeKey.
const MinArgon2MemoryKB = 65536

// MinArgon2Time is the smallest Argon2 time cost this package will write. It is
// the format's own minimum; a zero or negative time cost is not a weak keyslot
// but a malformed one.
const MinArgon2Time = 1

// MinArgon2Parallel is the smallest Argon2 parallelism this package will write.
// Like MinArgon2Time it is the format's own minimum rather than a security
// judgement: Argon2 parallelism is a uint8 in 1..255, so zero or negative is
// malformed, not weak.
//
// Its CEILING, like Time's and Memory's, is the read side's own
// (maxArgon2Parallel, keyslotvalidation.go), applied by validateArgon2CreateCost
// so nothing is written that the reader would refuse (#249, A5).
const MinArgon2Parallel = 1

// validateArgon2CreateCost bounds the Argon2 costs a CALLER supplies.
//
// Split out of ValidateFormatOptions so AddKey can apply the identical bound
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
func validateArgon2CreateCost(opts FormatOptions) error {
	if !isArgon2Type(resolveKDFType(normalizeKDFType(opts.KDFType), formatArgon2CostGiven(opts))) {
		return nil
	}
	// Each cost has a FLOOR -- what this package will write -- and a CEILING,
	// which is exactly what validateKDFCost refuses when the header is read
	// back (#249, A5). Without the ceiling, Format with Argon2Memory 8 GiB on a
	// host that had the RAM derived, wrote and reported success, and every
	// later unlock refused the keyslot: a volume nothing can open, created on
	// request. The read-side bounds are the ones used, not restated, so the
	// two can never disagree about what a keyslot may cost.
	if opts.Argon2Memory != 0 && (opts.Argon2Memory < MinArgon2MemoryKB || opts.Argon2Memory > maxArgon2Memory) {
		return &Argon2CostError{
			Parameter: "memory",
			Value:     opts.Argon2Memory,
			Minimum:   MinArgon2MemoryKB,
			Maximum:   maxArgon2Memory,
			Err:       ErrInvalidArgon2Memory,
		}
	}
	if opts.Argon2Time != 0 && (opts.Argon2Time < MinArgon2Time || opts.Argon2Time > maxArgon2Time) {
		return &Argon2CostError{
			Parameter: "time",
			Value:     opts.Argon2Time,
			Minimum:   MinArgon2Time,
			Maximum:   maxArgon2Time,
			Err:       ErrInvalidArgon2Time,
		}
	}
	// Parallelism is checked HERE, with its siblings, rather than being left to
	// deriveArgon2 (#176). It was refused -- `cpus must be between 1 and 255`
	// -- but one layer later, after the pre-check had passed, and as a
	// CryptoError rather than the Argon2CostError the other two produce. Same
	// mistake by the caller, two different error shapes and two different
	// moments.
	if opts.Argon2Parallel != 0 && (opts.Argon2Parallel < MinArgon2Parallel || opts.Argon2Parallel > maxArgon2Parallel) {
		return &Argon2CostError{
			Parameter: "parallelism",
			Value:     opts.Argon2Parallel,
			Minimum:   MinArgon2Parallel,
			Maximum:   maxArgon2Parallel,
			Err:       ErrInvalidArgon2Parallel,
		}
	}
	return nil
}

// ValidateFormatOptions validates all format options
func ValidateFormatOptions(opts FormatOptions) error {
	// Validate device path
	if err := ValidateDevicePath(opts.Device); err != nil {
		return err
	}

	// Validate passphrase
	if err := ValidatePassphrase(opts.Passphrase); err != nil {
		return err
	}

	// Validate key size
	if opts.KeySize != 0 && opts.KeySize != 256 && opts.KeySize != 512 {
		return ErrInvalidKeySize
	}

	// Validate sector size
	if opts.SectorSize != 0 && opts.SectorSize != 512 && opts.SectorSize != 4096 {
		return ErrInvalidSectorSize
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
		afSize := keyBytes * AFStripes
		if afSize/AFStripes != keyBytes {
			return ErrIntegerOverflow
		}
	}

	return nil
}

// validateMetadataSize checks FormatOptions.MetadataSize against exactly the
// set cryptsetup's --luks2-metadata-size accepts: zero for the default, or a
// power of two from LUKS2HeaderMinSize to LUKS2HeaderMaxSize. Measured against
// cryptsetup 2.7.0 on #47 -- 8k, 12288, 20k and 8m are all refused there with
// "Unsupported LUKS2 metadata size options".
func validateMetadataSize(size int) error {
	if size == 0 {
		return nil
	}
	if size < LUKS2HeaderMinSize || size > LUKS2HeaderMaxSize || !isPowerOf2(size) {
		return ErrInvalidMetadataSize
	}
	return nil
}

// ConstantTimeEqual compares two byte slices in constant time
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// CheckOverflow checks if a*b would overflow
func CheckOverflow(a, b int) error {
	if a > 0 && b > 0 && a > math.MaxInt/b {
		return ErrIntegerOverflow
	}
	return nil
}

// openDevice is the ONE way this package opens a device, and it exists so that
// the CLASSIFICATION of a failure lives in one place rather than at every call
// site.
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
//
// The mode argument is deliberately absent: nothing here passes O_CREATE, so
// the permission bits would never be consulted. 0600 is passed for the write
// paths purely to match what the sites this replaced spelled out.
func openDevice(op, device string, flag int) (*os.File, error) {
	f, err := openFileFunc(device, flag, 0600) // #nosec G304 -- the device path is the caller's subject and is validated by ValidateDevicePath before every LUKS2 operation; this function exists precisely so that check and this open are not in different places
	if err != nil {
		return nil, classifyDeviceOpen(op, err)
	}
	return f, nil
}

// openFileFunc is the filesystem seam openDevice goes through, in the same
// idiom as the dm value in devicemapper.go.
//
// It is here for a measured reason. A permission failure cannot be produced by
// permission bits in a test: CI job containers run as ROOT, and root bypasses
// discretionary access checks, so an os.Chmod-based negative test passes
// locally and fails on the runner. That is why this project's testing rules
// forbid building a failure case out of permission bits: inject faults only
// through means that hold for EVERY uid. Four candidate uid-independent EACCES
// sources were measured on a
// dev host -- /proc/version and /proc/self/cmdline opened O_RDWR,
// /sys/kernel/vmcoreinfo, /proc/1/mem -- and root opened ALL FOUR. There is no
// real open that fails this way for every uid, so the fault is injected at the
// seam instead, which holds for root and for uid 1000 alike.
var openFileFunc = os.OpenFile

// dropDeviceCache evicts f's clean pages from the page cache, so the next read
// of them comes from the medium. It is called only after the device has been
// synced, when no page of it should be dirty; one that is (written since by
// another process) is not evicted, which is the kernel's contract and leaves
// what is read current rather than stale.
//
// A seam for the same reason syncDevice is one: what is in the cache and what
// is on the medium cannot be made to differ from a test without a failing
// device, so this package's tests substitute it to model exactly that.
// Unexported, substituted only by this package's tests.
var dropDeviceCache = func(f *os.File) error {
	return unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED)
}

// classifyDeviceOpen adds the package's typed vocabulary to an open failure,
// and returns anything it cannot classify UNCHANGED.
//
// Returning the original error for the unclassified case is deliberate. The
// alternative -- wrapping everything in a house error type -- would rewrite the
// message of every failure in the package to buy a distinction only one of them
// needs, and *fs.PathError already says which path and which syscall.
//
// The permission case keeps the cause reachable through the chain, so
// errors.Is(err, os.ErrPermission) and errors.Is(err, ErrPermissionDenied) are
// both true of the same value: a caller that already branched on the standard
// library's sentinel does not have to change.
func classifyDeviceOpen(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%w: could not %s: %w. %s", ErrPermissionDenied, op, err, permissionRemedy)
	}
	// EBUSY is what an O_EXCL open of a block device returns while the device
	// is mounted, mapped or claimed by another exclusive opener.
	if errors.Is(err, syscall.EBUSY) {
		return &detailError{Kind: ErrDeviceInUse, Detail: "could not " + op + ": it is mounted, mapped or held open exclusively", Err: err}
	}
	return err
}

// permissionRemedy is the operator guidance carried by every permission
// failure, in the same spirit as keyringRemedy: an operator should be able to
// act on the error without reading the source.
const permissionRemedy = "A LUKS2 container's header, keyslots and data segment are read and written on the RAW BLOCK DEVICE rather than through a filesystem, " +
	"so every operation in this library needs direct access to the device node -- there is no unprivileged path that does less. " +
	"Run as root, or give this process access to the node itself (on most distributions the node is owned by root and the `disk` group)."

// FileLock represents a file lock for concurrent access protection
type FileLock struct {
	file *os.File

	// cryptsetup is cryptsetup's own lock for a block device, held too so
	// that cryptsetup is excluded as well (cryptsetuplock.go). nil for a
	// regular file, whose flock above is already cryptsetup's lock.
	cryptsetup *cryptsetupLock
}

// Lock wait budget and backoff schedule.
//
// DefaultLockWait is what AcquireFileLock spends before giving up. It is a
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
const (
	DefaultLockWait = 30 * time.Second

	// The backoff runs from 1ms to 100ms. The floor keeps a lock released
	// microseconds after the first attempt from costing a full sleep; the
	// ceiling keeps a long wait from turning into a handful of samples that
	// overshoot the budget. Doubling between them reaches the ceiling in seven
	// steps, so a 30s wait is roughly 300 attempts rather than 30000 -- the
	// point of a backoff being that a lock nobody drops must not cost a core.
	lockBackoffMin = time.Millisecond
	lockBackoffMax = 100 * time.Millisecond
)

// AcquireFileLock acquires an exclusive lock on a device, waiting up to
// DefaultLockWait for a competing holder to release it.
//
// IT WAITS, AND THAT IS THE POINT. This call used to be LOCK_NB with no retry:
// the first caller won and every other caller failed IMMEDIATELY with a bare
// "resource temporarily unavailable". On a host-global device -- which is what
// the integration suite locks -- that turns ordinary concurrency into a
// failure, and one that presents inconsistently enough to be filed as
// flakiness rather than as contention (#107). Shortening the hold time hides
// it; bounding the wait fixes it.
func AcquireFileLock(path string) (*FileLock, error) {
	return AcquireFileLockTimeout(path, DefaultLockWait)
}

// AcquireFileLockTimeout is AcquireFileLock with an explicit wait budget, for
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
func AcquireFileLockTimeout(path string, wait time.Duration) (*FileLock, error) {
	return acquireFileLock(path, wait, systemClock{})
}

// acquireFileLock is AcquireFileLockTimeout on the given clock.
func acquireFileLock(path string, wait time.Duration, clk clock) (*FileLock, error) {
	f, err := openDevice("lock the device", path, os.O_RDWR)
	if err != nil {
		return nil, err
	}

	started := clk.Now()
	deadline := started.Add(wait)
	if err := pollFlock(f, path, lockExclusive, started, deadline, clk); err != nil {
		_ = f.Close()
		return nil, err
	}
	cs, err := acquireCryptsetupLockFor(f, path, started, deadline, clk)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	fileLockHeld(path)
	return &FileLock{file: f, cryptsetup: cs}, nil
}

// fileLockHeld runs once both locks are held, before the caller reads or
// writes anything under them. A seam: it is how a test holds an operation at
// that point and watches cryptsetup wait for it, which no result of the
// operation can show. A no-op in production. Unexported, substituted only by
// this package's tests.
var fileLockHeld = func(string) {}

// pollFlock flocks f in mode, retrying with backoff while another holder has
// it, until deadline. It always makes one attempt, so a lock that is free is
// never reported as contended, whatever the budget.
func pollFlock(f *os.File, path string, mode lockMode, started, deadline time.Time, clk clock) error {
	backoff := lockBackoffMin
	for attempt := 1; ; attempt++ {
		err := unix.Flock(int(f.Fd()), mode.flockOp())
		if err == nil {
			return nil
		}

		// CLASSIFY, do not assume contention. EWOULDBLOCK means someone else
		// holds it and waiting is the right answer. Anything else -- EBADF, a
		// descriptor closed underneath us -- will not improve by being retried,
		// and retrying it for the whole budget would report a real fault as a
		// timeout.
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return &DeviceError{Device: path, Op: "lock", Err: err}
		}

		// Checked AFTER an attempt, so a zero budget still tries once.
		remaining := deadline.Sub(clk.Now())
		if remaining <= 0 {
			return &LockTimeoutError{
				Path:     path,
				Waited:   clk.Now().Sub(started),
				Attempts: attempt,
				Err:      err,
			}
		}

		// Never sleep past the deadline: doing so would report a longer wait
		// than the caller allowed, and Waited above is meant to be true.
		clk.Sleep(min(backoff, remaining))
		backoff = min(backoff*2, lockBackoffMax)
	}
}

// Release releases the file lock
func (l *FileLock) Release() error {
	if l.file == nil {
		return nil
	}
	// cryptsetup's lock is released first: it was taken second.
	_ = l.cryptsetup.release()
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN) // Ignore unlock error
	return l.file.Close()
}

// OpenFileSecure opens a file with proper permissions
func OpenFileSecure(path string, flag int) (*os.File, error) {
	return os.OpenFile(path, flag, 0600) // #nosec G304 -- wrapper for secure file operations
}

// SafeUint64ToInt64 converts uint64 to int64 safely, returning error on overflow
func SafeUint64ToInt64(v uint64) (int64, error) {
	if v > math.MaxInt64 {
		return 0, ErrIntegerOverflow
	}
	return int64(v), nil
}

// SafeUint64ToInt converts uint64 to int safely, returning error on overflow
func SafeUint64ToInt(v uint64) (int, error) {
	if v > uint64(math.MaxInt) {
		return 0, ErrIntegerOverflow
	}
	return int(v), nil
}

// SafeInt64ToUint64 converts int64 to uint64 safely, returning error on negative
func SafeInt64ToUint64(v int64) (uint64, error) {
	if v < 0 {
		return 0, ErrIntegerOverflow
	}
	return uint64(v), nil
}
