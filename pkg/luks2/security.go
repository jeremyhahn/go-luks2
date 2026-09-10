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
	"strings"
	"syscall"
	"time"
)

// Security constants
const (
	MinPassphraseLength = 8
	MaxPassphraseLength = 512
	MinKeySize          = 256
	MaxKeySize          = 512
	MinSectorSize       = 512
	MaxSectorSize       = 4096
	// DigestIterations is the PBKDF2 iteration count for the master-key digest.
	// createDigest reads it, so changing it changes what Format writes for newly
	// formatted volumes; a volume already on disk carries its own count in its
	// header and is unaffected.
	//
	// TestSecurityConstants asserts only that this is >= 100000. The specific
	// value 600000 is not pinned by anything.
	//
	// The comment this replaced attributed 600000 to NIST SP 800-132. That
	// standard sets a minimum iteration count far below this and does not
	// specify 600000, so the attribution is dropped rather than restated.
	DigestIterations = 600000
)

// Validation errors
var (
	ErrInvalidPath         = errors.New("invalid device path")
	ErrPassphraseTooShort  = errors.New("passphrase too short (minimum 8 bytes)")
	ErrPassphraseTooLong   = errors.New("passphrase too long (maximum 512 bytes)")
	ErrInvalidKeySize      = errors.New("invalid key size (must be 256 or 512 bits)")
	ErrInvalidSectorSize   = errors.New("invalid sector size (must be 512 or 4096)")
	ErrInvalidArgon2Memory = errors.New("invalid Argon2 memory (must be >= 65536 KB)")
	ErrInvalidArgon2Time   = errors.New("invalid Argon2 time cost (must be >= 1)")
	ErrIntegerOverflow     = errors.New("integer overflow detected")

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

	// Clean the path
	cleaned := filepath.Clean(device)

	// Check for path traversal attempts
	if strings.Contains(cleaned, "..") {
		return ErrInvalidPath
	}

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

// ValidatePassphrase validates passphrase length
func ValidatePassphrase(passphrase []byte) error {
	if len(passphrase) < MinPassphraseLength {
		return ErrPassphraseTooShort
	}
	if len(passphrase) > MaxPassphraseLength {
		return ErrPassphraseTooLong
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

	// Validate Argon2 parameters if specified
	if opts.KDFType == "argon2id" || opts.KDFType == "argon2i" {
		if opts.Argon2Memory != 0 && opts.Argon2Memory < 65536 {
			return ErrInvalidArgon2Memory
		}
		if opts.Argon2Time != 0 && opts.Argon2Time < 1 {
			return ErrInvalidArgon2Time
		}
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
	f, err := openDevice("lock the device", path, os.O_RDWR)
	if err != nil {
		return nil, err
	}

	started := time.Now()
	deadline := started.Add(wait)
	backoff := lockBackoffMin

	for attempt := 1; ; attempt++ {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &FileLock{file: f}, nil
		}

		// CLASSIFY, do not assume contention. EWOULDBLOCK means someone else
		// holds it and waiting is the right answer. Anything else -- EBADF, a
		// descriptor closed underneath us -- will not improve by being retried,
		// and retrying it for the whole budget would report a real fault as a
		// timeout.
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = f.Close()
			return nil, &DeviceError{Device: path, Op: "lock", Err: err}
		}

		// Checked AFTER an attempt, so a zero budget still tries once and a
		// lock that is free is never reported as contended.
		remaining := time.Until(deadline)
		if remaining <= 0 {
			_ = f.Close()
			return nil, &LockTimeoutError{
				Path:     path,
				Waited:   time.Since(started),
				Attempts: attempt,
				Err:      err,
			}
		}

		// Never sleep past the deadline: doing so would report a longer wait
		// than the caller allowed, and Waited above is meant to be true.
		if backoff > remaining {
			backoff = remaining
		}
		time.Sleep(backoff)
		if backoff < lockBackoffMax {
			backoff *= 2
			if backoff > lockBackoffMax {
				backoff = lockBackoffMax
			}
		}
	}
}

// Release releases the file lock
func (l *FileLock) Release() error {
	if l.file == nil {
		return nil
	}
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
