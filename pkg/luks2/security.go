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

// FileLock represents a file lock for concurrent access protection
type FileLock struct {
	file *os.File
}

// AcquireFileLock acquires an exclusive lock on a file
func AcquireFileLock(path string) (*FileLock, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- device path for file locking
	if err != nil {
		return nil, err
	}

	// Try to acquire exclusive lock
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close() // Ignore close error since we're returning lock error
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}

	return &FileLock{file: f}, nil
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
