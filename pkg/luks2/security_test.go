// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/internal/clock"
)

func TestValidateDevicePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"empty path", "", true},
		{"relative path", "relative/path", true},
		{"non-existent", "/nonexistent/device/path", true},
		{"path with dots", "../../../etc/passwd", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDevicePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDevicePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}

	// Test valid file
	t.Run("valid file", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "luks-test-*")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Remove(tmpFile.Name()) }()
		_ = tmpFile.Close()

		if err := validateDevicePath(tmpFile.Name()); err != nil {
			t.Errorf("ValidateDevicePath(valid file) = %v, want nil", err)
		}
	})
}

func TestValidateDevicePath_InvalidFile(t *testing.T) {
	// Create a directory instead of a file
	tmpDir, err := os.MkdirTemp("", "luks-test-dir-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	err = validateDevicePath(tmpDir)
	if !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("ValidateDevicePath(directory) = %v, want %v", err, ErrInvalidArgument)
	}
}

func TestValidatePassphraseBytes(t *testing.T) {
	tests := []struct {
		name       string
		passphrase []byte
		wantErr    error
	}{
		{"empty passphrase", []byte{}, ErrInvalidCredential},
		{"too short", []byte("short"), ErrInvalidCredential},
		{"one byte below minimum", make([]byte, MinPassphraseLength-1), ErrInvalidCredential},
		{"minimum length", []byte("12345678"), nil},
		{"valid length", []byte("this-is-a-valid-passphrase"), nil},
		{"maximum length", make([]byte, MaxPassphraseLength), nil},
		{"too long", make([]byte, MaxPassphraseLength+1), ErrInvalidCredential},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePassphraseBytes(tt.passphrase)
			if err != tt.wantErr {
				t.Errorf("validatePassphraseBytes() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateFormatOptionsForTest(t *testing.T) {
	// Create a temp file for testing
	tmpFile, err := os.CreateTemp("", "luks-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	tests := []struct {
		name    string
		opts    formatOptionsForTest
		wantErr bool
	}{
		{
			name: "valid options",
			opts: formatOptionsForTest{
				Device:     tmpFile.Name(),
				Passphrase: []byte("valid-passphrase"),
				KeySize:    512,
				SectorSize: 512,
			},
			wantErr: false,
		},
		{
			name: "valid with 256 key size",
			opts: formatOptionsForTest{
				Device:     tmpFile.Name(),
				Passphrase: []byte("valid-passphrase"),
				KeySize:    256,
				SectorSize: 512,
			},
			wantErr: false,
		},
		{
			name: "valid with 4096 sector size",
			opts: formatOptionsForTest{
				Device:     tmpFile.Name(),
				Passphrase: []byte("valid-passphrase"),
				KeySize:    512,
				SectorSize: 4096,
			},
			wantErr: false,
		},
		{
			name: "zero key size is valid (defaults will be used)",
			opts: formatOptionsForTest{
				Device:     tmpFile.Name(),
				Passphrase: []byte("valid-passphrase"),
				KeySize:    0,
				SectorSize: 512,
			},
			wantErr: false,
		},
		{
			name: "zero sector size is valid (defaults will be used)",
			opts: formatOptionsForTest{
				Device:     tmpFile.Name(),
				Passphrase: []byte("valid-passphrase"),
				KeySize:    512,
				SectorSize: 0,
			},
			wantErr: false,
		},
		{
			name: "invalid key size",
			opts: formatOptionsForTest{
				Device:     tmpFile.Name(),
				Passphrase: []byte("valid-passphrase"),
				KeySize:    128,
			},
			wantErr: true,
		},
		{
			name: "invalid sector size",
			opts: formatOptionsForTest{
				Device:     tmpFile.Name(),
				Passphrase: []byte("valid-passphrase"),
				SectorSize: 1024,
			},
			wantErr: true,
		},
		{
			name: "short passphrase",
			opts: formatOptionsForTest{
				Device:     tmpFile.Name(),
				Passphrase: []byte("short"),
			},
			wantErr: true,
		},
		{
			name: "invalid device path",
			opts: formatOptionsForTest{
				Device:     "/nonexistent/path",
				Passphrase: []byte("valid-passphrase"),
			},
			wantErr: true,
		},
		{
			name: "argon2id with valid parameters",
			opts: formatOptionsForTest{
				Device:       tmpFile.Name(),
				Passphrase:   []byte("valid-passphrase"),
				KDFType:      "argon2id",
				Argon2Memory: 65536,
				Argon2Time:   1,
			},
			wantErr: false,
		},
		{
			name: "argon2i with valid parameters",
			opts: formatOptionsForTest{
				Device:       tmpFile.Name(),
				Passphrase:   []byte("valid-passphrase"),
				KDFType:      "argon2i",
				Argon2Memory: 131072,
				Argon2Time:   4,
			},
			wantErr: false,
		},
		{
			name: "argon2id with insufficient memory",
			opts: formatOptionsForTest{
				Device:       tmpFile.Name(),
				Passphrase:   []byte("valid-passphrase"),
				KDFType:      "argon2id",
				Argon2Memory: 32768,
			},
			wantErr: true,
		},
		{
			name: "argon2id with negative time cost",
			opts: formatOptionsForTest{
				Device:       tmpFile.Name(),
				Passphrase:   []byte("valid-passphrase"),
				KDFType:      "argon2id",
				Argon2Memory: 65536,
				Argon2Time:   -1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFormatOptionsForTest(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateFormatOptionsForTest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckOverflow(t *testing.T) {
	tests := []struct {
		name    string
		a, b    int
		wantErr bool
	}{
		{"no overflow small numbers", 100, 200, false},
		{"no overflow zero values", 0, 1000000, false},
		{"no overflow zero a", 0, math.MaxInt, false},
		{"no overflow zero b", math.MaxInt, 0, false},
		{"no overflow negative", -100, 200, false},
		{"large but safe", 1000000, 1000, false},
		{"overflow at max", math.MaxInt, 2, true},
		{"overflow large numbers", math.MaxInt / 2, 3, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkOverflow(tt.a, tt.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckOverflow(%d, %d) error = %v, wantErr %v", tt.a, tt.b, err, tt.wantErr)
			}
			if err != nil && err != ErrInvalidArgument {
				t.Errorf("CheckOverflow() error = %v, want %v", err, ErrInvalidArgument)
			}
		})
	}
}

func TestCheckOverflow_EdgeCases(t *testing.T) {
	t.Run("exactly at boundary", func(t *testing.T) {
		// math.MaxInt / 2 * 2 should not overflow
		err := checkOverflow(math.MaxInt/2, 2)
		if err != nil {
			t.Errorf("CheckOverflow(MaxInt/2, 2) = %v, want nil", err)
		}
	})

	t.Run("just over boundary", func(t *testing.T) {
		// (math.MaxInt / 2 + 1) * 2 should overflow
		err := checkOverflow(math.MaxInt/2+1, 2)
		if err == nil {
			t.Error("CheckOverflow(MaxInt/2+1, 2) = nil, want error")
		}
	})
}

func TestFileLock(t *testing.T) {
	// Create a temp file
	tmpFile, err := os.CreateTemp("", "luks-lock-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	// Acquire lock
	lock, err := acquireDeviceLock(tmpFile.Name())
	if err != nil {
		t.Fatalf("acquireDeviceLock() error = %v", err)
	}

	// Try to acquire again while the first is held. This uses the explicit
	// budget: acquireDeviceLock now waits DefaultLockWait (30s) before giving
	// up, so calling it here would make this test sit for half a minute to
	// assert a failure that is decided in the first millisecond.
	_, err = acquireDeviceLockTimeout(tmpFile.Name(), 20*time.Millisecond)
	if err == nil {
		t.Error("Expected error acquiring second lock, got nil")
	}

	// Release lock
	if err := lock.Release(); err != nil {
		t.Errorf("Release() error = %v", err)
	}

	// Should be able to acquire again
	lock2, err := acquireDeviceLock(tmpFile.Name())
	if err != nil {
		t.Fatalf("acquireDeviceLock() after release error = %v", err)
	}
	defer func() { _ = lock2.Release() }()
}

func TestFileLock_NonexistentFile(t *testing.T) {
	_, err := acquireDeviceLock("/nonexistent/file/path")
	if err == nil {
		t.Error("acquireDeviceLock(nonexistent) = nil, want error")
	}
}

func TestFileLock_ReleaseNilFile(t *testing.T) {
	lock := &deviceLock{locked: nil}
	if err := lock.Release(); err != nil {
		t.Errorf("Release() on nil file = %v, want nil", err)
	}
}

func TestFileLock_MultipleRelease(t *testing.T) {
	defer parallel(t)()

	tmpFile, err := os.CreateTemp("", "luks-lock-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	lock, err := acquireDeviceLock(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	// First release
	if err := lock.Release(); err != nil {
		t.Errorf("First Release() error = %v", err)
	}

	// Second release should not crash (file is closed)
	// This tests defensive programming
	if err := lock.Release(); err == nil {
		// File is already closed, so we expect an error
		t.Log("Second Release() returned nil (expected error for closed file)")
	}
}

func TestValidateDevicePath_SymlinkHandling(t *testing.T) {
	// Create a temp file
	tmpFile, err := os.CreateTemp("", "luks-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	// Create a symlink to it
	symlinkPath := filepath.Join(os.TempDir(), "luks-test-symlink")
	if err := os.Symlink(tmpFile.Name(), symlinkPath); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(symlinkPath) }()

	// Symlink should be validated successfully
	if err := validateDevicePath(symlinkPath); err != nil {
		t.Errorf("ValidateDevicePath(symlink) = %v, want nil", err)
	}
}

func TestSecurityConstants(t *testing.T) {
	// Verify security constants have reasonable values
	tests := []struct {
		name  string
		value int
		min   int
	}{
		{"MinPassphraseLength", MinPassphraseLength, 8},
		{"MaxPassphraseLength", MaxPassphraseLength, 512},
		{"MinKeySize", minKeySize, 256},
		{"MaxKeySize", maxKeySize, 512},
		{"MinSectorSize", minSectorSize, 512},
		{"MaxSectorSize", maxSectorSize, 4096},
		// The digest cost is calibrated; see TestDigestCalibrationTargetsItsBudget and DigestIterationTargetMs.
		{"DigestIterationTargetMs", digestIterationTargetMs, 1},
		{"DigestCalibrationKeyLen", digestCalibrationKeyLen, 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value < tt.min {
				t.Errorf("%s = %d, want >= %d", tt.name, tt.value, tt.min)
			}
		})
	}
}

// A permission failure must be typed; faults are injected at openFileFunc because root bypasses permission bits.

// failOpensWith makes every openDevice call fail with err wrapped in the
// *fs.PathError shape the kernel produces, and restores the seam afterwards.
func failOpensWith(t *testing.T, err error) volumeSys {
	t.Helper()

	sys := testVolumeSys()
	sys.openFile = func(name string, _ int, _ os.FileMode) (*os.File, error) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	return sys
}

// TestClassifyDeviceOpen_TypesAPermissionFailure is the contract itself: both
// errnos the kernel uses for "you may not", classified, with the cause still
// reachable.
func TestClassifyDeviceOpen_TypesAPermissionFailure(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EACCES, syscall.EPERM} {
		t.Run(errno.Error(), func(t *testing.T) {
			cause := &fs.PathError{Op: "open", Path: "/dev/sdb1", Err: errno}

			err := classifyDeviceOpen("read the LUKS2 header", cause)
			if !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("classifyDeviceOpen = %v, want an error wrapping ErrPermissionDenied", err)
			}
			// A caller that already branched on the standard library's sentinel
			// must not have to change.
			if !errors.Is(err, os.ErrPermission) {
				t.Fatalf("the classified error no longer matches os.ErrPermission: %v", err)
			}
			if !errors.Is(err, errno) {
				t.Fatalf("the classified error no longer reaches the errno: %v", err)
			}
			// Naming the operation is the difference between a verdict and a
			// remedy: the message has to say what was being attempted.
			if !strings.Contains(err.Error(), "read the LUKS2 header") {
				t.Fatalf("the classified error does not name the operation: %v", err)
			}
			if !strings.Contains(err.Error(), "RAW BLOCK DEVICE") {
				t.Fatalf("the classified error carries no remedy: %v", err)
			}
		})
	}
}

// TestClassifyDeviceOpen_LeavesEverythingElseAlone is the other half. Wrapping
// every open failure would rewrite the message of every failure in the package
// to buy a distinction only one of them needs.
func TestClassifyDeviceOpen_LeavesEverythingElseAlone(t *testing.T) {
	for errno, kind := range map[syscall.Errno]error{syscall.ENOENT: ErrDeviceNotFound, syscall.ENOTDIR: ErrIO, syscall.EIO: ErrIO} {
		t.Run(errno.Error(), func(t *testing.T) {
			cause := &fs.PathError{Op: "open", Path: "/dev/sdb1", Err: errno}

			err := classifyDeviceOpen("read the LUKS2 header", cause)
			var e *Error
			if !errors.As(err, &e) || !errors.Is(err, kind) {
				t.Fatalf("classifyDeviceOpen of a %v failure = %v, want an *Error of kind %v", errno, err, kind)
			}
			if !errors.Is(err, cause) {
				t.Fatalf("the cause of a %v failure is not reachable: %v", errno, err)
			}
			if errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("a %v failure was classified as a permission failure: %v", errno, err)
			}
		})
	}

	if err := classifyDeviceOpen("read the LUKS2 header", nil); err != nil {
		t.Fatalf("classifyDeviceOpen(nil) = %v, want nil", err)
	}
}

// TestOpenDeviceClassifiesAPermissionFailure covers the wrapper rather than the
// classifier, so a future openDevice that forgot to call it would be caught.
func TestOpenDeviceClassifiesAPermissionFailure(t *testing.T) {
	sys := failOpensWith(t, syscall.EACCES)

	f, err := openDevice("read the LUKS2 header", "/dev/sdb1", os.O_RDONLY, sys)
	if err == nil {
		_ = f.Close()
		t.Fatal("openDevice reported success against a seam that always refuses")
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("openDevice = %v, want an error wrapping ErrPermissionDenied", err)
	}
}

// TestTheExportedPathsReportAPermissionFailureAsOne: every exported entry point reports a classified open failure.
func TestTheExportedPathsReportAPermissionFailureAsOne(t *testing.T) {
	// A real readable file, so the failure is the open, not the path check.
	device := newImage(t, "permission.img")

	tests := []struct {
		name string
		call func(sys volumeSys) error
	}{
		{"ReadHeader", func(sys volumeSys) error { _, _, err := readHeaderForTestWithSys(device, sys); return err }},
		{"IsLUKS", func(sys volumeSys) error { _, err := isLUKSForTestWithSys(device, sys); return err }},
		{"IsLUKS2", func(sys volumeSys) error { _, err := isLUKS2ForTestWithSys(device, sys); return err }},
		{"AcquireFileLock", func(sys volumeSys) error {
			_, err := acquireFileLock(context.Background(), device, DefaultLockWait, clock.System{}, sys)
			return err
		}},
		{"Format", func(sys volumeSys) error {
			return formatWithSys(formatOptionsForTest{
				Device:        device,
				Passphrase:    []byte(conformancePassphrase),
				KDFType:       kdfTypePBKDF2,
				PBKDFIterTime: 1,
			}, sys)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sys := failOpensWith(t, syscall.EACCES)

			err := tt.call(sys)
			if err == nil {
				t.Fatal("the call reported success against a seam that always refuses to open the device")
			}
			if !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("%s = %v, want an error wrapping ErrPermissionDenied", tt.name, err)
			}
			if !errors.Is(err, os.ErrPermission) {
				t.Fatalf("%s lost the underlying cause: %v", tt.name, err)
			}
		})
	}
}

// TestAcquireFileLockWaitsForARelease: a waiting acquire succeeds soon after the release, not at the deadline.
func TestAcquireFileLockWaitsForARelease(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "luks-lock-wait-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	held, err := acquireDeviceLock(tmpFile.Name())
	if err != nil {
		t.Fatalf("first acquireDeviceLock() error = %v", err)
	}

	// The holder lets go 150ms into the wait, on a clock only the wait moves.
	const holdFor = 150 * time.Millisecond
	clk := clock.NewFake(t)
	released := false
	clk.OnWait(func(time.Time) {
		if !released && clk.Elapsed() >= holdFor {
			if err := held.Release(); err != nil {
				t.Errorf("Release() error = %v", err)
			}
			released = true
		}
	})

	second, err := acquireFileLock(context.Background(), tmpFile.Name(), 10*time.Second, clk, testVolumeSys())
	if err != nil {
		t.Fatalf("second acquireFileLock() error = %v, want it to queue and succeed", err)
	}
	defer func() { _ = second.Release() }()

	if !released {
		t.Fatal("the second lock was granted while the first was still held -- it cannot have been exclusive")
	}
	// Noticed within one backoff of the release, not at the deadline.
	if waited := clk.Elapsed(); waited < holdFor || waited > holdFor+lockBackoffMax {
		t.Errorf("acquired after %v, want within %v of the %v release", waited, lockBackoffMax, holdFor)
	}
	// The pacing: the documented backoff, doubling from the minimum.
	if len(clk.Waits()) < 2 || clk.Waits()[0] != lockBackoffMin || clk.Waits()[1] != 2*lockBackoffMin {
		t.Errorf("backoff began %v, want %v then %v", clk.Waits(), lockBackoffMin, 2*lockBackoffMin)
	}
	for i, d := range clk.Waits() {
		if d > lockBackoffMax {
			t.Errorf("sleep %d was %v, above the %v backoff ceiling", i, d, lockBackoffMax)
		}
	}
}

// TestAcquireFileLockTimesOutWithATypedError covers the other side: a holder
// that never releases must produce a bounded, typed, actionable failure rather
// than an unbounded wait.
func TestAcquireFileLockTimesOutWithATypedError(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "luks-lock-timeout-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	held, err := acquireDeviceLock(tmpFile.Name())
	if err != nil {
		t.Fatalf("acquireDeviceLock() error = %v", err)
	}
	defer func() { _ = held.Release() }()

	const budget = 120 * time.Millisecond
	clk := clock.NewFake(t)
	_, err = acquireFileLock(context.Background(), tmpFile.Name(), budget, clk, testVolumeSys())
	if err == nil {
		t.Fatal("acquireFileLock() on a held lock = nil, want a timeout")
	}

	if !errors.Is(err, ErrLockContended) {
		t.Errorf("errors.Is(err, ErrLockContended) = false for %#v; a caller cannot tell contention from a broken device", err)
	}

	var lockErr *LockTimeoutError
	if !errors.As(err, &lockErr) {
		t.Fatalf("errors.As(err, *LockTimeoutError) = false for %v", err)
	}
	if lockErr.Path != tmpFile.Name() {
		t.Errorf("LockTimeoutError.Path = %q, want %q", lockErr.Path, tmpFile.Name())
	}
	// The budget is honored exactly: the last sleep is cut to what remains.
	if clk.Elapsed() != budget || lockErr.Waited != budget {
		t.Errorf("waited %v and reported %v against a %v budget", clk.Elapsed(), lockErr.Waited, budget)
	}
	if lockErr.Attempts != len(clk.Waits())+1 {
		t.Errorf("LockTimeoutError.Attempts = %d after %d sleeps, want one attempt more than the sleeps between them",
			lockErr.Attempts, len(clk.Waits()))
	}
	// The message must name the device; an operator reading a CI log has
	// nothing else to go on.
	if !strings.Contains(err.Error(), tmpFile.Name()) {
		t.Errorf("error %q does not name the locked path", err.Error())
	}
}

// TestAcquireFileLockZeroBudgetTriesOnce pins the documented degenerate case:
// a non-positive budget is the old non-blocking behavior, on purpose.
func TestAcquireFileLockZeroBudgetTriesOnce(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "luks-lock-zero-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	// Free: one attempt suffices, so a zero budget still succeeds.
	free, err := acquireDeviceLockTimeout(tmpFile.Name(), 0)
	if err != nil {
		t.Fatalf("acquireDeviceLockTimeout(free, 0) error = %v, want success on the first attempt", err)
	}

	// Held: one attempt is not enough, and there is no budget to spend -- so
	// there is no sleep at all.
	clk := clock.NewFake(t)
	_, err = acquireFileLock(context.Background(), tmpFile.Name(), 0, clk, testVolumeSys())
	if err == nil {
		t.Fatal("acquireFileLock(held, 0) = nil, want a timeout")
	}
	if !errors.Is(err, ErrLockContended) {
		t.Errorf("errors.Is(err, ErrLockContended) = false for %v", err)
	}
	if len(clk.Waits()) != 0 {
		t.Errorf("a zero budget slept %v -- it is not returning immediately", clk.Waits())
	}
	_ = free.Release()
}

// TestAcquireFileLockOnAnUnopenableDeviceIsNotAContentionError separates the
// two failure classes. An open that fails is a device fault and must keep its
// device-open classification; reporting it as contention would send an
// operator looking for a lock holder that does not exist.
func TestAcquireFileLockOnAnUnopenableDeviceIsNotAContentionError(t *testing.T) {
	_, err := acquireDeviceLockTimeout("/nonexistent/file/path", 50*time.Millisecond)
	if err == nil {
		t.Fatal("acquireDeviceLockTimeout(nonexistent) = nil, want error")
	}
	if errors.Is(err, ErrLockContended) {
		t.Errorf("a missing device is reported as lock contention: %v", err)
	}
}
