// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package interop_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"
	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

// Unlock, Lock, IsUnlocked and GetMappedDevicePath are the old
// luks2.Unlock/Lock/IsUnlocked/GetMappedDevicePath free functions, forwarded
// across the two packages they collapsed into (#268): pkg/luks2 derives the
// key and pkg/dmcrypt activates it. See cmd/luks2/cli.go's
// DefaultLuksOperations for the same forward.
func Unlock(device string, passphrase []byte, name string) error {
	ctx := context.Background()
	v, err := luks2.Open(ctx, device)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy(passphrase)
	if err != nil {
		return err
	}
	defer func() { _ = pass.Destroy() }()

	key, err := v.Unlock(ctx, pass)
	if err != nil {
		return err
	}
	defer key.Destroy()

	_, err = dmcrypt.Activate(ctx, v, key, name)
	return err
}

func Lock(name string) error {
	return dmcrypt.Deactivate(context.Background(), name)
}

func IsUnlocked(name string) bool {
	_, err := dmcrypt.Lookup(context.Background(), name)
	return err == nil
}

func GetMappedDevicePath(name string) (string, error) {
	m, err := dmcrypt.Lookup(context.Background(), name)
	if err != nil {
		return "", err
	}
	return m.Path(), nil
}

// run executes name with args and fails the test on a non-zero exit,
// returning combined output -- moved from test/integration/pkg's
// keyring_test.go (#274), which fipsimport_test.go and sha1af_test.go
// (also moved here) still need.
func run(t *testing.T, name string, args ...string) string {
	t.Helper()

	out, err := exec.Command(name, args...).CombinedOutput() // #nosec G204 -- arguments are test constants
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// lockWithRetry rides out the transient EBUSY the host's own udev produces
// right after a write to a mapped device (#274, moved from
// test/integration/pkg's keyring_test.go): the suite shares the HOST's
// device-mapper, and closing a device just written to can lose the race
// against udev's blkid probe.
func lockWithRetry(t *testing.T, volumeName string) {
	t.Helper()

	var err error
	for i := 0; i < 100; i++ {
		if err = Lock(volumeName); err == nil {
			return
		}
		if !strings.Contains(err.Error(), "busy") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("Lock failed: %v", err)
}

// createTestFile creates a test file with the given size, moved from
// test/integration/pkg's common_test.go (#274).
func createTestFile(path string, sizeMB int) error {
	f, err := os.Create(path) // #nosec G304 -- path is a test fixture under t.TempDir()
	if err != nil {
		return err
	}
	defer f.Close()

	return f.Truncate(int64(sizeMB * 1024 * 1024))
}

// This package is test/integration/interop/: cryptsetup and systemd are the
// real peer (testing-guidelines), checked in both directions. Only
// compatmatrix_integration_test.go moves here from pkg/luks2 (#274):
// lockcompat_integration_test.go and lockwait_integration_test.go's
// TestCompatMetadataLockDirectoryStates and TestCryptsetupWaitsForEvery-
// WritePath each re-exec this package's own test binary and tweak a
// pkg/luks2-private seam inside it (calibratedCountFloor/keyslotLockWait,
// fileLockHeld) that has no external setter -- the same class of gap
// test/integration/pkg's own TestMain already accepted on 2026-09-01 for
// dm.create's write-ahead ledger, for the same reason: new exported surface
// on a Layer-0 library is an owner's decision, not a lane's. Both stay in
// pkg/luks2, flagged there for the owner.

var runSuite *harness.Suite

func runVolume(t *testing.T, base string) string {
	t.Helper()
	if runSuite == nil {
		t.Fatalf("runVolume(%q): TestMain did not register the suite, so this name would be "+
			"host-global and could collide with a concurrent run.", base)
	}
	name, err := runSuite.VolumeName(base)
	if err != nil {
		t.Fatalf("runVolume(%q): %v", base, err)
	}
	return name
}

func releaseVolume(t *testing.T, volumeName string) {
	t.Helper()

	const timeout = 10 * time.Second
	var last error
	deadline := time.Now().Add(timeout)
	for {
		if err := Lock(volumeName); err != nil && !errors.Is(err, dmcrypt.ErrNotActive) {
			last = err
		}
		if mappingConfirmedGone(volumeName) {
			return
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Errorf("device-mapper mapping %q is STILL PRESENT after %s. Last error from Lock: %v", volumeName, timeout, last)
}

func mappingConfirmedGone(volumeName string) bool {
	out, err := exec.Command("dmsetup", "info", volumeName).CombinedOutput()
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "device does not exist")
}

func requireCryptsetupDeclared(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		t.Fatalf("cryptsetup is not installed (%v). This tier DECLARES it.", err)
	}
}

// parallel marks t parallel and holds a locked-memory slot until the
// returned function is called, the same throttle pkg/luks2's own
// lockedmemorybudget_test.go uses (#233) -- reimplemented here since this
// is a separate test binary with its own mlock budget to share.
var (
	parallelSlotsOnce sync.Once
	parallelSlots     chan struct{}
)

func parallelSlotCount() int {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil || lim.Cur == unix.RLIM_INFINITY {
		return max(runtime.GOMAXPROCS(0), 1)
	}
	const reserve, perTest = 8 << 20, 2 << 20
	if lim.Cur <= reserve+perTest {
		return 1
	}
	if n := int((lim.Cur - reserve) / perTest); n < runtime.GOMAXPROCS(0) {
		return max(n, 1)
	}
	return max(runtime.GOMAXPROCS(0), 1)
}

func parallel(t *testing.T) func() {
	t.Helper()
	t.Parallel()
	parallelSlotsOnce.Do(func() { parallelSlots = make(chan struct{}, parallelSlotCount()) })
	parallelSlots <- struct{}{}
	var once sync.Once
	return func() { once.Do(func() { <-parallelSlots }) }
}

func activationImage(t *testing.T, name string, sizeMiB int, fill []byte) string {
	t.Helper()
	image := filepath.Join(t.TempDir(), name)
	f, err := os.Create(image) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatalf("creating %s failed: %v", image, err)
	}
	if err := f.Truncate(int64(sizeMiB) << 20); err != nil {
		t.Fatalf("sizing %s failed: %v", image, err)
	}
	if fill != nil {
		if _, err := f.WriteAt(fill, 0); err != nil {
			t.Fatalf("filling %s failed: %v", image, err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing %s failed: %v", image, err)
	}
	return image
}

func attachLoop(t *testing.T, image string) string {
	t.Helper()
	loopDev, err := harness.SetupLoopDevice(image)
	if err != nil {
		t.Fatalf("attaching %s failed: %v", image, err)
	}
	t.Cleanup(func() { _ = harness.DetachLoopDevice(loopDev) })
	return loopDev
}

func activationLoop(t *testing.T, name string, sizeMiB int, fill []byte) (loopDev, image string) {
	t.Helper()
	image = activationImage(t, name, sizeMiB, fill)
	return attachLoop(t, image), image
}

func deviceDigest(t *testing.T, device string, n int64) [32]byte {
	t.Helper()
	f, err := os.Open(device) // #nosec G304 -- a loop device this test attached
	if err != nil {
		t.Fatalf("opening %s failed: %v", device, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.CopyN(h, f, n); err != nil {
		t.Fatalf("reading %s failed: %v", device, err)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

func TestMain(m *testing.M) {
	suite, err := harness.BeginSuite(os.Stderr)
	if err != nil {
		os.Stderr.WriteString("integration suite: " + err.Error() + "\n")
		os.Exit(1)
	}
	runSuite = suite
	os.Exit(suite.Finish(m.Run(), os.Stderr))
}
