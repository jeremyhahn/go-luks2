// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package interop_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
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
	mapping, err := activateUnrecorded(ctx, device, passphrase, name, dmcrypt.Activate)
	if err != nil {
		return err
	}

	// Write-ahead for the host state Activate just created, so a run that dies
	// before its teardown still leaves a ledger entry a later run's reaper can
	// remove (#96). A Record failure is fatal to the activation: an unrecorded
	// mapping is host state nothing can attribute.
	if err := recordMapping(name, mapping.UUID); err != nil {
		_ = dmcrypt.Deactivate(ctx, name)
		return err
	}

	return nil
}

// recordMapping records name's mapping in the run ledger. A process with no
// registered suite -- a FIPS child, which exits from init() before TestMain
// runs -- gets an error, not a nil dereference.
func recordMapping(name, uuid string) error {
	if runSuite == nil {
		return fmt.Errorf("recording dm %q: TestMain did not register the suite in this process", name)
	}
	if err := runSuite.Ledger.Record(harness.KindMapping, name, uuid); err != nil {
		return fmt.Errorf("recording dm %q in the run ledger: %w", name, err)
	}
	return nil
}

// activator is dmcrypt.Activate's shape, so the FIPS child can run its path
// with a stand-in for device-mapper (fipsChildRoleStandIn).
type activator func(context.Context, *luks2.Volume, *luks2.Key, string) (*dmcrypt.Mapping, error)

// activateUnrecorded is Unlock without the ledger record: Open, Unlock, and
// activate. The FIPS child runs this alone, and its parent records the
// mapping it left (unlockInFIPSProcess).
func activateUnrecorded(ctx context.Context, device string, passphrase []byte, name string, activate activator) (*dmcrypt.Mapping, error) {
	v, err := luks2.Open(ctx, device)
	if err != nil {
		return nil, err
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy(passphrase)
	if err != nil {
		return nil, err
	}
	defer func() { _ = pass.Destroy() }()

	key, err := v.Unlock(ctx, pass)
	if err != nil {
		return nil, err
	}
	defer key.Destroy()

	return activate(ctx, v, key, name)
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
// returning combined output (moved here with fipsimport_test.go and
// sha1af_test.go in #274, when test/integration/pkg was removed).
func run(t *testing.T, name string, args ...string) string {
	t.Helper()

	out, err := exec.Command(name, args...).CombinedOutput() // #nosec G204 -- arguments are test constants
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// lockWithRetry rides out the transient EBUSY the host's own udev produces
// right after a write to a mapped device (moved here in #274,
// when test/integration/pkg was removed): the suite shares the HOST's
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

// createTestFile creates a test file with the given size (moved here in #274,
// when test/integration/pkg was removed).
func createTestFile(path string, sizeMB int) error {
	f, err := os.Create(path) // #nosec G304 -- path is a test fixture under t.TempDir()
	if err != nil {
		return err
	}
	defer f.Close()

	return f.Truncate(int64(sizeMB * 1024 * 1024))
}

// This package is test/integration/interop/: cryptsetup and systemd are the
// real peer (testing-guidelines), checked in both directions. The two
// pkg/luks2 tests that re-exec their own test binary (see
// pkg/luks2/lockcompat_integration_test.go and lockwait_integration_test.go:
// TestCompatMetadataLockDirectoryStates and TestCryptsetupWaitsForEveryWritePath)
// stay in pkg/luks2, because they set unexported seams (volumeSys.lockHeld and
// volumeSys.calibratedCountFloor, and the package var keyslotLockWait) that
// have no external setter.

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
