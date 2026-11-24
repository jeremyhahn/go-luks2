// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	looppkg "github.com/jeremyhahn/go-luks2/pkg/loop"
)

// cryptsetupWriteLockFlock is which flock call of a cryptsetup 2.7.5 metadata write takes the write lock.
const cryptsetupWriteLockFlock = 4

// cryptsetupWriteHold is how long strace keeps cryptsetup holding its write
// lock before it writes. Shared by lockwait_integration_test.go.
const cryptsetupWriteHold = 5 * time.Second

// Helpers for the integration tests that need this package's unexported seams (openFileFunc, volumeSys.lockHeld, calibratedCountFloor, keyslotLockWait).

// boolPtr is the integration build's copy of the helper unknownfields_test.go
// (`!integration`) keeps for the unit build; token_test.go (untagged) needs
// it in both. See that file's own comment.
func boolPtr(b bool) *bool { return &b }

// laneDLoop formats a fresh image attached to a loop device without direct
// I/O, and returns the loop device and the image. Shared by
// pinnedpaths_integration_test.go, lockwait_integration_test.go and
// lockcompat_integration_test.go.
func laneDLoop(t *testing.T) (loop, image string) {
	t.Helper()
	requireRoot(t)

	image = canonicalImage(t, "lane-d.img")
	loopDevice, err := looppkg.Attach(context.Background(), image)
	if err != nil {
		t.Fatalf("loop.Attach: %v", err)
	}
	t.Cleanup(func() { _, _ = loopDevice.Detach(context.Background()) })
	loop = loopDevice.Path()
	if err := formatForTest(formatOptionsForTest{Device: loop, Passphrase: []byte(laneDPassphrase), KDFType: kdfTypePBKDF2, PBKDFIterTime: 1}); err != nil {
		t.Fatalf("Format: %v", err)
	}
	return loop, image
}

const laneDPassphrase = "lane-d-passphrase"

// requireRoot fails the calling test when it is not running as uid 0.
func requireRoot(t *testing.T) {
	t.Helper()
	if uid := os.Getuid(); uid != 0 {
		t.Fatalf("THIS INTEGRATION TEST REQUIRES ROOT -- running as uid %d.", uid)
	}
}

// lockFileFor returns cryptsetup's lock file for the block device at path.
// Shared by lockwait_integration_test.go.
func lockFileFor(t *testing.T, path string) string {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	rdev := uint64(st.Rdev) // #nosec G115 -- a device number
	return filepath.Join(cryptsetupLockDir, "L_"+strconv.FormatUint(uint64(unix.Major(rdev)), 10)+":"+strconv.FormatUint(uint64(unix.Minor(rdev)), 10))
}

// flockWaiterOn reports whether /proc/locks shows a process blocked on a flock of inode ino.
func flockWaiterOn(t *testing.T, ino uint64) bool {
	t.Helper()
	f, err := os.Open("/proc/locks")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	suffix := ":" + strconv.FormatUint(ino, 10)
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) > 6 && fields[1] == "->" && fields[2] == "FLOCK" && strings.HasSuffix(fields[6], suffix) {
			return true
		}
	}
	return false
}

// deviceDigest hashes the first n bytes of a device. Shared by
// lockcompat_integration_test.go.
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

// exclusiveHolder reports whether someone holds path with LOCK_EX -- a
// shared, non-blocking flock of it is refused -- and the inode it names. A
// missing file is not held. Shared by lockwait_integration_test.go.
func exclusiveHolder(t *testing.T, path string) (ino uint64, held bool) {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- cryptsetup's lock file for a loop device this test made
	if errors.Is(err, os.ErrNotExist) {
		return 0, false
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	err = unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB)
	if err == nil {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		return st.Ino, false
	}
	if !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatal(err)
	}
	return st.Ino, true
}

// delayedTheWriteLock reports whether the one flock strace delayed was a
// blocking LOCK_EX -- the write lock's acquisition. Shared by
// lockwait_integration_test.go.
func delayedTheWriteLock(trace string) bool {
	for _, line := range strings.Split(trace, "\n") {
		if strings.Contains(line, "DELAYED") {
			return strings.Contains(line, "LOCK_EX)") && !strings.Contains(line, "LOCK_NB")
		}
	}
	return false
}
