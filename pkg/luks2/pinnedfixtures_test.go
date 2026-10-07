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

// cryptsetupWriteLockFlock is which flock(2) call of a cryptsetup metadata
// write takes the WRITE lock, under strace's injected delay. Measured
// against cryptsetup 2.7.5: the read lock is LOCK_SH, its release LOCK_UN
// then LOCK_EX|LOCK_NB (to unlink); the fourth call is the blocking LOCK_EX
// of the write. Shared by lockwait_integration_test.go.
const cryptsetupWriteLockFlock = 4

// cryptsetupWriteHold is how long strace keeps cryptsetup holding its write
// lock before it writes. Shared by lockwait_integration_test.go.
const cryptsetupWriteHold = 5 * time.Second

// This file backs what pkg/luks2's own integration tier still keeps after
// #274 (H12c): unlockreadlock_integration_test.go moved out to
// test/integration/luks2/ (it no longer needed any unexported seam -- see
// its new home's own comment). canonicalconformance_integration_test.go
// needs none of this either. The remaining three are white-box in a way
// nothing outside this package can reach --
//
//   - pinnedpaths_integration_test.go drives relinkAfterFirstOpen
//     (relink_test.go), which re-points a symlink from inside pkg/luks2's
//     own unexported openFileFunc seam at the exact moment this package's
//     locked-descriptor reopen (Locked.Claim) makes its first writable
//     open. There is no path to that seam from outside the package. It no
//     longer activates a real mapping to produce its "device in use"
//     fixture (#268 moved activation to pkg/dmcrypt, which pkg/luks2
//     cannot import): an exclusive O_EXCL open of the loop device is the
//     same kernel condition WipeKeyslot's own busy check reacts to, per
//     the file's own comment, so that stands in instead. relinkAfterFirstOpen
//     itself still keeps this file from moving out: DESIGN.md §E's
//     "exported-within-internal API" for openFileFunc would mean relocating
//     a seam device.OpenFunc already shadows (volumeSys.openFile) into an
//     internal/ package that every other pkg/luks2 production call site
//     (format.go, medium.go, security.go, wipe.go) would need to switch to
//     -- flagged for the owner rather than attempted here, the same
//     reasoning as the two below.
//   - lockwait_integration_test.go's TestCryptsetupWaitsForEveryWritePath
//     substitutes fileLockHeld (security.go), another unexported seam, to
//     catch a write path exactly after it has taken its locks.
//   - lockcompat_integration_test.go's TestCompatMetadataLockDirectoryStates
//     re-execs this package's own test binary and, inside that child, sets
//     calibratedCountFloor and keyslotLockWait -- both unexported package
//     vars -- before running a go-luks2 operation. A copy of the binary
//     re-exec'd from test/integration/interop would be THAT package's test
//     binary, which cannot reach these vars either.
//
// All three are flagged for the owner, the same way test/integration/pkg's
// own TestMain already flags the dm.create write-ahead-ledger gap it
// accepted on 2026-09-01: new exported-within-internal surface on a Layer-0
// library's production seams is an owner's decision, not a lane's to invent
// -- doubly so here, where the candidate seams (random-number source,
// lock-held observer, KDF calibration floor) are security-relevant and the
// relocation touches production call sites well beyond these three tests.

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

// flockWaiterOn reports whether /proc/locks shows a process BLOCKED on a
// flock of the file with inode ino -- the "->" lines. Shared by
// lockwait_integration_test.go.
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
