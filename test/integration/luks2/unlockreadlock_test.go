// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"
	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// cryptsetupLockDir is cryptsetup's default locking directory (see
// pkg/luks2/cryptsetuplock.go's own comment); a fixed convention, not a
// seam, so this black-box package hardcodes it rather than needing access
// to pkg/luks2's unexported copy.
const cryptsetupLockDir = "/run/cryptsetup"

// cryptsetupWriteLockFlock is which flock(2) call of `cryptsetup token import`
// takes the WRITE lock. Measured with strace against cryptsetup 2.7.5: the
// read lock is LOCK_SH, its release LOCK_UN then LOCK_EX|LOCK_NB (to unlink);
// the fourth call is the blocking LOCK_EX of the write. The test checks the
// trace afterwards, so a cryptsetup that orders them differently fails it
// loudly rather than passing on a delay that landed somewhere else.
const cryptsetupWriteLockFlock = 4

// cryptsetupWriteHold is how long strace keeps cryptsetup holding its write
// lock before it writes: long enough that Unlock, started once the hold is
// seen, reaches its read inside it on a loaded host.
const cryptsetupWriteHold = 5 * time.Second

// lockFileFor returns cryptsetup's lock file for the block device at path.
func lockFileFor(t *testing.T, path string) string {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	rdev := uint64(st.Rdev) // #nosec G115 -- a device number
	return filepath.Join(cryptsetupLockDir, "L_"+strconv.FormatUint(uint64(unix.Major(rdev)), 10)+":"+strconv.FormatUint(uint64(unix.Minor(rdev)), 10))
}

// TestUnlockWaitsForCryptsetupsWriteLock: real cryptsetup holding its write
// lock on the device holds Volume.Unlock's metadata read off until it has
// written, moved from pkg/luks2/unlockreadlock_integration_test.go (#274).
//
// `cryptsetup token import` runs under strace, which delays the return of
// the flock that takes its write lock: cryptsetup then HOLDS the lock and has
// not yet written token 7. Unlock is started inside that window.
//
// The original asserted this by substituting pkg/luks2's own unexported
// readUnlockHeader seam to see whether the header it read carried token 7 --
// a seam that no longer exists after the H9 rewrite folded that read into
// header.ReadHeaderCopyFrom with no package-level var left to intercept, and
// that this black-box package could not reach even if it did. What the seam
// proved is instead proven by TIMING: Volume.Unlock's first step is an
// flock(2) that must itself block behind cryptsetup's held LOCK_EX. A read
// that raced ahead would return in microseconds; one that genuinely waited
// returns only once cryptsetup's hold -- still writeHoldSeen away from being
// released when Unlock starts -- ends.
func TestUnlockWaitsForCryptsetupsWriteLock(t *testing.T) {
	requireCryptsetupDeclared(t)
	stracePath, err := exec.LookPath("strace")
	if err != nil {
		t.Fatalf("strace is not installed (%v). This tier DECLARES it -- build/docker/integration/Dockerfile "+
			"installs it -- and without it nothing can make cryptsetup hold its lock on cue.", err)
	}
	loop, _ := laneDLoop(t)
	lockPath := lockFileFor(t, loop)

	tokenFile := filepath.Join(t.TempDir(), "token.json")
	if err := os.WriteFile(tokenFile, []byte(`{"type":"x-read-lock-probe","keyslots":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	traceLog := filepath.Join(t.TempDir(), "strace.log")
	// #nosec G204 -- fixed arguments and paths this test made
	cmd := exec.Command(stracePath, "-f", "-qq", "-o", traceLog, "-e", "trace=flock",
		"-e", "inject=flock:delay_exit="+strconv.FormatInt(cryptsetupWriteHold.Microseconds(), 10)+":when="+strconv.Itoa(cryptsetupWriteLockFlock),
		"cryptsetup", "token", "import", "--json-file", tokenFile, "--token-id", "7", loop)
	var output strings.Builder
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	// Whatever ends this test, the child does not outlive it.
	defer func() { _ = cmd.Process.Kill() }()

	// Polled, re-checking the real condition each pass: cryptsetup holds the
	// file exclusively when a shared, non-blocking flock of it is refused.
	// It is the WRITE lock once that has stayed true, on one inode, for
	// writeHoldSeen: cryptsetup's only other exclusive hold -- the try-lock
	// its read-lock release makes before unlinking -- lasts microseconds.
	const writeHoldSeen = 200 * time.Millisecond
	var heldIno uint64
	var heldSince time.Time
	for {
		ino, held := exclusiveHolder(t, lockPath)
		if !held {
			heldIno = 0
		} else if ino != heldIno {
			heldIno, heldSince = ino, time.Now()
		} else if time.Since(heldSince) >= writeHoldSeen {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("cryptsetup finished (%v) before it was seen holding %s:\n%s", err, lockPath, output.String())
		default:
			time.Sleep(time.Millisecond)
		}
	}

	ctx := context.Background()
	v, err := luks2.Open(ctx, loop)
	if err != nil {
		t.Fatalf("Open beside cryptsetup's write: %v", err)
	}
	defer func() { _ = v.Close() }()
	pass, err := enclave.NewMemoryEnclaveCopy([]byte(canonicalPassphrase))
	if err != nil {
		t.Fatalf("could not hold the passphrase in protected memory: %v", err)
	}
	defer func() { _ = pass.Destroy() }()
	unlockStart := time.Now()
	key, err := v.Unlock(ctx, pass)
	if err != nil {
		t.Fatalf("Unlock beside cryptsetup's write: %v", err)
	}
	defer key.Destroy()
	unlockWait := time.Since(unlockStart)

	if err := <-done; err != nil {
		t.Fatalf("cryptsetup token import: %v\n%s", err, output.String())
	}
	trace, err := os.ReadFile(traceLog) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !delayedTheWriteLock(string(trace)) {
		t.Fatalf("strace did not delay cryptsetup's blocking LOCK_EX -- its lock sequence is not the one measured:\n%s", trace)
	}

	// writeHoldSeen (200ms) is how long cryptsetup had ALREADY held its
	// write lock by the time Unlock started; the threshold here is far
	// below the remaining hold (cryptsetupWriteHold, 5s) and far above
	// what an unblocked flock(2)+read takes, so it separates "waited" from
	// "raced ahead" without being sensitive to exactly how much of the
	// hold was left.
	if unlockWait < writeHoldSeen {
		t.Fatalf("Unlock returned after %s, before cryptsetup's write lock was seen held for %s: the read did not wait for cryptsetup's write lock", unlockWait, writeHoldSeen)
	}
}

// exclusiveHolder reports whether someone holds path with LOCK_EX -- a
// shared, non-blocking flock of it is refused -- and the inode it names. A
// missing file is not held.
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
// blocking LOCK_EX -- the write lock's acquisition.
func delayedTheWriteLock(trace string) bool {
	for _, line := range strings.Split(trace, "\n") {
		if strings.Contains(line, "DELAYED") {
			return strings.Contains(line, "LOCK_EX)") && !strings.Contains(line, "LOCK_NB")
		}
	}
	return false
}
