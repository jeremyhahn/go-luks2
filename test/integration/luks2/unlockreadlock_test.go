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

// cryptsetupWriteLockFlock is which flock call of `cryptsetup token import` (2.7.5) takes the write lock; the trace is checked afterwards.
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

// TestUnlockWaitsForCryptsetupsWriteLock: with cryptsetup holding its write lock under strace, Unlock's flock blocks until the hold ends, shown by timing.
func TestUnlockWaitsForCryptsetupsWriteLock(t *testing.T) {
	requireCryptsetupDeclared(t)
	stracePath, err := exec.LookPath("strace")
	if err != nil {
		t.Fatalf("strace is not installed (%v). This tier DECLARES it -- the integration stage of build/docker/devcontainer/Dockerfile "+
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

	// cryptsetup holds the write lock once a shared non-blocking flock has been refused on one inode for writeHoldSeen.
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
	pass, err := enclave.NewMemoryCopy([]byte(canonicalPassphrase))
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

	// The threshold sits far below the remaining hold and far above an unblocked flock and read.
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
