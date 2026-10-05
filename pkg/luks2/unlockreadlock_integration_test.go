// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

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

// TestUnlockWaitsForCryptsetupsWriteLock: real cryptsetup holding its write
// lock on the device holds Unlock's metadata read off until it has written.
//
// `cryptsetup token import` runs under strace, which delays the return of
// the flock that takes its write lock: cryptsetup then HOLDS the lock and has
// not yet written token 7. Unlock is started inside that window. Reading the
// header with no lock -- as it used to -- it sees the header from before the
// write, without token 7. Under cryptsetup's read lock it waits, and the
// header it reads carries token 7.
func TestUnlockWaitsForCryptsetupsWriteLock(t *testing.T) {
	requireCryptsetupDeclared(t)
	stracePath, err := exec.LookPath("strace")
	if err != nil {
		t.Fatalf("strace is not installed (%v). This tier DECLARES it -- test/integration/Dockerfile "+
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

	previous := readUnlockHeader
	t.Cleanup(func() { readUnlockHeader = previous })
	sawToken := false
	readUnlockHeader = func(f io.ReaderAt, offset int64) (*LUKS2BinaryHeader, *LUKS2Metadata, error) {
		hdr, metadata, err := previous(f, offset)
		if err == nil {
			_, sawToken = metadata.Tokens["7"]
		}
		return hdr, metadata, err
	}

	name := runVolume(t, "read-lock")
	defer releaseVolume(t, name)
	if err := Unlock(loop, []byte(laneDPassphrase), name); err != nil {
		t.Fatalf("Unlock beside cryptsetup's write: %v", err)
	}

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

	if !sawToken {
		t.Fatal("Unlock read the header cryptsetup was about to rewrite: the read did not wait for cryptsetup's write lock")
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
