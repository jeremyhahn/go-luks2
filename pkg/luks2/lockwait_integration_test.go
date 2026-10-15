// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Every go-luks2 write path against a cryptsetup write on the same volume, in
// both orders. TestCryptsetupWaitsForTheDeviceLock and
// TestUnlockWaitsForCryptsetupsWriteLock prove the lock for a bare
// acquireDeviceLock and for Unlock; these prove it for each operation that
// rewrites the header, and that the result is one header both tools read,
// carrying both changes:
//
//   - cryptsetup waits for go-luks2: the operation is held just after it takes
//     the locks, cryptsetup is seen blocked on its lock file, and only after
//     the operation returns does cryptsetup write.
//   - go-luks2 waits for cryptsetup: cryptsetup holds its write lock (strace
//     delays the flock that took it) and the operation, started inside that
//     window, writes only after cryptsetup has -- or cryptsetup's token
//     would be missing from the header the operation wrote.

const (
	mutualSlotOnePassphrase = "mutual-slot-one-passphrase"
	mutualNewPassphrase     = "mutual-new-passphrase"
	mutualCryptsetupToken   = `{"type":"x-mutual-cryptsetup","keyslots":[]}`
	mutualLibraryToken      = `{"type":"x-mutual-go-luks2","keyslots":[]}`
)

// mutualWriteOp is one go-luks2 operation that rewrites the header, and how
// to tell afterwards that it took effect.
type mutualWriteOp struct {
	name   string
	run    func(device string, sys volumeSys) error
	effect func(t *testing.T, device string)
}

var mutualWriteOps = []mutualWriteOp{
	{"AddKey", func(d string, sys volumeSys) error {
		_, err := addKeyWithPolicy(context.Background(), d, []byte(laneDPassphrase), []byte(mutualNewPassphrase),
			&addKeyOptionsForTest{KDFType: kdfTypePBKDF2, PBKDFIterTime: 1}, callerSuppliedCredential, sys)
		return err
	}, func(t *testing.T, d string) {
		mustCryptsetupPassphrase(t, mutualNewPassphrase, "open", "--test-passphrase", d)
	}},
	{"RemoveKey", func(d string, sys volumeSys) error {
		return removeKeyForTest(d, []byte(mutualSlotOnePassphrase), 1, withTestSys(sys))
	}, func(t *testing.T, d string) { assertNoKeyslot(t, d, "1") }},
	{"KillSlot", func(d string, sys volumeSys) error {
		return killSlotForTest(d, []byte(laneDPassphrase), 1, withTestSys(sys))
	}, func(t *testing.T, d string) { assertNoKeyslot(t, d, "1") }},
	{"ChangeKey", func(d string, sys volumeSys) error {
		return changeKeyWithSys(d, []byte(mutualSlotOnePassphrase), []byte(mutualNewPassphrase), 1, sys)
	}, func(t *testing.T, d string) {
		mustCryptsetupPassphrase(t, mutualNewPassphrase, "open", "--test-passphrase", "--key-slot", "1", d)
		if out, ok := cryptsetupWithStdin(t, mutualSlotOnePassphrase, "open", "--test-passphrase", d); ok {
			t.Errorf("the replaced passphrase still opens the volume:\n%s", out)
		}
	}},
	{"SetToken", func(d string, sys volumeSys) error {
		return setTokenJSONForTest(d, 4, []byte(mutualLibraryToken), withTestSys(sys))
	}, func(t *testing.T, d string) {
		mustCryptsetupPassphrase(t, "", "token", "export", "--token-id", "4", d)
	}},
	{"RemoveToken", func(d string, sys volumeSys) error {
		return removeTokenForTest(d, 2, withTestSys(sys))
	}, func(t *testing.T, d string) {
		if out, ok := cryptsetupWithStdin(t, "", "token", "export", "--token-id", "2", d); ok {
			t.Errorf("cryptsetup still exports the removed token:\n%s", out)
		}
	}},
	{"ReplacePrimaryHeader", func(d string, sys volumeSys) error {
		return replacePrimaryHeaderForTest(d, withTestSys(sys))
	}, func(t *testing.T, d string) {}},
	{"RemoveKeyslot", func(d string, sys volumeSys) error {
		v, err := Open(context.Background(), d, withTestSys(sys))
		if err != nil {
			return err
		}
		defer func() { _ = v.Close() }()
		return v.RemoveKeyslot(context.Background(), 1)
	}, func(t *testing.T, d string) { assertNoKeyslot(t, d, "1") }},
}

// mutualFixture is a volume with keyslot 1 beside keyslot 0 and token 2, so
// every operation has something to act on.
func mutualFixture(t *testing.T) string {
	t.Helper()
	loop, _ := laneDLoop(t)
	if _, err := addKeyForTest(loop, []byte(laneDPassphrase), []byte(mutualSlotOnePassphrase), &addKeyOptionsForTest{KDFType: kdfTypePBKDF2, PBKDFIterTime: 1}); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	if err := setTokenJSONForTest(loop, 2, []byte(`{"type":"x-mutual-fixture","keyslots":[]}`)); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	return loop
}

// assertMutualResult holds the volume to what both writers did: one header
// both tools read, both header copies at one sequence id, cryptsetup's token
// present and the operation's effect visible.
func assertMutualResult(t *testing.T, device string, sequenceBefore uint64, op mutualWriteOp, cryptsetupTokenID string) {
	t.Helper()
	mustCryptsetupPassphrase(t, "", "isLuks", device)
	mustCryptsetupPassphrase(t, "", "luksDump", device)
	mustCryptsetupPassphrase(t, laneDPassphrase, "open", "--test-passphrase", "--key-slot", "0", device)
	if err := testKeyForTest(device, []byte(laneDPassphrase)); err != nil {
		t.Errorf("TestKey: %v", err)
	}
	primary, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	secondary, _, err := readSecondaryHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadSecondaryHeader: %v", err)
	}
	if primary.SequenceID != secondary.SequenceID {
		t.Errorf("the header copies are at sequence ids %d and %d", primary.SequenceID, secondary.SequenceID)
	}
	if primary.SequenceID < sequenceBefore+2 {
		t.Errorf("sequence id %d after two writes from %d: one write was lost", primary.SequenceID, sequenceBefore)
	}
	if _, ok := metadata.Tokens[cryptsetupTokenID]; !ok {
		t.Errorf("cryptsetup's token %s is missing: a write was lost", cryptsetupTokenID)
	}
	op.effect(t, device)
}

func assertNoKeyslot(t *testing.T, device, id string) {
	t.Helper()
	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if _, ok := metadata.Keyslots[id]; ok {
		t.Errorf("keyslot %s is still in the header", id)
	}
	if out, ok := cryptsetupWithStdin(t, mutualSlotOnePassphrase, "open", "--test-passphrase", device); ok {
		t.Errorf("cryptsetup still opens the removed keyslot:\n%s", out)
	}
}

// cryptsetupWithStdin runs cryptsetup and reports whether it succeeded.
func cryptsetupWithStdin(t *testing.T, stdin string, args ...string) (string, bool) {
	t.Helper()
	cmd := exec.Command("cryptsetup", args...) // #nosec G204 -- test constants and devices this test made
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("running cryptsetup: %v", err)
	}
	return string(out), err == nil
}

// cryptsetupLockHeldExclusively reports whether this process holds the
// exclusive flock on cryptsetup's lock file for device, read from /proc/locks.
// It runs inside the lock hook, so it reports a failure as false rather than
// failing the test from a goroutine that is not the test's.
func cryptsetupLockHeldExclusively(device string) bool {
	var dev unix.Stat_t
	if err := unix.Stat(device, &dev); err != nil {
		return false
	}
	rdev := uint64(dev.Rdev) // #nosec G115 -- a device number
	lockPath := filepath.Join(cryptsetupLockDir, "L_"+strconv.FormatUint(uint64(unix.Major(rdev)), 10)+":"+strconv.FormatUint(uint64(unix.Minor(rdev)), 10))
	var lock unix.Stat_t
	if err := unix.Stat(lockPath, &lock); err != nil {
		return false
	}
	f, err := os.Open("/proc/locks")
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	suffix := ":" + strconv.FormatUint(lock.Ino, 10)
	pid := strconv.Itoa(os.Getpid())
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) > 5 && fields[1] == "FLOCK" && fields[3] == "WRITE" && fields[4] == pid && strings.HasSuffix(fields[5], suffix) {
			return true
		}
	}
	return false
}

func sequenceID(t *testing.T, device string) uint64 {
	t.Helper()
	hdr, _, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	return hdr.SequenceID
}

// TestCryptsetupWaitsForEveryWritePath: each operation is held just after it
// has taken the locks, and a cryptsetup write started then waits on its lock
// file until the operation is done.
//
// The hold is the operation's own Volume.sys.lockHeld, so no other test's
// lock passes through it.
func TestCryptsetupWaitsForEveryWritePath(t *testing.T) {
	requireCryptsetupDeclared(t)
	tokenFile := filepath.Join(t.TempDir(), "token.json")
	if err := os.WriteFile(tokenFile, []byte(mutualCryptsetupToken), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, op := range mutualWriteOps {
		t.Run(op.name, func(t *testing.T) {
			loop := mutualFixture(t)
			before := sequenceID(t, loop)

			held, proceed := make(chan struct{}), make(chan struct{})
			var once sync.Once
			sys := defaultVolumeSys()
			// Only the exclusive acquisition is held. An operation that is now
			// an Unlock under a shared lock followed by a write under an
			// exclusive one would otherwise stop at the shared read, where
			// cryptsetup loads the header and queues for its write lock, and
			// then fail on the header this operation rewrote in between.
			sys.lockHeld = func(path string) {
				if path == loop && cryptsetupLockHeldExclusively(path) {
					once.Do(func() { close(held); <-proceed })
				}
			}
			released := false
			release := func() {
				if !released {
					released = true
					close(proceed)
				}
			}
			defer release()

			result := make(chan error, 1)
			go func() { result <- op.run(loop, sys) }()
			<-held

			var st unix.Stat_t
			if err := unix.Stat(lockFileFor(t, loop), &st); err != nil {
				t.Fatalf("%s does not hold cryptsetup's lock file: %v", op.name, err)
			}
			cmd := exec.Command("cryptsetup", "token", "import", "--token-id", "9", "--json-file", tokenFile, loop) // #nosec G204 -- a loop device this test made
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			defer func() { _ = cmd.Process.Kill() }()

			// Polled, re-checking the real condition each pass; the bound is
			// the test binary's -timeout.
			for !flockWaiterOn(t, st.Ino) {
				select {
				case err := <-done:
					t.Fatalf("cryptsetup finished (%v) while %s held the lock:\n%s", err, op.name, out.String())
				default:
					time.Sleep(10 * time.Millisecond)
				}
			}

			release()
			if err := <-result; err != nil {
				t.Fatalf("%s: %v", op.name, err)
			}
			if err := <-done; err != nil {
				t.Fatalf("cryptsetup token import after %s: %v\n%s", op.name, err, out.String())
			}
			assertMutualResult(t, loop, before, op, "9")
		})
	}
}

// TestEveryWritePathWaitsForCryptsetup: cryptsetup holds its write lock, the
// operation runs inside the hold, and the header it leaves carries
// cryptsetup's token -- which it would not, had it read the header before
// cryptsetup wrote it.
func TestEveryWritePathWaitsForCryptsetup(t *testing.T) {
	requireCryptsetupDeclared(t)
	stracePath, err := exec.LookPath("strace")
	if err != nil {
		t.Fatalf("strace is not installed (%v); the integration stage of build/docker/devcontainer/Dockerfile installs it", err)
	}

	for _, op := range mutualWriteOps {
		t.Run(op.name, func(t *testing.T) {
			defer parallel(t)()

			loop := mutualFixture(t)
			before := sequenceID(t, loop)
			lockPath := lockFileFor(t, loop)
			tokenFile := filepath.Join(t.TempDir(), "token.json")
			if err := os.WriteFile(tokenFile, []byte(mutualCryptsetupToken), 0o600); err != nil {
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
			defer func() { _ = cmd.Process.Kill() }()

			// As TestUnlockWaitsForCryptsetupsWriteLock: it is the write lock
			// once an exclusive hold has lasted writeHoldSeen on one inode.
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

			if err := op.run(loop, defaultVolumeSys()); err != nil {
				t.Fatalf("%s beside cryptsetup's write: %v", op.name, err)
			}
			if err := <-done; err != nil {
				t.Fatalf("cryptsetup token import: %v\n%s", err, output.String())
			}
			trace, err := os.ReadFile(traceLog) // #nosec G304 -- under t.TempDir()
			if err != nil {
				t.Fatal(err)
			}
			if !delayedTheWriteLock(string(trace)) {
				t.Fatalf("strace did not delay cryptsetup's blocking LOCK_EX:\n%s", trace)
			}
			assertMutualResult(t, loop, before, op, "7")
		})
	}
}
