// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package command

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// trustedDir returns a fresh directory only this user can write.
func trustedDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// t.TempDir makes its directories 0777 less the umask, and a program
	// directory others can write to is refused.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	return dir
}

// writeScript writes an executable shell script.
func writeScript(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatalf("writing %s failed: %v", path, err)
	}
}

// childPIDFIFO makes a FIFO the script under test writes its backgrounded
// child's PID into. Opening a FIFO blocks until the other end opens it, so
// the read in readChildPID is the handshake itself: no polling for a file.
func childPIDFIFO(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "child.pid")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo %s failed: %v", path, err)
	}
	return path
}

// readChildPID blocks until the script has written the PID into fifo and
// closed it, and fails the test if that does not happen within 5 s.
func readChildPID(t *testing.T, fifo string) int {
	t.Helper()
	got := make(chan []byte, 1)
	go func() {
		b, _ := os.ReadFile(fifo) // #nosec G304 -- path built from t.TempDir()
		got <- b
	}()
	select {
	case b := <-got:
		pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil {
			t.Fatalf("the recorded PID %q does not parse: %v", b, err)
		}
		return pid
	case <-time.After(5 * time.Second):
		t.Fatal("the backgrounded child never recorded its PID")
	}
	return 0
}

func TestSystemLooksOnlyInSystemDirectoriesWithTheCLocale(t *testing.T) {
	s := System()
	for _, dir := range s.Dirs {
		if !filepath.IsAbs(dir) || strings.Contains(dir, "local") && !strings.HasPrefix(dir, "/usr/local/") {
			t.Errorf("System().Dirs holds %q", dir)
		}
	}
	if strings.Join(s.Env, " ") != "PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin LC_ALL=C" {
		t.Errorf("System().Env = %q", s.Env)
	}
}

// TestResolveRefusesWhatItCannotTrust covers the resolver's refusals on their
// own: a non-bare name, a missing program, a file that is not an executable,
// and an executable in a directory others can write.
func TestResolveRefusesWhatItCannotTrust(t *testing.T) {
	bin := trustedDir(t)
	if err := os.WriteFile(filepath.Join(bin, "not-exec"), nil, 0o600); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}
	if err := os.Mkdir(filepath.Join(bin, "a-directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(bin, "nowhere"), filepath.Join(bin, "dangling")); err != nil {
		t.Fatal(err)
	}
	tools := Tools{Dirs: []string{bin}}

	for _, name := range []string{"", "../bin/sh", "/bin/sh", "absent", "not-exec", "a-directory", "dangling"} {
		if prog, err := tools.Resolve(name); !errors.Is(err, ErrTool) {
			t.Errorf("Resolve(%q) = %v, %v; want ErrTool", name, prog, err)
		}
	}

	shared := t.TempDir()
	if err := os.Chmod(shared, 0o777); err != nil { // #nosec G302 -- deliberately unsafe, to be refused
		t.Fatal(err)
	}
	writeScript(t, filepath.Join(shared, "prog"), "exit 0\n")
	if _, err := (Tools{Dirs: []string{shared}}).Resolve("prog"); !errors.Is(err, ErrTool) {
		t.Fatalf("Resolve from a world-writable directory = %v, want ErrTool", err)
	}

	writable := filepath.Join(bin, "group-writable")
	writeScript(t, writable, "exit 0\n")
	if err := os.Chmod(writable, 0o770); err != nil { // #nosec G302 -- deliberately unsafe, to be refused
		t.Fatal(err)
	}
	if _, err := tools.Resolve("group-writable"); !errors.Is(err, ErrTool) {
		t.Fatalf("Resolve of a group-writable program = %v, want ErrTool", err)
	}
}

// TestASymlinkIsFollowedOnlyIntoATrustedDirectory: a directory entry that is a
// symlink is judged by what it resolves to, and runs under the name it was
// found by -- mke2fs decides what to make from argv[0].
func TestASymlinkIsFollowedOnlyIntoATrustedDirectory(t *testing.T) {
	bin := trustedDir(t)
	shared := t.TempDir()
	if err := os.Chmod(shared, 0o777); err != nil { // #nosec G302 -- deliberately unsafe, to be refused
		t.Fatal(err)
	}
	writeScript(t, filepath.Join(shared, "mke2fs"), "exit 0\n")
	link := filepath.Join(bin, "mkfs.ext4")
	if err := os.Symlink(filepath.Join(shared, "mke2fs"), link); err != nil {
		t.Fatal(err)
	}
	tools := Tools{Dirs: []string{bin}}
	if _, err := tools.Run(context.Background(), "mkfs.ext4"); !errors.Is(err, ErrTool) {
		t.Fatalf("Run through a link into a world-writable directory = %v, want ErrTool", err)
	}

	trusted := trustedDir(t)
	writeScript(t, filepath.Join(trusted, "mke2fs"), "echo made\n")
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(trusted, "mke2fs"), link); err != nil {
		t.Fatal(err)
	}
	prog, err := tools.Resolve("mkfs.ext4")
	if err != nil {
		t.Fatalf("Resolve through a trusted link = %v", err)
	}
	defer func() { _ = prog.Close() }()
	cmd := tools.command(context.Background(), prog, "-q")
	if cmd.Args[0] != link || cmd.Args[1] != "-q" {
		t.Fatalf("runs as %q, want %q -q", cmd.Args, link)
	}
	if out, err := cmd.Output(); err != nil || string(out) != "made\n" {
		t.Fatalf("the trusted target ran with %q, %v", out, err)
	}
}

// TestRunPassesOnlyTheGivenEnvironment is C7's environment half: nothing the
// caller's environment carries -- LD_PRELOAD above all -- reaches the program.
func TestRunPassesOnlyTheGivenEnvironment(t *testing.T) {
	bin := trustedDir(t)
	writeScript(t, filepath.Join(bin, "show-env"), "env\n")
	t.Setenv("LD_PRELOAD", "/nonexistent/evil.so")
	t.Setenv("LUKS2_TEST_INHERITED", "must-not-reach-the-tool")

	out, err := Tools{Dirs: []string{bin}, Env: []string{"LC_ALL=C"}}.Run(context.Background(), "show-env")
	if err != nil {
		t.Fatalf("Run = %v", err)
	}
	for _, leaked := range []string{"LD_PRELOAD", "LUKS2_TEST_INHERITED"} {
		if strings.Contains(string(out), leaked+"=") {
			t.Errorf("%s reached the program's environment:\n%s", leaked, out)
		}
	}
	if !strings.Contains(string(out), "LC_ALL=C") {
		t.Errorf("the program ran without the given environment:\n%s", out)
	}
	if _, err := (Tools{Dirs: []string{bin}}).Run(context.Background(), "absent"); !errors.Is(err, ErrTool) {
		t.Fatalf("Run of a missing program = %v, want ErrTool", err)
	}
}

// TestAnEntryInAnUntrustedDirectoryIsRefusedEvenWhenItsTargetIsTrusted: the
// directory the name was found in is judged too, because whoever can write it
// can repoint the entry after this check.
func TestAnEntryInAnUntrustedDirectoryIsRefusedEvenWhenItsTargetIsTrusted(t *testing.T) {
	trusted := trustedDir(t)
	writeScript(t, filepath.Join(trusted, "prog"), "exit 0\n")
	shared := t.TempDir()
	if err := os.Chmod(shared, 0o777); err != nil { // #nosec G302 -- deliberately unsafe, to be refused
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(trusted, "prog"), filepath.Join(shared, "prog")); err != nil {
		t.Fatal(err)
	}
	if _, err := (Tools{Dirs: []string{shared}}).Resolve("prog"); !errors.Is(err, ErrTool) {
		t.Fatalf("Resolve through a world-writable directory = %v, want ErrTool", err)
	}
}

// TestCommandWithAnAlreadyCancelledCtxNeverStartsTheProgram is D.2's exec row,
// the fail-fast half: a ctx canceled before Start is called means the
// program never runs at all.
func TestCommandWithAnAlreadyCancelledCtxNeverStartsTheProgram(t *testing.T) {
	bin := trustedDir(t)
	marker := filepath.Join(bin, "ran")
	writeScript(t, filepath.Join(bin, "prog"), "touch "+marker+"\n")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := (Tools{Dirs: []string{bin}}).Run(ctx, "prog"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run with an already-canceled ctx = %v, want context.Canceled", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("the program ran despite its ctx being canceled before Start")
	}
}

// TestRunKillsTheWholeProcessGroupOnCancel is D.2's exec row, the live-process
// half: canceling ctx while the program runs kills its whole process group,
// not just the program named directly -- mkfs.* and friends can fork helpers
// of their own, and a cancellation that left those running would not be one.
func TestRunKillsTheWholeProcessGroupOnCancel(t *testing.T) {
	bin := trustedDir(t)
	pidFile := childPIDFIFO(t, bin)
	writeScript(t, filepath.Join(bin, "longrun"), "sleep 30 &\necho $! > "+pidFile+"\nwait\n")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := (Tools{Dirs: []string{bin}}).Run(ctx, "longrun")
		done <- err
	}()

	pid := readChildPID(t, pidFile)

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run canceled while running = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within the wait-delay budget after cancellation")
	}

	// Not a liveness check by kill(pid, 0): a terminated child is reparented
	// to PID 1, and a container's PID 1 is not guaranteed to reap it, so it
	// can sit as a zombie -- still "alive" by that signal -- indefinitely.
	// /proc's State is read instead: gone, or zombie, both mean the signal
	// that killed the group reached this grandchild too; only a process
	// still actually running (R/S/D) means it did not. The SIGKILL may not have
	// been delivered yet when Run returns, so poll for a moment.
	for end := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		state, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)) // #nosec G304 -- /proc/<pid> of a PID this test itself started
		if err != nil || strings.Contains(string(state), "State:\tZ ") {
			return // gone (reaped) or a zombie: terminated either way
		}
		if time.Now().After(end) {
			t.Fatalf("the backgrounded grandchild (pid %d) is still running after cancellation:\n%s", pid, state)
		}
	}
}

// TestRunKillsTheWholeGroupWhenTermIsIgnored is S8: a program and a helper
// that both ignore SIGTERM outlast the grace, and the kill that follows it
// takes the process group (-pgid), not only the leader.
func TestRunKillsTheWholeGroupWhenTermIsIgnored(t *testing.T) {
	bin := trustedDir(t)
	pidFile := childPIDFIFO(t, bin)
	writeScript(t, filepath.Join(bin, "stubborn"),
		"trap '' TERM\n(trap '' TERM; exec sleep 30) &\necho $! > "+pidFile+"\nwait\n")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := (Tools{Dirs: []string{bin}, KillGrace: 200 * time.Millisecond}).Run(ctx, "stubborn")
		done <- err
	}()

	pid := readChildPID(t, pidFile)

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run canceled while running = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the grace expired")
	}

	// The SIGKILL of the group is sent as the grace expires; give the kernel a
	// moment to deliver it. A zombie or an absent entry is a dead process.
	for end := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		state, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)) // #nosec G304 -- /proc/<pid> of a PID this test itself started
		if err != nil || strings.Contains(string(state), "State:\tZ ") {
			return
		}
		if time.Now().After(end) {
			t.Fatalf("the SIGTERM-ignoring grandchild (pid %d) survived the grace expiry:\n%s", pid, state)
		}
	}
}

// TestOutputMapsACanceledCtxToItsError is S9: the stdout-only runner reports
// a cancellation the way Run does.
func TestOutputMapsACanceledCtxToItsError(t *testing.T) {
	bin := trustedDir(t)
	writeScript(t, filepath.Join(bin, "slow"), "sleep 30\n")

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	_, err := (Tools{Dirs: []string{bin}, KillGrace: 200 * time.Millisecond}).Output(ctx, "slow")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Output canceled while running = %v, want context.Canceled", err)
	}
}

// TestOwnershipRule: a file must be owned by root or this user and writable
// by neither group nor others; a directory may be group- or world-writable
// only when it is sticky.
func TestOwnershipRule(t *testing.T) {
	self := uint32(os.Geteuid()) // #nosec G115 -- a uid
	other := self + 1
	if other == 0 {
		other++
	}
	for _, tc := range []struct {
		name     string
		uid      uint32
		mode     os.FileMode
		stickyOK bool
		trusted  bool
	}{
		{"root-owned, read-only to others", 0, 0o755, false, true},
		{"own, read-only to others", self, 0o700, false, true},
		{"someone else's", other, 0o755, false, other == 0},
		{"group-writable", 0, 0o775, false, false},
		{"a sticky world-writable directory", 0, os.ModeDir | os.ModeSticky | 0o777, true, true},
		{"a sticky directory where none is allowed", 0, os.ModeDir | os.ModeSticky | 0o777, false, false},
	} {
		err := ownedAndUnwritable("/x", tc.uid, tc.mode, tc.stickyOK)
		if (err == nil) != tc.trusted {
			t.Errorf("%s: ownedAndUnwritable = %v, trusted %v", tc.name, err, tc.trusted)
		}
		if err != nil && !errors.Is(err, ErrTool) {
			t.Errorf("%s: %v does not match ErrTool", tc.name, err)
		}
	}
}
