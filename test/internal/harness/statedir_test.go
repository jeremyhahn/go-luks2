// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The state directory is a host-wide device-removal primitive with a file for
// an input: the reaper runs as root, before the #85 guard, and removes whatever
// a ledger names. /var/tmp is world-writable and sticky, so on a shared runner
// an unprivileged user can create that directory first and drop forged ledgers
// into it.
//
// The dm half has partial cover -- removal needs the live mapping to still
// carry the recorded UUID -- but the loop half has none and cannot: for a loop
// device the recorded PATH is the identity, so a forgeable ledger is an
// aimable detach. A KindLoopRoot of "/home" would have a privileged container
// detach every loop device under /home.
//
// These drive validateStateDir with constructed modes and uids rather than by
// chmod'ing a real directory. That is deliberate twice over: it makes the
// owner branch reachable without root or chown, and it tests the DECISION
// rather than the kernel's enforcement -- this code reads mode bits and
// refuses, it never relies on the OS to deny access, so a fixture that leaned
// on permission bits would be testing the wrong thing (and would behave
// differently under the root CI containers, per the fault-injection rule).

func TestValidateStateDirRejectsEveryUntrustworthyShape(t *testing.T) {
	const euid = 0 // the reaper's case: running as root

	for _, tc := range []struct {
		name  string
		mode  os.FileMode
		owner uint32
		want  string
	}{
		{
			name: "a symlink, which can be repointed after it is checked",
			mode: os.ModeSymlink | 0o700, owner: 0,
			want: "symlink",
		},
		{
			name: "not a directory at all",
			mode: 0o600, owner: 0,
			want: "not a directory",
		},
		{
			name: "world-writable: anyone on the box can aim the reaper",
			mode: os.ModeDir | 0o777, owner: 0,
			want: "writable by group or other",
		},
		{
			name: "group-writable",
			mode: os.ModeDir | 0o770, owner: 0,
			want: "writable by group or other",
		},
		{
			name: "owned by another user, so another user maintains the records",
			mode: os.ModeDir | 0o700, owner: 1000,
			want: "owned by uid 1000",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateStateDir("/var/tmp/go-luks2-test-state", tc.mode, tc.owner, euid)
			if err == nil {
				t.Fatalf("validateStateDir accepted %v owned by %d", tc.mode, tc.owner)
			}
			if !errors.Is(err, ErrLedgerUnavailable) {
				t.Fatalf("error = %v, want it to match ErrLedgerUnavailable so the run refuses to start", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to explain %q", err, tc.want)
			}
			// An operator has to be able to act on it.
			if !strings.Contains(err.Error(), "/var/tmp/go-luks2-test-state") {
				t.Errorf("error = %q, want it to name the directory", err)
			}
		})
	}
}

// TestValidateStateDirAcceptsTheConfigurationsWeActuallyUse is the control. A
// check that rejects everything is not a check, and both of these are real: CI
// gets a root-owned directory because Docker creates a missing bind-mount
// source as root, and a developer's own run owns its own.
func TestValidateStateDirAcceptsTheConfigurationsWeActuallyUse(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  os.FileMode
		owner uint32
		euid  int
	}{
		{"root-owned 0700, root process (host integration under sudo)", os.ModeDir | 0o700, 0, 0},
		{"root-owned 0755, root process (Docker-created bind mount)", os.ModeDir | 0o755, 0, 0},
		{"root-owned, unprivileged process reading it", os.ModeDir | 0o755, 0, 1000},
		{"owned by the running user", os.ModeDir | 0o700, 1000, 1000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateStateDir("/x", tc.mode, tc.owner, tc.euid); err != nil {
				t.Fatalf("validateStateDir rejected a configuration we rely on: %v", err)
			}
		})
	}
}

// TestEnsureTrustedStateDirCreatesItPrivateAndAcceptsIt covers the create path
// end to end, including that what it creates passes its own check.
func TestEnsureTrustedStateDirCreatesItPrivateAndAcceptsIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")

	if err := ensureTrustedStateDir(dir); err != nil {
		t.Fatalf("ensureTrustedStateDir: %v", err)
	}

	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("created the state directory with mode %04o, want no group or other access", perm)
	}

	// Idempotent: a second run must accept what the first created.
	if err := ensureTrustedStateDir(dir); err != nil {
		t.Fatalf("ensureTrustedStateDir rejected the directory it had just created: %v", err)
	}
}

// TestEnsureTrustedStateDirRefusesASymlink is the one real-filesystem case
// worth having, because it is the check Lstat-vs-Stat exists for and a
// refactor to Stat would silently pass it.
func TestEnsureTrustedStateDirRefusesASymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	err := ensureTrustedStateDir(link)
	if err == nil {
		t.Fatal("ensureTrustedStateDir followed a symlink; the target can be repointed after the check")
	}
	if !errors.Is(err, ErrLedgerUnavailable) {
		t.Fatalf("error = %v, want it to match ErrLedgerUnavailable", err)
	}
}

// TestOpenLedgerAndReapBothValidateTheStateDirectory: a check on one path only
// is a check an attacker routes around by racing the other.
func TestOpenLedgerAndReapBothValidateTheStateDirectory(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	t.Run("the writer refuses", func(t *testing.T) {
		if _, err := OpenLedger(link, "run"); err == nil {
			t.Fatal("OpenLedger wrote into an untrusted state directory")
		}
	})

	t.Run("the reaper refuses", func(t *testing.T) {
		_, err := Reap(link, "run", newFakeRemover(), os.Stderr)
		if err == nil {
			t.Fatal("Reap acted on ledgers from an untrusted state directory")
		}
	})
}

// TestPermissionFailuresNameThePrivilegeRequirement: the bare errno is accurate
// and useless. "open /dev/mapper/control: permission denied" reads as a broken
// installation rather than as the suite being run without the privileges its
// tier requires -- and someone will meet it, because
// `go test -tags=integration ./...` is the obvious thing to type and is not how
// this tier runs.
func TestPermissionFailuresNameThePrivilegeRequirement(t *testing.T) {
	for _, cause := range []error{os.ErrPermission, unix.EACCES, unix.EPERM} {
		if !isPermissionDenied(fmt.Errorf("opening /dev/mapper/control: %w", cause)) {
			t.Errorf("isPermissionDenied did not recognize %v", cause)
		}
	}
	// Not everything is a privilege problem; a bare failure must not acquire a
	// remedy that does not apply to it.
	if isPermissionDenied(errors.New("no such device")) {
		t.Error("isPermissionDenied treated an unrelated failure as a privilege problem")
	}

	for _, want := range []string{"root", "CAP_SYS_ADMIN", "/dev/mapper/control", "make integration-test"} {
		if !strings.Contains(dmPrivilegeRemedy, want) {
			t.Errorf("the remedy does not mention %q; an operator cannot act on it", want)
		}
	}
}

// TestEphemeralStateDirectoryIsRefused is the second half of the blocking
// finding on ebeb2e0: two `make` targets ran the privileged container without
// the state-directory mount, so the ledger lived in the container and died
// with it while the host devices it recorded did not.
//
// Adding the mount to those targets fixes today. This makes the omission
// IMPOSSIBLE TO REPEAT SILENTLY: the image declares its own directory
// ephemeral, a bind mount shadows that declaration, and the harness refuses
// when it can still see it.
//
// Running without persistence is worse than not running at all -- the suite
// creates host devices and records them nowhere that survives.
func TestEphemeralStateDirectoryIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	t.Run("a persistent directory is accepted", func(t *testing.T) {
		if err := ensureTrustedStateDir(dir); err != nil {
			t.Fatalf("a persistent state directory was refused: %v", err)
		}
	})

	// The image's own directory carries the marker; a mount would hide it.
	if err := os.WriteFile(filepath.Join(dir, EphemeralMarker), nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Run("the image's own directory is refused", func(t *testing.T) {
		err := ensureTrustedStateDir(dir)
		if err == nil {
			t.Fatal("the harness ran against a state directory that dies with the container")
		}
		if !errors.Is(err, ErrLedgerUnavailable) {
			t.Fatalf("error = %v, want it to match ErrLedgerUnavailable", err)
		}
		// The operator needs to know what to do, not merely that it refused.
		for _, want := range []string{"persistent mount", "docker run -v"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error = %q, want it to mention %q", err, want)
			}
		}
	})

	t.Run("both the writer and the reaper refuse", func(t *testing.T) {
		if _, err := OpenLedger(dir, "run"); err == nil {
			t.Error("OpenLedger wrote into an ephemeral state directory")
		}
		if _, err := Reap(dir, "run", newFakeRemover(), os.Stderr); err == nil {
			t.Error("Reap acted on ledgers in an ephemeral state directory")
		}
	})
}

// TestEnsureTrustedStateDirRefusesWhatItCannotCreate: no directory configured
// at all, and a directory that cannot be created because a FILE holds a
// component of its path. Both refuse with ErrLedgerUnavailable, the sentinel
// that stops a suite before it creates anything it could not record.
func TestEnsureTrustedStateDirRefusesWhatItCannotCreate(t *testing.T) {
	if err := ensureTrustedStateDir(""); !errors.Is(err, ErrLedgerUnavailable) {
		t.Errorf("an unconfigured state dir: %v, want ErrLedgerUnavailable", err)
	}

	file := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatalf("creating the blocking file: %v", err)
	}
	err := ensureTrustedStateDir(filepath.Join(file, "state"))
	if !errors.Is(err, ErrLedgerUnavailable) || !strings.Contains(err.Error(), "creating") {
		t.Errorf("a state dir under a regular file: %v, want ErrLedgerUnavailable naming the create", err)
	}
}

// ensureTrustedStateDir opens and validates dir the way OpenLedger and the
// reaper do, then releases the handle: the decision alone, for these tests.
func ensureTrustedStateDir(dir string) error {
	d, err := openTrustedStateDir(dir)
	if err != nil {
		return err
	}
	return d.Close()
}
