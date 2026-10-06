// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package command

import (
	"errors"
	"os"
	"path/filepath"
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
		if path, _, err := tools.Resolve(name); !errors.Is(err, ErrTool) {
			t.Errorf("Resolve(%q) = %q, %v; want ErrTool", name, path, err)
		}
	}

	shared := t.TempDir()
	if err := os.Chmod(shared, 0o777); err != nil { // #nosec G302 -- deliberately unsafe, to be refused
		t.Fatal(err)
	}
	writeScript(t, filepath.Join(shared, "prog"), "exit 0\n")
	if _, _, err := (Tools{Dirs: []string{shared}}).Resolve("prog"); !errors.Is(err, ErrTool) {
		t.Fatalf("Resolve from a world-writable directory = %v, want ErrTool", err)
	}

	writable := filepath.Join(bin, "group-writable")
	writeScript(t, writable, "exit 0\n")
	if err := os.Chmod(writable, 0o770); err != nil { // #nosec G302 -- deliberately unsafe, to be refused
		t.Fatal(err)
	}
	if _, _, err := tools.Resolve("group-writable"); !errors.Is(err, ErrTool) {
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
	if _, err := tools.Command("mkfs.ext4"); !errors.Is(err, ErrTool) {
		t.Fatalf("Command through a link into a world-writable directory = %v, want ErrTool", err)
	}

	trusted := trustedDir(t)
	writeScript(t, filepath.Join(trusted, "mke2fs"), "exit 0\n")
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(trusted, "mke2fs"), link); err != nil {
		t.Fatal(err)
	}
	cmd, err := tools.Command("mkfs.ext4", "-q")
	if err != nil {
		t.Fatalf("Command through a trusted link = %v", err)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(trusted, "mke2fs"))
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Path != resolved || cmd.Args[0] != link || cmd.Args[1] != "-q" {
		t.Fatalf("runs %q as %q, want %q as %q", cmd.Path, cmd.Args, resolved, link)
	}
}

// TestRunPassesOnlyTheGivenEnvironment is C7's environment half: nothing the
// caller's environment carries -- LD_PRELOAD above all -- reaches the program.
func TestRunPassesOnlyTheGivenEnvironment(t *testing.T) {
	bin := trustedDir(t)
	writeScript(t, filepath.Join(bin, "show-env"), "env\n")
	t.Setenv("LD_PRELOAD", "/nonexistent/evil.so")
	t.Setenv("LUKS2_TEST_INHERITED", "must-not-reach-the-tool")

	out, err := Tools{Dirs: []string{bin}, Env: []string{"LC_ALL=C"}}.Run("show-env")
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
	if _, err := (Tools{Dirs: []string{bin}}).Run("absent"); !errors.Is(err, ErrTool) {
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
	if _, _, err := (Tools{Dirs: []string{shared}}).Resolve("prog"); !errors.Is(err, ErrTool) {
		t.Fatalf("Resolve through a world-writable directory = %v, want ErrTool", err)
	}
}

// fileInfo is an os.FileInfo with a chosen mode and owner record, for the
// ownership rule, which reads both from what Lstat returned.
type fileInfo struct {
	mode os.FileMode
	sys  any
}

func (f fileInfo) Name() string       { return "f" }
func (f fileInfo) Size() int64        { return 0 }
func (f fileInfo) Mode() os.FileMode  { return f.mode }
func (f fileInfo) ModTime() time.Time { return time.Time{} }
func (f fileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fileInfo) Sys() any           { return f.sys }

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
		info     fileInfo
		stickyOK bool
		trusted  bool
	}{
		{"root-owned, read-only to others", fileInfo{0o755, &syscall.Stat_t{Uid: 0}}, false, true},
		{"own, read-only to others", fileInfo{0o700, &syscall.Stat_t{Uid: self}}, false, true},
		{"someone else's", fileInfo{0o755, &syscall.Stat_t{Uid: other}}, false, other == 0},
		{"group-writable", fileInfo{0o775, &syscall.Stat_t{Uid: 0}}, false, false},
		{"a sticky world-writable directory", fileInfo{os.ModeDir | os.ModeSticky | 0o777, &syscall.Stat_t{Uid: 0}}, true, true},
		{"a sticky directory where none is allowed", fileInfo{os.ModeDir | os.ModeSticky | 0o777, &syscall.Stat_t{Uid: 0}}, false, false},
		{"no owner record", fileInfo{0o755, nil}, false, false},
	} {
		err := ownedAndUnwritable("/x", tc.info, tc.stickyOK)
		if (err == nil) != tc.trusted {
			t.Errorf("%s: ownedAndUnwritable = %v, trusted %v", tc.name, err, tc.trusted)
		}
		if err != nil && !errors.Is(err, ErrTool) {
			t.Errorf("%s: %v does not match ErrTool", tc.name, err)
		}
	}
}
