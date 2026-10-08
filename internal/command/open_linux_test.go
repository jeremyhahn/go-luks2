// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package command

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// openAndRun opens path and runs it, returning its stdout.
func openAndRun(t *testing.T, path string) (string, error) {
	t.Helper()
	prog, err := Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = prog.Close() }()
	out, err := prog.Cmd(context.Background()).Output()
	return string(out), err
}

// TestOpenRefusesASymlinkedDirectoryInAWritableDirectory: a symlink to a
// trusted directory, sitting in a directory anyone can write, is refused --
// whoever can write that directory can repoint the link. Resolving the
// symlinks first and judging only the directories left would never see it.
func TestOpenRefusesASymlinkedDirectoryInAWritableDirectory(t *testing.T) {
	trusted := trustedDir(t)
	writeScript(t, filepath.Join(trusted, "helper"), "echo ran\n")
	shared := t.TempDir()
	if err := os.Symlink(trusted, filepath.Join(shared, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil { // #nosec G302 -- deliberately unsafe, to be refused
		t.Fatal(err)
	}

	if out, err := openAndRun(t, filepath.Join(shared, "link", "helper")); !errors.Is(err, ErrTool) {
		t.Fatalf("Open through a link in a world-writable directory = %q, %v; want ErrTool", out, err)
	}
	if out, err := openAndRun(t, filepath.Join(trusted, "helper")); err != nil || out != "ran\n" {
		t.Fatalf("Open of the same helper by its own path = %q, %v", out, err)
	}
}

// TestReadlinkRefusesASymlinkOwnedByAnotherUser drives readlink with the
// status of a real link whose owner is rewritten to another user, so it needs
// neither root nor a chown.
func TestReadlinkRefusesASymlinkOwnedByAnotherUser(t *testing.T) {
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink("/nonexistent-target", link); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(link, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}

	if target, err := readlink(fd, link, &st); err != nil || target != "/nonexistent-target" {
		t.Fatalf("readlink of the caller's own link = %q, %v", target, err)
	}

	st.Uid = uint32(os.Geteuid()) + 1 // neither root nor the caller
	target, err := readlink(fd, link, &st)
	if !errors.Is(err, ErrTool) {
		t.Fatalf("readlink of a link owned by another user = %q, %v; want ErrTool", target, err)
	}
	if target != "" {
		t.Fatalf("readlink returned the target %q of a link it refused", target)
	}
}

// TestOpenRefusesAGroupWritableDirectoryReachedThroughASymlink: a link in a
// trusted directory leads into a group-writable one, whose own link leads to a
// trusted helper. The group-writable directory is on the way to the helper
// only through symlinks, and is judged all the same.
func TestOpenRefusesAGroupWritableDirectoryReachedThroughASymlink(t *testing.T) {
	trusted := trustedDir(t)
	writeScript(t, filepath.Join(trusted, "helper"), "echo ran\n")
	group := t.TempDir()
	if err := os.Symlink(trusted, filepath.Join(group, "onward")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(group, 0o775); err != nil { // #nosec G302 -- deliberately unsafe, to be refused
		t.Fatal(err)
	}
	entry := trustedDir(t)
	if err := os.Symlink(group, filepath.Join(entry, "via")); err != nil {
		t.Fatal(err)
	}

	if out, err := openAndRun(t, filepath.Join(entry, "via", "onward", "helper")); !errors.Is(err, ErrTool) {
		t.Fatalf("Open through a group-writable directory = %q, %v; want ErrTool", out, err)
	}
}

// TestOpenFollowsSymlinksThroughCheckedDirectories: a relative link with ".."
// in it is walked like any other path, from the directory holding the link,
// and a loop is refused.
func TestOpenFollowsSymlinksThroughCheckedDirectories(t *testing.T) {
	parent := trustedDir(t)
	for _, dir := range []string{"bin", "libexec"} {
		if err := os.Mkdir(filepath.Join(parent, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeScript(t, filepath.Join(parent, "libexec", "helper"), "echo ran\n")
	if err := os.Symlink("../libexec/./helper", filepath.Join(parent, "bin", "helper")); err != nil {
		t.Fatal(err)
	}
	if out, err := openAndRun(t, filepath.Join(parent, "bin", "helper")); err != nil || out != "ran\n" {
		t.Fatalf("Open through a relative link = %q, %v", out, err)
	}

	if err := os.Symlink("loop", filepath.Join(parent, "loop")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(parent, "loop")); !errors.Is(err, ErrTool) {
		t.Fatalf("Open of a symlink loop = %v, want ErrTool", err)
	}
	if _, err := Open(filepath.Join(parent, "libexec")); !errors.Is(err, ErrTool) {
		t.Fatalf("Open of a directory = %v, want ErrTool", err)
	}
	if _, err := Open(filepath.Join(parent, "libexec", "helper", "x")); !errors.Is(err, ErrTool) {
		t.Fatalf("Open beneath a file = %v, want ErrTool", err)
	}
}

// TestOpenRunsTheFileItChecked: the program is replaced at its path after
// Open checked it and before it is started, and the file that runs is still
// the one checked -- the inode the pinned descriptor holds, not the one the
// path names by then.
func TestOpenRunsTheFileItChecked(t *testing.T) {
	bin := trustedDir(t)
	path := filepath.Join(bin, "helper")
	writeScript(t, path, "echo checked\n")
	var before syscall.Stat_t
	if err := syscall.Stat(path, &before); err != nil {
		t.Fatal(err)
	}

	prog, err := Open(path)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}
	defer func() { _ = prog.Close() }()

	swapped := filepath.Join(bin, "swapped")
	writeScript(t, swapped, "echo swapped\n")
	if err := os.Rename(swapped, path); err != nil {
		t.Fatal(err)
	}

	var pinned syscall.Stat_t
	if err := syscall.Fstat(int(prog.file.Fd()), &pinned); err != nil { // #nosec G115 -- a descriptor
		t.Fatal(err)
	}
	if pinned.Ino != before.Ino || pinned.Dev != before.Dev {
		t.Fatalf("the pinned descriptor is inode %d, the checked file was %d", pinned.Ino, before.Ino)
	}
	out, err := prog.Cmd(context.Background()).Output()
	if err != nil || string(out) != "checked\n" {
		t.Fatalf("after the swap the program printed %q, %v; want the checked file to run", out, err)
	}
}

// TestOpenRunsASystemProgram: an ordinary root-owned program under /usr/bin
// passes, through whatever symlinks the system's /usr layout has.
func TestOpenRunsASystemProgram(t *testing.T) {
	out, err := openAndRun(t, "/usr/bin/true")
	if err != nil || out != "" {
		t.Fatalf("Open of /usr/bin/true = %q, %v", out, err)
	}
	if out, err := (System()).Output(context.Background(), "echo", "ran"); err != nil || string(out) != "ran\n" {
		t.Fatalf("System().Output(echo) = %q, %v", out, err)
	}
}
