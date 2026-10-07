// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !integration

package loop

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// writeFakeNode creates a plain file standing in for a device node: nothing
// here opens or stats the result as a block device, so a regular file is
// sufficient and avoids needing root.
func writeFakeNode(t *testing.T, path string) {
	t.Helper()

	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("failed to create %s: %v", path, err)
	}
}

// fakeLoopSysfs builds a sysfs root with one bound loop device whose
// backing_file reads backing.
func fakeLoopSysfs(t *testing.T, backing string) string {
	t.Helper()

	root := t.TempDir()
	dir := filepath.Join(root, "loop5", "loop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("building the fake sysfs failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "backing_file"), []byte(backing+"\n"), 0o600); err != nil {
		t.Fatalf("building the fake sysfs failed: %v", err)
	}
	return root
}

// identitySys returns a sys whose loopBackingIdentity reports dev and ino
// for every device, with readDir real (the tests build real sysfs fixture
// directories).
func identitySys(dev, ino uint64) sys {
	s := defaultSys()
	s.loopBackingIdentity = func(string) (uint64, uint64, error) { return dev, ino, nil }
	return s
}

func statIdentity(t *testing.T, path string) (dev, ino uint64) {
	t.Helper()

	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	return uint64(st.Dev), st.Ino //nolint:unconvert // Dev is not uint64 on every GOARCH
}

// TestFindLoopDeviceMatchesTheFileNotItsPath is go-luks2 C8: the loop driver
// recorded the file under another path (here, the target of the symlink the
// caller names). The path comparison reported it unattached.
func TestFindLoopDeviceMatchesTheFileNotItsPath(t *testing.T) {
	file := filepath.Join(t.TempDir(), "backing.img")
	writeFakeNode(t, file)
	link := filepath.Join(t.TempDir(), "alias.img")
	if err := os.Symlink(file, link); err != nil {
		t.Fatalf("symlink failed: %v", err)
	}
	root := fakeLoopSysfs(t, file)
	dev, ino := statIdentity(t, file)

	got, _, err := findLoopDeviceIn(root, link, identitySys(dev, ino))
	if err != nil || got != "/dev/loop5" {
		t.Fatalf("findLoopDeviceIn(%s) = %q, %v; want /dev/loop5", link, got, err)
	}
}

// TestFindLoopDeviceDoesNotMatchAReplacedFile is C8's other direction: the
// path sysfs prints is the caller's path, but the file there now is a
// different one than the loop device is backed by.
func TestFindLoopDeviceDoesNotMatchAReplacedFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "backing.img")
	writeFakeNode(t, file)
	root := fakeLoopSysfs(t, file)
	dev, ino := statIdentity(t, file)

	if got, _, err := findLoopDeviceIn(root, file, identitySys(dev, ino+1)); err == nil {
		t.Fatalf("findLoopDeviceIn = %q; a loop device backed by another inode was reported as this file's", got)
	}
}

// TestFindLoopDeviceCountsAnUnidentifiableDevice: a bound device whose
// backing file cannot be identified is not evidence of absence.
func TestFindLoopDeviceCountsAnUnidentifiableDevice(t *testing.T) {
	file := filepath.Join(t.TempDir(), "backing.img")
	writeFakeNode(t, file)
	root := fakeLoopSysfs(t, file)

	s := defaultSys()
	s.loopBackingIdentity = func(string) (uint64, uint64, error) { return 0, 0, unix.EACCES }

	_, _, err := findLoopDeviceIn(root, file, s)
	if !errors.Is(err, errs.ErrIO) || !errors.Is(err, unix.EACCES) || errors.Is(err, ErrNotFound) {
		t.Fatalf("findLoopDeviceIn = %v, want an ErrIO error carrying the cause, not not-found", err)
	}

	// A device released between the sysfs read and the ioctl is unbound.
	s.loopBackingIdentity = func(string) (uint64, uint64, error) { return 0, 0, unix.ENXIO }
	if _, _, err := findLoopDeviceIn(root, file, s); !errors.Is(err, ErrNotFound) {
		t.Fatalf("findLoopDeviceIn = %v, want plain not-found for a released device", err)
	}
}

// TestLookupRequiresALoopNode is S10: Detach sends LOOP_CLR_FD to whatever
// Lookup returned, so a block device that is not a loop device is refused.
func TestLookupRequiresALoopNode(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"sda", "loop0", "loop0p1"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s := defaultSys()
	s.sysBlockRoot = root

	for _, path := range []string{"/dev/sda", "/dev/loop0p1", "/dev/block/7:0", "loop0", "/tmp/loop0"} {
		if _, err := lookup(context.Background(), path, s); !errors.Is(err, errs.ErrInvalidArgument) {
			t.Errorf("lookup(%q) = %v, want ErrInvalidArgument", path, err)
		}
	}
	if _, err := lookup(context.Background(), "/dev/loop0", s); err != nil {
		t.Errorf("lookup(/dev/loop0) = %v", err)
	}
}

// TestExportedEntriesStampOpAndPath is S12 for Find and Lookup.
func TestExportedEntriesStampOpAndPath(t *testing.T) {
	_, err := Lookup(context.Background(), "/dev/sda")
	var e *Error
	if !errors.As(err, &e) || e.Op != "Lookup" || e.Path != "/dev/sda" {
		t.Fatalf("Lookup error = %#v, want Op Lookup and Path /dev/sda", err)
	}
	_, err = Find(context.Background(), "/nonexistent-loop-backing")
	if !errors.As(err, &e) || e.Op != "Find" || e.Path != "/nonexistent-loop-backing" {
		t.Fatalf("Find error = %#v, want Op Find and the path", err)
	}
}

// TestFindRefusesAnAlreadyCancelledContext and TestLookupRefusesAnAlreadyCancelledContext
// pin the ctx-first boundary check DESIGN.md D rules every new exported
// function to.
func TestFindRefusesAnAlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := find(ctx, "/nonexistent.img", defaultSys()); !errors.Is(err, context.Canceled) {
		t.Errorf("find() with a canceled context = %v, want context.Canceled", err)
	}
}

func TestLookupRefusesAnAlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := lookup(ctx, "/dev/loop0", defaultSys()); !errors.Is(err, context.Canceled) {
		t.Errorf("lookup() with a canceled context = %v, want context.Canceled", err)
	}
}

// TestLookupReportsAnUnattachedDevice is Lookup's own contract: unlike Find,
// it does not require the device to be currently attached.
func TestLookupReportsAnUnattachedDevice(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "loop0"), 0o755); err != nil {
		t.Fatalf("failed to build the fixture: %v", err)
	}
	s := defaultSys()
	s.sysBlockRoot = root

	d, err := lookup(context.Background(), "/dev/loop0", s)
	if err != nil {
		t.Fatalf("lookup() returned error: %v", err)
	}
	if d.BackingFile() != "" {
		t.Errorf("BackingFile() = %q, want \"\" for an unattached device", d.BackingFile())
	}
	if d.Path() != "/dev/loop0" {
		t.Errorf("Path() = %q, want %q", d.Path(), "/dev/loop0")
	}
}
