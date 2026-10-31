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

// TestFindLoopDeviceDoesNotMatchAReplacedFile is C8's other direction: the
// path sysfs prints is the caller's path, but the file there now is a
// different one than the loop device is backed by.
func TestFindLoopDeviceDoesNotMatchAReplacedFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "backing.img")
	writeFakeNode(t, file)
	root := fakeLoopSysfs(t, file)
	dev, ino := statIdentity(t, file)

	if got, _, _, err := findLoopDeviceIn(root, file, identitySys(dev, ino+1)); err == nil {
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

	_, _, _, err := findLoopDeviceIn(root, file, s)
	if !errors.Is(err, errs.ErrIO) || !errors.Is(err, unix.EACCES) || errors.Is(err, ErrNotFound) {
		t.Fatalf("findLoopDeviceIn = %v, want an ErrIO error carrying the cause, not not-found", err)
	}

	// A device released between the sysfs read and the ioctl is unbound.
	s.loopBackingIdentity = func(string) (uint64, uint64, error) { return 0, 0, unix.ENXIO }
	if _, _, _, err := findLoopDeviceIn(root, file, s); !errors.Is(err, ErrNotFound) {
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
// pin the ctx-first boundary check every exported function makes: a
// context already canceled is refused before any work.
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

// TestLookupRecordsTheBackingIdentity pins what Detach is later held to: the
// device and inode the loop driver reports for an attached device, and no
// identity for one released before it could be read.
func TestLookupRecordsTheBackingIdentity(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "loop0", "loop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "loop0", "loop", "backing_file"), []byte("/img\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := defaultSys()
	s.sysBlockRoot = root

	s.loopBackingIdentity = func(string) (uint64, uint64, error) { return 2049, 12, nil }
	d, err := lookup(context.Background(), "/dev/loop0", s)
	if err != nil {
		t.Fatalf("lookup() = %v", err)
	}
	if want := (backingIdentity{dev: 2049, ino: 12, known: true}); d.ident != want {
		t.Errorf("ident = %+v, want %+v", d.ident, want)
	}

	s.loopBackingIdentity = func(string) (uint64, uint64, error) { return 0, 0, unix.ENXIO }
	d, err = lookup(context.Background(), "/dev/loop0", s)
	if err != nil {
		t.Fatalf("lookup() = %v", err)
	}
	if d.ident.known || d.BackingFile() != "" {
		t.Errorf("ident = %+v, backing %q; want neither for a released device", d.ident, d.BackingFile())
	}
}
