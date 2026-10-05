// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/anatol/devmapper.go"
	"golang.org/x/sys/unix"
)

// Unlock reads the metadata under cryptsetup's READ lock: LOCK_SH on the
// device node, then LOCK_SH on /run/cryptsetup/L_<maj>:<min>, released before
// device-mapper is touched. These tests drive it on the fake device mapper,
// which stands the image in for loop device 7:3 and gives cryptsetup's lock
// directory a temporary home (withImageAsBlockDevice). That cryptsetup itself
// is held off is proved against the real binary in
// unlockreadlock_integration_test.go.
//
// None of them is parallel: they replace package seams.

// withUnlockClock runs Unlock's lock wait on clk for the rest of the test.
func withUnlockClock(t *testing.T, clk clock) {
	t.Helper()
	previous := unlockClock
	t.Cleanup(func() { unlockClock = previous })
	unlockClock = clk
}

// countHeaderReads counts the header reads Unlock makes, calling onRead first.
func countHeaderReads(t *testing.T, onRead func()) *int {
	t.Helper()
	previous := readUnlockHeader
	t.Cleanup(func() { readUnlockHeader = previous })
	reads := 0
	readUnlockHeader = func(f io.ReaderAt, offset int64) (*LUKS2BinaryHeader, *LUKS2Metadata, error) {
		reads++
		if onRead != nil {
			onRead()
		}
		return previous(f, offset)
	}
	return &reads
}

// holdFlock opens path, creating it, and flocks it with how. The hold ends
// when the test does, or earlier through the returned release.
func holdFlock(t *testing.T, path string, how int) (release func()) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(f.Fd()), how|unix.LOCK_NB); err != nil {
		t.Fatalf("flock %s: %v", path, err)
	}
	done := false
	release = func() {
		if !done {
			done = true
			_ = f.Close()
		}
	}
	t.Cleanup(release)
	return release
}

// fakeLockFile is cryptsetup's lock file for the fake backing device 7:3.
func fakeLockFile() string {
	return filepath.Join(cryptsetupLockDir, "L_7:3")
}

// TestUnlockWaitsForAWriterOfTheMetadata: a writer holding cryptsetup's lock
// file exclusively -- what cryptsetup is while it rewrites the header -- or
// the device node exclusively -- what this package's own writers are -- keeps
// Unlock from reading the header at all, and it gives up within its budget
// with ErrLockContended. Unlock used to read the metadata with no lock, so it
// could parse a header cryptsetup was halfway through rewriting.
func TestUnlockWaitsForAWriterOfTheMetadata(t *testing.T) {
	for _, writer := range []string{"cryptsetup's lock file", "the device node"} {
		t.Run(writer, func(t *testing.T) {
			device, passphrase := unlockableVolume(t)
			fake := newFakeDeviceMapper()
			fake.install(t)
			clk := newFakeClock(t)
			withUnlockClock(t, clk)
			reads := countHeaderReads(t, nil)

			held := device
			if writer == "cryptsetup's lock file" {
				held = fakeLockFile()
			}
			holdFlock(t, held, unix.LOCK_EX)

			err := Unlock(device, passphrase, "behind-a-writer")
			var timeout *LockTimeoutError
			if !errors.Is(err, ErrLockContended) || !errors.As(err, &timeout) {
				t.Fatalf("Unlock while %s is held exclusively = %v, want ErrLockContended", writer, err)
			}
			if *reads != 0 || len(fake.created) != 0 {
				t.Fatalf("read the header %d times and created %v while a writer held %s", *reads, fake.created, writer)
			}
			if clk.elapsed() < metadataReadLockWait || timeout.Attempts < 2 {
				t.Fatalf("gave up after %v and %d attempts; the %v budget was not spent", clk.elapsed(), timeout.Attempts, metadataReadLockWait)
			}
		})
	}
}

// TestUnlockReadsOnceTheWriterIsDone: the writer finishes while Unlock waits,
// and the header is read after that and not before.
func TestUnlockReadsOnceTheWriterIsDone(t *testing.T) {
	device, passphrase := unlockableVolume(t)
	fake := newFakeDeviceMapper()
	fake.install(t)
	clk := newFakeClock(t)
	withUnlockClock(t, clk)

	release := holdFlock(t, fakeLockFile(), unix.LOCK_EX)
	writerDone := false
	clk.onSleep = func(now time.Time) {
		if now.Sub(clk.start) >= time.Second && !writerDone {
			writerDone = true
			_ = os.Remove(fakeLockFile()) // cryptsetup unlinks as it releases
			release()
		}
	}
	countHeaderReads(t, func() {
		if !writerDone {
			t.Error("the header was read while the writer still held the lock")
		}
	})

	if err := Unlock(device, passphrase, "after-the-writer"); err != nil {
		t.Fatalf("Unlock after the writer released = %v", err)
	}
	if len(fake.created) != 1 {
		t.Fatalf("created %v, want the one mapping", fake.created)
	}
}

// TestUnlockDoesNotWaitForOtherReaders: the lock is SHARED. Another reader --
// cryptsetup open, or a second Unlock -- holding both locks shared does not
// delay this one.
func TestUnlockDoesNotWaitForOtherReaders(t *testing.T) {
	device, passphrase := unlockableVolume(t)
	fake := newFakeDeviceMapper()
	fake.install(t)
	clk := newFakeClock(t)
	withUnlockClock(t, clk)

	holdFlock(t, fakeLockFile(), unix.LOCK_SH)
	holdFlock(t, device, unix.LOCK_SH)

	if err := Unlock(device, passphrase, "beside-a-reader"); err != nil {
		t.Fatalf("Unlock beside another reader = %v", err)
	}
	if len(clk.slept) != 0 {
		t.Fatalf("waited %v for a reader; readers share the lock", clk.slept)
	}
}

// TestUnlockReleasesTheReadLockBeforeDeviceMapper: by the time the table is
// loaded, a writer can take both locks -- the metadata has been read, and the
// device-mapper work does not hold cryptsetup up -- and once Unlock returns,
// on success or failure, the lock file is gone, as cryptsetup leaves it.
func TestUnlockReleasesTheReadLockBeforeDeviceMapper(t *testing.T) {
	device, passphrase := unlockableVolume(t)
	fake := newFakeDeviceMapper()
	fake.install(t)

	writerCould := func() error {
		for _, path := range []string{device, fakeLockFile()} {
			f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- under t.TempDir()
			if err != nil {
				return err
			}
			err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
			_ = f.Close()
			if err != nil {
				return &DeviceError{Device: path, Op: "lock exclusively", Err: err}
			}
		}
		return nil
	}
	checked := false
	fake.onLoad = func(string, string, []devmapper.Table) {
		checked = true
		if err := writerCould(); err != nil {
			t.Errorf("a writer could not lock the metadata while the table was loading: %v", err)
		}
		_ = os.Remove(fakeLockFile())
	}

	if err := Unlock(device, passphrase, "released-early"); err != nil {
		t.Fatalf("Unlock = %v", err)
	}
	if !checked {
		t.Fatal("the table was never loaded")
	}

	// The failure paths release too: a passphrase that opens nothing.
	if err := Unlock(device, []byte("not-the-passphrase-at-all"), "wrong-passphrase"); !errors.Is(err, ErrMasterKeyVerification) {
		t.Fatalf("Unlock with the wrong passphrase = %v", err)
	}
	if _, err := os.Lstat(fakeLockFile()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the lock file outlived a failed Unlock (%v); cryptsetup removes it", err)
	}
	if err := writerCould(); err != nil {
		t.Fatalf("the lock was still held after a failed Unlock: %v", err)
	}
}
