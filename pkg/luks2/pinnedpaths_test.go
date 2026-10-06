// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Every writer locks one open of the device path and must then do all its I/O
// through that descriptor, or through a second open PROVEN to be the same file.
// These tests re-point the device symlink the moment the lock's open has
// happened, so any later open of the path reaches a different device -- and
// require that the different device is never touched.
//
// None is parallel: they substitute the package's open seam.

// retargetedPair is two copies of the token parity fixture -- a cryptsetup
// volume with keyslots 0 and 1 and tokens 0 and 1 -- and a symlink naming the
// first that is re-pointed at the second once it has been opened. It returns
// the link, the locked device, the other device and the other's digest.
func retargetedPair(t *testing.T) (link, locked, other string, otherBefore [32]byte) {
	t.Helper()
	locked = tokenParityFixture(t)
	golden, err := os.ReadFile(locked) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	other = filepath.Join(t.TempDir(), "other.img")
	if err := os.WriteFile(other, golden, 0o600); err != nil {
		t.Fatal(err)
	}
	link = filepath.Join(t.TempDir(), "device")
	if err := os.Symlink(locked, link); err != nil {
		t.Fatal(err)
	}
	relinkAfterFirstOpen(t, link, other)
	return link, locked, other, fileDigest(t, other)
}

// TestTheExclusiveClaimTargetsTheLockedDescriptorDespiteARetarget: Wipe and
// WipeKeyslot used to take their O_EXCL claim by reopening the path after the
// lock, so a path re-pointed in between claimed, wiped -- and for
// WipeKeyslot, vetted -- a device that was never locked. The claim now
// reopens the LOCKED descriptor's own /proc/self/fd entry (Locked.Claim)
// rather than resolving the path again, so it cannot be retargeted: the
// operation lands on the file that was locked, and the device the path was
// re-pointed at is never touched.
func TestTheExclusiveClaimTargetsTheLockedDescriptorDespiteARetarget(t *testing.T) {
	for _, op := range []struct {
		name string
		run  func(device string) error
	}{
		{"Wipe header-only", func(d string) error { return Wipe(WipeOptions{Device: d, HeaderOnly: true}) }},
		{"Wipe full", func(d string) error { return Wipe(WipeOptions{Device: d, Passes: 1}) }},
		{"WipeKeyslot", func(d string) error { return WipeKeyslot(d, 1) }},
	} {
		t.Run(op.name, func(t *testing.T) {
			link, locked, other, otherBefore := retargetedPair(t)
			lockedBefore := fileDigest(t, locked)

			if err := op.run(link); err != nil {
				t.Fatalf("%s through a re-pointed path = %v, want success on the locked file", op.name, err)
			}
			if fileDigest(t, other) != otherBefore {
				t.Fatal("the device the path was re-pointed at was written to")
			}
			if fileDigest(t, locked) == lockedBefore {
				t.Fatal("the locked device was not written to")
			}
		})
	}
}

// TestHeaderWritersStayOnTheDeviceTheyLocked: ImportToken, RemoveToken and
// WriteHeader read and wrote the header by reopening the path after taking
// the lock, so a re-pointed link had one device's header -- or a header read
// from it -- written onto another. They now read and write through the locked
// descriptor: the change lands on the device that was locked, and the other
// is not touched.
func TestHeaderWritersStayOnTheDeviceTheyLocked(t *testing.T) {
	for _, op := range []struct {
		name string
		// run acts on link. locked is read only directly, never through the
		// link, so the first open of the link is the operation's own lock.
		run   func(t *testing.T, link, locked string) error
		check func(t *testing.T, metadata *LUKS2Metadata)
	}{
		{"ImportToken", func(_ *testing.T, link, _ string) error {
			return ImportToken(link, 5, &Token{Type: "x-pinned", Keyslots: []string{"0"}})
		}, func(t *testing.T, m *LUKS2Metadata) {
			if m.Tokens["5"] == nil {
				t.Fatal("token 5 is not on the locked device")
			}
		}},
		{"RemoveToken", func(_ *testing.T, link, _ string) error { return RemoveToken(link, 1) },
			func(t *testing.T, m *LUKS2Metadata) {
				if m.Tokens["1"] != nil {
					t.Fatal("token 1 is still on the locked device")
				}
			}},
		{"WriteHeader", func(t *testing.T, link, locked string) error {
			hdr, metadata, err := ReadHeader(locked)
			if err != nil {
				t.Fatal(err)
			}
			hdr.SequenceID += 10
			return WriteHeader(link, hdr, metadata)
		}, nil},
	} {
		t.Run(op.name, func(t *testing.T) {
			link, locked, other, otherBefore := retargetedPair(t)
			before, _, err := ReadHeader(locked)
			if err != nil {
				t.Fatal(err)
			}

			if err := op.run(t, link, locked); err != nil {
				t.Fatalf("%s: %v", op.name, err)
			}
			if fileDigest(t, other) != otherBefore {
				t.Fatal("the device the path was re-pointed at was written to")
			}
			hdr, metadata, err := ReadHeader(locked)
			if err != nil {
				t.Fatalf("the locked device no longer reads: %v", err)
			}
			if hdr.SequenceID <= before.SequenceID {
				t.Fatalf("the locked device's header was not rewritten (sequence %d, was %d)", hdr.SequenceID, before.SequenceID)
			}
			if op.check != nil {
				op.check(t, metadata)
			}
		})
	}
}

// TestAddRecoveryKeyReportsTheVolumeItEnrolled: the recovery key names the
// volume it was enrolled on -- the UUID that goes into a saved recovery file.
// It used to be read by reopening the path after the enrollment, so a link
// re-pointed after the lock named a different volume than the one holding the
// credential. It now comes from the header the enrollment read under its lock.
func TestAddRecoveryKeyReportsTheVolumeItEnrolled(t *testing.T) {
	locked := tokenParityFixture(t)
	other := tokenParityFixture(t)
	lockedHdr, _, err := ReadHeader(locked)
	if err != nil {
		t.Fatal(err)
	}
	otherHdr, _, err := ReadHeader(other)
	if err != nil {
		t.Fatal(err)
	}
	if lockedHdr.UUID == otherHdr.UUID {
		t.Fatal("the two fixtures share a UUID; the test would measure nothing")
	}
	otherBefore := fileDigest(t, other)
	link := filepath.Join(t.TempDir(), "device")
	if err := os.Symlink(locked, link); err != nil {
		t.Fatal(err)
	}
	relinkAfterFirstOpen(t, link, other)

	key, err := AddRecoveryKey(link, []byte(tokenParityPassphrase), &RecoveryKeyOptions{
		KDFType: KDFTypePBKDF2, Hash: "sha512", PBKDFIterations: minPBKDF2Iterations})
	if err != nil {
		t.Fatalf("AddRecoveryKey: %v", err)
	}
	defer key.Clear()

	if want := string(bytes.TrimRight(lockedHdr.UUID[:], "\x00")); key.VolumeUUID != want {
		t.Fatalf("the recovery key names volume %q, want the enrolled %q", key.VolumeUUID, want)
	}
	if fileDigest(t, other) != otherBefore {
		t.Fatal("the device the path was re-pointed at was written to")
	}
}
