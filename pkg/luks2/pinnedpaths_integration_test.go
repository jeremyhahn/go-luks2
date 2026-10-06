// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The pinned-path fixes against the real kernel, where O_EXCL is the kernel's
// in-use claim on a loop device and not the no-op it is on a regular file.

// imageDigest hashes a loop device's backing image.
func imageDigest(t *testing.T, image string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(image) // #nosec G304 -- a test image under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

// TestWipeKeyslotRefusesAnActiveDeviceDespiteARetarget is the HIGH finding
// from #246: device A is IN USE -- open as a mapping, which is what the
// exclusive claim exists to protect -- and the link naming it is re-pointed
// at an idle device B after the lock is taken. The claim used to be taken by
// path, so it claimed idle B, passed, and the keyslot was zeroed on A under
// its live mapping. H6 makes the claim reopen the LOCKED descriptor itself
// (Locked.Claim, via /proc/self/fd), so the busy check it performs is always
// against A regardless of where the path now points: the operation is
// refused with ErrDeviceInUse, the same error an active device gets with no
// symlink involved at all (TestWipeRefusesADeviceInUse), and A and B are
// both untouched.
func TestWipeKeyslotRefusesAnActiveDeviceDespiteARetarget(t *testing.T) {
	loopA, imageA := laneDLoop(t)
	loopB, imageB := laneDLoop(t)
	if _, err := AddKey(loopA, []byte(laneDPassphrase), []byte("a-second-passphrase"), &AddKeyOptions{KDFType: KDFTypePBKDF2, PBKDFIterTime: 1}); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	name := runVolume(t, "pinned-claim")
	defer releaseVolume(t, name)
	if err := Unlock(loopA, []byte(laneDPassphrase), name); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	beforeA, beforeB := imageDigest(t, imageA), imageDigest(t, imageB)

	link := filepath.Join(t.TempDir(), "device")
	if err := os.Symlink(loopA, link); err != nil {
		t.Fatal(err)
	}
	relinkAfterFirstOpen(t, link, loopB)

	if err := WipeKeyslot(link, 1); !errors.Is(err, ErrDeviceInUse) {
		t.Fatalf("WipeKeyslot through a link re-pointed from an open volume to an idle one = %v, want ErrDeviceInUse", err)
	}
	if imageDigest(t, imageA) != beforeA {
		t.Fatal("the open volume the lock was taken on was written to")
	}
	if imageDigest(t, imageB) != beforeB {
		t.Fatal("the idle device the link was re-pointed at was written to")
	}
}

// TestWipeAndTokenWritesStayOnTheLockedLoopDevice: on real loop devices, a
// link re-pointed after the lock never receives a byte. The exclusive claim
// (Wipe) and the header rewrite (ImportToken) both reopen the LOCKED
// descriptor via /proc/self/fd (H6) rather than resolving the path again, so
// both operations succeed and land on the device that was locked; the
// device the link now names is never touched.
func TestWipeAndTokenWritesStayOnTheLockedLoopDevice(t *testing.T) {
	for _, op := range []struct {
		name   string
		run    func(link string) error
		verify func(t *testing.T, loopA string)
	}{
		{"Wipe", func(l string) error { return Wipe(WipeOptions{Device: l, HeaderOnly: true}) },
			func(t *testing.T, loopA string) {
				if _, _, err := ReadHeader(loopA); err == nil {
					t.Fatal("the locked device still reads as LUKS2 after a header-only wipe")
				}
			}},
		{"ImportToken", func(l string) error {
			return ImportToken(l, 3, &Token{Type: "x-pinned", Keyslots: []string{"0"}})
		}, func(t *testing.T, loopA string) {
			_, metadata, err := ReadHeader(loopA)
			if err != nil || metadata.Tokens["3"] == nil {
				t.Fatalf("token 3 is not on the locked device: %v", err)
			}
		}},
	} {
		t.Run(op.name, func(t *testing.T) {
			loopA, imageA := laneDLoop(t)
			loopB, imageB := laneDLoop(t)
			beforeA, beforeB := imageDigest(t, imageA), imageDigest(t, imageB)

			link := filepath.Join(t.TempDir(), "device")
			if err := os.Symlink(loopA, link); err != nil {
				t.Fatal(err)
			}
			relinkAfterFirstOpen(t, link, loopB)

			if err := op.run(link); err != nil {
				t.Fatalf("%s: %v", op.name, err)
			}
			if imageDigest(t, imageB) != beforeB {
				t.Fatalf("%s wrote to the device the link was re-pointed at", op.name)
			}
			if imageDigest(t, imageA) == beforeA {
				t.Fatalf("%s did not write to the locked device", op.name)
			}
			op.verify(t, loopA)
		})
	}
}
