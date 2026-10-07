// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"context"
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
	if _, err := addKeyForTest(loopA, []byte(laneDPassphrase), []byte("a-second-passphrase"), &addKeyOptionsForTest{KDFType: kdfTypePBKDF2, PBKDFIterTime: 1}); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	// A device is "in use" to WipeKeyslot's O_EXCL check for the same
	// kernel reason regardless of who holds the exclusive open -- a real
	// dm-crypt mapping (what the original, pre-#268 Unlock produced here)
	// or, as below, this test's own exclusive open of the block device.
	// Activation now lives in pkg/dmcrypt, which pkg/luks2 cannot import
	// (DESIGN.md A.2), so this stands in for it; see the file comment.
	excl, err := os.OpenFile(loopA, os.O_RDWR|os.O_EXCL, 0) // #nosec G304 -- a loop device this test attached
	if err != nil {
		t.Fatalf("holding an exclusive open on %s failed: %v", loopA, err)
	}
	defer func() { _ = excl.Close() }()
	beforeA, beforeB := imageDigest(t, imageA), imageDigest(t, imageB)

	link := filepath.Join(t.TempDir(), "device")
	if err := os.Symlink(loopA, link); err != nil {
		t.Fatal(err)
	}
	sys := relinkAfterFirstOpen(t, link, loopB)

	v, err := Open(context.Background(), link, withTestSys(sys))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()
	if err := v.RemoveKeyslot(context.Background(), 1); !errors.Is(err, ErrDeviceInUse) {
		t.Fatalf("RemoveKeyslot through a link re-pointed from an open volume to an idle one = %v, want ErrDeviceInUse", err)
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
// (Erase) and the header rewrite (ImportToken) both reopen the LOCKED
// descriptor via /proc/self/fd (H6) rather than resolving the path again, so
// both operations succeed and land on the device that was locked; the
// device the link now names is never touched.
func TestWipeAndTokenWritesStayOnTheLockedLoopDevice(t *testing.T) {
	for _, op := range []struct {
		name   string
		run    func(link string, sys volumeSys) error
		verify func(t *testing.T, loopA string)
	}{
		{"Erase", func(l string, sys volumeSys) error {
			v, err := Open(context.Background(), l, withTestSys(sys))
			if err != nil {
				return err
			}
			defer func() { _ = v.Close() }()
			return v.Erase(context.Background())
		},
			func(t *testing.T, loopA string) {
				if _, _, err := readHeaderForTest(loopA); err == nil {
					t.Fatal("the locked device still reads as LUKS2 after a header-only wipe")
				}
			}},
		{"SetToken", func(l string, sys volumeSys) error {
			return setTokenForTest(l, 3, Token{Type: "x-pinned", Keyslots: []int{0}}, withTestSys(sys))
		}, func(t *testing.T, loopA string) {
			_, metadata, err := readHeaderForTest(loopA)
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
			sys := relinkAfterFirstOpen(t, link, loopB)

			if err := op.run(link, sys); err != nil {
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
