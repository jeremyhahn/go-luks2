// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"crypto"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/header"
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
func retargetedPair(t *testing.T) (link, locked, other string, otherBefore [32]byte, sys volumeSys) {
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
	sys = relinkAfterFirstOpen(t, link, other)
	return link, locked, other, fileDigest(t, other), sys
}

// TestTheExclusiveClaimTargetsTheLockedDescriptorDespiteARetarget: Erase and
// RemoveKeyslot (WipeKeyslot's successor, B.6) used to take their O_EXCL
// claim by reopening the path after the lock, so a path re-pointed in
// between claimed, wiped -- and for RemoveKeyslot, vetted -- a device that
// was never locked. The claim now reopens the LOCKED descriptor's own
// /proc/self/fd entry (Locked.Claim) rather than resolving the path again,
// so it cannot be retargeted: the operation lands on the file that was
// locked, and the device the path was re-pointed at is never touched.
func TestTheExclusiveClaimTargetsTheLockedDescriptorDespiteARetarget(t *testing.T) {
	defer parallel(t)()
	for _, op := range []struct {
		name string
		run  func(device string, sys volumeSys) error
	}{
		{"Erase", func(d string, sys volumeSys) error {
			v, err := Open(context.Background(), d, withTestSys(sys))
			if err != nil {
				return err
			}
			defer func() { _ = v.Close() }()
			return v.Erase(context.Background())
		}},
		{"RemoveKeyslot", func(d string, sys volumeSys) error {
			v, err := Open(context.Background(), d, withTestSys(sys))
			if err != nil {
				return err
			}
			defer func() { _ = v.Close() }()
			return v.RemoveKeyslot(context.Background(), 1)
		}},
	} {
		t.Run(op.name, func(t *testing.T) {
			link, locked, other, otherBefore, sys := retargetedPair(t)
			lockedBefore := fileDigest(t, locked)

			if err := op.run(link, sys); err != nil {
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

// TestHeaderWritersStayOnTheDeviceTheyLocked: SetToken, RemoveToken and
// WriteHeader read and wrote the header by reopening the path after taking
// the lock, so a re-pointed link had one device's header -- or a header read
// from it -- written onto another. They now read and write through the locked
// descriptor: the change lands on the device that was locked, and the other
// is not touched.
func TestHeaderWritersStayOnTheDeviceTheyLocked(t *testing.T) {
	defer parallel(t)()
	for _, op := range []struct {
		name string
		// run acts on link. locked is read only directly, never through the
		// link, so the first open of the link is the operation's own lock.
		run   func(t *testing.T, link, locked string, sys volumeSys) error
		check func(t *testing.T, metadata *header.Metadata)
	}{
		{"SetToken", func(_ *testing.T, link, _ string, sys volumeSys) error {
			v, err := Open(context.Background(), link, withTestSys(sys))
			if err != nil {
				return err
			}
			defer func() { _ = v.Close() }()
			return v.SetToken(context.Background(), 5, Token{Type: "x-pinned", Keyslots: []int{0}})
		}, func(t *testing.T, m *header.Metadata) {
			if m.Tokens["5"] == nil {
				t.Fatal("token 5 is not on the locked device")
			}
		}},
		{"RemoveToken", func(_ *testing.T, link, _ string, sys volumeSys) error {
			v, err := Open(context.Background(), link, withTestSys(sys))
			if err != nil {
				return err
			}
			defer func() { _ = v.Close() }()
			return v.RemoveToken(context.Background(), 1)
		},
			func(t *testing.T, m *header.Metadata) {
				if m.Tokens["1"] != nil {
					t.Fatal("token 1 is still on the locked device")
				}
			}},
		{"WriteHeader", func(t *testing.T, link, locked string, sys volumeSys) error {
			hdr, metadata, err := readHeaderForTest(locked)
			if err != nil {
				t.Fatal(err)
			}
			hdr.SequenceID += 10
			return writeHeaderWithSys(link, hdr, metadata, sys)
		}, nil},
	} {
		t.Run(op.name, func(t *testing.T) {
			link, locked, other, otherBefore, sys := retargetedPair(t)
			before, _, err := readHeaderForTest(locked)
			if err != nil {
				t.Fatal(err)
			}

			if err := op.run(t, link, locked, sys); err != nil {
				t.Fatalf("%s: %v", op.name, err)
			}
			if fileDigest(t, other) != otherBefore {
				t.Fatal("the device the path was re-pointed at was written to")
			}
			hdr, metadata, err := readHeaderForTest(locked)
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

// TestAddRecoveryKeyReportsTheVolumeItEnrolled: the volume a recovery key was
// enrolled on is the one Open pinned, not whatever the path names afterward.
// Reading it by reopening the path after the enrollment -- as the
// pre-redesign free AddRecoveryKey did -- let a link re-pointed after the
// lock name a different volume than the one holding the credential; Open's
// pin closes that off structurally rather than depending on this call site
// reading the UUID under its own lock.
func TestAddRecoveryKeyReportsTheVolumeItEnrolled(t *testing.T) {
	defer parallel(t)()
	locked := tokenParityFixture(t)
	other := tokenParityFixture(t)
	lockedHdr, _, err := readHeaderForTest(locked)
	if err != nil {
		t.Fatal(err)
	}
	otherHdr, _, err := readHeaderForTest(other)
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
	sys := relinkAfterFirstOpen(t, link, other)

	ctx := context.Background()
	v, err := Open(ctx, link, withTestSys(sys))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryCopy([]byte(tokenParityPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(ctx, pass)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer key.Destroy()

	rk, err := NewRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	defer rk.Destroy()

	if _, err := v.AddRecoveryKey(ctx, key, rk, KeyslotParams{KDF: KDFParams{Type: KDFPBKDF2, Hash: crypto.SHA512, Iterations: minPBKDF2Iterations}}); err != nil {
		t.Fatalf("AddRecoveryKey: %v", err)
	}

	// The volume this enrolled is the one Open pinned, regardless of where
	// the path points now: v.Header reads through that pinned descriptor
	// rather than reopening by path, which is what used to require reading
	// the UUID from under the enrollment's own lock instead.
	h, err := v.Header(ctx)
	if err != nil {
		t.Fatalf("Header: %v", err)
	}
	if want := string(bytes.TrimRight(lockedHdr.UUID[:], "\x00")); h.UUID() != want {
		t.Fatalf("the enrolled volume reports UUID %q, want the enrolled %q", h.UUID(), want)
	}
	if fileDigest(t, other) != otherBefore {
		t.Fatal("the device the path was re-pointed at was written to")
	}
}
