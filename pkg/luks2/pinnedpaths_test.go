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

// Writers must do all I/O through the locked descriptor; these tests re-point the symlink after the lock's open. None is parallel: they substitute the open seam.

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

// TestTheExclusiveClaimTargetsTheLockedDescriptorDespiteARetarget: Erase and RemoveKeyslot claim the locked descriptor, not the re-pointed path.
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

// TestHeaderWritersStayOnTheDeviceTheyLocked: SetToken, RemoveToken and WriteHeader write only the locked device.
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

// TestAddRecoveryKeyReportsTheVolumeItEnrolled: the reported volume is the one Open pinned.
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
