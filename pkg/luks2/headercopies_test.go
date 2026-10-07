// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// Every read used the primary header copy alone (H1). A crash that tears the
// primary write -- the primary is written first -- left the secondary holding
// the previous header, complete, and Unlock failed with ErrInvalidHeader at
// boot while `cryptsetup open` succeeded. These tests hold the readers to
// cryptsetup's choice: the valid copy with the higher sequence id.

// headerCopyVolume formats a volume and damages it as damage says, given the
// header area size (the secondary's offset).
func headerCopyVolume(t *testing.T, name string, damage func(t *testing.T, path string, area int64)) string {
	t.Helper()
	path := formattedVolumeImage(t, name, "", "")
	secondary, _, err := readSecondaryHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadSecondaryHeader: %v", err)
	}
	damage(t, path, int64(secondary.HeaderOffset)) // #nosec G115 -- a legal header area size
	return path
}

func tearPrimary(t *testing.T, path string, _ int64) {
	writeBytesAt(t, path, header.HeaderSize, []byte("torn"))
}

func tearSecondary(t *testing.T, path string, area int64) {
	writeBytesAt(t, path, area+header.HeaderSize, []byte("torn"))
}

// staleCopyAt leaves the copy at staleOffset one header write behind the
// other: a token was added after it was saved.
func staleCopyAt(staleOffset func(area int64) int64) func(t *testing.T, path string, area int64) {
	return func(t *testing.T, path string, area int64) {
		at := staleOffset(area)
		stale := readAreaBytes(t, path, at, area)
		if err := setTokenForTest(path, 0, Token{Type: TokenTypeRecovery, Keyslots: []int{0}}); err != nil {
			t.Fatalf("SetToken: %v", err)
		}
		writeBytesAt(t, path, at, stale)
	}
}

func openTestVolume(t *testing.T, path string) *Volume {
	t.Helper()
	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

func TestVolumeReadsUseTheValidHeaderCopy(t *testing.T) {
	cases := []struct {
		name       string
		damage     func(t *testing.T, path string, area int64)
		wantTokens int
	}{
		{name: "the primary is torn", damage: tearPrimary},
		{name: "the secondary is torn", damage: tearSecondary},
		{name: "the secondary is newer", damage: staleCopyAt(func(int64) int64 { return 0 }), wantTokens: 1},
		{name: "the primary is newer", damage: staleCopyAt(func(area int64) int64 { return area }), wantTokens: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := headerCopyVolume(t, "copies.img", tc.damage)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			v := openTestVolume(t, path)

			pass := newTestPassphrase(t)
			defer func() { _ = pass.Destroy() }()
			key, err := v.Unlock(context.Background(), pass)
			if err != nil {
				t.Fatalf("Unlock: %v", err)
			}
			key.Destroy()
			key, err = v.UnlockKeyslot(context.Background(), 0, pass)
			if err != nil {
				t.Fatalf("UnlockKeyslot: %v", err)
			}
			key.Destroy()

			h, err := v.Header(context.Background())
			if err != nil {
				t.Fatalf("Header: %v", err)
			}
			if got := len(h.Tokens()); got != tc.wantTokens {
				t.Fatalf("Header lists %d tokens, want the current copy's %d", got, tc.wantTokens)
			}

			// A read under the shared lock leaves the medium alone.
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("a read changed the device")
			}
		})
	}

	t.Run("both copies are torn", func(t *testing.T) {
		path := headerCopyVolume(t, "copies-both.img", func(t *testing.T, path string, area int64) {
			tearPrimary(t, path, area)
			tearSecondary(t, path, area)
		})
		v := openTestVolume(t, path)
		pass := newTestPassphrase(t)
		defer func() { _ = pass.Destroy() }()
		if _, err := v.Unlock(context.Background(), pass); !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("Unlock: got %v, want ErrInvalidHeader", err)
		}
		if _, err := v.Header(context.Background()); !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("Header: got %v, want ErrInvalidHeader", err)
		}
	})
}

// TestKeyslotWriteRepairsTheStaleHeaderCopy: a write takes the exclusive lock,
// reads the current copy, and leaves both copies level with it before its own
// read-modify-write -- the repair cryptsetup's LUKS2_hdr_read makes.
func TestKeyslotWriteRepairsTheStaleHeaderCopy(t *testing.T) {
	cases := []struct {
		name       string
		damage     func(t *testing.T, path string, area int64)
		wantTokens int
	}{
		{name: "the primary is torn", damage: tearPrimary},
		{name: "the secondary is torn", damage: tearSecondary},
		{name: "the secondary is newer", damage: staleCopyAt(func(int64) int64 { return 0 }), wantTokens: 1},
		{name: "the primary is newer", damage: staleCopyAt(func(area int64) int64 { return area }), wantTokens: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := headerCopyVolume(t, "repair.img", tc.damage)
			v := openTestVolume(t, path)

			pass := newTestPassphrase(t)
			defer func() { _ = pass.Destroy() }()
			key, err := v.Unlock(context.Background(), pass)
			if err != nil {
				t.Fatalf("Unlock: %v", err)
			}
			defer key.Destroy()

			newPass := newPassphraseEnclave(t, "a second credential")
			defer func() { _ = newPass.Destroy() }()
			if _, err := v.AddKeyslot(context.Background(), key, newPass, KeyslotParams{
				Priority: PriorityNormal,
				KDF:      KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond},
			}); err != nil {
				t.Fatalf("AddKeyslot: %v", err)
			}

			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			if err := headerCopiesAgree(f); err != nil {
				t.Fatalf("the header copies after the write: %v", err)
			}
			_, metadata, err := readHeaderCopyFrom(f, header.PrimaryHeaderOffset)
			if err != nil {
				t.Fatalf("the primary after the write: %v", err)
			}
			if len(metadata.Keyslots) != 2 || len(metadata.Tokens) != tc.wantTokens {
				t.Fatalf("after the write: %d keyslots and %d tokens, want 2 and the current copy's %d",
					len(metadata.Keyslots), len(metadata.Tokens), tc.wantTokens)
			}
		})
	}
}

// TestKeyslotDeviceReadRepairsOnlyAStaleCopy: when the copies agree, the
// read writes nothing at all.
func TestKeyslotDeviceReadRepairsOnlyAStaleCopy(t *testing.T) {
	path := formattedVolumeImage(t, "repair-none.img", "", "")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dev := lockedDevice(t, path)
	if _, _, err := dev.readHeader(); err != nil {
		t.Fatalf("readHeader: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("reading an intact header wrote to the device")
	}
}

// TestKeyslotDeviceRepairsOnlyAtTheOperationsFirstRead: a read after the
// operation's own writes -- its verification -- must see a copy damaged since,
// not rewrite it.
func TestKeyslotDeviceRepairsOnlyAtTheOperationsFirstRead(t *testing.T) {
	path := formattedVolumeImage(t, "repair-first.img", "", "")
	secondary, _, err := readSecondaryHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadSecondaryHeader: %v", err)
	}
	dev := lockedDevice(t, path)
	if _, _, err := dev.readHeader(); err != nil {
		t.Fatalf("the first readHeader: %v", err)
	}

	tearSecondary(t, path, int64(secondary.HeaderOffset)) // #nosec G115 -- a legal header area size
	if _, _, err := dev.readHeader(); err != nil {
		t.Fatalf("a later readHeader: %v", err)
	}
	if _, _, err := readSecondaryHeaderForTest(path); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("the torn secondary after a later read: got %v, want it still torn", err)
	}
}
