// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// TestVolumeEraseIsACryptoErase holds (*Volume).Erase to the same property
// TestWipeHeaderOnlyIsACryptoErase holds Wipe(WipeOptions{HeaderOnly:
// true}) to (#246 D3): every header copy and the keyslot area -- the
// wrapped volume key -- end up all zero, so a copy of the header taken
// before the erase (a luksHeaderBackup, a snapshot) opens nothing.
func TestVolumeEraseIsACryptoErase(t *testing.T) {
	defer parallel(t)()

	path := formattedVolumeImage(t, "volume-erase.img", "", "")
	hdr, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	_, keyslotsEnd, err := keyslotsAreaBounds(hdr, metadata)
	if err != nil {
		t.Fatalf("keyslotsAreaBounds failed: %v", err)
	}

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if err := v.Erase(context.Background()); err != nil {
		t.Fatalf("Erase failed: %v", err)
	}

	region := readImageAt(t, path, 0, int(keyslotsEnd))
	if !bytes.Equal(region, make([]byte, len(region))) {
		t.Fatal("the header copies and keyslots area are not all zero after Erase")
	}

	if _, err := v.Header(context.Background()); err == nil {
		t.Fatal("Header succeeded after Erase, want the zeroed header to be refused")
	}
}

func TestVolumeEraseOnAClosedVolumeFailsWithErrClosed(t *testing.T) {
	path := formattedVolumeImage(t, "volume-erase-closed.img", "", "")
	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if err := v.Erase(context.Background()); !errors.Is(err, ErrClosed) {
		t.Errorf("Erase on a closed Volume = %v, want ErrClosed", err)
	}
}

func TestVolumeEraseOnAReadOnlyVolumeFailsWithErrReadOnly(t *testing.T) {
	defer parallel(t)()

	path := formattedVolumeImage(t, "volume-erase-readonly.img", "", "")
	before := readAreaBytes(t, path, 0, goldenPrefixBytes)

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()), WithReadOnly())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	if err := v.Erase(context.Background()); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Erase on a read-only Volume = %v, want ErrReadOnly", err)
	}
	if !bytes.Equal(before, readAreaBytes(t, path, 0, goldenPrefixBytes)) {
		t.Fatal("Erase on a read-only Volume wrote to the device")
	}
}
