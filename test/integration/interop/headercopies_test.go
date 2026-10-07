// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package interop_test

import (
	"context"
	"os"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// Both tools must choose the same header copy (H1). cryptsetup reads both
// copies and uses the valid one with the higher sequence id; this library used
// the primary alone, so a crash that tore the primary write left a volume
// `cryptsetup open` opens and Unlock refused at boot.

// headerArea is where the secondary header copy of device begins.
func headerArea(t *testing.T, device string) int64 {
	t.Helper()
	f, err := os.Open(device) // #nosec G304 -- a loop device this test attached
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	hdr, _, err := header.ReadSecondaryHeaderFrom(f)
	if err != nil {
		t.Fatalf("read the secondary header of %s: %v", device, err)
	}
	return int64(hdr.HeaderOffset) // #nosec G115 -- a legal header area size
}

// tearHeaderCopy overwrites bytes inside the JSON area of the copy at offset,
// so its checksum no longer matches: a header write interrupted part way.
func tearHeaderCopy(t *testing.T, device string, offset int64) {
	t.Helper()
	f, err := os.OpenFile(device, os.O_RDWR, 0) // #nosec G304 -- a loop device this test attached
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteAt([]byte("torn"), offset+header.HeaderSize+10); err != nil {
		t.Fatalf("tear the header copy at %d: %v", offset, err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
}

func libraryUnlocks(t *testing.T, device string, passphrase []byte) {
	t.Helper()
	ctx := context.Background()
	v, err := luks2.Open(ctx, device)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = v.Close() }()
	pass, err := enclave.NewMemoryEnclaveCopy(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(ctx, pass)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	key.Destroy()
}

func TestHeaderCopyChoiceMatchesCryptsetup(t *testing.T) {
	copies := []struct {
		name   string
		offset func(area int64) int64
	}{
		{"primary", func(int64) int64 { return header.PrimaryHeaderOffset }},
		{"secondary", func(area int64) int64 { return area }},
	}

	// The defect as reported: cryptsetup formats, the primary tears, and the
	// library must open the volume from the secondary as cryptsetup does.
	for _, torn := range copies {
		t.Run("the library unlocks a cryptsetup volume whose "+torn.name+" is torn", func(t *testing.T) {
			defer parallel(t)()
			loop := csVolume(t)
			tearHeaderCopy(t, loop, torn.offset(headerArea(t, loop)))

			libraryUnlocks(t, loop, []byte(matrixPassphrase))
			if !csOpens(t, loop, []byte(matrixPassphrase)) {
				t.Fatal("cryptsetup does not open it either")
			}
		})
	}

	// The reverse: the library repairs the torn copy before its own write, and
	// each copy it leaves is, ALONE, one cryptsetup opens -- the other is torn
	// before cryptsetup reads, so its own repair cannot stand in for ours.
	for _, torn := range copies {
		for _, kept := range copies {
			t.Run("cryptsetup opens the "+kept.name+" the library wrote after the "+torn.name+" tore", func(t *testing.T) {
				defer parallel(t)()
				loop := csVolume(t)
				area := headerArea(t, loop)
				tearHeaderCopy(t, loop, torn.offset(area))

				if err := AddKey(loop, []byte(matrixPassphrase), []byte(matrixSecond), matrixAddKeyOptions); err != nil {
					t.Fatalf("AddKey over a torn %s: %v", torn.name, err)
				}
				for _, other := range copies {
					if other.name != kept.name {
						tearHeaderCopy(t, loop, other.offset(area))
					}
				}
				for _, pass := range []string{matrixPassphrase, matrixSecond} {
					if !csOpens(t, loop, []byte(pass)) {
						t.Fatalf("cryptsetup does not open the library's %s copy with %q", kept.name, pass)
					}
				}
			})
		}
	}
}
