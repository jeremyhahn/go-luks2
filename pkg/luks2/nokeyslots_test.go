// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"strconv"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// A volume with no keyslot the unlock path can try reports ErrNoKeyslots, not a credential failure.

// noUsableKeyslotVolume writes a container with an empty keyslots object, or with only a reencrypt keyslot, and returns its path.
func noUsableKeyslotVolume(t *testing.T, name string, reencryptOnly bool) string {
	t.Helper()

	path := newImage(t, name)
	formatWithLibrary(t, path)

	hdr, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	if reencryptOnly {
		metadata.Keyslots = map[string]*header.Keyslot{
			"0": {
				// A reencrypt keyslot carries no kdf object at all, which is
				// why reaching the derivation with one used to dereference nil.
				Type:    "reencrypt",
				KeySize: 1,
				Area:    &header.KeyslotArea{Type: "checksum", Offset: "32768", Size: "4096"},
			},
		}
	} else {
		// No keyslots, and so no digest naming one: a header cryptsetup
		// itself accepts, as it is left by removing the last keyslot.
		metadata.Keyslots = map[string]*header.Keyslot{}
		metadata.Digests["0"].Keyslots = []string{}
	}

	if err := writeHeaderUnvalidated(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the no-usable-keyslot fixture: %v", err)
	}
	return path
}

// TestAVolumeWithNoUsableKeyslotIsNotReportedAsAWrongPassphrase is the fix for
// #30, asserted on the scan and on the exported paths that reach it.
func TestAVolumeWithNoUsableKeyslotIsNotReportedAsAWrongPassphrase(t *testing.T) {
	defer parallel(t)()

	passphrase := []byte(conformancePassphrase)

	for _, tc := range []struct {
		name          string
		reencryptOnly bool
	}{
		{"the header declares no keyslots", false},
		{"every keyslot is one the unlock path cannot try", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := noUsableKeyslotVolume(t, "no-keyslots-"+strconv.FormatBool(tc.reencryptOnly)+".img", tc.reencryptOnly)

			_, metadata, err := readHeaderForTest(path)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}

			// The reencrypt case must still look populated.
			if tc.reencryptOnly {
				slots, err := listKeyslotsForTest(path)
				if err != nil {
					t.Fatalf("ListKeyslots failed: %v", err)
				}
				if len(slots) == 0 {
					t.Fatal("the reencrypt fixture reports no keyslots at all, so it does not exercise the looks-populated case")
				}
			}

			key, err := getMasterKey(path, passphrase, metadata, testVolumeSys())
			if err == nil {
				mustDestroy(t, key)
				t.Fatal("a container with no usable keyslot opened")
			}
			if !errors.Is(err, ErrNoKeyslots) {
				t.Fatalf("a container with no usable keyslot is not reported as such: %v", err)
			}
			// The two errors an operator would act on wrongly. A verification
			// verdict says a credential was judged; nothing was judged here.
			if errors.Is(err, ErrWrongKey) {
				t.Fatalf("no keyslot was tried, yet the failure claims verification was attempted: %v", err)
			}

			// The exported paths that reach the same scan must carry the
			// sentinel through rather than flatten it.
			if err := testKeyForTest(path, passphrase); !errors.Is(err, ErrNoKeyslots) {
				t.Fatalf("TestKey does not report the container state: %v", err)
			}
			if err := killSlotForTest(path, passphrase, 0); !errors.Is(err, ErrNoKeyslots) {
				t.Fatalf("KillSlot does not report the container state: %v", err)
			}
		})
	}

	// Control: a healthy container with a wrong passphrase still reports verification failure, not ErrNoKeyslots.
	t.Run("a healthy volume still reports verification failure for a wrong passphrase", func(t *testing.T) {
		path := newImage(t, "healthy.img")
		formatWithLibrary(t, path)

		_, metadata, err := readHeaderForTest(path)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}

		key, err := getMasterKey(path, []byte(conformanceWrongPassphrase), metadata, testVolumeSys())
		if err == nil {
			mustDestroy(t, key)
			t.Fatal("a wrong passphrase opened a healthy volume")
		}
		if errors.Is(err, ErrNoKeyslots) {
			t.Fatalf("a healthy volume met with a wrong passphrase reports no keyslots: %v", err)
		}
		if !errors.Is(err, ErrWrongKey) {
			t.Fatalf("a credential that was judged and rejected is not reported as such: %v", err)
		}

		// And the right passphrase still opens it, so the fixture is a volume
		// and not a brick.
		key, err = getMasterKey(path, []byte(conformancePassphrase), metadata, testVolumeSys())
		if err != nil {
			t.Fatalf("the correct passphrase no longer opens a healthy volume: %v", err)
		}
		mustDestroy(t, key)
	})
}
