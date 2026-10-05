// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"strconv"
	"testing"
)

// Issue #30: a volume with no keyslot the unlock path can try used to be
// reported as a wrong passphrase.
//
// The scan fell through its loop without executing the body, and the function
// ended at a bare credential verdict. So an operator whose container carries no
// openable keyslot was told their passphrase was wrong. They retype it, reach
// for their backup passphrase, and conclude they have lost the credential --
// when no passphrase would ever have worked and the credential was never the
// problem.
//
// ErrNoKeyslots was declared for exactly this state and returned by nothing.
// The sentinel was not vestigial; the path that should have raised it raised
// something misleading instead.
//
// The state is reachable without anything exotic. A `reencrypt`-only container
// is the sharpest case, because it looks POPULATED: ListKeyslots reports the
// slot -- deliberately, it keeps a broader view than the unlock path -- while
// nothing can open it.

// noUsableKeyslotVolume writes a container in one of the two reachable
// no-usable-keyslot states and returns its path.
//
// reencryptOnly=false empties the keyslots object outright; true replaces the
// keyslot with a `reencrypt` one, which is spec-legal, survives the header
// read's validation, and is the state a container interrupted mid-reencryption
// is actually in.
func noUsableKeyslotVolume(t *testing.T, name string, reencryptOnly bool) string {
	t.Helper()

	path := newImage(t, name)
	formatWithLibrary(t, path)

	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	if reencryptOnly {
		metadata.Keyslots = map[string]*Keyslot{
			"0": {
				// A reencrypt keyslot carries no kdf object at all, which is
				// why reaching the derivation with one used to dereference nil.
				Type:    "reencrypt",
				KeySize: 1,
				Area:    &KeyslotArea{Type: "checksum", Offset: "32768", Size: "4096"},
			},
		}
	} else {
		// No keyslots, and so no digest naming one: a header cryptsetup
		// itself accepts, as it is left by removing the last keyslot.
		metadata.Keyslots = map[string]*Keyslot{}
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

			_, metadata, err := ReadHeader(path)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}

			// Non-vacuity for the reencrypt case: the container must still LOOK
			// populated, or this is just the empty-map case under another name.
			if tc.reencryptOnly {
				slots, err := ListKeyslots(path)
				if err != nil {
					t.Fatalf("ListKeyslots failed: %v", err)
				}
				if len(slots) == 0 {
					t.Fatal("the reencrypt fixture reports no keyslots at all, so it does not exercise the looks-populated case")
				}
			}

			key, err := getMasterKey(path, passphrase, metadata)
			if err == nil {
				mustDestroy(t, key)
				t.Fatal("a container with no usable keyslot opened")
			}
			if !errors.Is(err, ErrNoKeyslots) {
				t.Fatalf("a container with no usable keyslot is not reported as such: %v", err)
			}
			// The two errors an operator would act on wrongly. A verification
			// verdict says a credential was judged; nothing was judged here.
			if errors.Is(err, ErrMasterKeyVerification) {
				t.Fatalf("no keyslot was tried, yet the failure claims verification was attempted: %v", err)
			}
			// The assertion that used to sit here -- that the failure is not
			// ErrInvalidPassphrase -- is GONE with the sentinel (#70). The
			// property it guarded is now structural: the package cannot report a
			// passphrase verdict because no such value exists to report.

			// The exported paths that reach the same scan must carry the
			// sentinel through rather than flatten it.
			if err := TestKey(path, passphrase); !errors.Is(err, ErrNoKeyslots) {
				t.Fatalf("TestKey does not report the container state: %v", err)
			}
			if err := KillSlot(path, passphrase, 0); !errors.Is(err, ErrNoKeyslots) {
				t.Fatalf("KillSlot does not report the container state: %v", err)
			}
		})
	}

	// THE CONTROL, and it is the one that matters most: the fix must not be
	// "never return a verification verdict again". A healthy container met with
	// a genuinely wrong passphrase must still say verification failed, and must
	// NOT say the container has no keyslots.
	t.Run("a healthy volume still reports verification failure for a wrong passphrase", func(t *testing.T) {
		path := newImage(t, "healthy.img")
		formatWithLibrary(t, path)

		_, metadata, err := ReadHeader(path)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}

		key, err := getMasterKey(path, []byte(conformanceWrongPassphrase), metadata)
		if err == nil {
			mustDestroy(t, key)
			t.Fatal("a wrong passphrase opened a healthy volume")
		}
		if errors.Is(err, ErrNoKeyslots) {
			t.Fatalf("a healthy volume met with a wrong passphrase reports no keyslots: %v", err)
		}
		if !errors.Is(err, ErrMasterKeyVerification) {
			t.Fatalf("a credential that was judged and rejected is not reported as such: %v", err)
		}

		// And the right passphrase still opens it, so the fixture is a volume
		// and not a brick.
		key, err = getMasterKey(path, []byte(conformancePassphrase), metadata)
		if err != nil {
			t.Fatalf("the correct passphrase no longer opens a healthy volume: %v", err)
		}
		mustDestroy(t, key)
	})
}
