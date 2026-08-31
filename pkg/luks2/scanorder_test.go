// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// keyslotMap builds a keyslot map with the given IDs. The values are only ever
// compared by identity here, so the contents do not matter.
func keyslotMap(ids ...string) map[string]*Keyslot {
	m := make(map[string]*Keyslot, len(ids))
	for _, id := range ids {
		m[id] = &Keyslot{Type: "luks2"}
	}
	return m
}

// TestKeyslotScanOrderIsAscendingNumeric pins the ordering itself.
//
// The discriminating case is two-digit IDs: LUKS2 keyslot IDs are decimal
// strings, so a lexical sort puts "10" before "9" and a volume's tenth keyslot
// would be tried before its ninth. Sorting the strings is the obvious wrong
// implementation and it passes every single-digit fixture.
func TestKeyslotScanOrderIsAscendingNumeric(t *testing.T) {
	for _, tc := range []struct {
		name string
		ids  []string
		want []string
	}{
		{"already ordered", []string{"0", "1", "2"}, []string{"0", "1", "2"}},
		{"reversed", []string{"2", "1", "0"}, []string{"0", "1", "2"}},
		{"single slot", []string{"0"}, []string{"0"}},
		{"empty", nil, []string{}},
		{
			// Lexical sorting fails this and only this.
			"two-digit IDs sort numerically, not lexically",
			[]string{"9", "10", "1", "31", "2"},
			[]string{"1", "2", "9", "10", "31"},
		},
		{
			// A gap is normal after any removal.
			"gaps preserved",
			[]string{"5", "0", "12"},
			[]string{"0", "5", "12"},
		},
		{
			// "7" and "007" parse to the same number, so the numeric comparison
			// alone leaves them tied and their order comes from the map. The
			// repo already tracks two-spellings-of-one-id as a real header
			// shape in #35.
			"two spellings of one number are ordered, not tied",
			[]string{"9", "007", "7", "08"},
			[]string{"007", "7", "08", "9"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := keyslotIDsInScanOrder(keyslotMap(tc.ids...))
			if !slices.Equal(got, tc.want) {
				t.Errorf("scan order = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestKeyslotScanOrderVisitsEveryKeyslot is the data-loss guard on the ordering.
//
// The natural implementation parses each ID with strconv.Atoi to sort it. The
// natural mistake is to drop the ones that fail to parse. A keyslot that the
// scan never visits is a credential that can no longer open the volume, and the
// operator sees "incorrect passphrase" for a passphrase that is correct — so an
// ID this function does not understand must still be returned, not discarded.
func TestKeyslotScanOrderVisitsEveryKeyslot(t *testing.T) {
	// "99999999999999999999" is a decimal number that strconv.Atoi still rejects,
	// because it does not fit an int. It takes the same tail path as a
	// non-numeric ID and must survive it for the same reason.
	ids := []string{"3", "0", "not-a-number", "11", "", "007", "1", "99999999999999999999"}
	m := keyslotMap(ids...)

	got := keyslotIDsInScanOrder(m)

	if len(got) != len(m) {
		t.Fatalf("scan order returned %d IDs for a map of %d: %v", len(got), len(m), got)
	}
	for id := range m {
		if !slices.Contains(got, id) {
			t.Errorf("keyslot %q is never visited by the scan; its credential could not open the volume", id)
		}
	}
	// Numeric IDs must still lead, so the common case keeps its ordering even on
	// a header carrying an ID this function cannot parse.
	if got[0] != "0" {
		t.Errorf("scan order starts at %q, want the lowest numeric ID first; got %v", got[0], got)
	}
}

// TestKeyslotScanOrderIsStableAcrossCalls is what makes the order an order.
//
// Go randomizes map iteration, so the pre-change code returned a different
// sequence on essentially every call. Sixteen IDs give 16! arrangements; an
// implementation that forgot to sort would not survive 50 rounds.
func TestKeyslotScanOrderIsStableAcrossCalls(t *testing.T) {
	ids := make([]string, 0, 32)
	for i := 0; i < 16; i++ {
		// Each number in two spellings, so a comparison that ties them is left
		// taking its order from the map and cannot survive the loop below.
		ids = append(ids, fmt.Sprint(i), fmt.Sprintf("%03d", i))
	}
	m := keyslotMap(ids...)

	first := keyslotIDsInScanOrder(m)
	for i := 0; i < 50; i++ {
		if got := keyslotIDsInScanOrder(m); !slices.Equal(got, first) {
			t.Fatalf("scan order changed between calls: %v then %v", first, got)
		}
	}
}

// TestAKeyslotAfterTheFirstStillOpensTheVolume is the negative control for the
// whole change, and it guards the regression the change invites.
//
// Making the scan deterministic and starting it at the lowest slot is one edit
// away from making it stop at the lowest slot. If that happened, only the
// Format-created credential would ever work: every passphrase added afterwards
// would be reported as incorrect, which is silent, total lockout for every
// operator who rotated a passphrase.
//
// So this asserts the property the cost fix must not buy: a credential held in
// a slot that is NOT visited first still opens the volume.
func TestAKeyslotAfterTheFirstStillOpensTheVolume(t *testing.T) {
	device := filepath.Join(t.TempDir(), "volume.img")
	if err := os.WriteFile(device, make([]byte, 32<<20), 0600); err != nil {
		t.Fatalf("failed to create the backing file: %v", err)
	}

	first := []byte("correct horse battery staple")
	if err := Format(FormatOptions{
		Device:        device,
		Passphrase:    first,
		KDFType:       KDFTypePBKDF2,
		HashAlgo:      "sha256",
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("Format returned error: %v", err)
	}

	second := []byte("a second credential entirely")
	if err := AddKey(device, first, second, &AddKeyOptions{
		KDFType:       KDFTypePBKDF2,
		Hash:          "sha256",
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("AddKey returned error: %v", err)
	}

	_, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader returned error: %v", err)
	}

	// The fixture is only meaningful if the second credential really is behind
	// the first in scan order, so establish that rather than narrate it. If
	// AddKey ever allocated into the first-scanned slot, this test would go
	// vacuous and stay green while the regression it exists to catch went
	// undetected.
	order := keyslotIDsInScanOrder(metadata.Keyslots)
	if len(order) < 2 {
		t.Fatalf("expected at least 2 keyslots, got %d: %v", len(order), order)
	}
	if _, err := unlockKeyslot(device, second, metadata.Keyslots[order[0]], metadata.Digests); err == nil {
		t.Fatalf("the added credential opens keyslot %s, the first slot scanned; "+
			"this fixture cannot show that the scan continues past it", order[0])
	}
	t.Logf("scan order is %v; the added credential does not open slot %s", order, order[0])

	// What this does NOT cover: it would still pass against a getMasterKey that
	// went back to ranging the map directly, because such a scan also reaches
	// the second credential eventually. Determinism is pinned one level down, on
	// the helper, by TestKeyslotScanOrderIsStableAcrossCalls. What this test
	// alone establishes is traversal -- that the scan does not stop early.
	key, err := getMasterKey(device, second, metadata)
	if err != nil {
		t.Fatalf("a credential in a later keyslot no longer opens the volume: %v", err)
	}
	key.Destroy()

	// And the first credential still works, so the scan did not merely move.
	key, err = getMasterKey(device, first, metadata)
	if err != nil {
		t.Fatalf("the original credential no longer opens the volume: %v", err)
	}
	key.Destroy()

	// A genuinely wrong passphrase must still be rejected, or the two
	// assertions above would pass against a function that accepts anything.
	if mk, err := getMasterKey(device, []byte("not either of them"), metadata); err == nil {
		mk.Destroy()
		t.Fatal("getMasterKey accepted a passphrase matching no keyslot")
	}
}
