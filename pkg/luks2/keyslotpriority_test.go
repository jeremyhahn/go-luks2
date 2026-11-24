// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// Keyslot priority tests: the member is optional, absent means normal (0 ignore, 1 normal, 2 prefer).

// TestAbsentKeyslotPriorityIsNormal: an absent priority, as cryptsetup writes for normal, reads as normal.
func TestAbsentKeyslotPriorityIsNormal(t *testing.T) {
	tests := []struct {
		name     string
		priority *int
		want     Priority
	}{
		{"absent", nil, PriorityNormal},
		{"explicit ignore", intPtr(keyslotPriorityIgnore), PriorityIgnore},
		{"explicit normal", intPtr(keyslotPriorityNormal), PriorityNormal},
		{"explicit prefer", intPtr(keyslotPriorityPrefer), PriorityPrefer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := sampleMetadata()
			metadata.Keyslots["0"].Priority = tt.priority

			slots, err := listKeyslotsFrom(metadata)
			if err != nil {
				t.Fatalf("listKeyslotsFrom failed: %v", err)
			}
			if len(slots) != 1 {
				t.Fatalf("listKeyslotsFrom returned %d slots, want 1", len(slots))
			}
			if slots[0].Priority != tt.want {
				t.Fatalf("priority = %d, want %d", slots[0].Priority, tt.want)
			}
		})
	}
}

// TestKeyslotPriorityConstantsMatchTheFormat pins the vocabulary itself. The
// values are the LUKS2 specification's and were confirmed against cryptsetup
// 2.7.0: `config --priority prefer` writes 2 and `--priority normal` deletes
// the member. An inverted constant here would silently invert every decision
// made from it.
func TestKeyslotPriorityConstantsMatchTheFormat(t *testing.T) {
	if keyslotPriorityIgnore != 0 || keyslotPriorityNormal != 1 || keyslotPriorityPrefer != 2 {
		t.Fatalf("priority constants are ignore=%d normal=%d prefer=%d, want 0/1/2",
			keyslotPriorityIgnore, keyslotPriorityNormal, keyslotPriorityPrefer)
	}
	if keyslotPriorityPrefer <= keyslotPriorityNormal {
		t.Fatal("prefer must sort above normal; the larger value is the one tried first")
	}
}

// TestCreateMetadataWritesNoPriorityMember: the encoded JSON has no priority member.
func TestCreateMetadataWritesNoPriorityMember(t *testing.T) {
	metadata := createMetadata(
		&header.KDF{Type: "pbkdf2", Hash: "sha512", Salt: "AAAA", Iterations: intPtr(210000)},
		&header.KDF{Type: "pbkdf2", Hash: "sha512", Salt: "AAAA", Iterations: intPtr(210000)},
		"AAAA",
		formatOptionsForTest{Cipher: "aes", CipherMode: "xts-plain64", HashAlgo: "sha512", SectorSize: 512},
		64, 0x8000, 258048, 16744448, 16777216,
	)

	if p := metadata.Keyslots["0"].Priority; p != nil {
		t.Fatalf("createMetadata set priority %d on a normal keyslot", *p)
	}

	encoded, err := header.MarshalCanonicalJSON(metadata)
	if err != nil {
		t.Fatalf("header.MarshalCanonicalJSON failed: %v", err)
	}
	if bytes.Contains(encoded, []byte(`"priority"`)) {
		t.Fatalf("the encoded metadata carries a priority member\n%s", encoded)
	}
}

// TestANonDefaultPriorityIsStillWritten is the control. Omitting the default
// must not become "priority can never be written": the member stays declared
// and omitempty precisely so a caller or a foreign container can carry a real
// priority, and a change that dropped the field entirely would pass the test
// above and lose data.
func TestANonDefaultPriorityIsStillWritten(t *testing.T) {
	for _, priority := range []int{keyslotPriorityIgnore, keyslotPriorityPrefer} {
		metadata := sampleMetadata()
		metadata.Keyslots["0"].Priority = intPtr(priority)

		encoded, err := header.MarshalCanonicalJSON(metadata)
		if err != nil {
			t.Fatalf("header.MarshalCanonicalJSON failed: %v", err)
		}

		// KeyslotPriorityIgnore is 0, which is exactly the value a
		// non-pointer omitempty field would silently drop. That is why
		// header.Keyslot.Priority is a *int, and this is the case that proves it.
		if !bytes.Contains(encoded, []byte(`"priority":`)) {
			t.Fatalf("priority %d was dropped from the encoding\n%s", priority, encoded)
		}

		var round header.Metadata
		if err := json.Unmarshal(encoded, &round); err != nil {
			t.Fatalf("failed to parse the encoding back: %v", err)
		}
		got := round.Keyslots["0"].Priority
		if got == nil || *got != priority {
			t.Fatalf("priority %d did not survive a round trip: %v", priority, got)
		}
	}
}
