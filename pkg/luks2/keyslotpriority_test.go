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

// Tests for the LUKS2 keyslot priority member, whose two failure modes were
// present at once and pull in opposite directions.
//
// The member is OPTIONAL and its default is NORMAL. Everything else follows:
// a writer that emits the default is writing noise, and a reader that treats
// the absent member as the zero value is reading "ignore" where the format says
// "normal". This package did both. The numbers do not help -- 0 ignore,
// 1 normal, 2 prefer -- because the larger value means "try this FIRST", which
// is how `priority := 2` came to sit under the comment "Lower priority".

// TestAbsentKeyslotPriorityIsNormal is the read half.
//
// It matters far beyond this package's own containers: cryptsetup DELETES the
// member for a normal keyslot, so essentially every keyslot in every
// cryptsetup-created container arrives with no priority at all. Reading those
// as 0 reported every one of them as a slot to skip.
func TestAbsentKeyslotPriorityIsNormal(t *testing.T) {
	tests := []struct {
		name     string
		priority *int
		want     Priority
	}{
		{"absent", nil, keyslotPriorityNormal},
		{"explicit ignore", intPtr(keyslotPriorityIgnore), keyslotPriorityIgnore},
		{"explicit normal", intPtr(keyslotPriorityNormal), keyslotPriorityNormal},
		{"explicit prefer", intPtr(keyslotPriorityPrefer), keyslotPriorityPrefer},
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
			if slots[0].Priority != Priority(tt.want) {
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

// TestCreateMetadataWritesNoPriorityMember is the write half on the format
// path, asserted on the ENCODED BYTES rather than on the struct: what matters
// is that the member is absent from the JSON, which is a fact about the tags
// and the nil pointer together.
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
