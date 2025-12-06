// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"strconv"
	"testing"
)

func TestFindAvailableKeyslot(t *testing.T) {
	tests := []struct {
		name          string
		existingSlots []int
		requestedSlot *int
		expectedSlot  int
		expectError   bool
	}{
		{
			name:          "first slot available",
			existingSlots: []int{},
			requestedSlot: nil,
			expectedSlot:  0,
			expectError:   false,
		},
		{
			name:          "slot 0 taken, find next",
			existingSlots: []int{0},
			requestedSlot: nil,
			expectedSlot:  1,
			expectError:   false,
		},
		{
			name:          "multiple slots taken",
			existingSlots: []int{0, 1, 2},
			requestedSlot: nil,
			expectedSlot:  3,
			expectError:   false,
		},
		{
			name:          "request specific available slot",
			existingSlots: []int{0},
			requestedSlot: intPtr(5),
			expectedSlot:  5,
			expectError:   false,
		},
		{
			name:          "request specific taken slot",
			existingSlots: []int{0, 1},
			requestedSlot: intPtr(1),
			expectedSlot:  0,
			expectError:   true,
		},
		{
			name:          "request invalid slot number",
			existingSlots: []int{0},
			requestedSlot: intPtr(32),
			expectedSlot:  0,
			expectError:   true,
		},
		{
			name:          "request negative slot number",
			existingSlots: []int{0},
			requestedSlot: intPtr(-1),
			expectedSlot:  0,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build metadata with existing slots
			metadata := &LUKS2Metadata{
				Keyslots: make(map[string]*Keyslot),
			}
			for _, slot := range tt.existingSlots {
				metadata.Keyslots[strconv.Itoa(slot)] = &Keyslot{Type: "luks2"}
			}

			opts := &AddKeyOptions{}
			if tt.requestedSlot != nil {
				opts.Keyslot = tt.requestedSlot
			}

			slot, err := findAvailableKeyslot(metadata, opts)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if slot != tt.expectedSlot {
					t.Errorf("expected slot %d, got %d", tt.expectedSlot, slot)
				}
			}
		})
	}
}

func TestCalculateNextKeyslotOffset(t *testing.T) {
	tests := []struct {
		name           string
		keyslots       map[string]*Keyslot
		expectedOffset int64
	}{
		{
			name:           "no existing keyslots",
			keyslots:       map[string]*Keyslot{},
			expectedOffset: 0x8000, // 32KB (after headers)
		},
		{
			name: "one keyslot",
			keyslots: map[string]*Keyslot{
				"0": {
					Area: &KeyslotArea{
						Offset: "32768",  // 0x8000
						Size:   "262144", // 256KB
					},
				},
			},
			expectedOffset: 294912, // 32768 + 262144 = 294912
		},
		{
			name: "multiple keyslots",
			keyslots: map[string]*Keyslot{
				"0": {
					Area: &KeyslotArea{
						Offset: "32768",
						Size:   "262144",
					},
				},
				"1": {
					Area: &KeyslotArea{
						Offset: "294912",
						Size:   "262144",
					},
				},
			},
			expectedOffset: 557056, // 294912 + 262144 = 557056
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := &LUKS2Metadata{
				Keyslots: tt.keyslots,
			}

			offset, err := calculateNextKeyslotOffset(metadata)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if offset != tt.expectedOffset {
				t.Errorf("expected offset %d, got %d", tt.expectedOffset, offset)
			}
		})
	}
}

func TestKeyslotInfoList(t *testing.T) {
	// Test KeyslotInfo struct fields
	info := KeyslotInfo{
		ID:         1,
		Type:       "luks2",
		KeySize:    64,
		Priority:   1,
		KDFType:    "argon2id",
		Encryption: "aes-xts-plain64",
	}

	if info.ID != 1 {
		t.Errorf("expected ID 1, got %d", info.ID)
	}
	if info.Type != "luks2" {
		t.Errorf("expected Type 'luks2', got %s", info.Type)
	}
	if info.KeySize != 64 {
		t.Errorf("expected KeySize 64, got %d", info.KeySize)
	}
	if info.Priority != 1 {
		t.Errorf("expected Priority 1, got %d", info.Priority)
	}
	if info.KDFType != "argon2id" {
		t.Errorf("expected KDFType 'argon2id', got %s", info.KDFType)
	}
	if info.Encryption != "aes-xts-plain64" {
		t.Errorf("expected Encryption 'aes-xts-plain64', got %s", info.Encryption)
	}
}

func TestAddKeyOptionsDefaults(t *testing.T) {
	// Test that nil options doesn't cause panic
	opts := &AddKeyOptions{}

	if opts.Keyslot != nil {
		t.Error("expected Keyslot to be nil by default")
	}
	if opts.KDFType != "" {
		t.Error("expected KDFType to be empty by default")
	}
	if opts.Argon2Time != 0 {
		t.Error("expected Argon2Time to be 0 by default")
	}
	if opts.Argon2Memory != 0 {
		t.Error("expected Argon2Memory to be 0 by default")
	}
	if opts.Argon2Parallel != 0 {
		t.Error("expected Argon2Parallel to be 0 by default")
	}
}

func TestMaxKeyslotsConstant(t *testing.T) {
	if MaxKeyslots != 32 {
		t.Errorf("expected MaxKeyslots to be 32, got %d", MaxKeyslots)
	}
}

func TestKeyslotAreaAlignment(t *testing.T) {
	if KeyslotAreaAlignment != 4096 {
		t.Errorf("expected KeyslotAreaAlignment to be 4096, got %d", KeyslotAreaAlignment)
	}
}
