// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks

import (
	"encoding/json"
	"testing"
)

// TestSegmentUnmarshalJSON tests segment JSON unmarshaling
func TestSegmentUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name: "valid-segment",
			input: `{
				"type": "crypt",
				"offset": "16777216",
				"size": "1048576",
				"iv_tweak": "0"
			}`,
			wantErr: false,
		},
		{
			name: "dynamic-size",
			input: `{
				"type": "crypt",
				"offset": "16777216",
				"size": "dynamic"
			}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var seg Segment
			err := json.Unmarshal([]byte(tt.input), &seg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestKeyslotUnmarshalJSON tests keyslot JSON unmarshaling
func TestKeyslotUnmarshalJSON(t *testing.T) {
	input := `{
		"type": "luks2",
		"key_size": 64,
		"area": {
			"type": "raw",
			"offset": "32768",
			"size": "258048"
		},
		"kdf": {
			"type": "argon2id",
			"salt": "test-salt",
			"time": 4,
			"memory": 1048576,
			"cpus": 4
		},
		"af": {
			"type": "luks1",
			"stripes": 4000,
			"hash": "sha256"
		}
	}`

	var ks Keyslot
	err := json.Unmarshal([]byte(input), &ks)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if ks.Type != "luks2" {
		t.Fatalf("Expected type 'luks2', got '%s'", ks.Type)
	}
	if ks.KeySize != 64 {
		t.Fatalf("Expected key_size 64, got %d", ks.KeySize)
	}
}
