// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import "testing"

// VolumeInfo.KeySize was declared and never set (#248, B7).
func TestGetVolumeInfoReportsTheVolumeKeySize(t *testing.T) {
	defer parallel(t)()

	path512 := newImage(t, "info-512.img")
	formatWithLibrary(t, path512)
	for path, want := range map[string]int{path512: 512, keySize256Volume(t): 256} {
		info, err := GetVolumeInfo(path)
		if err != nil {
			t.Fatalf("GetVolumeInfo: %v", err)
		}
		if info.KeySize != want {
			t.Errorf("KeySize = %d, want %d", info.KeySize, want)
		}
	}

	// No keyslot attested for the segment: no key size to report.
	m := structureFixture()
	m.Digests["0"].Keyslots = []string{}
	if got := volumeKeyBits(m, "0"); got != 0 {
		t.Errorf("volumeKeyBits with no attested keyslot = %d, want 0", got)
	}
	m = structureFixture()
	m.Digests["0"].Segments = []string{}
	if got := volumeKeyBits(m, "0"); got != 0 {
		t.Errorf("volumeKeyBits with no digest for the segment = %d, want 0", got)
	}
}
