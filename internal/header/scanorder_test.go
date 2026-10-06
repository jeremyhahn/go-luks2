// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"reflect"
	"testing"
)

func TestCanonicalKeyslotID(t *testing.T) {
	tests := []struct {
		key  string
		id   int
		want bool
	}{
		{"0", 0, true},
		{"31", 31, true},
		{"00", 0, false},
		{"-1", 0, false},
		{"x", 0, false},
		{"32", 0, false},
	}
	for _, tc := range tests {
		id, ok := CanonicalKeyslotID(tc.key)
		if ok != tc.want || (ok && id != tc.id) {
			t.Errorf("CanonicalKeyslotID(%q) = (%d, %v), want (%d, %v)", tc.key, id, ok, tc.id, tc.want)
		}
	}
}

func TestKeyslotIDsInScanOrderOrdersNumerically(t *testing.T) {
	keyslots := map[string]*Keyslot{
		"10": {}, "2": {}, "x": {}, "1": {}, "a": {},
	}
	got := KeyslotIDsInScanOrder(keyslots)
	want := []string{"1", "2", "10", "a", "x"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestVolumeKeyScanOrderPrefersKeyslotsBoundToEverySegment(t *testing.T) {
	m := &Metadata{
		Keyslots: map[string]*Keyslot{"0": {}, "1": {}},
		Segments: map[string]*Segment{"0": {}, "1": {}},
		Digests: map[string]*Digest{
			"0": {Keyslots: []string{"0"}, Segments: []string{"0"}},
			"1": {Keyslots: []string{"1"}, Segments: []string{"0", "1"}},
		},
	}
	order := VolumeKeyScanOrder(m)
	if len(order) != 2 || order[0] != "1" || order[1] != "0" {
		t.Errorf("VolumeKeyScanOrder = %v, want [1 0]", order)
	}
}

func TestVolumeKeyDigestsViewKeepsOnlyDigestsBindingEverySegment(t *testing.T) {
	m := &Metadata{
		Segments: map[string]*Segment{"0": {}, "1": {}},
		Digests: map[string]*Digest{
			"0": {Segments: []string{"0"}},
			"1": {Segments: []string{"0", "1"}},
		},
	}
	view := VolumeKeyDigestsView(m)
	if len(view.Digests) != 1 || view.Digests["1"] == nil {
		t.Errorf("VolumeKeyDigestsView.Digests = %v, want only \"1\"", view.Digests)
	}
}

func TestDigestCovers(t *testing.T) {
	if digestCovers(nil, "0") {
		t.Error("nil digest covers nothing")
	}
	d := &Digest{Keyslots: []string{"0", "1"}}
	if !digestCovers(d, "1") || digestCovers(d, "2") {
		t.Error("digestCovers disagrees with the Keyslots list")
	}
}
