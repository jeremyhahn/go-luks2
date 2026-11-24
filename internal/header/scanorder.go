// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"cmp"
	"slices"
	"strconv"
)

// CanonicalKeyslotID parses key as a canonical LUKS2 keyslot id: a decimal
// integer, spelled without leading zeros or a sign, in 0..MaxKeyslots-1.
func CanonicalKeyslotID(key string) (int, bool) {
	id, err := strconv.Atoi(key)
	if err != nil || strconv.Itoa(id) != key {
		return 0, false
	}
	if id < 0 || id >= MaxKeyslots {
		return 0, false
	}
	return id, true
}

// KeyslotIDsInScanOrder returns keyslots' ids in the order a scan tries them:
// ascending numeric order, with ids that do not parse as a number after those
// in lexical order.
func KeyslotIDsInScanOrder(keyslots map[string]*Keyslot) []string {
	ids := make([]string, 0, len(keyslots))
	for id := range keyslots {
		ids = append(ids, id)
	}

	slices.SortFunc(ids, func(a, b string) int {
		na, errA := strconv.Atoi(a)
		nb, errB := strconv.Atoi(b)
		switch {
		case errA == nil && errB == nil:
			// Equal numbers break ties on the raw string, since SortFunc is not stable.
			if c := cmp.Compare(na, nb); c != 0 {
				return c
			}
			return cmp.Compare(a, b)
		case errA == nil:
			return -1
		case errB == nil:
			return 1
		default:
			return cmp.Compare(a, b)
		}
	})

	return ids
}

// dataSegmentIDs returns every segment id the header declares, sorted.
func dataSegmentIDs(metadata *Metadata) []string {
	ids := make([]string, 0, len(metadata.Segments))
	for id, segment := range metadata.Segments {
		if segment != nil {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids
}

// digestCovers reports whether digest attests keyslotID. Private copy of
// pkg/luks2/keyslotscreen.go's helper; see dataSegmentIDs.
func digestCovers(digest *Digest, keyslotID string) bool {
	return digest != nil && slices.Contains(digest.Keyslots, keyslotID)
}

// keyslotDeclaredForAllSegments reports whether keyslot id's digests together name every data segment.
func keyslotDeclaredForAllSegments(metadata *Metadata, id string) bool {
	var bound []string
	for _, digest := range metadata.Digests {
		if digestCovers(digest, id) {
			bound = append(bound, digest.Segments...)
		}
	}
	for _, segment := range dataSegmentIDs(metadata) {
		if !slices.Contains(bound, segment) {
			return false
		}
	}
	return true
}

// VolumeKeyDigestsView returns metadata with Digests narrowed to those that
// bind EVERY data segment -- the view the keyslot scan reasons about when
// deciding whether a keyslot holds the whole-volume key.
func VolumeKeyDigestsView(metadata *Metadata) *Metadata {
	segments := dataSegmentIDs(metadata)
	view := *metadata
	view.Digests = make(map[string]*Digest, len(metadata.Digests))
	for id, digest := range metadata.Digests {
		if digest == nil || len(segments) == 0 {
			continue
		}
		bindsAll := true
		for _, segment := range segments {
			if !slices.Contains(digest.Segments, segment) {
				bindsAll = false
				break
			}
		}
		if bindsAll {
			view.Digests[id] = digest
		}
	}
	return &view
}

// VolumeKeyScanOrder orders metadata's keyslot ids so that every keyslot whose
// digests bind all data segments is tried before one that does not.
func VolumeKeyScanOrder(metadata *Metadata) []string {
	all := KeyslotIDsInScanOrder(metadata.Keyslots)
	order := make([]string, 0, len(all))
	var rest []string
	for _, id := range all {
		if keyslotDeclaredForAllSegments(metadata, id) {
			order = append(order, id)
		} else {
			rest = append(rest, id)
		}
	}
	return append(order, rest...)
}
