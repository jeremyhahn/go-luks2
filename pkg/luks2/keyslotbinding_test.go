// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// The segment-binding predicates (#249, A1): which keyslots hold the key the
// data is encrypted with, as the header declares it and as a recovered key
// satisfies it.

// bindingFixture returns a real container's metadata and volume key, so the
// digests below are genuine ones a recovered key can be evaluated against.
func bindingFixture(t *testing.T) (*header.Metadata, []byte) {
	t.Helper()

	device := newImage(t, "binding.img")
	formatWithLibrary(t, device)
	key := volumeKey(t, device, migrationPassphrase)
	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	return metadata, key
}

// withDigests returns a shallow copy of metadata carrying digests instead of its
// own, so each case below states the exact digest set it is about.
func withDigests(metadata *header.Metadata, digests map[string]*header.Digest) *header.Metadata {
	m := *metadata
	m.Digests = digests
	return &m
}

// digestVariant returns a copy of d naming the given keyslots and segments.
func digestVariant(d *header.Digest, keyslots, segments []string) *header.Digest {
	c := *d
	c.Keyslots = keyslots
	c.Segments = segments
	return &c
}

func TestKeyslotBoundToSegment(t *testing.T) {
	defer parallel(t)()

	metadata, _ := bindingFixture(t)
	bound := metadata.Digests["0"]
	unusable := digestVariant(bound, []string{"0"}, []string{"0"})
	unusable.Digest = "not base64!"

	for _, tc := range []struct {
		name    string
		digests map[string]*header.Digest
		segment string
		want    bool
	}{
		{"a digest binding the segment", map[string]*header.Digest{"0": bound}, "0", true},
		{"an unbound digest, as cryptsetup luksAddKey --unbound writes",
			map[string]*header.Digest{"0": digestVariant(bound, []string{"0"}, []string{})}, "0", false},
		{"a digest bound to another segment",
			map[string]*header.Digest{"0": digestVariant(bound, []string{"0"}, []string{"1"})}, "0", false},
		{"no digest attests the keyslot",
			map[string]*header.Digest{"0": digestVariant(bound, []string{"1"}, []string{"0"})}, "0", false},
		// A declaration, not an evaluation: whether the digest can be USED is
		// the screen's question, reported there as the header fault it is.
		{"the only binding digest is damaged", map[string]*header.Digest{"0": unusable}, "0", true},
		{"a damaged unbound digest beside a bound one",
			map[string]*header.Digest{"0": bound, "1": func() *header.Digest {
				d := digestVariant(bound, []string{"0"}, nil)
				d.Digest = "not base64!"
				return d
			}()}, "0", false},
		{"a bound and an unbound digest both attest it, which no static check can resolve",
			map[string]*header.Digest{"0": bound, "1": digestVariant(bound, []string{"0"}, nil)}, "0", false},
		{"the segment does not exist", map[string]*header.Digest{"0": bound}, "7", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := keyslotBoundToSegment(withDigests(metadata, tc.digests), "0", tc.segment); got != tc.want {
				t.Fatalf("keyslotBoundToSegment = %v, want %v", got, tc.want)
			}
		})
	}

	if keyslotBoundToSegment(nil, "0", "0") {
		t.Error("nil metadata reports a binding")
	}
}

func TestKeyslotBoundToDataSegments(t *testing.T) {
	defer parallel(t)()

	metadata, _ := bindingFixture(t)
	if !keyslotBoundToDataSegments(metadata, "0") {
		t.Fatal("keyslot 0 of a freshly formatted volume is not bound to its data segment")
	}

	twoSegments := *metadata
	twoSegments.Segments = map[string]*header.Segment{"0": metadata.Segments["0"], "1": metadata.Segments["0"]}
	if keyslotBoundToDataSegments(&twoSegments, "0") {
		t.Error("a keyslot bound to segment 0 only is reported bound to segments 0 and 1")
	}

	noSegments := *metadata
	noSegments.Segments = map[string]*header.Segment{}
	if keyslotBoundToDataSegments(&noSegments, "0") {
		t.Error("a header with no segment reports a keyslot bound to all of them")
	}
	if keyslotBoundToDataSegments(nil, "0") {
		t.Error("nil metadata reports a binding")
	}
}

func TestRecoveredKeyBoundToSegment(t *testing.T) {
	defer parallel(t)()

	metadata, key := bindingFixture(t)
	mk := secretOf(t, key)
	other := secretOf(t, bytes.Repeat([]byte{0x5a}, len(key)))
	bound := metadata.Digests["0"]

	for _, tc := range []struct {
		name    string
		digests map[string]*header.Digest
		segment string
		want    bool
	}{
		{"the key matches a digest binding the segment", map[string]*header.Digest{"0": bound}, "0", true},
		{"the key matches only an unbound digest",
			map[string]*header.Digest{"0": digestVariant(bound, []string{"0"}, nil)}, "0", false},
		{"the binding digest names another keyslot",
			map[string]*header.Digest{"0": digestVariant(bound, []string{"3"}, []string{"0"})}, "0", false},
		{"the segment does not exist", map[string]*header.Digest{"0": bound}, "9", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := recoveredKeyBoundToSegment(withDigests(metadata, tc.digests), "0", tc.segment, mk); got != tc.want {
				t.Fatalf("recoveredKeyBoundToSegment = %v, want %v", got, tc.want)
			}
		})
	}

	if recoveredKeyBoundToSegment(metadata, "0", "0", other) {
		t.Error("a key no digest matches is reported bound")
	}
	if recoveredKeyBoundToSegment(metadata, "0", "0", nil) || recoveredKeyBoundToSegment(nil, "0", "0", mk) {
		t.Error("a nil key or nil metadata is reported bound")
	}
}
