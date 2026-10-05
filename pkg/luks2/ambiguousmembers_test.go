// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// encoding/json binds a member to a struct field case-insensitively and lets
// the last duplicate win; cryptsetup's json-c is case-sensitive. A header that
// spells a modeled member twice, or in another case, reads one way here and
// another way to cryptsetup (#248, B6).

// writeHeaderJSON replaces path's JSON area, in both copies, with jsonData,
// checksummed: a header whose bytes no writer of this package could produce.
func writeHeaderJSON(t *testing.T, path, jsonData string) {
	t.Helper()
	hdr, _, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	if err := writeEncodedHeader(f, hdr, []byte(jsonData), LUKS2HeaderMinSize); err != nil {
		t.Fatalf("writeEncodedHeader: %v", err)
	}
}

func TestReadHeaderRefusesAmbiguousMembers(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "ambiguous-base.img")
	formatWithLibrary(t, path)
	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	encoded, err := marshalCanonicalJSON(metadata)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	base := string(encoded)

	inject := func(anchor, with string) string {
		if !strings.Contains(base, anchor) {
			t.Fatalf("the base header has no %q", anchor)
		}
		return strings.Replace(base, anchor, anchor+with, 1)
	}

	for _, tc := range []struct{ name, json string }{
		{"a top-level member in another case", inject(`{`, `"Keyslots":{},`)},
		{"a top-level member twice", inject(`{`, `"tokens":{},`)},
		{"a keyslot id twice", inject(`"keyslots":{`, `"0":{"type":"luks2","key_size":32},`)},
		{"a segment id twice", inject(`"segments":{`, `"0":{"type":"linear","offset":"0","size":"dynamic"},`)},
		{"a digest member in another case", inject(`"digests":{"0":{`, `"Keyslots":["9"],`)},
		{"a segment member in another case", inject(`"segments":{"0":{`, `"OFFSET":"0",`)},
		{"a config member twice", inject(`"config":{`, `"keyslots_size":"4096",`)},
		{"a keyslot area member in another case", inject(`"area":{`, `"Offset":"0",`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			image := newImage(t, "ambiguous.img")
			formatWithLibrary(t, image)
			writeHeaderJSON(t, image, tc.json)
			_, _, err := ReadHeader(image)
			if !errors.Is(err, ErrInvalidHeader) || !errors.Is(err, ErrAmbiguousJSONMember) {
				t.Fatalf("ReadHeader: got %v, want ErrInvalidHeader and ErrAmbiguousJSONMember", err)
			}
		})
	}

	// A member this package does not model is carried, not interpreted, so
	// two of them differing only in case are not ambiguous to it.
	t.Run("unmodeled members differing in case", func(t *testing.T) {
		image := newImage(t, "unmodeled-case.img")
		formatWithLibrary(t, image)
		writeHeaderJSON(t, image, inject(`"segments":{"0":{`, `"note":"a","NOTE":"b",`))
		if _, _, err := ReadHeader(image); err != nil {
			t.Fatalf("ReadHeader: %v", err)
		}
	})
}

func TestImportTokenJSONRefusesAmbiguousMembers(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "token-ambiguous.img")
	formatWithLibrary(t, path)
	for _, doc := range []string{
		`{"type":"systemd-recovery","keyslots":["0"],"Keyslots":["7"]}`,
		`{"type":"systemd-recovery","keyslots":["0"],"keyslots":[]}`,
	} {
		if err := ImportTokenJSON(path, 0, []byte(doc)); !errors.Is(err, ErrAmbiguousJSONMember) {
			t.Errorf("ImportTokenJSON(%s): got %v, want ErrAmbiguousJSONMember", doc, err)
		}
	}
	if err := ImportTokenJSON(path, 0, []byte(`{"type":"systemd-recovery","keyslots":["0"]`)); err == nil {
		t.Error("ImportTokenJSON accepted a truncated object")
	}
}

// TestReadHeaderRequiresTheMandatoryObjects: cryptsetup refuses a header whose
// keyslots, tokens, segments, digests or config member is absent or is not an
// object, and the typed decode cannot tell those from an empty object (#248).
func TestReadHeaderRequiresTheMandatoryObjects(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "mandatory-base.img")
	formatWithLibrary(t, path)
	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	encoded, err := marshalCanonicalJSON(metadata)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	base := string(encoded)
	if !strings.Contains(base, `"tokens":{}`) {
		t.Fatalf("the base header has no empty tokens object: %s", base)
	}

	for name, doc := range map[string]string{
		"tokens null":   strings.Replace(base, `"tokens":{}`, `"tokens":null`, 1),
		"tokens absent": strings.Replace(base, `"tokens":{},`, ``, 1),
		"tokens array":  strings.Replace(base, `"tokens":{}`, `"tokens":[]`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			image := newImage(t, "mandatory.img")
			formatWithLibrary(t, image)
			writeHeaderJSON(t, image, doc)
			if _, _, err := ReadHeader(image); !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("ReadHeader: got %v, want ErrInvalidHeader", err)
			}
		})
	}
}
