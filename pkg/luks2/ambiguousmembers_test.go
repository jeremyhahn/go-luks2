// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// encoding/json binds a member to a struct field case-insensitively and lets
// the last duplicate win; cryptsetup's json-c is case-sensitive. A header that
// spells a modeled member twice, or in another case, reads one way here and
// another way to cryptsetup (#248, B6).

// writeHeaderJSON replaces path's JSON area, in both copies, with jsonData,
// checksummed: a header whose bytes no writer of this package could produce.
func writeHeaderJSON(t *testing.T, path, jsonData string) {
	t.Helper()
	hdr, _, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	if err := writeEncodedHeader(f, hdr, []byte(jsonData), header.HeaderMinSize, (*os.File).Sync); err != nil {
		t.Fatalf("writeEncodedHeader: %v", err)
	}
}

func TestReadHeaderRefusesAmbiguousMembers(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "ambiguous-base.img")
	formatWithLibrary(t, path)
	_, metadata, err := readHeaderForTest(path)
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
			_, _, err := readHeaderForTest(image)
			if !errors.Is(err, ErrInvalidHeader) || !errors.Is(err, header.ErrAmbiguousJSONMember) {
				t.Fatalf("ReadHeader: got %v, want ErrInvalidHeader and header.ErrAmbiguousJSONMember", err)
			}
		})
	}

	// A member this package does not model is carried, not interpreted, so
	// two of them differing only in case are not ambiguous to it.
	t.Run("unmodeled members differing in case", func(t *testing.T) {
		image := newImage(t, "unmodeled-case.img")
		formatWithLibrary(t, image)
		writeHeaderJSON(t, image, inject(`"segments":{"0":{`, `"note":"a","NOTE":"b",`))
		if _, _, err := readHeaderForTest(image); err != nil {
			t.Fatalf("ReadHeader: %v", err)
		}
	})
}

func TestSetTokenRefusesAmbiguousMembers(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "token-ambiguous.img")
	formatWithLibrary(t, path)
	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	// A case-insensitive duplicate -- the typed Keyslots field's own spelling
	// and an unmodeled member differing only in case -- is still caught: the
	// write path round-trips the token through LegacyToken (toLegacyToken),
	// whose decoder is the same case-sensitive one a header read uses. An
	// EXACT duplicate key ("keyslots" twice) is not: encoding/json collapses
	// it to the last occurrence while decoding the caller's JSON into Token's
	// Members map, before this package ever sees two keys to compare.
	doc := `{"type":"systemd-recovery","keyslots":["0"],"Keyslots":["7"]}`
	var token Token
	if err := json.Unmarshal([]byte(doc), &token); err != nil {
		t.Fatalf("Unmarshal(%s): %v", doc, err)
	}
	if err := v.SetToken(context.Background(), 0, token); !errors.Is(err, header.ErrAmbiguousJSONMember) {
		t.Errorf("SetToken(%s): got %v, want header.ErrAmbiguousJSONMember", doc, err)
	}

	var truncated Token
	if err := json.Unmarshal([]byte(`{"type":"systemd-recovery","keyslots":["0"]`), &truncated); err == nil {
		t.Error("Unmarshal accepted a truncated object")
	}
}

// TestReadHeaderRequiresTheMandatoryObjects: cryptsetup refuses a header whose
// keyslots, tokens, segments, digests or config member is absent or is not an
// object, and the typed decode cannot tell those from an empty object (#248).
func TestReadHeaderRequiresTheMandatoryObjects(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "mandatory-base.img")
	formatWithLibrary(t, path)
	_, metadata, err := readHeaderForTest(path)
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
			if _, _, err := readHeaderForTest(image); !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("ReadHeader: got %v, want ErrInvalidHeader", err)
			}
		})
	}
}
