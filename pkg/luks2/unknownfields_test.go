// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// realReencryptKeyslot is cryptsetup's online-reencryption keyslot shape, with members this package does not model.
const realReencryptKeyslot = `{
	"type": "reencrypt",
	"key_size": 1,
	"mode": "reencrypt",
	"direction": "forward",
	"area": {
		"type": "datashift-checksum",
		"offset": "32768",
		"size": "4096",
		"hash": "sha256",
		"sector_size": 4096,
		"shift_size": "33554432"
	}
}`

// asObject parses JSON into a generic map so encodings compare by value.
func asObject(t *testing.T, data []byte) map[string]any {
	t.Helper()

	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatalf("not a JSON object: %v\n%s", err, data)
	}
	return obj
}

// memberOrder returns the member names of a JSON object in the order they
// appear on the wire, which is the one thing a map cannot tell us.
func memberOrder(t *testing.T, data []byte) []string {
	t.Helper()

	dec := json.NewDecoder(strings.NewReader(string(data)))
	tok, err := dec.Token()
	if err != nil {
		t.Fatalf("failed to read the opening token: %v\n%s", err, data)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		t.Fatalf("expected a JSON object, got %v\n%s", tok, data)
	}

	var names []string
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			t.Fatalf("failed to read a member name: %v\n%s", err, data)
		}
		name, ok := key.(string)
		if !ok {
			t.Fatalf("member name is not a string: %v\n%s", key, data)
		}
		names = append(names, name)

		var discard json.RawMessage
		if err := dec.Decode(&discard); err != nil {
			t.Fatalf("failed to read the value of %q: %v\n%s", name, err, data)
		}
	}
	return names
}

// Passthrough conformance against cryptsetup 2.7.0: cryptsetup writes the token, this package makes an unrelated change, cryptsetup reads it back.

// systemdFIDO2TokenOnKeyslot0 is the systemd-fido2 token, bound to the
// keyslot a standard conformance container actually has. `cryptsetup token
// import` refuses a token naming a keyslot that does not exist.
const systemdFIDO2TokenOnKeyslot0 = `{"type":"systemd-fido2","keyslots":["0"],` +
	`"fido2-credential":"H8Dr2V30mX4ofJ9PCM69PhtnL3abgvQJm/z99FurO9LnG7z4Pd9dlqfilOBwexlvqEe/Nju9bE2O/IJarDVRgw==",` +
	`"fido2-salt":"0VzT3vYlabI+BXN0Pn1FiYmp66CPmZ3mxKtVeH1ByQs=",` +
	`"fido2-rp":"io.systemd.cryptsetup",` +
	`"fido2-clientPin-required":true,"fido2-up-required":true,"fido2-uv-required":false}`

// writeTokenFile puts a token where `cryptsetup token import --json-file` can
// read it.
func writeTokenFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "token.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("failed to write the token file: %v", err)
	}
	return path
}

// boolPtr is also needed by token_test.go's non-integration build; see
// token_integration_test.go's copy for the integration build.
func boolPtr(b bool) *bool { return &b }

// readHeaderJSONArea returns the primary header's JSON as on disk, up to its null terminator.
func readHeaderJSONArea(t *testing.T, path string) []byte {
	t.Helper()

	f, err := os.Open(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	var hdr header.BinaryHeader
	if err := binaryRead(f, &hdr); err != nil {
		t.Fatalf("failed to read the binary header of %s: %v", path, err)
	}
	if hdr.HeaderSize <= header.HeaderSize {
		t.Fatalf("header size %d leaves no JSON area", hdr.HeaderSize)
	}

	area := make([]byte, hdr.HeaderSize-header.HeaderSize)
	if _, err := f.ReadAt(area, header.HeaderSize); err != nil {
		t.Fatalf("failed to read the JSON area of %s: %v", path, err)
	}
	if end := bytes.IndexByte(area, 0); end != -1 {
		area = area[:end]
	}
	return area
}

// binaryRead decodes the fixed-size LUKS2 binary header. It is spelled out
// here so the helper above does not depend on which of this package's readers
// happens to be exported.
func binaryRead(r io.Reader, hdr *header.BinaryHeader) error {
	return binary.Read(r, binary.BigEndian, hdr)
}

// TestConformance_TokenSurvivesAnUnrelatedKeyslotChange: every fido2 token member survives a keyslot rewrite.
func TestConformance_TokenSurvivesAnUnrelatedKeyslotChange(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	const secondPassphrase = "second-conformance-passphrase"

	mutations := map[string]func(t *testing.T, path string){
		"AddKey": func(t *testing.T, path string) {
			if _, err := addKeyForTest(path, []byte(conformancePassphrase), []byte(secondPassphrase), &addKeyOptionsForTest{
				KDFType:       kdfTypePBKDF2,
				Hash:          "sha256",
				PBKDFIterTime: 1,
			}); err != nil {
				t.Fatalf("AddKey failed: %v", err)
			}
		},
		"SetToken into another slot": func(t *testing.T, path string) {
			if err := setTokenForTest(path, 5, Token{Type: TokenTypeRecovery, Keyslots: []int{0}}); err != nil {
				t.Fatalf("SetToken failed: %v", err)
			}
		},
		"RemoveToken from another slot": func(t *testing.T, path string) {
			if err := setTokenForTest(path, 5, Token{Type: TokenTypeRecovery, Keyslots: []int{0}}); err != nil {
				t.Fatalf("SetToken failed: %v", err)
			}
			if err := removeTokenForTest(path, 5); err != nil {
				t.Fatalf("RemoveToken failed: %v", err)
			}
		},
	}

	tokenFile := writeTokenFile(t, systemdFIDO2TokenOnKeyslot0)

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			path := newImage(t, "token-passthrough.img")
			formatWithLibrary(t, path)

			// cryptsetup writes the token, so nothing about it originates in
			// the code under test.
			if code, out := runCryptsetup(t, "", "token", "import", "--token-id", "0", "--json-file", tokenFile, path); code != 0 {
				t.Fatalf("cryptsetup token import failed (exit %d)\n%s", code, out)
			}

			mutate(t, path)

			// cryptsetup reads it back.
			code, out := runCryptsetup(t, "", "token", "export", "--token-id", "0", path)
			if code != 0 {
				t.Fatalf("cryptsetup token export failed after %s (exit %d)\n%s", name, code, out)
			}

			want := asObject(t, []byte(systemdFIDO2TokenOnKeyslot0))
			got := asObject(t, []byte(out))
			if !reflect.DeepEqual(want, got) {
				t.Errorf("%s changed a token it never touched\n want %v\n  got %v", name, want, got)
			}

			// And the container is still one cryptsetup will open, so the
			// passthrough did not buy the token back at the cost of the
			// header.
			if code, out := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", path); code != 0 {
				t.Fatalf("after %s, cryptsetup rejected the passphrase (exit %d)\n%s", name, code, out)
			}
		})
	}
}

// TestConformance_UnmodeledTokenMembersSurviveOurRewrite covers arbitrary token types.
func TestConformance_UnmodeledTokenMembersSurviveOurRewrite(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	const vendorToken = `{"type":"com.example.vendor","keyslots":["0"],` +
		`"vendor-handle":18446744073709551615,` +
		`"vendor-nested":{"a":[1,2,3],"b":{"c":null}},` +
		`"vendor-flag":false,` +
		`"vendor-text":"a \" quote and a \\ backslash"}`

	path := newImage(t, "vendor-token.img")
	formatWithLibrary(t, path)

	tokenFile := writeTokenFile(t, vendorToken)
	if code, out := runCryptsetup(t, "", "token", "import", "--token-id", "3", "--json-file", tokenFile, path); code != 0 {
		t.Fatalf("cryptsetup token import failed (exit %d)\n%s", code, out)
	}

	if _, err := addKeyForTest(path, []byte(conformancePassphrase), []byte("another-passphrase"), &addKeyOptionsForTest{
		KDFType:       kdfTypePBKDF2,
		Hash:          "sha256",
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}

	code, out := runCryptsetup(t, "", "token", "export", "--token-id", "3", path)
	if code != 0 {
		t.Fatalf("cryptsetup token export failed (exit %d)\n%s", code, out)
	}

	want := asObject(t, []byte(vendorToken))
	got := asObject(t, []byte(out))
	if !reflect.DeepEqual(want, got) {
		t.Errorf("a vendor token did not survive an unrelated AddKey\n want %v\n  got %v", want, got)
	}

	// A 64-bit handle would lose precision as float64, so the raw bytes are checked too.
	if !strings.Contains(out, "18446744073709551615") {
		t.Errorf("the 64-bit member was rounded: %s", out)
	}
}

// TestConformance_HeaderMemberOrderMatchesCryptsetup: written member order matches cryptsetup's, so headers can be diffed.
func TestConformance_HeaderMemberOrderMatchesCryptsetup(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	ours := newImage(t, "ours.img")
	formatWithLibrary(t, ours)

	theirs := newImage(t, "theirs.img")
	if code, out := runCryptsetup(t, conformancePassphrase, "luksFormat", "--type", "luks2",
		"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--batch-mode", theirs); code != 0 {
		t.Fatalf("cryptsetup luksFormat failed (exit %d)\n%s", code, out)
	}

	type object struct {
		name string
		at   func(t *testing.T, area []byte) []byte
	}

	keyslot := func(t *testing.T, area []byte) []byte {
		t.Helper()
		var top struct {
			Keyslots map[string]json.RawMessage `json:"keyslots"`
		}
		if err := json.Unmarshal(area, &top); err != nil {
			t.Fatalf("failed to parse the JSON area: %v", err)
		}
		return top.Keyslots["0"]
	}
	nested := func(member string) func(t *testing.T, area []byte) []byte {
		return func(t *testing.T, area []byte) []byte {
			t.Helper()
			var inner map[string]json.RawMessage
			if err := json.Unmarshal(keyslot(t, area), &inner); err != nil {
				t.Fatalf("failed to parse keyslot 0: %v", err)
			}
			return inner[member]
		}
	}

	objects := []object{
		{name: "top level", at: func(_ *testing.T, area []byte) []byte { return area }},
		{name: "keyslots.0", at: keyslot},
		{name: "keyslots.0.area", at: nested("area")},
		{name: "keyslots.0.af", at: nested("af")},
	}

	ourArea := readHeaderJSONArea(t, ours)
	theirArea := readHeaderJSONArea(t, theirs)

	for _, obj := range objects {
		t.Run(obj.name, func(t *testing.T) {
			want := withoutPriority(memberOrder(t, obj.at(t, theirArea)))
			got := withoutPriority(memberOrder(t, obj.at(t, ourArea)))
			if !reflect.DeepEqual(want, got) {
				t.Errorf("member order differs from cryptsetup's\n cryptsetup %v\n         us %v", want, got)
			}
		})
	}

	// Compared without priority; cryptsetup emits priority last, after kdf, as internal/header's types.go declares.
	if order := memberOrder(t, keyslot(t, ourArea)); slices.Contains(order, "priority") && order[len(order)-1] != "priority" {
		t.Errorf("priority is emitted, but not last as cryptsetup emits it: %v", order)
	}

	// The keyslot KDFs are deliberately NOT compared: this package formats
	// with pbkdf2 here and the two sides would have to be pinned to the same
	// KDF for the comparison to mean anything. TestKeyslotMemberOrderMatchesCryptsetup
	// and TestArgon2KDFMemberOrderMatchesCryptsetup (internal/header) pin both
	// shapes against the measured orders instead.

	// priority is deliberately NOT compared. cryptsetup writes no member at
	// all for a normal keyslot; whether this package does is decided in
	// createMetadata, which is not this file's to change. What IS asserted
	// here is that when a priority exists it is emitted where cryptsetup
	// emits one -- last.
	if bytes.Contains(theirArea, []byte(`"priority"`)) {
		t.Fatalf("premise broken: cryptsetup wrote a priority member for a default keyslot\n%s", theirArea)
	}

	if code, out := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", ours); code != 0 {
		t.Fatalf("cryptsetup rejected our container (exit %d)\n%s", code, out)
	}
}

// withoutPriority drops the priority member from a member-order listing.
//
// See TestConformance_HeaderMemberOrderMatchesCryptsetup for why the
// comparison is made without it.
func withoutPriority(order []string) []string {
	filtered := make([]string, 0, len(order))
	for _, name := range order {
		if name == "priority" {
			continue
		}
		filtered = append(filtered, name)
	}
	return filtered
}

// TestConformance_ReencryptKeyslotSurvivesOnDisk: a hand-built reencrypt keyslot survives the real write path, checked against the bytes.
func TestConformance_ReencryptKeyslotSurvivesOnDisk(t *testing.T) {
	requireCryptsetup(t)

	path := newImage(t, "reencrypt-on-disk.img")
	formatWithLibrary(t, path)

	// The write path is sound before the reencrypt keyslot is introduced.
	if code, out := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", path); code != 0 {
		t.Fatalf("premise broken: cryptsetup rejected the freshly formatted container (exit %d)\n%s", code, out)
	}

	var injected header.Keyslot
	if err := json.Unmarshal([]byte(realReencryptKeyslot), &injected); err != nil {
		t.Fatalf("failed to parse the reencrypt keyslot: %v", err)
	}
	// Clear of keyslot 0's area, which runs from 32768 for 258048 bytes.
	injected.Area.Offset = "294912"

	hdr, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Keyslots["1"] = &injected
	hdr.SequenceID++
	if err := writeHeaderUnvalidated(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the header carrying the reencrypt keyslot: %v", err)
	}

	want := asObject(t, readHeaderJSONArea(t, path))["keyslots"].(map[string]any)["1"]

	// A write is refused with such a keyslot, and the refusal leaves it on disk untouched.
	if err := setTokenForTest(path, 2, Token{Type: TokenTypeRecovery, Keyslots: []int{0}}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("ImportToken beside an orphan reencrypt keyslot: got %v, want ErrInvalidHeader", err)
	}
	if got := asObject(t, readHeaderJSONArea(t, path))["keyslots"].(map[string]any)["1"]; !reflect.DeepEqual(want, got) {
		t.Fatalf("a refused write changed the reencrypt keyslot\n want %v\n  got %v", want, got)
	}

	// Re-encoding with an unrelated change must reproduce the reencrypt keyslot member for member.
	hdr, metadata, err = readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Tokens["2"] = &LegacyToken{Type: TokenTypeRecovery, Keyslots: []string{"0"}}
	hdr.SequenceID++
	if err := writeHeaderUnvalidated(path, hdr, metadata); err != nil {
		t.Fatalf("re-encoding the header failed: %v", err)
	}

	got := asObject(t, readHeaderJSONArea(t, path))["keyslots"].(map[string]any)["1"]
	if !reflect.DeepEqual(want, got) {
		t.Errorf("a header write changed a reencrypt keyslot it never touched\n want %v\n  got %v", want, got)
	}

	// And the shape on disk is the one that went in, member for member --
	// which is the assertion that fails if af, kdf, area.encryption or
	// area.key_size lose their omitempty.
	expected := asObject(t, []byte(realReencryptKeyslot))
	expected["area"].(map[string]any)["offset"] = "294912"
	if !reflect.DeepEqual(expected, got) {
		t.Errorf("the reencrypt keyslot on disk is not the one that was written\n want %v\n  got %v", expected, got)
	}
	for _, invented := range []string{"af", "kdf"} {
		if _, present := got.(map[string]any)[invented]; present {
			t.Errorf("a %q member was invented on a keyslot that has none: %v", invented, got)
		}
	}
}

// TestConformance_CryptsetupKeyslotRoundTripsUnchanged: a cryptsetup keyslot is written back byte-identical.
func TestConformance_CryptsetupKeyslotRoundTripsUnchanged(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	path := newImage(t, "theirs-roundtrip.img")
	if code, out := runCryptsetup(t, conformancePassphrase, "luksFormat", "--type", "luks2",
		"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--batch-mode", path); code != 0 {
		t.Fatalf("cryptsetup luksFormat failed (exit %d)\n%s", code, out)
	}

	before := asObject(t, readHeaderJSONArea(t, path))

	if err := setTokenForTest(path, 0, Token{Type: TokenTypeRecovery, Keyslots: []int{0}}); err != nil {
		t.Fatalf("ImportToken failed: %v", err)
	}

	after := asObject(t, readHeaderJSONArea(t, path))

	if !reflect.DeepEqual(before["keyslots"], after["keyslots"]) {
		t.Errorf("importing a token changed the keyslots object\n before %v\n  after %v",
			before["keyslots"], after["keyslots"])
	}
	if !reflect.DeepEqual(before["digests"], after["digests"]) {
		t.Errorf("importing a token changed the digests object\n before %v\n  after %v",
			before["digests"], after["digests"])
	}
	if !reflect.DeepEqual(before["segments"], after["segments"]) {
		t.Errorf("importing a token changed the segments object\n before %v\n  after %v",
			before["segments"], after["segments"])
	}

	if code, out := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", path); code != 0 {
		t.Fatalf("cryptsetup rejected the rewritten container (exit %d)\n%s", code, out)
	}
}
