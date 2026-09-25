// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// No build constraint. Everything here runs in memory or on a file under
// t.TempDir() and needs no system binary, so it belongs in both tiers -- and
// tokenIDVolume/stampTokens below are the fixture the integration tier's
// cryptsetup measurement builds on (token_integration_test.go).

package luks2

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestGetToken_InvalidTokenID(t *testing.T) {
	tests := []struct {
		name    string
		tokenID int
	}{
		{"negative ID", -1},
		{"ID too large", MaxTokenSlots},
		{"ID way too large", 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetToken("/dev/null", tt.tokenID)
			if err == nil {
				t.Error("expected error for invalid token ID")
			}
		})
	}
}

func TestGetToken_InvalidDevice(t *testing.T) {
	_, err := GetToken("/nonexistent/device", 0)
	if err == nil {
		t.Error("expected error for nonexistent device")
	}
}

func TestListTokens_InvalidDevice(t *testing.T) {
	_, err := ListTokens("/nonexistent/device")
	if err == nil {
		t.Error("expected error for nonexistent device")
	}
}

func TestExportToken_InvalidDevice(t *testing.T) {
	_, err := ExportToken("/nonexistent/device", 0)
	if err == nil {
		t.Error("expected error for nonexistent device")
	}
}

func TestImportToken_InvalidTokenID(t *testing.T) {
	token := &Token{Type: "test"}
	tests := []struct {
		name    string
		tokenID int
	}{
		{"negative ID", -1},
		{"ID too large", MaxTokenSlots},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ImportToken("/dev/null", tt.tokenID, token)
			if err == nil {
				t.Error("expected error for invalid token ID")
			}
		})
	}
}

func TestImportToken_NilToken(t *testing.T) {
	err := ImportToken("/dev/null", 0, nil)
	if err == nil {
		t.Error("expected error for nil token")
	}
}

func TestImportToken_EmptyType(t *testing.T) {
	token := &Token{Type: ""}
	err := ImportToken("/dev/null", 0, token)
	if err == nil {
		t.Error("expected error for empty token type")
	}
}

func TestImportToken_InvalidDevice(t *testing.T) {
	token := &Token{Type: "test", Keyslots: []string{"0"}}
	err := ImportToken("/nonexistent/device", 0, token)
	if err == nil {
		t.Error("expected error for invalid device")
	}
}

func TestImportTokenJSON_InvalidJSON(t *testing.T) {
	err := ImportTokenJSON("/dev/null", 0, []byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestRemoveToken_InvalidTokenID(t *testing.T) {
	tests := []struct {
		name    string
		tokenID int
	}{
		{"negative ID", -1},
		{"ID too large", MaxTokenSlots},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RemoveToken("/dev/null", tt.tokenID)
			if err == nil {
				t.Error("expected error for invalid token ID")
			}
		})
	}
}

func TestRemoveToken_InvalidDevice(t *testing.T) {
	err := RemoveToken("/nonexistent/device", 0)
	if err == nil {
		t.Error("expected error for invalid device")
	}
}

func TestFindFreeTokenSlot_InvalidDevice(t *testing.T) {
	_, err := FindFreeTokenSlot("/nonexistent/device")
	if err == nil {
		t.Error("expected error for invalid device")
	}
}

func TestTokenExists_InvalidTokenID(t *testing.T) {
	tests := []struct {
		name    string
		tokenID int
	}{
		{"negative ID", -1},
		{"ID too large", MaxTokenSlots},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := TokenExists("/dev/null", tt.tokenID)
			if err == nil {
				t.Error("expected error for invalid token ID")
			}
		})
	}
}

func TestTokenExists_InvalidDevice(t *testing.T) {
	_, err := TokenExists("/nonexistent/device", 0)
	if err == nil {
		t.Error("expected error for invalid device")
	}
}

func TestCountTokens_InvalidDevice(t *testing.T) {
	_, err := CountTokens("/nonexistent/device")
	if err == nil {
		t.Error("expected error for invalid device")
	}
}

func TestTokenJSONMarshal(t *testing.T) {
	token := &Token{
		Type:            TokenTypeSystemdFIDO2,
		Keyslots:        []string{"1"},
		FIDO2Credential: "dGVzdC1jcmVkZW50aWFs",
		FIDO2Salt:       "dGVzdC1zYWx0",
		FIDO2RP:         "test.example.com",
		FIDO2UPRequired: boolPtr(true),
	}

	data, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("failed to marshal token: %v", err)
	}

	var parsed Token
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal token: %v", err)
	}

	if parsed.Type != token.Type {
		t.Errorf("type mismatch: got %s, want %s", parsed.Type, token.Type)
	}
	if len(parsed.Keyslots) != len(token.Keyslots) {
		t.Errorf("keyslots length mismatch: got %d, want %d", len(parsed.Keyslots), len(token.Keyslots))
	}
	if parsed.FIDO2Credential != token.FIDO2Credential {
		t.Errorf("FIDO2Credential mismatch: got %s, want %s", parsed.FIDO2Credential, token.FIDO2Credential)
	}
	if parsed.FIDO2Salt != token.FIDO2Salt {
		t.Errorf("FIDO2Salt mismatch: got %s, want %s", parsed.FIDO2Salt, token.FIDO2Salt)
	}
	if parsed.FIDO2RP != token.FIDO2RP {
		t.Errorf("FIDO2RP mismatch: got %s, want %s", parsed.FIDO2RP, token.FIDO2RP)
	}
	if parsed.FIDO2UPRequired == nil || *parsed.FIDO2UPRequired != *token.FIDO2UPRequired {
		t.Errorf("FIDO2UPRequired mismatch: got %v, want %v", parsed.FIDO2UPRequired, *token.FIDO2UPRequired)
	}
}

// TestSystemdTPM2TokenSurvivesUnmodeled is what replaced the typed TPM2
// fields (#189).
//
// go-xkms owns TPM2, so this package models none of that token's members. The
// property that matters is therefore not "we parse it" but "we do not damage
// it": a systemd-tpm2 token read from a foreign header and written back must
// come out byte-identical, because this package reads a whole header, changes
// one keyslot, and writes the lot back.
//
// The member shapes below are the ones libsystemd-shared-255.so actually
// contains -- tpm2-blob, tpm2-pcrs, tpm2-pcr-bank, tpm2-primary-alg,
// tpm2-policy-hash, tpm2-pin -- read out of the library that holds
// tpm2_make_luks2_json rather than taken from the spec or from memory. Their
// meaning is go-xkms's business; their survival is this package's.
func TestSystemdTPM2TokenSurvivesUnmodeled(t *testing.T) {
	const real = `{"type":"systemd-tpm2","keyslots":["2"],` +
		`"tpm2-blob":"dGVzdC1ibG9i","tpm2-pcrs":[0,1,2,3,7],` +
		`"tpm2-pcr-bank":"sha256","tpm2-primary-alg":"ecc",` +
		`"tpm2-policy-hash":"dGVzdC1wb2xpY3ktaGFzaA==","tpm2-pin":false}`

	var token Token
	if err := json.Unmarshal([]byte(real), &token); err != nil {
		t.Fatalf("decoding a systemd-tpm2 token: %v", err)
	}

	// The two members LUKS2 itself defines are modeled and must decode.
	if token.Type != "systemd-tpm2" {
		t.Errorf("Type = %q, want %q", token.Type, "systemd-tpm2")
	}
	if len(token.Keyslots) != 1 || token.Keyslots[0] != "2" {
		t.Errorf("Keyslots = %v, want [2]", token.Keyslots)
	}

	// Value receiver on purpose: json.Marshal of a bare Token does not take
	// its address, and a pointer-receiver marshaler would silently not fire.
	out, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("re-encoding: %v", err)
	}

	for _, member := range []string{
		`"tpm2-blob":"dGVzdC1ibG9i"`,
		`"tpm2-pcrs":[0,1,2,3,7]`,
		`"tpm2-pcr-bank":"sha256"`,
		`"tpm2-primary-alg":"ecc"`,
		`"tpm2-policy-hash":"dGVzdC1wb2xpY3ktaGFzaA=="`,
		`"tpm2-pin":false`,
	} {
		if !strings.Contains(string(out), member) {
			t.Errorf("%s did not survive the round trip\n got: %s", member, out)
		}
	}
}

// TestTPM2MembersAreNotModelled pins the boundary itself: if someone adds a
// typed TPM2 field back, this fails and points at the ruling rather than at a
// style preference.
func TestTPM2MembersAreNotModelled(t *testing.T) {
	for _, name := range jsonMemberNames(reflect.TypeOf(Token{})) {
		if strings.HasPrefix(name, "tpm2-") {
			t.Errorf("Token models the TPM2 member %q. go-xkms owns TPM2 (#189); "+
				"a consumer that needs to interpret such a token supplies it through "+
				"KeyProvider, and the passthrough carries it meanwhile.", name)
		}
	}
}

func TestMaxTokenSlots(t *testing.T) {
	if MaxTokenSlots != 32 {
		t.Errorf("MaxTokenSlots should be 32, got %d", MaxTokenSlots)
	}
}

func TestErrTokenNotFound(t *testing.T) {
	if ErrTokenNotFound == nil {
		t.Error("ErrTokenNotFound should not be nil")
	}
	if ErrTokenNotFound.Error() != "token not found" {
		t.Errorf("unexpected error message: %s", ErrTokenNotFound.Error())
	}
}

func TestErrNoFreeTokenSlot(t *testing.T) {
	if ErrNoFreeTokenSlot == nil {
		t.Error("ErrNoFreeTokenSlot should not be nil")
	}
	if ErrNoFreeTokenSlot.Error() != "no free token slots available" {
		t.Errorf("unexpected error message: %s", ErrNoFreeTokenSlot.Error())
	}
}

// tokenIDVolume writes a container whose token map carries the given keys
// VERBATIM, so a non-canonical spelling reaches the disk. ImportToken cannot
// produce one -- it keys by strconv.Itoa -- which is exactly why the fixture
// goes through the header writer instead.
//
// Each token's Type names the key it was written under, so a listing that
// returns the wrong one of two colliding entries is caught by identity rather
// than by count.
//
// The Format underneath runs once per process and each call gets a copy
// (formattedImage): the tokens are the subject, the container is setup, and
// the table-driven callers were paying a full Format per row (#92).
func tokenIDVolume(t *testing.T, name string, keys ...string) string {
	t.Helper()

	path := formattedImage(t, "tokenIDVolume", name, 64<<20, func() FormatOptions {
		return FormatOptions{
			Passphrase:    []byte("token-id-fixture-passphrase"),
			Cipher:        "aes",
			CipherMode:    "xts-plain64",
			KeySize:       512,
			HashAlgo:      "sha512",
			SectorSize:    512,
			KDFType:       KDFTypePBKDF2,
			PBKDFIterTime: 1,
		}
	})

	tokens := make(map[string]*Token, len(keys))
	for _, key := range keys {
		tokens[key] = &Token{Type: "written-as-" + key, Keyslots: []string{"0"}}
	}
	stampTokens(t, path, tokens)
	return path
}

// stampTokens replaces a container's token map with exactly the map given,
// through the header writer, so entries the exported token API cannot create --
// a non-canonical id, a JSON null -- reach the disk.
func stampTokens(t *testing.T, path string, tokens map[string]*Token) {
	t.Helper()

	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Tokens = tokens
	if err := writeHeaderInternal(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the token fixture: %v", err)
	}
}

// TestListTokensDoesNotCollapseTwoSpellingsOfOneTokenID is the fix for #35.
//
// strconv.Atoi accepts "01" and returns 1, so a header carrying both "1" and
// "01" produced ONE entry in the returned map[int]*Token -- whichever spelling
// Go's randomized map iteration reached last silently overwrote the other. The
// damage is not that "01" is invisible; it is that the WORKING token at "1"
// could disappear from inspection, on a different read each time.
//
// The assertion is on WHICH token came back, not on the count: a fix that
// returned one entry by keeping the wrong one would satisfy a count check.
func TestListTokensDoesNotCollapseTwoSpellingsOfOneTokenID(t *testing.T) {
	path := tokenIDVolume(t, "token-id-collision.img", "1", "01")

	// Repeated because the defect is decided by map iteration order: a single
	// read passes roughly half the time against the unfixed code.
	for i := 0; i < 25; i++ {
		tokens, err := ListTokens(path)
		if err != nil {
			t.Fatalf("ListTokens failed on read %d: %v", i, err)
		}
		if len(tokens) != 1 {
			t.Fatalf("read %d returned %d tokens, want 1", i, len(tokens))
		}
		if tokens[1] == nil {
			t.Fatalf("read %d returned no token at slot 1", i)
		}
		if tokens[1].Type != "written-as-1" {
			t.Fatalf("read %d returned the token written under %q at slot 1; the non-canonical spelling displaced the real one",
				i, strings.TrimPrefix(tokens[1].Type, "written-as-"))
		}
	}
}

// TestListTokensSkipsANonCanonicalTokenIDOnItsOwn covers the case with no
// collision to hide behind: a header whose only token is spelled "01" lists no
// tokens, because that is the entry no LUKS2 implementation can address --
// cryptsetup included, which is the measurement that decided this (see
// TestCryptsetupCannotReachAnUnaddressableTokenID, integration tier).
func TestListTokensSkipsANonCanonicalTokenIDOnItsOwn(t *testing.T) {
	path := tokenIDVolume(t, "token-id-lone.img", "01")

	tokens, err := ListTokens(path)
	if err != nil {
		t.Fatalf("ListTokens failed: %v", err)
	}
	if len(tokens) != 0 {
		t.Fatalf("ListTokens = %v, want no tokens: %q is not a token id any implementation can reach", tokens, "01")
	}

	// The header is still readable and still opens. Refusing it would be the
	// bricking direction the tokens-are-tolerated ruling exists to avoid.
	if _, _, err := ReadHeader(path); err != nil {
		t.Fatalf("the header no longer reads: %v", err)
	}
}

// TestCanonicalTokenIDRejectsEverySpellingThatIsNotItsOwn pins the rule at the
// value, so an off-by-one in the round trip is caught without a container.
func TestCanonicalTokenIDRejectsEverySpellingThatIsNotItsOwn(t *testing.T) {
	for _, tc := range []struct {
		key    string
		id     int
		wantOK bool
	}{
		// In range and canonically spelled.
		{"0", 0, true},
		{"1", 1, true},
		{"31", 31, true},

		// Canonical spelling, OUT OF RANGE. These are the ones the spelling
		// check alone admits, and every other token entry point rejects them.
		{"-1", 0, false},
		{"32", 0, false},
		{"999", 0, false},

		// In range, but not the canonical spelling of it.
		{"01", 0, false},
		{"001", 0, false},
		{"+1", 0, false},
		{"-0", 0, false},
		{" 1", 0, false},
		{"1 ", 0, false},
		{"1.0", 0, false},
		{"", 0, false},
		{"one", 0, false},
		{"99999999999999999999", 0, false},
	} {
		id, ok := canonicalTokenID(tc.key)
		if ok != tc.wantOK {
			t.Errorf("canonicalTokenID(%q) ok = %v, want %v", tc.key, ok, tc.wantOK)
			continue
		}
		if ok && id != tc.id {
			t.Errorf("canonicalTokenID(%q) = %d, want %d", tc.key, id, tc.id)
		}
	}
}

// TestCountTokensCountsOnlyTheTokensAnyoneCanAddress keeps the count from
// disagreeing with the listing on the same header. len() on the map counts an
// entry no implementation can reach, so a container carrying "1" and "01"
// reported two tokens while every listing and every lookup found one.
func TestCountTokensCountsOnlyTheTokensAnyoneCanAddress(t *testing.T) {
	for _, tc := range []struct {
		name string
		keys []string
		want int
	}{
		{"one canonical", []string{"1"}, 1},
		{"one non-canonical", []string{"01"}, 0},
		{"both spellings of one slot", []string{"1", "01"}, 1},
		{"two real tokens and a junk key", []string{"0", "1", "007"}, 2},
		{"the highest legal slot", []string{"31"}, 1},
		{"one past the highest slot", []string{"32"}, 0},
		{"far past the highest slot", []string{"999"}, 0},
		{"a negative slot", []string{"-1"}, 0},
		{"a real token beside an out-of-range one", []string{"1", "32"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := tokenIDVolume(t, "token-count.img", tc.keys...)

			count, err := CountTokens(path)
			if err != nil {
				t.Fatalf("CountTokens failed: %v", err)
			}
			if count != tc.want {
				t.Fatalf("CountTokens = %d, want %d", count, tc.want)
			}

			tokens, err := ListTokens(path)
			if err != nil {
				t.Fatalf("ListTokens failed: %v", err)
			}
			if len(tokens) != count {
				t.Fatalf("CountTokens = %d but ListTokens returned %d entries; the two must describe the same header",
					count, len(tokens))
			}
		})
	}
}

// TestListTokensIsUnaffectedByKeysThatAreNotNumbersAtAll is the control on the
// skip: a key that never looked like a token id was already skipped, and the
// canonical rule must not have made that path stricter or looser.
func TestListTokensIsUnaffectedByKeysThatAreNotNumbersAtAll(t *testing.T) {
	path := tokenIDVolume(t, "token-id-junk.img", "0", "keyring", "")

	tokens, err := ListTokens(path)
	if err != nil {
		t.Fatalf("ListTokens failed: %v", err)
	}
	ids := make([]int, 0, len(tokens))
	for id := range tokens {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []int{0}) {
		t.Fatalf("ListTokens returned slots %v, want [0]", ids)
	}
}

// TestGetTokenNeverReturnsNilWithoutAnError is the standing guard for #69.
//
// #69 was measured on dev/main at 1cef774, BEFORE null entries were normalized
// at the parse. Then, a token written as JSON null survived the round trip as
// a present key holding a nil pointer, and GetToken's `token, exists :=` check
// reported it as FOUND -- so it returned (nil, nil) and a caller following the
// documented contract dereferenced nil. The parse-time normalization closed it:
// the entry is removed before GetToken ever sees the map, so "present and null"
// no longer exists as a state.
//
// This test is what stops that from being re-opened silently. It asserts the
// CONTRACT rather than the mechanism -- (nil, nil) is never returned -- so it
// fails if the normalization is removed, if a second read path skips it, or if
// GetToken is ever handed metadata from somewhere that does not normalize.
//
// No nil guard was added inside GetToken. It could not fire today, and #62
// records what this package pays for controls that cannot fire: they look like
// safety, they are never exercised, and their tests pass for reasons unrelated
// to them.
func TestGetTokenNeverReturnsNilWithoutAnError(t *testing.T) {
	path := tokenIDVolume(t, "null-token-api.img")
	stampTokens(t, path, map[string]*Token{
		"0": nil,
		"1": {Type: "healthy", Keyslots: []string{"0"}},
	})

	t.Run("GetToken reports the null slot as absent", func(t *testing.T) {
		token, err := GetToken(path, 0)
		// The VALUE first: a store that reports missing as (nil, nil) makes an
		// error-only assertion vacuous, and (nil, nil) is precisely the state
		// under test.
		if token != nil {
			t.Fatalf("GetToken(0) returned a token for a null entry: %+v", token)
		}
		if err == nil {
			t.Fatal("GetToken(0) returned (nil, nil): absent and present-but-null are again indistinguishable")
		}
		if !errors.Is(err, ErrTokenNotFound) {
			t.Fatalf("GetToken(0) error = %v, want ErrTokenNotFound", err)
		}
	})

	t.Run("the healthy token is untouched", func(t *testing.T) {
		token, err := GetToken(path, 1)
		if err != nil {
			t.Fatalf("GetToken(1) failed: %v", err)
		}
		if token == nil || token.Type != "healthy" {
			t.Fatalf("GetToken(1) = %+v, want the healthy token", token)
		}
	})

	t.Run("ListTokens hands no nil to its callers", func(t *testing.T) {
		tokens, err := ListTokens(path)
		if err != nil {
			t.Fatalf("ListTokens failed: %v", err)
		}
		for id, token := range tokens {
			if token == nil {
				t.Fatalf("ListTokens returned a nil token at slot %d; every caller iterating this map dereferences it", id)
			}
		}
		if len(tokens) != 1 || tokens[1] == nil {
			t.Fatalf("ListTokens = %v, want only the healthy token at slot 1", tokens)
		}
	})

	t.Run("TokenExists and CountTokens agree with the listing", func(t *testing.T) {
		exists, err := TokenExists(path, 0)
		if err != nil {
			t.Fatalf("TokenExists failed: %v", err)
		}
		if exists {
			t.Fatal("TokenExists(0) reports the null entry as a token")
		}
		count, err := CountTokens(path)
		if err != nil {
			t.Fatalf("CountTokens failed: %v", err)
		}
		if count != 1 {
			t.Fatalf("CountTokens = %d, want 1", count)
		}
	})

	t.Run("ExportToken does not marshal a nil token", func(t *testing.T) {
		data, err := ExportToken(path, 0)
		if data != nil {
			t.Fatalf("ExportToken(0) produced %q for a null entry", data)
		}
		if !errors.Is(err, ErrTokenNotFound) {
			t.Fatalf("ExportToken(0) error = %v, want ErrTokenNotFound", err)
		}
	})

	t.Run("the caller can learn the entry was dropped", func(t *testing.T) {
		// The other half of the contract, from #27: absent-because-never-there
		// and absent-because-removed are different facts about a container, and
		// a caller that only sees ErrTokenNotFound cannot tell them apart.
		_, metadata, err := ReadHeader(path)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}
		want := []DroppedEntry{{Kind: DroppedKindToken, ID: "0"}}
		if !slices.Equal(metadata.DroppedNullEntries, want) {
			t.Fatalf("DroppedNullEntries = %v, want %v", metadata.DroppedNullEntries, want)
		}
	})
}

// TestListTokensSkipsAnIDNoOtherEntryPointAccepts is the second half of #35,
// and it is a different defect from the spelling collision.
//
// "-1", "32" and "999" are canonical spellings of numbers, so the round-trip
// check admits them on its own. Every other token entry point rejects them --
// GetToken, ImportToken, RemoveToken and TokenExists all bound the id to
// 0..MaxTokenSlots-1 -- so listing them produced exactly the state #35 exists
// to remove: a listing naming a token no caller can retrieve.
//
// The assertion is the AGREEMENT, not the count. It retrieves every id the
// listing reports and requires the retrieval to succeed, so a listing and a
// getter that disagree fail here however they came to disagree.
func TestListTokensSkipsAnIDNoOtherEntryPointAccepts(t *testing.T) {
	for _, tc := range []struct {
		name string
		keys []string
		want []int
	}{
		{"one past the highest slot", []string{"32"}, nil},
		{"far past the highest slot", []string{"999"}, nil},
		{"a negative slot", []string{"-1"}, nil},
		{"a real token beside an out-of-range one", []string{"1", "32"}, []int{1}},
		{"a real token beside a negative one", []string{"0", "-1"}, []int{0}},
		{"the highest legal slot is still listed", []string{"31"}, []int{31}},
		{"the whole legal range is still listed", []string{"0", "31"}, []int{0, 31}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := tokenIDVolume(t, "token-range.img", tc.keys...)

			tokens, err := ListTokens(path)
			if err != nil {
				t.Fatalf("ListTokens failed: %v", err)
			}
			got := make([]int, 0, len(tokens))
			for id := range tokens {
				got = append(got, id)
			}
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("ListTokens returned slots %v, want %v", got, tc.want)
			}

			// Every listed id must be retrievable. This is the property, and
			// it is what a count assertion cannot express.
			for _, id := range got {
				token, err := GetToken(path, id)
				if err != nil {
					t.Fatalf("ListTokens reported slot %d but GetToken(%d) failed: %v", id, id, err)
				}
				if token == nil {
					t.Fatalf("ListTokens reported slot %d but GetToken(%d) returned no token", id, id)
				}
			}

			// The header stays readable either way: an out-of-range token id is
			// tolerated, not grounds to refuse a container. An operator has to
			// be able to inspect a damaged header, which is precisely when they
			// need to.
			if _, _, err := ReadHeader(path); err != nil {
				t.Fatalf("the header no longer reads: %v", err)
			}
		})
	}
}
