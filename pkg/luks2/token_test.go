// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// No build constraint. Everything here runs in memory or on a file under
// t.TempDir() and needs no system binary, so it belongs in both tiers -- and
// tokenIDVolume/stampTokens below are the fixture the integration tier's
// cryptsetup measurement builds on (token_integration_test.go). The ForTest
// helpers below are needed by both tiers too, which is why they live in this
// untagged file rather than in token_v2_test.go (!integration).

package luks2

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// setTokenForTest, removeTokenForTest, getTokenForTest, listTokensForTest and
// countTokensForTest open device, do the one call, and close it again -- the
// way the pre-redesign library's luks2.ImportToken/RemoveToken/GetToken/
// ListTokens/CountTokens did before B.6 moved them onto
// (*luks2.Volume).SetToken/RemoveToken and (*Header).Tokens().
func setTokenForTest(device string, id int, t Token, opts ...Option) error {
	v, err := Open(context.Background(), device, cheapOpts(opts)...)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()
	return v.SetToken(context.Background(), id, t)
}

// setTokenJSONForTest is setTokenForTest for a caller holding raw token
// JSON rather than a Token value -- the way the pre-redesign library's
// luks2.ImportTokenJSON did before B.6 deleted it in favor of
// json.Unmarshal onto luks2.Token.
func setTokenJSONForTest(device string, id int, data []byte, opts ...Option) error {
	var t Token
	if err := json.Unmarshal(data, &t); err != nil {
		return err
	}
	return setTokenForTest(device, id, t, opts...)
}

func removeTokenForTest(device string, id int, opts ...Option) error {
	v, err := Open(context.Background(), device, cheapOpts(opts)...)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()
	return v.RemoveToken(context.Background(), id)
}

func getTokenForTest(device string, id int) (Token, bool, error) {
	v, err := Open(context.Background(), device, withTestSys(testVolumeSys()))
	if err != nil {
		return Token{}, false, err
	}
	defer func() { _ = v.Close() }()
	hdr, err := v.Header(context.Background())
	if err != nil {
		return Token{}, false, err
	}
	t, ok := hdr.Tokens()[id]
	return t, ok, nil
}

func listTokensForTest(device string) (map[int]Token, error) {
	v, err := Open(context.Background(), device, withTestSys(testVolumeSys()))
	if err != nil {
		return nil, err
	}
	defer func() { _ = v.Close() }()
	hdr, err := v.Header(context.Background())
	if err != nil {
		return nil, err
	}
	return hdr.Tokens(), nil
}

func countTokensForTest(device string) (int, error) {
	tokens, err := listTokensForTest(device)
	if err != nil {
		return 0, err
	}
	return len(tokens), nil
}

func TestTokenJSONMarshal(t *testing.T) {
	token := &LegacyToken{
		Type:            "systemd-fido2",
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

	var parsed LegacyToken
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

	var token LegacyToken
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

	// Value receiver on purpose: json.Marshal of a bare LegacyToken does not take
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
	for _, name := range header.JSONMemberNames(reflect.TypeOf(LegacyToken{})) {
		if strings.HasPrefix(name, "tpm2-") {
			t.Errorf("LegacyToken models the TPM2 member %q. go-xkms owns TPM2 (#189); "+
				"a consumer that needs to interpret such a token supplies it through "+
				"KeyProvider, and the passthrough carries it meanwhile.", name)
		}
	}
}

func TestMaxTokens(t *testing.T) {
	if MaxTokens != 32 {
		t.Errorf("MaxTokens should be 32, got %d", MaxTokens)
	}
}

func TestErrTokenNotFound(t *testing.T) {
	if ErrTokenNotFound == nil {
		t.Error("ErrTokenNotFound should not be nil")
	}
	if ErrTokenNotFound.Error() != "luks2: token not found" {
		t.Errorf("unexpected error message: %s", ErrTokenNotFound.Error())
	}
}

func TestErrNoFreeTokenSlot(t *testing.T) {
	if ErrNoSpace == nil {
		t.Error("ErrNoSpace should not be nil")
	}
	if ErrNoSpace.Error() != "luks2: no space" {
		t.Errorf("unexpected error message: %s", ErrNoSpace.Error())
	}
}

// tokenIDVolume writes a container whose token map carries the given keys
// VERBATIM, so a non-canonical spelling reaches the disk. SetToken cannot
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

	path := formattedImage(t, "tokenIDVolume", name, 64<<20, func() formatOptionsForTest {
		return formatOptionsForTest{
			Passphrase:    []byte("token-id-fixture-passphrase"),
			Cipher:        "aes",
			CipherMode:    "xts-plain64",
			KeySize:       512,
			HashAlgo:      "sha512",
			SectorSize:    512,
			KDFType:       kdfTypePBKDF2,
			PBKDFIterTime: 1,
		}
	})

	tokens := make(map[string]*LegacyToken, len(keys))
	for _, key := range keys {
		tokens[key] = &LegacyToken{Type: "written-as-" + key, Keyslots: []string{"0"}}
	}
	stampTokens(t, path, tokens)
	return path
}

// stampTokens replaces a container's token map with exactly the map given,
// through the header writer, so entries the exported token API cannot create --
// a non-canonical id, a JSON null -- reach the disk.
func stampTokens(t *testing.T, path string, tokens map[string]*LegacyToken) {
	t.Helper()

	hdr, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Tokens = tokens
	if err := writeHeaderUnvalidated(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the token fixture: %v", err)
	}
}

// TestListTokensDoesNotCollapseTwoSpellingsOfOneTokenID is the fix for #35.
//
// strconv.Atoi accepts "01" and returns 1, so a header carrying both "1" and
// "01" produced ONE entry in the returned map[int]Token -- whichever spelling
// Go's randomized map iteration reached last silently overwrote the other. The
// damage is not that "01" is invisible; it is that the WORKING token at "1"
// could disappear from inspection, on a different read each time.
//
// The assertion is on WHICH token came back, not on the count: a fix that
// returned one entry by keeping the wrong one would satisfy a count check.
func TestListTokensDoesNotCollapseTwoSpellingsOfOneTokenID(t *testing.T) {
	defer parallel(t)()

	path := tokenIDVolume(t, "token-id-collision.img", "1", "01")

	// Repeated because the defect is decided by map iteration order: a single
	// read passes roughly half the time against the unfixed code.
	for i := 0; i < 25; i++ {
		tokens, err := listTokensForTest(path)
		if err != nil {
			t.Fatalf("Tokens failed on read %d: %v", i, err)
		}
		if len(tokens) != 1 {
			t.Fatalf("read %d returned %d tokens, want 1", i, len(tokens))
		}
		tok, ok := tokens[1]
		if !ok {
			t.Fatalf("read %d returned no token at slot 1", i)
		}
		if tok.Type != "written-as-1" {
			t.Fatalf("read %d returned the token written under %q at slot 1; the non-canonical spelling displaced the real one",
				i, strings.TrimPrefix(tok.Type, "written-as-"))
		}
	}
}

// TestListTokensSkipsANonCanonicalTokenIDOnItsOwn covers the case with no
// collision to hide behind: a header whose only token is spelled "01" lists no
// tokens, because that is the entry no LUKS2 implementation can address --
// cryptsetup included, which is the measurement that decided this (see
// TestCryptsetupCannotReachAnUnaddressableTokenID, integration tier).
func TestListTokensSkipsANonCanonicalTokenIDOnItsOwn(t *testing.T) {
	defer parallel(t)()

	path := tokenIDVolume(t, "token-id-lone.img", "01")

	tokens, err := listTokensForTest(path)
	if err != nil {
		t.Fatalf("Tokens failed: %v", err)
	}
	if len(tokens) != 0 {
		t.Fatalf("Tokens() = %v, want no tokens: %q is not a token id any implementation can reach", tokens, "01")
	}

	// The header is still readable and still opens. Refusing it would be the
	// bricking direction the tokens-are-tolerated ruling exists to avoid.
	if _, _, err := readHeaderForTest(path); err != nil {
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
	defer parallel(t)()

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

			count, err := countTokensForTest(path)
			if err != nil {
				t.Fatalf("countTokensForTest failed: %v", err)
			}
			if count != tc.want {
				t.Fatalf("len(Tokens()) = %d, want %d", count, tc.want)
			}

			tokens, err := listTokensForTest(path)
			if err != nil {
				t.Fatalf("Tokens failed: %v", err)
			}
			if len(tokens) != count {
				t.Fatalf("count = %d but Tokens() returned %d entries; the two must describe the same header",
					count, len(tokens))
			}
		})
	}
}

// TestListTokensIsUnaffectedByKeysThatAreNotNumbersAtAll is the control on the
// skip: a key that never looked like a token id was already skipped, and the
// canonical rule must not have made that path stricter or looser.
func TestListTokensIsUnaffectedByKeysThatAreNotNumbersAtAll(t *testing.T) {
	defer parallel(t)()

	path := tokenIDVolume(t, "token-id-junk.img", "0", "keyring", "")

	tokens, err := listTokensForTest(path)
	if err != nil {
		t.Fatalf("Tokens failed: %v", err)
	}
	ids := make([]int, 0, len(tokens))
	for id := range tokens {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []int{0}) {
		t.Fatalf("Tokens returned slots %v, want [0]", ids)
	}
}

// TestTokensNormalizesTheNullSlotAsAbsent is the standing guard for #69.
//
// #69 was measured on dev/main at 1cef774, BEFORE null entries were normalized
// at the parse. Then, a token written as JSON null survived the round trip as
// a present key holding a nil pointer, and the old GetToken's `token, exists :=`
// check reported it as FOUND -- so it returned (nil, nil) and a caller
// following the documented contract dereferenced nil. The parse-time
// normalization closed it: the entry is removed before any token lookup ever
// sees the map, so "present and null" no longer exists as a state.
//
// This test is what stops that from being re-opened silently: it fails if the
// normalization is removed, if a second read path skips it, or if Tokens is
// ever handed metadata from somewhere that does not normalize.
func TestTokensNormalizesTheNullSlotAsAbsent(t *testing.T) {
	defer parallel(t)()

	path := tokenIDVolume(t, "null-token-api.img")
	stampTokens(t, path, map[string]*LegacyToken{
		"0": nil,
		"1": {Type: "healthy", Keyslots: []string{"0"}},
	})

	t.Run("Tokens reports the null slot as absent", func(t *testing.T) {
		_, ok, err := getTokenForTest(path, 0)
		if err != nil {
			t.Fatalf("getTokenForTest(0): %v", err)
		}
		if ok {
			t.Fatal("Tokens()[0] reports a token for a null entry")
		}
	})

	t.Run("the healthy token is untouched", func(t *testing.T) {
		token, ok, err := getTokenForTest(path, 1)
		if err != nil {
			t.Fatalf("getTokenForTest(1): %v", err)
		}
		if !ok || token.Type != "healthy" {
			t.Fatalf("Tokens()[1] = %+v, %v; want the healthy token", token, ok)
		}
	})

	t.Run("Tokens hands no null entry to its callers", func(t *testing.T) {
		tokens, err := listTokensForTest(path)
		if err != nil {
			t.Fatalf("listTokensForTest failed: %v", err)
		}
		if _, ok := tokens[1]; len(tokens) != 1 || !ok {
			t.Fatalf("Tokens() = %v, want only the healthy token at slot 1", tokens)
		}
	})

	t.Run("the count agrees with the listing", func(t *testing.T) {
		count, err := countTokensForTest(path)
		if err != nil {
			t.Fatalf("countTokensForTest failed: %v", err)
		}
		if count != 1 {
			t.Fatalf("len(Tokens()) = %d, want 1", count)
		}
	})

	t.Run("the caller can learn the entry was dropped", func(t *testing.T) {
		// The other half of the contract, from #27: absent-because-never-there
		// and absent-because-removed are different facts about a container, and
		// a caller that only sees an absent slot cannot tell them apart.
		_, metadata, err := readHeaderForTest(path)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}
		want := []header.DroppedEntry{{Kind: header.DroppedKindToken, ID: "0"}}
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
// AddToken, SetToken and RemoveToken all bound the id to 0..MaxTokens-1 -- so
// listing them produced exactly the state #35 exists to remove: a listing
// naming a token no caller can retrieve.
//
// The assertion is the AGREEMENT, not the count. It retrieves every id the
// listing reports and requires the retrieval to succeed, so a listing and a
// getter that disagree fail here however they came to disagree.
func TestListTokensSkipsAnIDNoOtherEntryPointAccepts(t *testing.T) {
	defer parallel(t)()

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

			tokens, err := listTokensForTest(path)
			if err != nil {
				t.Fatalf("Tokens failed: %v", err)
			}
			got := make([]int, 0, len(tokens))
			for id := range tokens {
				got = append(got, id)
			}
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("Tokens returned slots %v, want %v", got, tc.want)
			}

			// Every listed id must be retrievable. This is the property, and
			// it is what a count assertion cannot express.
			for _, id := range got {
				_, ok, err := getTokenForTest(path, id)
				if err != nil {
					t.Fatalf("Tokens reported slot %d but getTokenForTest(%d) failed: %v", id, id, err)
				}
				if !ok {
					t.Fatalf("Tokens reported slot %d but Tokens()[%d] returned no token", id, id)
				}
			}

			// The header stays readable either way: an out-of-range token id is
			// tolerated, not grounds to refuse a container. An operator has to
			// be able to inspect a damaged header, which is precisely when they
			// need to.
			if _, _, err := readHeaderForTest(path); err != nil {
				t.Fatalf("the header no longer reads: %v", err)
			}
		})
	}
}
