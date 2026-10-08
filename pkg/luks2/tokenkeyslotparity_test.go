// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// tokenParityPassphrase opens keyslot 0 of the token parity fixture, and
// tokenParitySecond keyslot 1.
const (
	tokenParityPassphrase = "token-parity-slot-0"
	tokenParitySecond     = "token-parity-slot-1"
)

// tokenParityFixture is a cryptsetup volume with keyslots 0 and 1 and two
// tokens imported by cryptsetup: token 0 names keyslot 1 only, token 1 names
// both.
func tokenParityFixture(t *testing.T) string {
	t.Helper()

	image := cryptsetupFormat(t, "token-parity.img", tokenParityPassphrase)
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing")
	second := filepath.Join(dir, "second")
	if err := os.WriteFile(existing, []byte(tokenParityPassphrase), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte(tokenParitySecond), 0o600); err != nil {
		t.Fatal(err)
	}
	args := append(append([]string{"luksAddKey"}, cheapCryptsetupArgs...), "--key-file", existing, image, second)
	if code, out := runCryptsetup(t, "", args...); code != 0 {
		t.Fatalf("cryptsetup luksAddKey exited %d\n%s", code, out)
	}
	for id, token := range map[string]string{
		"0": `{"type":"systemd-recovery","keyslots":["1"]}`,
		"1": `{"type":"x-parity","keyslots":["0","1"]}`,
	} {
		if code, out := runCryptsetup(t, token, "token", "import", "--token-id", id, image); code != 0 {
			t.Fatalf("cryptsetup token import %s exited %d\n%s", id, code, out)
		}
	}
	return image
}

// cryptsetupTokens is the tokens object of the header cryptsetup reads from
// image, as cryptsetup prints it.
func cryptsetupTokens(t *testing.T, image string) map[string]json.RawMessage {
	t.Helper()

	code, out := runCryptsetup(t, "", "luksDump", "--dump-json-metadata", image)
	if code != 0 {
		t.Fatalf("cryptsetup luksDump --dump-json-metadata exited %d\n%s", code, out)
	}
	var metadata struct {
		Tokens map[string]json.RawMessage `json:"tokens"`
	}
	if err := json.Unmarshal([]byte(out[strings.Index(out, "{"):]), &metadata); err != nil {
		t.Fatalf("cryptsetup printed metadata that is not JSON: %v\n%s", err, out)
	}
	return metadata.Tokens
}

// TestKeyslotRemovalUpdatesTokensAsCryptsetupDoes: removing a keyslot removes
// it from every token that names it and KEEPS the token, with an empty
// keyslots array where it named nothing else. That is what cryptsetup 2.7.5's
// luksKillSlot does (LUKS2_keyslot_wipe unassigns the keyslot from every
// token; measured in the integration devcontainer), so every removal path is
// held to cryptsetup's own result on the same header, as cryptsetup prints it.
func TestKeyslotRemovalUpdatesTokensAsCryptsetupDoes(t *testing.T) {
	defer parallel(t)()

	fixture := tokenParityFixture(t)
	golden, err := os.ReadFile(fixture) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	clone := func(name string) string {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, golden, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	reference := clone("cryptsetup.img")
	if code, out := runCryptsetup(t, tokenParityPassphrase, "luksKillSlot", "--batch-mode", reference, "1"); code != 0 {
		t.Fatalf("cryptsetup luksKillSlot exited %d\n%s", code, out)
	}
	want := cryptsetupTokens(t, reference)
	if len(want) != 2 {
		t.Fatalf("cryptsetup kept %d tokens, want both: %s", len(want), want)
	}

	paths := map[string]func(device string) error{
		"KillSlot":    func(d string) error { return killSlotForTest(d, []byte(tokenParityPassphrase), 1) },
		"KillKeyslot": func(d string) error { return killKeyslotForTest(d, 1) },
		"RemoveKey":   func(d string) error { return removeKeyForTest(d, []byte(tokenParitySecond), 1) },
	}
	for name, remove := range paths {
		device := clone(name + ".img")
		if err := remove(device); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		got := cryptsetupTokens(t, device)
		if !reflect.DeepEqual(canonicalTokens(t, got), canonicalTokens(t, want)) {
			t.Errorf("%s left tokens %s; cryptsetup leaves %s", name, got, want)
		}
	}
}

// canonicalTokens decodes each token so two printings compare by value.
func canonicalTokens(t *testing.T, tokens map[string]json.RawMessage) map[string]any {
	t.Helper()
	out := make(map[string]any, len(tokens))
	for id, raw := range tokens {
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("token %s is not JSON: %v", id, err)
		}
		out[id] = v
	}
	return out
}

// TestCryptsetupWritesASHA256HeaderChecksum pins the measurement
// header.HeaderChecksumAlgorithm rests on: the header cryptsetup luksFormat writes
// names sha256 in its csum_alg field, and this package reads it.
func TestCryptsetupWritesASHA256HeaderChecksum(t *testing.T) {
	defer parallel(t)()

	image := cryptsetupFormat(t, "csum-alg.img", tokenParityPassphrase)
	hdr, _, err := readHeaderForTest(image)
	if err != nil {
		t.Fatalf("ReadHeader of a cryptsetup header: %v", err)
	}
	if got := strings.TrimRight(string(hdr.ChecksumAlgorithm[:]), "\x00"); got != header.HeaderChecksumAlgorithm {
		t.Fatalf("cryptsetup wrote csum_alg %q, want %q", got, header.HeaderChecksumAlgorithm)
	}
}
