// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// DefaultLuksOperations is a delegation table, and a delegation table's failure
// mode is a MIS-WIRE: ListTokens calling ListKeyslots, ReadSecondaryHeader
// calling ReadHeader, IsLUKS2 calling IsLUKS. Every one of those compiles, and
// every one of them is invisible to a test that mocks this layer away -- which
// is every other test in this package.
//
// So this drives the real thing against a real container and checks that each
// shim does what its name says. It is not coverage for its own sake: it is the
// only place the wiring is checked at all.
//
// It runs unprivileged on a file image, like the conformance tests in
// pkg/luks2, and it keeps every KDF at the cheapest setting the library
// accepts -- the point is which function was called, not how long a derivation
// takes.

// cheapKeyslot is the KDF configuration every keyslot written here uses.
//
// argon2id at its floor rather than pbkdf2, and that is not arbitrary: ChangeKey
// COPIES an argon2 slot's cost parameters when it rewrites it, while for a
// pbkdf2 slot it recalibrates against the 2000 ms default budget and takes
// several seconds. A unit test cannot afford that, and cost is not what this
// test is about.
func cheapKeyslot() *luks2.AddKeyOptions {
	return &luks2.AddKeyOptions{
		KDFType:        "argon2id",
		Argon2Time:     1,
		Argon2Memory:   65536,
		Argon2Parallel: 1,
	}
}

func TestDefaultOperationsAreWiredToTheRightLibraryCalls(t *testing.T) {
	requireCryptsetupCLI(t)

	dir := t.TempDir()
	const passphrase = "the-original-passphrase"
	image := newLUKSImage(t, writeFile(t, dir, "pw", passphrase))

	ops := &DefaultLuksOperations{}

	t.Run("IsLUKS and IsLUKS2", func(t *testing.T) {
		is, err := ops.IsLUKS(image)
		if err != nil || !is {
			t.Fatalf("IsLUKS() = %v, %v; want true, nil", is, err)
		}
		is, err = ops.IsLUKS2(image)
		if err != nil || !is {
			t.Fatalf("IsLUKS2() = %v, %v; want true, nil", is, err)
		}

		// A file that is not a container answers no, and does not error: "this
		// is not LUKS" is an answer, not a failure.
		plain := writeFile(t, dir, "plain.img", "not a luks container")
		if is, err := ops.IsLUKS(plain); err == nil && is {
			t.Error("IsLUKS() called an ordinary file a LUKS container")
		}
	})

	t.Run("ReadHeader and ReadSecondaryHeader", func(t *testing.T) {
		primary, metadata, err := ops.ReadHeader(image)
		if err != nil {
			t.Fatalf("ReadHeader() error = %v", err)
		}
		if primary.Version != 2 || len(metadata.Keyslots) == 0 {
			t.Fatalf("ReadHeader() returned version %d with %d keyslots", primary.Version, len(metadata.Keyslots))
		}

		secondary, _, err := ops.ReadSecondaryHeader(image)
		if err != nil {
			t.Fatalf("ReadSecondaryHeader() error = %v", err)
		}
		// The two copies describe the same container but are read from
		// different offsets, which is what distinguishes the two calls.
		if secondary.HeaderOffset == primary.HeaderOffset {
			t.Errorf("both header reads came from offset %d; ReadSecondaryHeader is reading the primary copy", primary.HeaderOffset)
		}
	})

	t.Run("TestKey", func(t *testing.T) {
		if err := ops.TestKey(image, []byte(passphrase)); err != nil {
			t.Fatalf("TestKey() rejected the passphrase: %v", err)
		}
		if err := ops.TestKey(image, []byte("not-the-passphrase")); err == nil {
			t.Error("TestKey() accepted a passphrase the container does not hold")
		}
	})

	t.Run("ListKeyslots", func(t *testing.T) {
		slots, err := ops.ListKeyslots(image)
		if err != nil {
			t.Fatalf("ListKeyslots() error = %v", err)
		}
		if len(slots) != 1 || slots[0].ID != 0 {
			t.Fatalf("ListKeyslots() = %+v, want the single slot cryptsetup wrote", slots)
		}
	})

	t.Run("tokens", func(t *testing.T) {
		count, err := ops.CountTokens(image)
		if err != nil || count != 0 {
			t.Fatalf("CountTokens() = %d, %v; want 0, nil", count, err)
		}

		free, err := ops.FindFreeTokenSlot(image)
		if err != nil || free != 0 {
			t.Fatalf("FindFreeTokenSlot() = %d, %v; want 0, nil", free, err)
		}

		exists, err := ops.TokenExists(image, 0)
		if err != nil || exists {
			t.Fatalf("TokenExists(0) = %v, %v; want false, nil", exists, err)
		}

		document := []byte(`{"type":"systemd-fido2","keyslots":["0"],"fido2-rp":"io.systemd.cryptsetup"}`)
		if err := ops.ImportTokenJSON(image, 0, document); err != nil {
			t.Fatalf("ImportTokenJSON() error = %v", err)
		}

		token, err := ops.GetToken(image, 0)
		if err != nil {
			t.Fatalf("GetToken() error = %v", err)
		}
		if token.Type != "systemd-fido2" {
			t.Errorf("GetToken() returned type %q", token.Type)
		}

		// ImportToken takes the struct, ImportTokenJSON the document. Both are
		// exercised, because the CLI reaches the first through the second.
		if err := ops.ImportToken(image, 1, token); err != nil {
			t.Fatalf("ImportToken() error = %v", err)
		}

		exported, err := ops.ExportToken(image, 1)
		if err != nil {
			t.Fatalf("ExportToken() error = %v", err)
		}
		var round luks2.Token
		if err := json.Unmarshal(exported, &round); err != nil {
			t.Fatalf("ExportToken() did not produce JSON: %v", err)
		}
		if round.Type != "systemd-fido2" {
			t.Errorf("ExportToken() returned type %q", round.Type)
		}

		tokens, err := ops.ListTokens(image)
		if err != nil {
			t.Fatalf("ListTokens() error = %v", err)
		}
		if len(tokens) != 2 {
			t.Errorf("ListTokens() returned %d tokens, want 2", len(tokens))
		}

		for _, id := range []int{0, 1} {
			if err := ops.RemoveToken(image, id); err != nil {
				t.Fatalf("RemoveToken(%d) error = %v", id, err)
			}
		}
		if count, err := ops.CountTokens(image); err != nil || count != 0 {
			t.Fatalf("CountTokens() after removal = %d, %v; want 0, nil", count, err)
		}
	})

	t.Run("AddKey, ChangeKey and RemoveKey", func(t *testing.T) {
		if _, err := ops.AddKey(image, []byte(passphrase), []byte("the-second-passphrase"), cheapKeyslot()); err != nil {
			t.Fatalf("AddKey() error = %v", err)
		}

		slots, err := ops.ListKeyslots(image)
		if err != nil {
			t.Fatalf("ListKeyslots() error = %v", err)
		}
		if len(slots) != 2 {
			t.Fatalf("after AddKey there are %d keyslots, want 2", len(slots))
		}
		added := slots[1].ID

		if err := ops.ChangeKey(image, []byte("the-second-passphrase"), []byte("the-third-passphrase"), added); err != nil {
			t.Fatalf("ChangeKey() error = %v", err)
		}
		if err := ops.TestKey(image, []byte("the-third-passphrase")); err != nil {
			t.Fatalf("the changed passphrase does not open the volume: %v", err)
		}

		if err := ops.RemoveKey(image, []byte("the-third-passphrase"), added); err != nil {
			t.Fatalf("RemoveKey() error = %v", err)
		}
		if err := ops.TestKey(image, []byte("the-third-passphrase")); err == nil {
			t.Error("the removed passphrase still opens the volume")
		}
	})

	t.Run("KillSlot", func(t *testing.T) {
		if _, err := ops.AddKey(image, []byte(passphrase), []byte("a-doomed-passphrase"), cheapKeyslot()); err != nil {
			t.Fatalf("AddKey() error = %v", err)
		}

		slots, err := ops.ListKeyslots(image)
		if err != nil {
			t.Fatalf("ListKeyslots() error = %v", err)
		}
		doomed := slots[len(slots)-1].ID

		// The distinguishing property of KillSlot: it authenticates with a
		// DIFFERENT credential than the one in the slot it removes.
		if err := ops.KillSlot(image, []byte(passphrase), doomed); err != nil {
			t.Fatalf("KillSlot() error = %v", err)
		}
		if err := ops.TestKey(image, []byte("a-doomed-passphrase")); err == nil {
			t.Error("the killed credential still opens the volume")
		}
	})

	t.Run("recovery keys", func(t *testing.T) {
		key, err := ops.GenerateRecoveryKey(luks2.RecoveryKeyLength, luks2.RecoveryKeyFormatDashed)
		if err != nil {
			t.Fatalf("GenerateRecoveryKey() error = %v", err)
		}
		defer key.Clear()

		saved := filepath.Join(dir, "generated.txt")
		if err := ops.SaveRecoveryKey(key, saved); err != nil {
			t.Fatalf("SaveRecoveryKey() error = %v", err)
		}
		if _, err := os.Stat(saved); err != nil {
			t.Fatalf("SaveRecoveryKey() wrote nothing: %v", err)
		}

		loaded, err := ops.LoadRecoveryCredential(saved)
		if err != nil {
			t.Fatalf("LoadRecoveryCredential() error = %v", err)
		}
		defer mustDestroy(t, loaded)

		formatted, err := key.FormattedString()
		if err != nil {
			t.Fatalf("FormattedString() error = %v", err)
		}
		typed, err := ops.RecoveryCredential(formatted)
		if err != nil {
			t.Fatalf("RecoveryCredential() error = %v", err)
		}
		defer mustDestroy(t, typed)

		// The saved file and the displayed string are two routes to the same
		// credential. If they ever disagree, one of the two commands that use
		// them is handing the volume something it will refuse.
		if !typed.EqualTo(mustOpen(t, loaded)) {
			t.Error("LoadRecoveryCredential and RecoveryCredential produced different credentials for the same recovery key")
		}
		// And both are the printed text itself, not a decoding of it.
		if string(mustOpen(t, typed)) != formatted {
			t.Errorf("RecoveryCredential() = %q, want the printed text %q", mustOpen(t, typed), formatted)
		}

		// This one is NOT enrolled, so the volume must say no.
		valid, err := ops.VerifyRecoveryKey(image, typed)
		if err != nil {
			t.Fatalf("VerifyRecoveryKey() error = %v", err)
		}
		if valid {
			t.Error("VerifyRecoveryKey() accepted a key that was never added to the volume")
		}

		// And an enrolled one must say yes.
		enrolled, err := ops.AddRecoveryKey(image, []byte(passphrase), &luks2.RecoveryKeyOptions{
			Format:         luks2.RecoveryKeyFormatDashed,
			Argon2Time:     1,
			Argon2Memory:   65536,
			Argon2Parallel: 1,
		})
		if err != nil {
			t.Fatalf("AddRecoveryKey() error = %v", err)
		}
		defer enrolled.Clear()

		if enrolled.TokenID < 0 {
			t.Error("AddRecoveryKey() wrote no token; nothing on the device says the slot is a recovery key")
		} else {
			token, err := ops.GetToken(image, enrolled.TokenID)
			if err != nil {
				t.Fatalf("GetToken(%d) error = %v", enrolled.TokenID, err)
			}
			if token.Type != "systemd-recovery" {
				t.Errorf("token type = %q, want systemd-recovery", token.Type)
			}
			if len(token.Keyslots) != 1 || token.Keyslots[0] != strconv.Itoa(enrolled.Keyslot) {
				t.Errorf("token keyslots = %v, want [%d]", token.Keyslots, enrolled.Keyslot)
			}
		}

		valid, err = ops.VerifyRecoveryKey(image, enrolled.Credential)
		if err != nil {
			t.Fatalf("VerifyRecoveryKey() error = %v", err)
		}
		if !valid {
			t.Error("VerifyRecoveryKey() refused the key AddRecoveryKey had just enrolled")
		}
	})

	t.Run("RestorePrimaryHeader", func(t *testing.T) {
		if err := ops.RestorePrimaryHeader(image); err != nil {
			t.Fatalf("RestorePrimaryHeader() error = %v", err)
		}
		// The container still opens afterwards, which is the only thing that
		// makes a header restore worth doing.
		if err := ops.TestKey(image, []byte(passphrase)); err != nil {
			t.Fatalf("the volume no longer opens after a header restore: %v", err)
		}
	})
}

// mustOpen copies an enclave's bytes out for comparison. Test-only.
func mustOpen(t *testing.T, e interface {
	WithBytes(func([]byte) error) error
}) []byte {
	t.Helper()

	var out []byte
	if err := e.WithBytes(func(b []byte) error {
		out = append([]byte(nil), b...)
		return nil
	}); err != nil {
		t.Fatalf("could not read an enclave: %v", err)
	}
	return out
}

// TestDefaultFileSystemOpen covers the seam the key-file path goes through.
func TestDefaultFileSystemOpen(t *testing.T) {
	fs := &DefaultFileSystem{}
	path := writeFile(t, t.TempDir(), "key", "content")

	f, err := fs.Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = f.Close() }()

	got, err := readKeyFile(f, path)
	if err != nil {
		t.Fatalf("readKeyFile() error = %v", err)
	}
	if string(got) != "content" {
		t.Errorf("read %q, want %q", got, "content")
	}

	if _, err := fs.Open(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("Open() succeeded on a file that does not exist")
	}
}
