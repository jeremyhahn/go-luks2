// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// LUKS2 conformance against the cryptsetup userspace tools, in both directions, unprivileged on file images.

const (
	// conformancePassphrase is the passphrase used on both sides of every
	// bidirectional test.
	conformancePassphrase = "conformance-test-passphrase"

	// conformanceWrongPassphrase must be rejected by both sides.
	conformanceWrongPassphrase = "not-the-conformance-passphrase"

	// conformanceImageSize is comfortably larger than the 16 MiB metadata +
	// keyslots area this library reserves, so a data segment exists.
	conformanceImageSize = 64 << 20
)

// requireCryptsetup fails the calling test when the cryptsetup binary is not installed.
func requireCryptsetup(t *testing.T) string {
	t.Helper()

	path, err := exec.LookPath("cryptsetup")
	if err != nil {
		// Fail, do not skip: a skip would turn a missing cryptsetup into a green result; the test images install cryptsetup-bin.
		t.Fatalf("LUKS2 CONFORMANCE CHECK CANNOT RUN -- cryptsetup is NOT INSTALLED on this host (%v). "+
			"This test verifies interoperability with a third-party LUKS2 implementation and there is "+
			"nothing it can verify without one. Install cryptsetup (Debian/Ubuntu: cryptsetup-bin); the "+
			"devcontainer and the integration image already carry it.", err)
	}
	return path
}

// runCryptsetup runs cryptsetup with the given passphrase on stdin and returns
// its exit code together with its combined output.
func runCryptsetup(t *testing.T, passphrase string, args ...string) (int, string) {
	t.Helper()

	cmd := exec.Command("cryptsetup", args...) // #nosec G204 -- arguments are test constants
	if passphrase != "" {
		cmd.Stdin = strings.NewReader(passphrase)
	}
	out, err := cmd.CombinedOutput()

	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, string(out)
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), string(out)
	default:
		t.Fatalf("failed to run cryptsetup %v: %v", args, err)
		return -1, ""
	}
}

// newImage creates a sparse image file of the standard conformance size.
func newImage(t *testing.T, name string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	f, err := os.Create(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to create image %s: %v", path, err)
	}
	if err := f.Truncate(conformanceImageSize); err != nil {
		_ = f.Close()
		t.Fatalf("failed to size image %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close image %s: %v", path, err)
	}
	return path
}

// standardFormatOptions is the one configuration 51 call sites format with. It
// is a function rather than a var so no test can mutate the shared value.
func standardFormatOptions(path string) formatOptionsForTest {
	return formatOptionsForTest{
		Device:        path,
		Passphrase:    []byte(conformancePassphrase),
		Cipher:        "aes",
		CipherMode:    "xts-plain64",
		KeySize:       512,
		HashAlgo:      "sha512",
		SectorSize:    512,
		KDFType:       kdfTypePBKDF2,
		PBKDFIterTime: 1, // keep the keyslot KDF cheap
	}
}

// formatWithLibrary formats the pinned configuration once per process and stamps the bytes for each caller; the error is carried out of the sync.Once.
func formatWithLibrary(t *testing.T, path string) {
	t.Helper()

	goldenStandardOnce.Do(func() {
		dir, err := os.MkdirTemp("", "luks2-golden-*")
		if err != nil {
			goldenStandardErr = err
			return
		}
		defer func() { _ = os.RemoveAll(dir) }()

		seed := filepath.Join(dir, "golden.img")
		f, err := os.Create(seed) // #nosec G304 -- path is under a temp dir this function made
		if err != nil {
			goldenStandardErr = err
			return
		}
		if err := f.Truncate(conformanceImageSize); err != nil {
			_ = f.Close()
			goldenStandardErr = err
			return
		}
		if err := f.Close(); err != nil {
			goldenStandardErr = err
			return
		}
		if err := formatForTest(standardFormatOptions(seed)); err != nil {
			goldenStandardErr = err
			return
		}
		if err := cheapenGoldenDigests(seed); err != nil {
			goldenStandardErr = err
			return
		}
		goldenStandardBytes, goldenStandardErr = readImagePrefix(seed)
	})

	if goldenStandardErr != nil {
		t.Fatalf("Format failed while building the shared golden container: %v", goldenStandardErr)
	}
	stampImagePrefix(t, path, goldenStandardBytes)
}

var (
	goldenStandardOnce  sync.Once
	goldenStandardBytes []byte
	goldenStandardErr   error
)

// goldenPrefixBytes is how much of a formatted image is stamped: the header copies and keyslot 0, not the full keyslots-area fill.
const goldenPrefixBytes = 2 << 20

func readImagePrefix(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- test fixture path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, goldenPrefixBytes)
	if _, err := f.ReadAt(buf, 0); err != nil {
		return nil, err
	}
	return buf, nil
}

func stampImagePrefix(t *testing.T, path string, golden []byte) {
	t.Helper()

	f, err := os.OpenFile(path, os.O_RDWR, 0600) // #nosec G304 -- test fixture path
	if err != nil {
		t.Fatalf("failed to open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }() // failure paths only: success closes, checked, below

	if _, err := f.WriteAt(golden, 0); err != nil {
		t.Fatalf("failed to stamp the golden container onto %s: %v", path, err)
	}
	// Closed, not fsynced: the page cache is coherent for every reader of a temp fixture.
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close %s: %v", path, err)
	}
}

// TestConformance_WeWrite_CryptsetupReads: a container this library writes must be a valid LUKS2 device to cryptsetup.
func TestConformance_WeWrite_CryptsetupReads(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	path := newImage(t, "we-write.img")
	formatWithLibrary(t, path)

	t.Run("isLuks accepts it", func(t *testing.T) {
		code, out := runCryptsetup(t, "", "isLuks", path)
		if code != 0 {
			t.Fatalf("cryptsetup isLuks exited %d, want 0\n%s", code, out)
		}
	})

	t.Run("luksDump renders it", func(t *testing.T) {
		code, out := runCryptsetup(t, "", "luksDump", path)
		if code != 0 {
			t.Fatalf("cryptsetup luksDump exited %d, want 0\n%s", code, out)
		}

		// Assert on what cryptsetup parsed: keyslots_size is the area's size, not its end offset.
		for _, want := range []string{
			"Version:       \t2",
			"Keyslots area: \t16744448 [bytes]",
			"offset: 16777216 [bytes]",
			"cipher: aes-xts-plain64",
			"Tokens:",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("luksDump output is missing %q\n%s", want, out)
			}
		}
	})

	t.Run("luksOpen accepts the correct passphrase", func(t *testing.T) {
		code, out := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", path)
		if code != 0 {
			t.Fatalf("cryptsetup luksOpen --test-passphrase exited %d for the CORRECT passphrase, want 0\n%s", code, out)
		}
	})

	t.Run("luksOpen rejects a wrong passphrase", func(t *testing.T) {
		code, out := runCryptsetup(t, conformanceWrongPassphrase, "luksOpen", "--test-passphrase", path)
		if code == 0 {
			t.Fatalf("cryptsetup luksOpen --test-passphrase exited 0 for a WRONG passphrase\n%s", out)
		}
	})

	t.Run("luksHeaderBackup succeeds", func(t *testing.T) {
		backup := filepath.Join(t.TempDir(), "header.bin")
		code, out := runCryptsetup(t, "", "luksHeaderBackup", path, "--header-backup-file", backup)
		if code != 0 {
			t.Fatalf("cryptsetup luksHeaderBackup exited %d, want 0\n%s", code, out)
		}
		if _, err := os.Stat(backup); err != nil {
			t.Fatalf("luksHeaderBackup reported success but wrote no file: %v", err)
		}
	})
}

// TestConformance_SecondaryHeaderMagic: with the primary destroyed, a secondary with the SKUL magic still opens.
func TestConformance_SecondaryHeaderMagic(t *testing.T) {
	requireCryptsetup(t)

	path := newImage(t, "secondary.img")
	formatWithLibrary(t, path)

	t.Run("on-disk magic is SKUL, not LUKS", func(t *testing.T) {
		f, err := os.Open(path) // #nosec G304 -- path is under t.TempDir()
		if err != nil {
			t.Fatalf("failed to open image: %v", err)
		}
		defer func() { _ = f.Close() }()

		magic := make([]byte, header.MagicLen)
		if _, err := f.ReadAt(magic, header.SecondaryHeaderOffset); err != nil {
			t.Fatalf("failed to read secondary magic: %v", err)
		}
		if !bytes.Equal(magic, []byte(header.SecondaryMagic)) {
			t.Fatalf("secondary header magic = %q, want %q", magic, header.SecondaryMagic)
		}
	})

	t.Run("this library can read back its own secondary header", func(t *testing.T) {
		hdr, metadata, err := readSecondaryHeaderForTest(path)
		if err != nil {
			t.Fatalf("ReadSecondaryHeader failed: %v", err)
		}
		if hdr.HeaderOffset != uint64(header.SecondaryHeaderOffset) {
			t.Errorf("secondary hdr.HeaderOffset = %d, want %d", hdr.HeaderOffset, header.SecondaryHeaderOffset)
		}
		if metadata.Config == nil || metadata.Config.KeyslotsSize == "" {
			t.Error("secondary header carries no usable config")
		}
	})

	t.Run("cryptsetup recovers a destroyed primary from it", func(t *testing.T) {
		// Zero the whole primary header area (16 KiB), leaving only the
		// secondary copy. This is the failure the second copy exists for.
		f, err := os.OpenFile(path, os.O_RDWR, 0600) // #nosec G304 -- path is under t.TempDir()
		if err != nil {
			t.Fatalf("failed to open image: %v", err)
		}
		if _, err := f.WriteAt(make([]byte, header.SecondaryHeaderOffset), 0); err != nil {
			_ = f.Close()
			t.Fatalf("failed to destroy primary header: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("failed to close image: %v", err)
		}

		// Read-only, so cryptsetup cannot silently repair the image and turn a
		// recovery test into a no-op.
		if err := os.Chmod(path, 0400); err != nil {
			t.Fatalf("failed to make image read-only: %v", err)
		}

		code, out := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", path)
		if code != 0 {
			t.Fatalf("with the primary header destroyed, cryptsetup luksOpen --test-passphrase exited %d, want 0"+
				" -- the secondary header is not serving as a backup\n%s", code, out)
		}
	})
}

// TestConformance_CryptsetupWrites_WeRead: a cryptsetup container with the pinned parameters (sha512 digest) opens with this library.
func TestConformance_CryptsetupWrites_WeRead(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	path := newImage(t, "they-write.img")

	code, out := runCryptsetup(t, conformancePassphrase,
		"luksFormat", "--type", "luks2",
		"--pbkdf", "pbkdf2",
		"--hash", "sha512",
		"--cipher", "aes-xts-plain64",
		"--key-size", "512",
		"--pbkdf-force-iterations", "1000", // keep the test fast
		"--batch-mode", path)
	if code != 0 {
		t.Fatalf("cryptsetup luksFormat exited %d, want 0\n%s", code, out)
	}

	t.Run("the header parses and stores a sha512-length digest", func(t *testing.T) {
		_, metadata, err := readHeaderForTest(path)
		if err != nil {
			t.Fatalf("ReadHeader failed on a cryptsetup-written container: %v", err)
		}
		if len(metadata.Digests) == 0 {
			t.Fatal("no digests in a cryptsetup-written header")
		}
		for id, digest := range metadata.Digests {
			raw, err := decodeBase64(digest.Digest)
			if err != nil {
				t.Fatalf("digest %s is not valid base64: %v", id, err)
			}
			wantLen, err := hashOutputLen(digest.Hash)
			if err != nil {
				t.Fatalf("digest %s declares an unknown hash %q: %v", id, digest.Hash, err)
			}
			if len(raw) != wantLen {
				t.Errorf("digest %s declares hash %s but stores %d bytes, want %d",
					id, digest.Hash, len(raw), wantLen)
			}
		}
	})

	t.Run("TestKey accepts the correct passphrase", func(t *testing.T) {
		if err := testKeyForTest(path, []byte(conformancePassphrase)); err != nil {
			t.Fatalf("TestKey rejected the CORRECT passphrase on a cryptsetup-written volume: %v", err)
		}
	})

	t.Run("TestKey rejects a wrong passphrase", func(t *testing.T) {
		if err := testKeyForTest(path, []byte(conformanceWrongPassphrase)); err == nil {
			t.Fatal("TestKey accepted a WRONG passphrase on a cryptsetup-written volume")
		}
	})
}

// TestConformance_CryptsetupMultiKeyslotDigestAssociation: cryptsetup registers both keyslots on one digest, and both passphrases open.
func TestConformance_CryptsetupMultiKeyslotDigestAssociation(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	const second = "the-second-conformance-passphrase"

	path := newImage(t, "two-keyslots.img")

	code, out := runCryptsetup(t, conformancePassphrase,
		"luksFormat", "--type", "luks2",
		"--pbkdf", "pbkdf2",
		"--pbkdf-force-iterations", "1000",
		"--batch-mode", path)
	if code != 0 {
		t.Fatalf("cryptsetup luksFormat exited %d, want 0\n%s", code, out)
	}

	// luksAddKey reads the existing passphrase then the new one, both on stdin.
	code, out = runCryptsetup(t, conformancePassphrase+"\n"+second+"\n",
		"luksAddKey", "--pbkdf", "pbkdf2",
		"--pbkdf-force-iterations", "1000",
		"--batch-mode", path)
	if code != 0 {
		t.Fatalf("cryptsetup luksAddKey exited %d, want 0\n%s", code, out)
	}

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed on a cryptsetup-written container: %v", err)
	}

	// The fixture is only meaningful if cryptsetup really wrote two keyslots
	// and really associated both with a digest. Without this the test would go
	// vacuous the moment luksAddKey silently failed.
	if len(metadata.Keyslots) != 2 {
		t.Fatalf("cryptsetup wrote %d keyslots, want 2", len(metadata.Keyslots))
	}
	associated := make(map[string]bool)
	for id, digest := range metadata.Digests {
		t.Logf("digest %s authenticates keyslots %v", id, digest.Keyslots)
		for _, ks := range digest.Keyslots {
			associated[ks] = true
		}
	}
	for id := range metadata.Keyslots {
		if !associated[id] {
			t.Fatalf("cryptsetup left keyslot %s associated with no digest; "+
				"the strict association would lock it out and this fixture cannot show otherwise", id)
		}
	}

	for _, passphrase := range []string{conformancePassphrase, second} {
		if err := testKeyForTest(path, []byte(passphrase)); err != nil {
			t.Fatalf("a cryptsetup-written keyslot no longer opens under the digest association rule: %v", err)
		}
	}

	if err := testKeyForTest(path, []byte(conformanceWrongPassphrase)); err == nil {
		t.Fatal("TestKey accepted a WRONG passphrase on a two-keyslot cryptsetup container")
	}
}

// TestConformance_StaysValidAfterMutation checks header-rewriting operations leave a container cryptsetup accepts.
func TestConformance_StaysValidAfterMutation(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	const secondPassphrase = "conformance-second-passphrase"

	assertStillValid := func(t *testing.T, path, stage string, passphrases ...string) {
		t.Helper()

		if code, out := runCryptsetup(t, "", "isLuks", path); code != 0 {
			t.Fatalf("after %s, cryptsetup isLuks exited %d, want 0\n%s", stage, code, out)
		}
		code, out := runCryptsetup(t, "", "luksDump", path)
		if code != 0 {
			t.Fatalf("after %s, cryptsetup luksDump exited %d, want 0\n%s", stage, code, out)
		}

		// The reserved keyslots area must not move; cryptsetup accepts a keyslots_size that is merely too small.
		const wantKeyslotsArea = "Keyslots area: \t16744448 [bytes]"
		if !strings.Contains(out, wantKeyslotsArea) {
			t.Fatalf("after %s, luksDump no longer reports %q\n%s", stage, wantKeyslotsArea, out)
		}
		for _, passphrase := range passphrases {
			code, out := runCryptsetup(t, passphrase, "luksOpen", "--test-passphrase", path)
			if code != 0 {
				t.Fatalf("after %s, cryptsetup rejected passphrase %q (exit %d)\n%s", stage, passphrase, code, out)
			}
		}
	}

	t.Run("after AddKey", func(t *testing.T) {
		path := newImage(t, "after-addkey.img")
		formatWithLibrary(t, path)
		assertStillValid(t, path, "Format", conformancePassphrase)

		if _, err := addKeyForTest(path, []byte(conformancePassphrase), []byte(secondPassphrase), &addKeyOptionsForTest{
			KDFType:       kdfTypePBKDF2,
			Hash:          "sha256",
			PBKDFIterTime: 1,
		}); err != nil {
			t.Fatalf("AddKey failed: %v", err)
		}

		assertStillValid(t, path, "AddKey", conformancePassphrase, secondPassphrase)

		// Both passphrases must still work through this library too, so the
		// check is not one-sided.
		for _, passphrase := range []string{conformancePassphrase, secondPassphrase} {
			if err := testKeyForTest(path, []byte(passphrase)); err != nil {
				t.Errorf("after AddKey, TestKey rejected %q: %v", passphrase, err)
			}
		}
	})

	// ChangeKey relocates the keyslot; cryptsetup must still open it.
	t.Run("after ChangeKey relocates a keyslot", func(t *testing.T) {
		path := newImage(t, "after-changekey.img")
		formatWithLibrary(t, path)
		assertStillValid(t, path, "Format", conformancePassphrase)

		_, before, err := readHeaderForTest(path)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}
		originalOffset := before.Keyslots["0"].Area.Offset

		if err := changeKeyForTest(path, []byte(conformancePassphrase), []byte(secondPassphrase), 0); err != nil {
			t.Fatalf("ChangeKey failed: %v", err)
		}

		_, after, err := readHeaderForTest(path)
		if err != nil {
			t.Fatalf("ReadHeader after ChangeKey failed: %v", err)
		}
		if after.Keyslots["0"].Area.Offset == originalOffset {
			t.Fatalf("the keyslot did not move, so this case is not exercising the relocation it exists for")
		}

		// The new credential only: the old one is retired, and cryptsetup
		// refusing it is the point.
		assertStillValid(t, path, "ChangeKey", secondPassphrase)
		if code, out := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", path); code == 0 {
			t.Fatalf("after ChangeKey, cryptsetup still accepts the retired passphrase\n%s", out)
		}
		if err := testKeyForTest(path, []byte(secondPassphrase)); err != nil {
			t.Errorf("after ChangeKey, TestKey rejected the new passphrase: %v", err)
		}
	})

	// A removal clears the keyslot id from tokens too; cryptsetup accepts an empty keyslots list on a token.
	t.Run("after removing a keyslot a token names", func(t *testing.T) {
		path := newImage(t, "after-keyslot-with-token.img")
		formatWithLibrary(t, path)

		if _, err := addKeyForTest(path, []byte(conformancePassphrase), []byte(secondPassphrase), &addKeyOptionsForTest{
			KDFType:       kdfTypePBKDF2,
			Hash:          "sha256",
			PBKDFIterTime: 1,
		}); err != nil {
			t.Fatalf("AddKey failed: %v", err)
		}
		if err := setTokenForTest(path, 0, Token{Type: "systemd-tpm2", Keyslots: []int{1}}); err != nil {
			t.Fatalf("SetToken failed: %v", err)
		}
		assertStillValid(t, path, "SetToken", conformancePassphrase, secondPassphrase)

		if err := killKeyslotForTest(path, 1); err != nil {
			t.Fatalf("KillKeyslot failed: %v", err)
		}
		assertStillValid(t, path, "KillKeyslot", conformancePassphrase)

		_, metadata, err := readHeaderForTest(path)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}
		for id, token := range metadata.Tokens {
			for _, named := range token.Keyslots {
				if named == "1" {
					t.Fatalf("token %s still names keyslot 1 after it was destroyed", id)
				}
			}
		}
	})

	t.Run("after importing and removing the last token", func(t *testing.T) {
		path := newImage(t, "after-token.img")
		formatWithLibrary(t, path)

		if err := setTokenForTest(path, 0, Token{Type: "systemd-tpm2", Keyslots: []int{0}}); err != nil {
			t.Fatalf("SetToken failed: %v", err)
		}
		assertStillValid(t, path, "SetToken", conformancePassphrase)

		if err := removeTokenForTest(path, 0); err != nil {
			t.Fatalf("RemoveToken failed: %v", err)
		}
		assertStillValid(t, path, "RemoveToken", conformancePassphrase)
	})
}

// TestConformance_LargeHeaderStaysValid: a header whose JSON exceeds 8192 bytes must still be a LUKS2 container to cryptsetup; keyslots are synthetic and non-overlapping.
func TestConformance_LargeHeaderStaysValid(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	const keyslots = 16

	path := newImage(t, "large-header.img")
	formatWithLibrary(t, path)

	hdr, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	padKeyslots(t, metadata, keyslots)
	if err := writeHeaderInternal(path, hdr, metadata); err != nil {
		t.Fatalf("writeHeaderInternal refused a %d-keyslot header that fits: %v", keyslots, err)
	}

	code, out := runCryptsetup(t, "", "luksDump", path)
	if code != 0 {
		t.Fatalf("cryptsetup luksDump exited %d on a %d-keyslot header, want 0\n%s", code, keyslots, out)
	}

	// The metadata area must still be the legal 16 KiB. The old code wrote
	// 20480 here, which is what made the container non-conformant even before
	// the backup header overwrote the primary's JSON.
	if want := "Metadata area: \t16384 [bytes]"; !strings.Contains(out, want) {
		t.Errorf("luksDump does not report %q\n%s", want, out)
	}

	// cryptsetup must see every keyslot, which it can only do if the JSON
	// survived intact.
	for i := 0; i < keyslots; i++ {
		if want := fmt.Sprintf("\n  %d: luks2", i); !strings.Contains(out, want) {
			t.Errorf("luksDump does not list keyslot %d\n%s", i, out)
		}
	}

	if code, out := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", path); code != 0 {
		t.Fatalf("cryptsetup rejected the correct passphrase on a %d-keyslot header (exit %d)\n%s",
			keyslots, code, out)
	}
}

// TestConformance_LegacyDigestLengthStillOpens: a 32-byte digest under a sha512 label still opens, since the read derives to the stored length.
func TestConformance_LegacyDigestLengthStillOpens(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "legacy-digest.img")
	formatWithLibrary(t, path)

	hdr, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	masterKey, err := getMasterKey(path, []byte(conformancePassphrase), metadata, testVolumeSys())
	if err != nil {
		t.Fatalf("failed to recover the master key: %v", err)
	}
	defer mustDestroy(t, masterKey)

	digest, ok := metadata.Digests["0"]
	if !ok {
		t.Fatal("digest 0 missing")
	}
	if digest.Hash != "sha512" {
		t.Fatalf("fixture precondition: digest hash = %q, want sha512", digest.Hash)
	}

	// Re-derive at the OLD hardcoded length of 32 bytes, leaving the "sha512"
	// label in place -- the exact inconsistency the old code wrote to disk.
	legacy, err := deriveKeySecret(context.Background(), masterKey, &header.KDF{
		Type:       digest.Type,
		Hash:       digest.Hash,
		Salt:       digest.Salt,
		Iterations: &digest.Iterations,
	}, 32, testVolumeSys())
	if err != nil {
		t.Fatalf("failed to derive the legacy digest: %v", err)
	}
	defer mustDestroy(t, legacy)

	if err := legacy.WithBytes(func(b []byte) error {
		digest.Digest = encodeBase64(b)
		return nil
	}); err != nil {
		t.Fatalf("failed to read the legacy digest back: %v", err)
	}
	if err := writeHeaderInternal(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the legacy fixture header: %v", err)
	}

	// Confirm the fixture really is a legacy one before asserting on it.
	_, reread, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed on the legacy fixture: %v", err)
	}
	raw, err := decodeBase64(reread.Digests["0"].Digest)
	if err != nil {
		t.Fatalf("legacy fixture digest is not valid base64: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("legacy fixture stores a %d-byte digest, want 32", len(raw))
	}

	if err := testKeyForTest(path, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("a container written by the OLD code (32-byte digest labeled sha512) no longer opens: %v", err)
	}
	if err := testKeyForTest(path, []byte(conformanceWrongPassphrase)); err == nil {
		t.Fatal("the legacy fixture accepted a WRONG passphrase")
	}
}

// TestConformance_MandatoryJSONObjectsArePresent checks the mandatory LUKS2 objects directly, without cryptsetup.
func TestConformance_MandatoryJSONObjectsArePresent(t *testing.T) {
	path := newImage(t, "mandatory-objects.img")
	formatWithLibrary(t, path)

	f, err := os.Open(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open image: %v", err)
	}
	defer func() { _ = f.Close() }()

	for _, hdrOffset := range []int64{header.PrimaryHeaderOffset, header.SecondaryHeaderOffset} {
		raw := make([]byte, header.DefaultSize)
		if _, err := f.ReadAt(raw, hdrOffset+header.HeaderSize); err != nil {
			t.Fatalf("failed to read the JSON area at offset %d: %v", hdrOffset, err)
		}
		if i := bytes.IndexByte(raw, 0); i != -1 {
			raw = raw[:i]
		}

		// Each is mandatory in LUKS2 and must be an object; an empty one is {}.
		for _, key := range []string{"keyslots", "tokens", "segments", "digests", "config"} {
			if !bytes.Contains(raw, []byte(`"`+key+`":`)) {
				t.Errorf("header at offset %d omits the mandatory %q object:\n%s", hdrOffset, key, raw)
			}
			if bytes.Contains(raw, []byte(`"`+key+`": null`)) {
				t.Errorf("header at offset %d writes %q as null, which is not an object", hdrOffset, key)
			}
		}
	}
}

// TestEnsureRequiredObjects checks the normalization that keeps a nil Go map from reaching the disk as `null`.
// cheapenGoldenDigests rewrites the shared golden's digests to a low iteration count, re-derived from its own master key so they still verify.
func cheapenGoldenDigests(device string) (err error) {
	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		return err
	}

	masterKey, err := getMasterKey(device, []byte(conformancePassphrase), metadata, testVolumeSys())
	if err != nil {
		return fmt.Errorf("the golden container does not open: %w", err)
	}
	// No *testing.T here, so the release report joins this helper's error:
	// a refused teardown fails the caller's setup rather than vanishing.
	defer func() {
		if derr := masterKey.Destroy(); derr != nil {
			err = errors.Join(err, fmt.Errorf("releasing the golden master key: %w", derr))
		}
	}()

	const cheapIterations = 1000
	for _, digest := range metadata.Digests {
		iterations := cheapIterations
		kdf := &header.KDF{Type: digest.Type, Hash: digest.Hash, Salt: digest.Salt, Iterations: &iterations}

		// Derived exactly as verifyMasterKey will re-derive it, to the length
		// already stored, so the rewritten digest verifies by the route
		// production takes rather than one this helper invented.
		expected, err := decodeBase64(digest.Digest)
		if err != nil {
			return err
		}
		derived, err := deriveKeySecret(context.Background(), masterKey, kdf, len(expected), testVolumeSys())
		if err != nil {
			return err
		}
		err = secret.Borrow("golden digest", derived, func(b []byte) error {
			digest.Digest = encodeBase64(b)
			return nil
		})
		if derr := derived.Destroy(); derr != nil {
			err = errors.Join(err, fmt.Errorf("releasing a golden digest key: %w", derr))
		}
		if err != nil {
			return err
		}
		digest.Iterations = cheapIterations
	}

	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		return err
	}

	// The golden must still open.
	if err := testKeyForTest(device, []byte(conformancePassphrase)); err != nil {
		return fmt.Errorf("the golden container stopped opening after its digests were cheapened: %w", err)
	}
	return nil
}
