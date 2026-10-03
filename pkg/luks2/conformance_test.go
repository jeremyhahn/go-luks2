// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// LUKS2 conformance tests, asserted against the cryptsetup userspace tools.
//
// WHY THESE TESTS EXIST AND WHY THEY LOOK LIKE THIS
//
// A round trip through this package alone is not evidence of conformance.
// Format and Unlock share every assumption they make about the on-disk format,
// so they agree with each other whether or not either agrees with LUKS2. That
// is exactly how #28 and #73 survived a green suite: a container this library
// wrote could not be read by cryptsetup at all -- `cryptsetup isLuks` exited 1
// and luksDump reported "is not a valid LUKS device", so luksDump,
// luksHeaderBackup, luksChangeKey and luksOpen were all unavailable and a
// volume had no recovery path -- while every self-round-trip test passed.
//
// So these tests assert against a THIRD PARTY. cryptsetup writes the container
// and this package reads it, or this package writes and cryptsetup reads.
// Nothing here is allowed to be verified only by this package's own output.
//
// All of this runs UNPRIVILEGED: LUKS2 header handling on a file image needs no
// root. Only dm activation does, which is why the "we -> them" direction stops
// at `luksOpen --test-passphrase` -- that verifies the passphrase against the
// keyslot and the master key against the digest without asking the kernel for a
// device-mapper target.

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

// requireCryptsetup skips the calling test when the cryptsetup binary is not
// installed, and does so LOUDLY: a conformance suite that silently reports
// success on a machine with no third party to check against is worse than no
// suite, because it converts "unverified" into "verified".
func requireCryptsetup(t *testing.T) string {
	t.Helper()

	path, err := exec.LookPath("cryptsetup")
	if err != nil {
		// FAILS, DOES NOT SKIP. A skip converts a missing dependency into a
		// green result, and this is the suite that must not do that: it holds
		// the bidirectional interoperability property -- cryptsetup opens what
		// this library writes, and the reverse -- which took seven review
		// rounds to earn, after a period when cryptsetup refused every
		// container this library produced and an encrypted volume had NO
		// recovery path.
		//
		// While this was a t.Skipf, a runner without cryptsetup ran every
		// TestConformance_* to a PASS having executed nothing. Measured on the
		// CI unit leg: nine such messages across this file and geometry_test.go,
		// job green (#90).
		//
		// The remedy ranking is in
		// ../handbook/software/conventions/testing-guidelines.md; fixing the
		// environment is the first of them. The devcontainer and the integration
		// image install cryptsetup-bin, and ci.yml now installs it for the unit
		// job too. So this branch means the environment is wrong, and it should
		// say so loudly rather than quietly exempting itself.
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
func standardFormatOptions(path string) FormatOptions {
	return FormatOptions{
		Device:        path,
		Passphrase:    []byte(conformancePassphrase),
		Cipher:        "aes",
		CipherMode:    "xts-plain64",
		KeySize:       512,
		HashAlgo:      "sha512",
		SectorSize:    512,
		KDFType:       KDFTypePBKDF2,
		PBKDFIterTime: 1, // keep the keyslot KDF cheap
	}
}

// formatWithLibrary gives a test a container formatted with the parameters the
// consuming project pins.
//
// It FORMATS ONCE PER PROCESS and stamps the resulting bytes thereafter. Every
// one of the 51 call sites asks for the identical configuration, and Format
// costs ~440ms, so the package was paying that repeatedly -- several call sites
// are inside table loops, which is how two tests reached 25-29s each.
//
// The bytes are produced by a REAL Format, so what is stamped is a genuine
// container and not a hand-built approximation. What each caller loses is that
// Format does not RUN for them: they no longer get a fresh random UUID and
// salts. Nothing in the package depends on two fixtures differing -- checked
// before making this change, not assumed -- and a test that needs Format's own
// behavior calls Format directly rather than coming through here.
//
// The failure is carried out of the sync.Once rather than reported inside it: a
// t.Fatalf in there would abort whichever test happened to be first, which is
// not necessarily the test that would have failed.
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
		if err := Format(standardFormatOptions(seed)); err != nil {
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

// goldenPrefixBytes is how much of a formatted image is captured and stamped.
//
// Format writes the two header copies and keyslot 0's area, all inside the
// first ~550 KiB. 2 MiB covers that with room for the multi-keyslot fixtures
// built on top, and copying the full 64 MiB image instead would reintroduce as
// cost what the memoization just removed.
//
// A STAMPED FIXTURE IS NOT BYTE-FOR-BYTE A FORMATTED CONTAINER PAST THIS
// POINT, and since the keyslots-area fill it no longer can be cheaply. Format
// now writes CSPRNG data over the whole keyslots area out to the data segment
// at 16 MiB (format.go), so a stamped image carries that fill for its first 2
// MiB and zeroes for the remaining ~14 MiB of keyslots area. Nothing here
// depends on the difference -- cryptsetup does not read unallocated keyslot
// space, and AddKey places new slots immediately after keyslot 0, well inside
// the prefix -- and a test that needs the real fill calls Format directly, as
// TestFormatFillsTheWholeKeyslotsAreaWithRandom does. Raising this to 16 MiB
// would put a 16 MiB copy on all 51 call sites to fix nothing.
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
	// CLOSED, NOT FSYNCED (#92). fsync buys durability across a power loss,
	// which a fixture under t.TempDir() does not need: the page cache is
	// coherent for every reader of the file -- this process, a cryptsetup
	// child, and O_DIRECT, which writes dirty pages back before it reads. It
	// was not free: on a loaded runner each fsync of a fixture this size took
	// ~330ms (measured: 45 fixture fsyncs, 14.8s, across three tests), paid by
	// every caller of every stamping helper for nothing it asserts.
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close %s: %v", path, err)
	}
}

// TestConformance_WeWrite_CryptsetupReads is direction A of #28: a container
// this library writes must be a valid LUKS2 device to cryptsetup.
//
// Before the fix, all of these failed at the first step -- isLuks exited 1 --
// which took luksDump, luksHeaderBackup, luksChangeKey and luksOpen with it and
// left a volume written by this library with no recovery path.
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

		// Assert on what cryptsetup PARSED, not merely that it exited 0.
		// "Keyslots area" is cryptsetup's reading of config.keyslots_size: the
		// defect it caught was storing the area's end offset (16777216) where
		// the spec wants the area's size (16744448), and cryptsetup rejected
		// the header with "keyslots_size is too large".
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

// TestConformance_SecondaryHeaderMagic is #64: the second header copy must
// carry the SKUL magic, and the point of it is recovery.
//
// The primary-magic-on-the-secondary defect does NOT by itself stop cryptsetup
// from opening a container whose primary header is intact -- measured, and
// worth stating plainly, because it means the defect is invisible until the day
// it matters. What it does is destroy the backup: with the primary header
// destroyed, a container whose secondary carries the correct magic still opens,
// and one whose secondary carries the primary magic is "not a valid LUKS
// device".
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

		magic := make([]byte, LUKS2MagicLen)
		if _, err := f.ReadAt(magic, LUKS2SecondaryHeaderOffset); err != nil {
			t.Fatalf("failed to read secondary magic: %v", err)
		}
		if !bytes.Equal(magic, []byte(LUKS2SecondaryMagic)) {
			t.Fatalf("secondary header magic = %q, want %q", magic, LUKS2SecondaryMagic)
		}
	})

	t.Run("this library can read back its own secondary header", func(t *testing.T) {
		hdr, metadata, err := ReadSecondaryHeader(path)
		if err != nil {
			t.Fatalf("ReadSecondaryHeader failed: %v", err)
		}
		if hdr.HeaderOffset != uint64(LUKS2SecondaryHeaderOffset) {
			t.Errorf("secondary hdr.HeaderOffset = %d, want %d", hdr.HeaderOffset, LUKS2SecondaryHeaderOffset)
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
		if _, err := f.WriteAt(make([]byte, LUKS2SecondaryHeaderOffset), 0); err != nil {
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

// TestConformance_CryptsetupWrites_WeRead is direction B of #73: a container
// cryptsetup writes with the consuming project's pinned parameters must open
// with this library.
//
// The parameters are pinned deliberately: --hash sha512 stores a 64-byte
// digest, and the hardcoded 32-byte derivation in verifyMasterKey could never
// reproduce it, so the CORRECT passphrase returned "incorrect passphrase".
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
		_, metadata, err := ReadHeader(path)
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
		if err := TestKey(path, []byte(conformancePassphrase)); err != nil {
			t.Fatalf("TestKey rejected the CORRECT passphrase on a cryptsetup-written volume: %v", err)
		}
	})

	t.Run("TestKey rejects a wrong passphrase", func(t *testing.T) {
		if err := TestKey(path, []byte(conformanceWrongPassphrase)); err == nil {
			t.Fatal("TestKey accepted a WRONG passphrase on a cryptsetup-written volume")
		}
	})
}

// TestConformance_CryptsetupMultiKeyslotDigestAssociation is the compatibility
// guard on the digest-to-keyslot rule.
//
// verifyMasterKey consults only the digests whose "keyslots" array names the
// keyslot being opened. That is what the LUKS2 format says the array is for,
// but reading a header field STRICTLY is exactly the change that can lock an
// operator out of a container some other implementation wrote -- and the
// implementation that matters is cryptsetup, which is what is in the field.
//
// So the association is checked against a container cryptsetup itself built and
// then added a second keyslot to, rather than against one this library wrote:
// a library that maintained the association wrongly and read it back the same
// wrong way would agree with itself and pass every self-round-trip.
//
// Measured against cryptsetup 2.7.0: it registers BOTH keyslots on the single
// digest ("keyslots": ["0", "1"]), and both passphrases open the container.
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

	// luksAddKey reads the EXISTING passphrase then the new one, both on stdin.
	code, out = runCryptsetup(t, conformancePassphrase+"\n"+second+"\n",
		"luksAddKey", "--pbkdf", "pbkdf2",
		"--pbkdf-force-iterations", "1000",
		"--batch-mode", path)
	if code != 0 {
		t.Fatalf("cryptsetup luksAddKey exited %d, want 0\n%s", code, out)
	}

	_, metadata, err := ReadHeader(path)
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
		if err := TestKey(path, []byte(passphrase)); err != nil {
			t.Fatalf("a cryptsetup-written keyslot no longer opens under the digest association rule: %v", err)
		}
	}

	if err := TestKey(path, []byte(conformanceWrongPassphrase)); err == nil {
		t.Fatal("TestKey accepted a WRONG passphrase on a two-keyslot cryptsetup container")
	}
}

// TestConformance_StaysValidAfterMutation checks that the operations which
// REWRITE a header leave a container cryptsetup still accepts.
//
// A format-time-only conformance test would have passed while AddKey wrote an
// absolute end offset into config.keyslots_size -- the same defect Format
// carried, and one that additionally SHRANK the reserved area -- and while
// RemoveToken nilled the tokens map so the last removal dropped the mandatory
// object. Both would have turned a conformant container into a rejected one on
// the second operation, not the first.
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

		// The RESERVED keyslots area must not move. cryptsetup accepts a
		// keyslots_size that is merely too SMALL, so "isLuks still exits 0" does
		// not catch an operation that rewrites the field to the end of the slot
		// it just added -- the container stays readable while quietly declaring
		// a fraction of the space it actually reserved, and the next AddKey is
		// then sized against a boundary that no longer describes the device.
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

		if _, err := AddKey(path, []byte(conformancePassphrase), []byte(secondPassphrase), &AddKeyOptions{
			KDFType:       KDFTypePBKDF2,
			Hash:          "sha256",
			PBKDFIterTime: 1,
		}); err != nil {
			t.Fatalf("AddKey failed: %v", err)
		}

		assertStillValid(t, path, "AddKey", conformancePassphrase, secondPassphrase)

		// Both passphrases must still work through this library too, so the
		// check is not one-sided.
		for _, passphrase := range []string{conformancePassphrase, secondPassphrase} {
			if err := TestKey(path, []byte(passphrase)); err != nil {
				t.Errorf("after AddKey, TestKey rejected %q: %v", passphrase, err)
			}
		}
	})

	// ChangeKey RELOCATES the keyslot: it writes the new material into a free
	// area of the keyslots region, re-points area.offset, and only then wipes the
	// area it left (#39). Nothing in LUKS2 requires keyslot areas to be
	// contiguous or to sit where a first format put them -- but "nothing
	// requires it" is a reading of the spec, and this is the check that the
	// reading is right. A relocated keyslot cryptsetup refuses to open would be
	// a volume this library can open and no other implementation can.
	t.Run("after ChangeKey relocates a keyslot", func(t *testing.T) {
		path := newImage(t, "after-changekey.img")
		formatWithLibrary(t, path)
		assertStillValid(t, path, "Format", conformancePassphrase)

		_, before, err := ReadHeader(path)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}
		originalOffset := before.Keyslots["0"].Area.Offset

		if err := ChangeKey(path, []byte(conformancePassphrase), []byte(secondPassphrase), 0); err != nil {
			t.Fatalf("ChangeKey failed: %v", err)
		}

		_, after, err := ReadHeader(path)
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
		if err := TestKey(path, []byte(secondPassphrase)); err != nil {
			t.Errorf("after ChangeKey, TestKey rejected the new passphrase: %v", err)
		}
	})

	// A removal now clears the removed keyslot's id out of the tokens as well as
	// the digests -- previously a token could outlive the keyslot it named, on
	// every route. That rewrite touches the tokens object of a container
	// cryptsetup has to keep reading, and a token's "keyslots" array is where
	// LUKS2 and this library's own digest handling differ (cryptsetup rejects an
	// empty keyslots list on a DIGEST and accepts one on a TOKEN), so it is
	// checked against cryptsetup rather than reasoned about.
	t.Run("after removing a keyslot a token names", func(t *testing.T) {
		path := newImage(t, "after-keyslot-with-token.img")
		formatWithLibrary(t, path)

		if _, err := AddKey(path, []byte(conformancePassphrase), []byte(secondPassphrase), &AddKeyOptions{
			KDFType:       KDFTypePBKDF2,
			Hash:          "sha256",
			PBKDFIterTime: 1,
		}); err != nil {
			t.Fatalf("AddKey failed: %v", err)
		}
		if err := ImportToken(path, 0, &Token{Type: "systemd-tpm2", Keyslots: []string{"1"}}); err != nil {
			t.Fatalf("ImportToken failed: %v", err)
		}
		assertStillValid(t, path, "ImportToken", conformancePassphrase, secondPassphrase)

		if err := KillKeyslot(path, 1); err != nil {
			t.Fatalf("KillKeyslot failed: %v", err)
		}
		assertStillValid(t, path, "KillKeyslot", conformancePassphrase)

		_, metadata, err := ReadHeader(path)
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

		if err := ImportToken(path, 0, &Token{Type: "systemd-tpm2", Keyslots: []string{"0"}}); err != nil {
			t.Fatalf("ImportToken failed: %v", err)
		}
		assertStillValid(t, path, "ImportToken", conformancePassphrase)

		if err := RemoveToken(path, 0); err != nil {
			t.Fatalf("RemoveToken failed: %v", err)
		}
		assertStillValid(t, path, "RemoveToken", conformancePassphrase)
	})
}

// TestConformance_LargeHeaderStaysValid is the cryptsetup half of the
// header-area regression.
//
// The unit tests in headerarea_test.go check that this package can still read
// back a header whose JSON exceeds the 8192 bytes at which the old sizing
// overflowed. That is necessary and not sufficient: the old code produced
// HeaderSize 20480, which is not a power of two and therefore not a legal LUKS2
// metadata size, and a self-consistent reader would have accepted it happily.
// Only cryptsetup can say whether the result is a LUKS2 container.
//
// The keyslots are synthetic rather than added with AddKey -- 15 real AddKey
// calls would cost a KDF derivation and a 256 KiB write each, and none of that
// changes the header layout under test. They are tiled at distinct,
// non-overlapping areas, which is what cryptsetup validates about them.
func TestConformance_LargeHeaderStaysValid(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	const keyslots = 16

	path := newImage(t, "large-header.img")
	formatWithLibrary(t, path)

	hdr, metadata, err := ReadHeader(path)
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

// TestConformance_LegacyDigestLengthStillOpens is the backward-compatibility
// half of #73, and it needs no cryptsetup.
//
// Containers already written by this library store a 32-byte digest under a
// "sha512" label. The write path now emits the spec-correct 64 bytes, but the
// read path derives to the length STORED IN THE HEADER rather than to the
// hash's natural length, precisely so those containers keep opening. Deriving
// to the hash length on read would have bricked every volume this library has
// ever written.
//
// The fixture is built rather than checked in: format normally, recover the
// master key through the package's own unlock path, and rewrite the digest to
// the 32 bytes the old code would have produced. Everything else -- keyslot,
// AF material, salts, iteration count -- is byte-for-byte what the old code
// wrote, because it IS what the current code wrote.
func TestConformance_LegacyDigestLengthStillOpens(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "legacy-digest.img")
	formatWithLibrary(t, path)

	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	masterKey, err := getMasterKey(path, []byte(conformancePassphrase), metadata)
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
	legacy, err := deriveKeySecret(masterKey, &KDF{
		Type:       digest.Type,
		Hash:       digest.Hash,
		Salt:       digest.Salt,
		Iterations: &digest.Iterations,
	}, 32)
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
	_, reread, err := ReadHeader(path)
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

	if err := TestKey(path, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("a container written by the OLD code (32-byte digest labeled sha512) no longer opens: %v", err)
	}
	if err := TestKey(path, []byte(conformanceWrongPassphrase)); err == nil {
		t.Fatal("the legacy fixture accepted a WRONG passphrase")
	}
}

// TestConformance_MandatoryJSONObjectsArePresent checks the JSON this library
// writes for the mandatory LUKS2 objects directly, without cryptsetup.
//
// It is a cheaper and more specific check than the cryptsetup one and it runs
// everywhere, but it is NOT a substitute: it asserts against the spec's list of
// mandatory objects, which is still this package's own reading of the spec.
// The cryptsetup tests above are the ones that hold the format honest.
func TestConformance_MandatoryJSONObjectsArePresent(t *testing.T) {
	path := newImage(t, "mandatory-objects.img")
	formatWithLibrary(t, path)

	f, err := os.Open(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open image: %v", err)
	}
	defer func() { _ = f.Close() }()

	for _, hdrOffset := range []int64{LUKS2PrimaryHeaderOffset, LUKS2SecondaryHeaderOffset} {
		raw := make([]byte, LUKS2DefaultSize)
		if _, err := f.ReadAt(raw, hdrOffset+LUKS2HeaderSize); err != nil {
			t.Fatalf("failed to read the JSON area at offset %d: %v", hdrOffset, err)
		}
		if i := bytes.IndexByte(raw, 0); i != -1 {
			raw = raw[:i]
		}

		// Every one of these is mandatory in LUKS2 and must be an OBJECT.
		// `"tokens": {}` is what a container with no tokens carries; omitting
		// the key made cryptsetup report `JSON area "" is missing "tokens"
		// (object) specification` and fail the whole header (#28).
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

// TestEnsureRequiredObjects checks the normalization that keeps a nil Go map
// from reaching the disk as `null`.
func TestEnsureRequiredObjects(t *testing.T) {
	t.Run("nil maps become empty objects", func(t *testing.T) {
		m := &LUKS2Metadata{}
		m.ensureRequiredObjects()

		if m.Keyslots == nil {
			t.Error("Keyslots is still nil")
		}
		if m.Tokens == nil {
			t.Error("Tokens is still nil")
		}
		if m.Segments == nil {
			t.Error("Segments is still nil")
		}
		if m.Digests == nil {
			t.Error("Digests is still nil")
		}
		if m.Config != nil {
			t.Error("Config was invented; an empty config would pass the presence check and fail on its members")
		}
	})

	t.Run("populated maps are left alone", func(t *testing.T) {
		m := &LUKS2Metadata{
			Keyslots: map[string]*Keyslot{"0": {Type: "luks2"}},
			Tokens:   map[string]*Token{"0": {Type: "systemd-tpm2"}},
			Segments: map[string]*Segment{"0": {Type: "crypt"}},
			Digests:  map[string]*Digest{"0": {Type: "pbkdf2"}},
		}
		m.ensureRequiredObjects()

		if len(m.Keyslots) != 1 || len(m.Tokens) != 1 || len(m.Segments) != 1 || len(m.Digests) != 1 {
			t.Fatalf("ensureRequiredObjects modified populated maps: %+v", m)
		}
	})
}

// cheapenGoldenDigests rewrites the shared golden's digests to a low iteration
// count, re-derived from its own master key so they still verify.
//
// This is the OTHER half of the fixture cost and it is larger than Format.
// createDigest hardcodes DigestIterations -- 600,000 rounds of PBKDF2-SHA512 --
// and verifyMasterKey pays it on EVERY unlock, so every test that opens a
// fixture paid ~295ms that has nothing to do with what it asserts. Format is
// paid once per fixture; the digest is paid once per unlock, and unlocks
// outnumber fixtures across this package.
//
// It runs ONCE, inside the same sync.Once that builds the golden, so the single
// expensive unlock it needs is amortized over every test in the package.
//
// Cheapening is safe here and would not be everywhere. Nothing in the package
// asserts a FIXTURE's digest iteration count -- checked, not assumed:
// TestSecurityConstants asserts the CONSTANT DigestIterations, which this does
// not touch, and crypto_helpers_test compares a digest to its own KDF within one
// createDigest call. A test whose subject IS the digest cost builds its own
// digest (kdfcost_test.go) and is unaffected.
//
// The digest value is a public header field, not a secret. The master key it is
// derived from is borrowed in place and never copied out.
func cheapenGoldenDigests(device string) (err error) {
	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		return err
	}

	masterKey, err := getMasterKey(device, []byte(conformancePassphrase), metadata)
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
		kdf := &KDF{Type: digest.Type, Hash: digest.Hash, Salt: digest.Salt, Iterations: &iterations}

		// Derived exactly as verifyMasterKey will re-derive it, to the length
		// already stored, so the rewritten digest verifies by the route
		// production takes rather than one this helper invented.
		expected, err := decodeBase64(digest.Digest)
		if err != nil {
			return err
		}
		derived, err := deriveKeySecret(masterKey, kdf, len(expected))
		if err != nil {
			return err
		}
		err = borrowSecret("golden digest", derived, func(b []byte) error {
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

	// The golden must still OPEN. Without this, a mistake here would hand every
	// test in the package a container that fails for a reason unrelated to what
	// it asserts, and the whole suite would go red for the wrong cause.
	if err := TestKey(device, []byte(conformancePassphrase)); err != nil {
		return fmt.Errorf("the golden container stopped opening after its digests were cheapened: %w", err)
	}
	return nil
}
