// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The structural validator (headervalidation.go) is a reproduction of
// cryptsetup's LUKS2_hdr_validate, and a reproduction is only as good as its
// agreement with the original. These tests hold it to the cryptsetup binary in
// both directions (#248): every header cryptsetup writes passes it, and every
// header cryptsetup refuses to read, it refuses too.

const agreementPassphrase = "agreement-passphrase"

// cryptsetupAgrees runs cryptsetup with the passphrase on stdin and returns its
// combined output and whether it succeeded.
func cryptsetupAgrees(t *testing.T, args ...string) (string, bool) {
	t.Helper()
	cmd := exec.Command("cryptsetup", args...) // #nosec G204 -- arguments are test constants and paths under t.TempDir()
	cmd.Stdin = strings.NewReader(agreementPassphrase)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("failed to run cryptsetup %s: %v", args[0], err)
		}
		return string(out), false
	}
	return string(out), true
}

// mustCryptsetup is cryptsetupAgrees for a step that has to succeed.
func mustCryptsetup(t *testing.T, args ...string) {
	t.Helper()
	if out, ok := cryptsetupAgrees(t, args...); !ok {
		t.Fatalf("cryptsetup %s failed:\n%s", strings.Join(args, " "), out)
	}
}

// agreementImage creates a sparse file of size bytes under t.TempDir().
func agreementImage(t *testing.T, name string, size int64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	if err := os.Truncate(path, size); err != nil {
		t.Fatalf("size %s: %v", path, err)
	}
	return path
}

// cheapLUKS2 is the luksFormat prefix every fixture here uses: the KDF cost is
// irrelevant to structure, so it is pinned low.
var cheapLUKS2 = []string{"luksFormat", "--type", "luks2", "--batch-mode", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000"}

// libraryAccepts reports whether this package reads path AND finds it valid
// under every structural rule, the per-entry ones included.
func libraryAccepts(path string) error {
	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		return err
	}
	return validateHeaderStructure(int(hdr.HeaderSize), metadata) // #nosec G115 -- ReadHeader bounds it to 4 MiB
}

func TestCryptsetupWrittenHeadersPassTheValidator(t *testing.T) {
	requireCryptsetupDeclared(t)

	for _, tc := range []struct {
		name  string
		build func(t *testing.T) string
	}{
		{"the defaults", func(t *testing.T) string {
			path := agreementImage(t, "default.img", 32<<20)
			mustCryptsetup(t, append(cheapLUKS2, path)...)
			return path
		}},
		{"a larger metadata and a smaller keyslots area", func(t *testing.T) string {
			path := agreementImage(t, "geometry.img", 32<<20)
			mustCryptsetup(t, append(cheapLUKS2, "--luks2-metadata-size", "64k", "--luks2-keyslots-size", "2m", path)...)
			return path
		}},
		{"4 KiB sectors and a data offset of its own", func(t *testing.T) string {
			path := agreementImage(t, "sector.img", 48<<20)
			mustCryptsetup(t, append(cheapLUKS2, "--sector-size", "4096", "--offset", "65536", path)...)
			return path
		}},
		{"aes-cbc-essiv with a 256-bit key, labels", func(t *testing.T) string {
			path := agreementImage(t, "cbc.img", 32<<20)
			mustCryptsetup(t, append(cheapLUKS2, "--cipher", "aes-cbc-essiv:sha256", "--key-size", "256",
				"--label", strings.Repeat("L", 47), "--subsystem", "sub", path)...)
			return path
		}},
		{"several keyslots and an imported token", func(t *testing.T) string {
			path := agreementImage(t, "keyslots.img", 32<<20)
			mustCryptsetup(t, append(cheapLUKS2, path)...)
			keyFile := filepath.Join(t.TempDir(), "second.key")
			if err := os.WriteFile(keyFile, []byte("a-second-passphrase"), 0o600); err != nil {
				t.Fatal(err)
			}
			mustCryptsetup(t, "luksAddKey", "--batch-mode", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", path, keyFile)
			tokenFile := filepath.Join(t.TempDir(), "token.json")
			if err := os.WriteFile(tokenFile, []byte(`{"type":"agreement-token","keyslots":["1"],"note":"x"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			mustCryptsetup(t, "token", "import", "--json-file", tokenFile, path)
			return path
		}},
		{"a detached header", func(t *testing.T) string {
			header := agreementImage(t, "detached-header.img", 16<<20)
			data := agreementImage(t, "detached-data.img", 16<<20)
			mustCryptsetup(t, append(cheapLUKS2, "--header", header, data)...)
			return header
		}},
		{"an online reencryption in progress", func(t *testing.T) string {
			path := agreementImage(t, "reencrypt.img", 32<<20)
			mustCryptsetup(t, append(cheapLUKS2, path)...)
			mustCryptsetup(t, "reencrypt", "--init-only", "--batch-mode", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", path)
			return path
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.build(t)
			if err := libraryAccepts(path); err != nil {
				t.Fatalf("a header cryptsetup wrote fails the structural validator: %v", err)
			}
		})
	}
}

// writeRawMetadata writes metadata to path exactly as marshaled, with nothing
// normalized or checked -- not even json_size or the requirements guard.
func writeRawMetadata(t *testing.T, path string, hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata) {
	t.Helper()
	jsonData, err := marshalCanonicalJSON(metadata)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	if err := writeEncodedHeader(f, hdr, jsonData, int(hdr.HeaderSize)); err != nil { // #nosec G115 -- read back from a header ReadHeader bounded
		t.Fatalf("write: %v", err)
	}
}

func TestHeadersCryptsetupRefusesAreRefused(t *testing.T) {
	requireCryptsetupDeclared(t)

	base := agreementImage(t, "refusal-base.img", 32<<20)
	mustCryptsetup(t, append(cheapLUKS2, base)...)
	keyFile := filepath.Join(t.TempDir(), "second.key")
	if err := os.WriteFile(keyFile, []byte("a-second-passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustCryptsetup(t, "luksAddKey", "--batch-mode", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", base, keyFile)
	tokenFile := filepath.Join(t.TempDir(), "token.json")
	if err := os.WriteFile(tokenFile, []byte(`{"type":"agreement-token","keyslots":["0"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	mustCryptsetup(t, "token", "import", "--json-file", tokenFile, base)
	pristine, err := os.ReadFile(base) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*LUKS2Metadata)
	}{
		{"the control, unchanged", nil},
		{"a segment offset off the sector grid", func(m *LUKS2Metadata) { m.Segments["0"].Offset = "16777217" }},
		{"a segment size off the sector grid", func(m *LUKS2Metadata) { m.Segments["0"].Size = "1000" }},
		{"a segment size of zero", func(m *LUKS2Metadata) { m.Segments["0"].Size = "0" }},
		{"a fixed size not a whole number of sectors", func(m *LUKS2Metadata) { m.Segments["0"].SectorSize, m.Segments["0"].Size = 4096, "1024" }},
		{"a sector size off the 512-byte grid", func(m *LUKS2Metadata) { m.Segments["0"].SectorSize = 768 }},
		{"an iv_tweak that is not a number", func(m *LUKS2Metadata) { m.Segments["0"].IVTweak = "0x0" }},
		{"an empty cipher", func(m *LUKS2Metadata) { m.Segments["0"].Encryption = "" }},
		{"a segment numbered past a gap", func(m *LUKS2Metadata) {
			m.Segments["1"] = m.Segments["0"]
			delete(m.Segments, "0")
			m.Digests["0"].Segments = []string{"1"}
		}},
		{"a crypt segment no digest attests", func(m *LUKS2Metadata) { m.Digests["0"].Segments = []string{} }},
		{"a keyslots area running into the data", func(m *LUKS2Metadata) { m.Config.KeyslotsSize = "16777216" }},
		{"a keyslots area off the 4 KiB grid", func(m *LUKS2Metadata) { m.Config.KeyslotsSize = "16744000" }},
		{"a json_size of another geometry", func(m *LUKS2Metadata) { m.Config.JSONSize = "28672" }},
		{"a token naming a missing keyslot", func(m *LUKS2Metadata) { m.Tokens["0"].Keyslots = []string{"7"} }},
		{"a token with no keyslots array", func(m *LUKS2Metadata) { m.Tokens["0"].Keyslots = nil }},
		{"a token id that is not a number", func(m *LUKS2Metadata) { m.Tokens["-1"] = m.Tokens["0"] }},
		{"a digest naming a missing segment", func(m *LUKS2Metadata) { m.Digests["0"].Segments = []string{"0", "4"} }},
		{"a digest naming a missing keyslot", func(m *LUKS2Metadata) { m.Digests["0"].Keyslots = []string{"0", "1", "9"} }},
		{"a keyslot id that is not a number", func(m *LUKS2Metadata) { m.Keyslots["x"] = m.Keyslots["1"] }},
		{"a keyslot id with a leading zero", func(m *LUKS2Metadata) {
			m.Keyslots["01"] = m.Keyslots["1"]
			delete(m.Keyslots, "1")
			m.Digests["0"].Keyslots = []string{"0", "01"}
		}},
		{"a keyslot area inside the header copies", func(m *LUKS2Metadata) { m.Keyslots["1"].Area.Offset = "16384" }},
		{"a keyslot area past the keyslots area", func(m *LUKS2Metadata) { m.Keyslots["1"].Area.Offset = "16773120" }},
		{"two keyslot areas that overlap", func(m *LUKS2Metadata) { m.Keyslots["1"].Area.Offset = m.Keyslots["0"].Area.Offset }},
		{"no tokens object", func(m *LUKS2Metadata) { m.Tokens = nil }},
		{"a luks2 keyslot no digest names", func(m *LUKS2Metadata) { m.Digests["0"].Keyslots = []string{"0"} }},
		{"a luks2 keyslot two digests name", func(m *LUKS2Metadata) {
			second := *m.Digests["0"]
			second.Keyslots, second.Segments = []string{"1"}, []string{}
			m.Digests["1"] = &second
		}},
		{"two online reencryptions", func(m *LUKS2Metadata) {
			m.Config.Requirements = &Requirements{Mandatory: []string{"online-reencrypt-v2", "online-reencrypt-v3"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "refusal.img")
			if err := os.WriteFile(path, pristine, 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.mutate != nil {
				hdr, metadata, err := ReadHeader(path)
				if err != nil {
					t.Fatalf("ReadHeader of the cryptsetup fixture: %v", err)
				}
				tc.mutate(metadata)
				hdr.SequenceID++
				writeRawMetadata(t, path, hdr, metadata)
			}

			out, cryptsetupReads := cryptsetupAgrees(t, "luksDump", path)
			ours := libraryAccepts(path)
			if tc.mutate == nil {
				if !cryptsetupReads || ours != nil {
					t.Fatalf("the control: cryptsetup reads it %v (%s), this package: %v", cryptsetupReads, out, ours)
				}
				return
			}
			if cryptsetupReads {
				t.Fatalf("cryptsetup READ the mutated header, so it is not a refusal this test can hold the validator to:\n%s", out)
			}
			if !errors.Is(ours, ErrInvalidHeader) {
				t.Fatalf("cryptsetup refuses this header and this package accepted it: %v", ours)
			}
		})
	}
}

// TestImportedTokensAreOnesCryptsetupReads is B2 against the real reader: a
// token imported with no keyslots is one cryptsetup reads and exports.
func TestImportedTokensAreOnesCryptsetupReads(t *testing.T) {
	requireCryptsetupDeclared(t)

	path := agreementImage(t, "imported-token.img", 32<<20)
	mustCryptsetup(t, append(cheapLUKS2, path)...)
	if err := ImportToken(path, 3, &Token{Type: TokenTypeSystemdRecovery}); err != nil {
		t.Fatalf("ImportToken: %v", err)
	}
	if err := ImportToken(path, 4, &Token{Type: TokenTypeSystemdRecovery, Keyslots: []string{"7"}}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("ImportToken naming a missing keyslot: got %v, want ErrInvalidHeader", err)
	}
	out, ok := cryptsetupAgrees(t, "token", "export", "--token-id", "3", path)
	if !ok || !strings.Contains(out, `"keyslots":[]`) {
		t.Fatalf("cryptsetup cannot export the imported token: %s", out)
	}
}

// TestADetachedHeaderIsNeverActivated is B1's activation half on the real
// kernel: cryptsetup's detached header reads, and Unlock refuses to map its
// offset-0 segment over the device that carries it -- creating no mapping.
func TestADetachedHeaderIsNeverActivated(t *testing.T) {
	requireRoot(t)
	requireCryptsetupDeclared(t)

	header := agreementImage(t, "detached-header.img", 17<<20)
	data := agreementImage(t, "detached-data.img", 16<<20)
	mustCryptsetup(t, append(cheapLUKS2, "--header", header, data)...)

	loop, err := SetupLoopDevice(header)
	if err != nil {
		t.Fatalf("SetupLoopDevice: %v", err)
	}
	defer func() { _ = DetachLoopDevice(loop) }()

	name := runVolume(t, "detached")
	err = Unlock(loop, []byte(agreementPassphrase), name)
	if IsUnlocked(name) {
		_ = Lock(name)
		t.Fatal("Unlock mapped a detached header's segment over the header itself")
	}
	// Two guards refuse this, and whichever runs first answers. The keyslot
	// scan refuses every keyslot first, since each one's area overlaps a data
	// segment that starts at 0 (#249, A2). Activation refuses the segment
	// itself (#248), which TestADetachedHeaderReadsButIsNeverActivated pins
	// directly. Either way nothing may be mapped, and the refusal must be about
	// the offset-0 segment.
	detached := errors.Is(err, ErrInvalidHeader) && strings.Contains(err.Error(), "detached")
	overlap := errors.Is(err, ErrKeyslotAreaOverlap) && strings.Contains(err.Error(), "starting at 0")
	if !detached && !overlap {
		t.Fatalf("Unlock of a detached header: got %v, want a refusal of its offset-0 data segment", err)
	}
}

// TestFormatRefusesADeviceInUse is B4's O_EXCL on the real kernel: while a
// device-mapper target holds the loop device, Format is refused with
// ErrDeviceInUse and the container on it is left exactly as it was. Once the
// target is gone, the same Format succeeds and cryptsetup opens the result --
// which also proves the aes-cbc-essiv:sha256 256-bit combination the allow-list
// admits is one dm-crypt sets up.
func TestFormatRefusesADeviceInUse(t *testing.T) {
	requireRoot(t)
	requireCryptsetupDeclared(t)

	image := agreementImage(t, "in-use.img", 32<<20)
	mustCryptsetup(t, append(cheapLUKS2, image)...)
	loop, err := SetupLoopDevice(image)
	if err != nil {
		t.Fatalf("SetupLoopDevice: %v", err)
	}
	defer func() { _ = DetachLoopDevice(loop) }()

	name := runVolume(t, "in-use")
	if err := Unlock(loop, []byte(agreementPassphrase), name); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	before, _, err := ReadHeader(loop)
	if err != nil {
		_ = Lock(name)
		t.Fatalf("ReadHeader: %v", err)
	}

	opts := FormatOptions{
		Device: loop, Passphrase: []byte("a-new-passphrase"),
		Cipher: "aes", CipherMode: "cbc-essiv:sha256", KeySize: 256,
		KDFType: KDFTypePBKDF2, PBKDFIterTime: 1,
	}
	err = Format(opts)
	after, _, readErr := ReadHeader(loop)
	if lockErr := Lock(name); lockErr != nil {
		t.Fatalf("Lock: %v", lockErr)
	}
	if !errors.Is(err, ErrDeviceInUse) {
		t.Fatalf("Format of a mapped device: got %v, want ErrDeviceInUse", err)
	}
	if readErr != nil || after.UUID != before.UUID || after.SequenceID != before.SequenceID {
		t.Fatalf("a refused Format changed the header: %v", readErr)
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format once the device is free: %v", err)
	}
	// cryptsetup opens the keyslot; the kernel sets up the segment's cipher.
	// The mapping is made through this package so the suite's ledger records it.
	cryptsetupOpens(t, loop, "a-new-passphrase", "the aes-cbc-essiv:sha256 volume Format wrote")
	opened := runVolume(t, "in-use-cbc")
	if err := Unlock(loop, []byte("a-new-passphrase"), opened); err != nil {
		t.Fatalf("dm-crypt does not set up the aes-cbc-essiv:sha256 volume Format wrote: %v", err)
	}
	if err := Lock(opened); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	info, err := GetVolumeInfo(loop)
	if err != nil || info.KeySize != 256 || info.Cipher != "aes-cbc-essiv:sha256" {
		t.Fatalf("GetVolumeInfo = %+v, %v; want a 256-bit aes-cbc-essiv:sha256 volume", info, err)
	}
}
