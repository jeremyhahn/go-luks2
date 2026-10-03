// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"strings"
	"testing"
)

// #106: the read path HONORS the mode half of keyslots.<n>.area.encryption.
//
// Until it did, unlockKeyslot took only the algorithm ("aes-cbc-essiv:sha256"
// -> "aes") and always ran AES-XTS, so a keyslot declaring a mode its material
// does not have opened perfectly for this package and for no conforming
// implementation. No writer-side test could catch a wrong declaration, because
// the reader that would have to notice it did not look. These tests are the
// read side that makes the declaration testable at all.

// TestParseKeyslotAreaEncryption pins the exact set of keyslot area specs the
// read path decrypts, and that everything else is refused with the typed error.
func TestParseKeyslotAreaEncryption(t *testing.T) {
	accepted := []string{
		// What cryptsetup and this package write by default.
		"aes-xts-plain64",
		// cryptsetup accepts it as --keyslot-cipher, and LUKS1 conversion
		// carries it over. Its IV is the sector index truncated to 32 bits,
		// identical to plain64 for every sector a keyslot area can hold.
		"aes-xts-plain",
	}
	for _, spec := range accepted {
		algo, err := parseKeyslotAreaEncryption(spec)
		if err != nil {
			t.Errorf("%q: refused a spec the read path decrypts: %v", spec, err)
			continue
		}
		if algo != "aes" {
			t.Errorf("%q: algorithm %q, want aes", spec, algo)
		}
	}

	refused := []string{
		// Right algorithm, wrong mode: the case #106 exists for.
		"aes-cbc-essiv:sha256",
		"aes-cbc-plain64",
		"aes-cbc-plain",
		"aes-ecb",
		"aes-lrw-benbi",
		// Right algorithm and mode, IV generator this package does not run.
		"aes-xts-essiv:sha256",
		"aes-xts-plain64be",
		"aes-xts-benbi",
		"aes-xts-null",
		// Not a spec at all, or a spec with the mode missing: taking the
		// algorithm and assuming XTS is exactly the guess this replaces.
		"aes",
		"aes-xts",
		"",
		"aes-xts-plain64-",
		"aes-xts-plain64:sha256",
		"AES-XTS-PLAIN64",
		" aes-xts-plain64",
		// Wrong algorithm.
		"serpent-xts-plain64",
		"twofish-xts-plain64",
		"capi:xts(aes)-plain64",
	}
	for _, spec := range refused {
		algo, err := parseKeyslotAreaEncryption(spec)
		if err == nil {
			t.Errorf("%q: accepted as algorithm %q; the read path cannot decrypt it", spec, algo)
			continue
		}
		if !errors.Is(err, ErrUnsupportedKeyslotCipher) {
			t.Errorf("%q: error %v does not wrap ErrUnsupportedKeyslotCipher", spec, err)
		}
		var cipherErr *UnsupportedKeyslotCipherError
		if !errors.As(err, &cipherErr) {
			t.Errorf("%q: error %v is not an *UnsupportedKeyslotCipherError", spec, err)
		} else if cipherErr.Spec != spec {
			t.Errorf("%q: error carries spec %q", spec, cipherErr.Spec)
		}
	}
}

// TestUnsupportedKeyslotCipherErrorMatchesBothSentinels pins the contract the
// keyslot scan depends on: the typed refusal is ErrUnsupportedKeyslotCipher for
// a caller asking why, and ErrInvalidKeyslot so getMasterKey moves on to the
// next keyslot rather than aborting.
func TestUnsupportedKeyslotCipherErrorMatchesBothSentinels(t *testing.T) {
	err := error(&UnsupportedKeyslotCipherError{Keyslot: "3", Spec: "aes-cbc-essiv:sha256"})
	if !errors.Is(err, ErrUnsupportedKeyslotCipher) {
		t.Errorf("%v does not match ErrUnsupportedKeyslotCipher", err)
	}
	if !errors.Is(err, ErrInvalidKeyslot) {
		t.Errorf("%v does not match ErrInvalidKeyslot", err)
	}
	if errors.Is(err, ErrMasterKeyVerification) {
		t.Errorf("%v matches ErrMasterKeyVerification", err)
	}
	msg := err.Error()
	for _, want := range []string{`"3"`, `"aes-cbc-essiv:sha256"`, "aes-xts-plain64"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q does not name %s", msg, want)
		}
	}
}

// TestKeyslotDeclaringAModeItDoesNotUseIsRefused is the mutation test the issue
// asks for: change ONLY the declared mode, leave the material alone, and the
// read path must go red -- with the typed error, not a digest mismatch.
//
// The control matters as much as the mutation: the untouched fixture must
// open, or a refusal proves nothing about the declaration.
func TestKeyslotDeclaringAModeItDoesNotUseIsRefused(t *testing.T) {
	defer parallel(t)()

	// declare stamps a fresh library-formatted container and rewrites ONLY
	// keyslot 0's declared area encryption. The material is untouched.
	declare := func(t *testing.T, spec string) string {
		t.Helper()
		device := newImage(t, "declared-mode.img")
		formatWithLibrary(t, device)
		hdr, metadata, err := ReadHeader(device)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}
		if got := metadata.Keyslots["0"].Area.Encryption; got != KeyslotAreaEncryption {
			t.Fatalf("fixture keyslot declares %q, want %q", got, KeyslotAreaEncryption)
		}
		metadata.Keyslots["0"].Area.Encryption = spec
		if err := writeHeaderInternal(device, hdr, metadata); err != nil {
			t.Fatalf("failed to write the header: %v", err)
		}
		return device
	}

	// The control: the declaration this material really has opens, as does
	// the other spelling cryptsetup uses for the same bytes. Without this a
	// refusal below would prove nothing about the declaration.
	for _, spec := range []string{KeyslotAreaEncryption, "aes-xts-plain"} {
		t.Run(spec+" opens", func(t *testing.T) {
			if err := TestKey(declare(t, spec), []byte(conformancePassphrase)); err != nil {
				t.Fatalf("a keyslot truthfully declaring %q was refused: %v", spec, err)
			}
		})
	}

	for _, spec := range []string{
		"aes-cbc-essiv:sha256",
		"aes-cbc-plain64",
		"aes-xts-essiv:sha256",
		"aes-xts-plain64be",
		"aes",
	} {
		t.Run(spec+" is refused", func(t *testing.T) {
			err := TestKey(declare(t, spec), []byte(conformancePassphrase))
			if err == nil {
				t.Fatalf("a keyslot declaring %q over AES-XTS material OPENED; no conforming implementation can open it", spec)
			}
			if !errors.Is(err, ErrUnsupportedKeyslotCipher) {
				t.Fatalf("refused, but not with ErrUnsupportedKeyslotCipher: %v", err)
			}
			if !errors.Is(err, ErrInvalidKeyslot) {
				t.Fatalf("refused, but not as ErrInvalidKeyslot, which is what keeps the keyslot scan going: %v", err)
			}
			if errors.Is(err, ErrMasterKeyVerification) {
				t.Fatalf("refused as a digest mismatch, which reads as a wrong passphrase: %v", err)
			}
			var cipherErr *UnsupportedKeyslotCipherError
			if !errors.As(err, &cipherErr) {
				t.Fatalf("refused, but not as an *UnsupportedKeyslotCipherError: %v", err)
			}
			if cipherErr.Keyslot != "0" || cipherErr.Spec != spec {
				t.Fatalf("error carries keyslot %q spec %q, want keyslot \"0\" spec %q",
					cipherErr.Keyslot, cipherErr.Spec, spec)
			}
		})
	}
}

// TestConformance_CryptsetupKeyslotCiphers holds the read path against keyslots
// CRYPTSETUP wrote with a chosen --keyslot-cipher, so the material genuinely is
// what the header says it is.
//
// The two XTS spellings must open. A genuine CBC-ESSIV keyslot must be refused
// with the typed error: before #106 it was decrypted as XTS and failed as a
// digest mismatch, which an operator cannot tell apart from a wrong passphrase.
func TestConformance_CryptsetupKeyslotCiphers(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	format := func(t *testing.T, keyslotCipher, keyslotKeyBits string) string {
		t.Helper()
		path := newImage(t, "keyslot-cipher.img")
		code, out := runCryptsetup(t, conformancePassphrase,
			"luksFormat", "--type", "luks2",
			"--pbkdf", "pbkdf2",
			"--hash", "sha512",
			"--cipher", "aes-xts-plain64",
			"--key-size", "512",
			"--keyslot-cipher", keyslotCipher,
			"--keyslot-key-size", keyslotKeyBits,
			"--pbkdf-force-iterations", "1000",
			"--batch-mode", path)
		if code != 0 {
			t.Fatalf("cryptsetup luksFormat --keyslot-cipher %s exited %d\n%s", keyslotCipher, code, out)
		}
		// Precondition: cryptsetup itself opens what it wrote.
		if code, out := runCryptsetup(t, conformancePassphrase,
			"luksOpen", "--test-passphrase", "--batch-mode", path); code != 0 {
			t.Fatalf("cryptsetup cannot open its own %s keyslot (exit %d)\n%s", keyslotCipher, code, out)
		}
		_, metadata, err := ReadHeader(path)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}
		if got := metadata.Keyslots["0"].Area.Encryption; got != keyslotCipher {
			t.Fatalf("cryptsetup wrote area.encryption %q, want %q", got, keyslotCipher)
		}
		return path
	}

	for _, spec := range []string{"aes-xts-plain64", "aes-xts-plain"} {
		t.Run(spec+" opens", func(t *testing.T) {
			path := format(t, spec, "512")
			if err := TestKey(path, []byte(conformancePassphrase)); err != nil {
				t.Fatalf("TestKey rejected a cryptsetup %s keyslot with the correct passphrase: %v", spec, err)
			}
			if err := TestKey(path, []byte(conformanceWrongPassphrase)); err == nil {
				t.Fatal("TestKey accepted a WRONG passphrase")
			}
		})
	}

	t.Run("aes-cbc-essiv:sha256 is refused, typed", func(t *testing.T) {
		// CBC takes a plain AES key, so 256 bits rather than XTS's 512;
		// cryptsetup refuses 512 here. The screen refuses on the spec before
		// any key size is consulted.
		path := format(t, "aes-cbc-essiv:sha256", "256")
		err := TestKey(path, []byte(conformancePassphrase))
		if err == nil {
			t.Fatal("a CBC-ESSIV keyslot opened through a reader that only runs XTS")
		}
		if !errors.Is(err, ErrUnsupportedKeyslotCipher) {
			t.Fatalf("refused, but not with ErrUnsupportedKeyslotCipher: %v", err)
		}
	})
}
