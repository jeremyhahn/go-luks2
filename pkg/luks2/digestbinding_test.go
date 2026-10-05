// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"os"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// A LUKS2 digest states WHICH keyslots it authenticates, and honoring that is
// what makes verification verify anything.
//
// A container can hold more than one volume key at a time -- that is the
// ordinary state of one being reencrypted -- and each digest attests exactly
// one of them, naming the keyslots that unwrap it. A scan that tried every
// digest against a key recovered from ONE keyslot accepted that key on the
// strength of an attestation made about a DIFFERENT keyslot: the unlock would
// then hand the caller a key it believed was authenticated for this keyslot's
// segments, and KillSlot would authorize a destructive change through an
// association the header never made.
//
// The header is attacker-controlled input in this package, and the "keyslots"
// array is part of it. Filtering on it does not make the digest trustworthy; it
// makes the code stop claiming an authentication the header does not assert.

// twoVolumeKeyContainer writes a container holding TWO unrelated master keys:
// keyslot 0 wraps keyA under passphrase A and is attested by digest 0, keyslot
// 1 wraps keyB under passphrase B and is attested by digest 1. Neither digest
// names the other's keyslot.
//
// This is the shape the strict association exists for and it cannot be
// simulated with one master key: with a single key, every digest in the header
// attests the same bytes, so a scan that ignored the association would reach
// the same verdict as one that honored it and the fixture would prove nothing.
func twoVolumeKeyContainer(t *testing.T, name string, passA, passB []byte) string {
	t.Helper()

	path := newImage(t, name)
	if err := Format(FormatOptions{
		Device:        path,
		Passphrase:    passA,
		Cipher:        "aes",
		CipherMode:    "xts-plain64",
		KeySize:       512,
		HashAlgo:      "sha256",
		SectorSize:    512,
		KDFType:       KDFTypePBKDF2,
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	reference := metadata.Keyslots["0"]
	if reference == nil {
		t.Fatal("Format did not write keyslot 0")
	}

	// A second volume key, unrelated to the one Format generated.
	rawB, err := randomBytes(reference.KeySize)
	if err != nil {
		t.Fatalf("randomBytes failed: %v", err)
	}
	keyB, err := adoptSecret("fixture second volume key", rawB)
	if err != nil {
		t.Fatalf("failed to hold the second volume key: %v", err)
	}
	defer mustDestroy(t, keyB)

	writeKeyslot(t, path, hdr, metadata, "1", reference, keyB, passB)

	// Digest 1 attests keyB and names keyslot 1 ALONE. Digest 0, written by
	// Format, attests keyA and names keyslot 0 alone.
	digestKDF, digestValue, err := createDigest(keyB, "sha256")
	if err != nil {
		t.Fatalf("createDigest for the second volume key failed: %v", err)
	}
	metadata.Digests["1"] = &Digest{
		Type:       "pbkdf2",
		Keyslots:   []string{"1"},
		Segments:   []string{"0"},
		Hash:       digestKDF.Hash,
		Iterations: *digestKDF.Iterations,
		Salt:       digestKDF.Salt,
		Digest:     digestValue,
	}

	if err := writeHeaderInternal(path, hdr, metadata); err != nil {
		t.Fatalf("failed to write the two-volume-key header: %v", err)
	}
	return path
}

// writeKeyslot adds a keyslot with the given ID that wraps masterKey under
// passphrase, updating metadata in place. It does NOT touch the digests: which
// digest attests the slot is the thing under test here, so the caller states it
// explicitly rather than having this helper decide.
func writeKeyslot(t *testing.T, path string, hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata,
	id string, reference *Keyslot, masterKey *enclave.MemoryEnclave, passphrase []byte) {
	t.Helper()

	kdf, err := CreateKDF(FormatOptions{KDFType: KDFTypePBKDF2, HashAlgo: "sha256", PBKDFIterTime: 1}, reference.KeySize)
	if err != nil {
		t.Fatalf("CreateKDF failed: %v", err)
	}

	passphraseKey, err := DeriveKeyEnclave(passphrase, kdf, reference.KeySize)
	if err != nil {
		t.Fatalf("DeriveKeyEnclave failed: %v", err)
	}
	defer mustDestroy(t, passphraseKey)

	afData, err := afSplitEnclave(masterKey, AFStripes, DefaultHashAlgo)
	if err != nil {
		t.Fatalf("afSplitEnclave failed: %v", err)
	}
	defer mustDestroy(t, afData)

	encrypted, err := encryptKeyMaterialEnclave(afData, passphraseKey, DefaultCipher)
	if err != nil {
		t.Fatalf("encryptKeyMaterialEnclave failed: %v", err)
	}
	defer clearBytes(encrypted)

	keyslotsStart, keyslotsEnd, err := keyslotsAreaBounds(hdr, metadata)
	if err != nil {
		t.Fatalf("keyslotsAreaBounds failed: %v", err)
	}
	offset, err := calculateNextKeyslotOffset(metadata, keyslotsStart)
	if err != nil {
		t.Fatalf("calculateNextKeyslotOffset failed: %v", err)
	}
	alignedSize := alignTo(int64(len(encrypted)), KeyslotAreaAlignment)
	if offset+alignedSize > keyslotsEnd {
		t.Fatalf("the fixture keyslot would end at %d, past the keyslots area end %d", offset+alignedSize, keyslotsEnd)
	}

	f, err := os.OpenFile(path, os.O_WRONLY, 0o600) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the image for writing: %v", err)
	}
	if _, err := f.WriteAt(encrypted, offset); err != nil {
		_ = f.Close()
		t.Fatalf("failed to write the fixture keyslot area: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close the image: %v", err)
	}

	priority := 1
	metadata.Keyslots[id] = &Keyslot{
		Type:     "luks2",
		KeySize:  reference.KeySize,
		Priority: &priority,
		Area: &KeyslotArea{
			Type:       "raw",
			KeySize:    reference.KeySize,
			Offset:     formatSize(offset),
			Size:       formatSize(alignedSize),
			Encryption: reference.Area.Encryption,
		},
		KDF: kdf,
		AF: &AntiForensic{
			Type:    "luks1",
			Stripes: AFStripes,
			Hash:    DefaultHashAlgo,
		},
	}
}

// TestADigestCannotAuthenticateAKeyslotItDoesNotName is the regression test for
// the cross-slot verification.
//
// The discriminating mutation is one field: digest 0 keeps the value that
// matches keyslot 0's master key and is RELABELLED to name keyslot 1 instead.
// Nothing about the key material changes, so a scan that tries every digest
// still finds a match and reports keyslot 0 as authenticated -- on the strength
// of a digest the header says belongs to another slot.
func TestADigestCannotAuthenticateAKeyslotItDoesNotName(t *testing.T) {
	defer parallel(t)()

	passA := []byte("the-first-credential")
	passB := []byte("the-second-credential")

	t.Run("each keyslot opens under its own digest", func(t *testing.T) {
		// The positive control, and it is what keeps the mutation below from
		// passing vacuously: an implementation that refused everything would
		// satisfy the mutated case and fail this one.
		path := twoVolumeKeyContainer(t, "binding-control.img", passA, passB)
		_, metadata, err := ReadHeader(path)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}

		for _, tc := range []struct{ id, pass string }{{"0", string(passA)}, {"1", string(passB)}} {
			key, err := unlockKeyslot(path, tc.id, []byte(tc.pass), metadata.Keyslots[tc.id], metadata.Digests)
			if err != nil {
				t.Fatalf("keyslot %s did not open under its own credential and digest: %v", tc.id, err)
			}
			mustDestroy(t, key)
		}
	})

	t.Run("a keyslot cannot borrow another keyslot's digest", func(t *testing.T) {
		path := twoVolumeKeyContainer(t, "binding-mutated.img", passA, passB)
		hdr, metadata, err := ReadHeader(path)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}

		// Digest 0 still holds the digest OF KEYSLOT 0's master key. Only the
		// association moves.
		metadata.Digests["0"].Keyslots = []string{"1"}
		if err := writeHeaderUnvalidated(path, hdr, metadata); err != nil {
			t.Fatalf("failed to write the mutated header: %v", err)
		}

		_, mutated, err := ReadHeader(path)
		if err != nil {
			t.Fatalf("ReadHeader after mutation failed: %v", err)
		}

		key, err := unlockKeyslot(path, "0", passA, mutated.Keyslots["0"], mutated.Digests)
		if err == nil {
			mustDestroy(t, key)
			t.Fatal("keyslot 0 authenticated against a digest the header associates only with keyslot 1")
		}
		// A header fault, not a credential verdict: the passphrase was right and
		// the key material was intact. What is broken is the container's own
		// statement about which digest attests this slot.
		if !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("a keyslot no digest names is not reported as a header fault: %v", err)
		}
		if errors.Is(err, ErrMasterKeyVerification) {
			t.Fatalf("a keyslot no digest names was reported as a failed verification: %v", err)
		}

		// And keyslot 1 is unaffected: the refusal above is scoped to the slot
		// whose association was removed, not applied to the whole container.
		key, err = unlockKeyslot(path, "1", passB, mutated.Keyslots["1"], mutated.Digests)
		if err != nil {
			t.Fatalf("keyslot 1 stopped opening after keyslot 0 lost its digest: %v", err)
		}
		mustDestroy(t, key)
	})
}
