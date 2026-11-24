// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/af"
	"github.com/jeremyhahn/go-luks2/internal/areacipher"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// A digest authenticates only the keyslots it names; verification honors that association.

// twoVolumeKeyContainer writes a container with two unrelated master keys, each keyslot attested only by its own digest.
func twoVolumeKeyContainer(t *testing.T, name string, passA, passB []byte) string {
	t.Helper()

	path := newImage(t, name)
	if err := formatForTest(formatOptionsForTest{
		Device:        path,
		Passphrase:    passA,
		Cipher:        "aes",
		CipherMode:    "xts-plain64",
		KeySize:       512,
		HashAlgo:      "sha256",
		SectorSize:    512,
		KDFType:       kdfTypePBKDF2,
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	hdr, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	reference := metadata.Keyslots["0"]
	if reference == nil {
		t.Fatal("Format did not write keyslot 0")
	}

	// A second volume key, unrelated to the one Format generated.
	rawB, err := randomBytes(reference.KeySize, testVolumeSys().cryptoRand)
	if err != nil {
		t.Fatalf("randomBytes failed: %v", err)
	}
	keyB, err := custody.Adopt("fixture second volume key", rawB)
	if err != nil {
		t.Fatalf("failed to hold the second volume key: %v", err)
	}
	defer mustDestroy(t, keyB)

	writeKeyslot(t, path, hdr, metadata, "1", reference, keyB, passB)

	// Digest 1 attests keyB and names keyslot 1 alone; digest 0 attests keyA and names keyslot 0 alone.
	digestKDF, digestValue, err := createDigest(keyB, "sha256", testVolumeSys())
	if err != nil {
		t.Fatalf("createDigest for the second volume key failed: %v", err)
	}
	metadata.Digests["1"] = &header.Digest{
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
func writeKeyslot(t *testing.T, path string, hdr *header.BinaryHeader, metadata *header.Metadata,
	id string, reference *header.Keyslot, masterKey enclave.ByteAccess, passphrase []byte) {
	t.Helper()

	kdf, err := createKDFStrict(formatOptionsForTest{KDFType: kdfTypePBKDF2, HashAlgo: "sha256", PBKDFIterTime: 1}, reference.KeySize)
	if err != nil {
		t.Fatalf("CreateKDF failed: %v", err)
	}

	passphraseKey, err := deriveKeyEnclave(context.Background(), passphrase, kdf, reference.KeySize, defaultVolumeSys())
	if err != nil {
		t.Fatalf("deriveKeyEnclave failed: %v", err)
	}
	defer mustDestroy(t, passphraseKey)

	afData, err := afCodec(testVolumeSys()).Split(masterKey, af.Params{Stripes: header.AFStripes, Hash: defaultHashAlgo})
	if err != nil {
		t.Fatalf("af Split failed: %v", err)
	}
	defer mustDestroy(t, afData)

	encrypted, err := areacipher.Default().EncryptEnclave(custody, afData, passphraseKey)
	if err != nil {
		t.Fatalf("EncryptEnclave failed: %v", err)
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
	alignedSize := alignTo(int64(len(encrypted)), keyslotAreaAlignment)
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
	metadata.Keyslots[id] = &header.Keyslot{
		Type:     "luks2",
		KeySize:  reference.KeySize,
		Priority: &priority,
		Area: &header.KeyslotArea{
			Type:       "raw",
			KeySize:    reference.KeySize,
			Offset:     formatSize(offset),
			Size:       formatSize(alignedSize),
			Encryption: reference.Area.Encryption,
		},
		KDF: kdf,
		AF: &header.AntiForensic{
			Type:    "luks1",
			Stripes: header.AFStripes,
			Hash:    defaultHashAlgo,
		},
	}
}

// TestADigestCannotAuthenticateAKeyslotItDoesNotName relabels digest 0 to name keyslot 1 and expects keyslot 0 unauthenticated.
func TestADigestCannotAuthenticateAKeyslotItDoesNotName(t *testing.T) {
	defer parallel(t)()

	passA := []byte("the-first-credential")
	passB := []byte("the-second-credential")

	t.Run("each keyslot opens under its own digest", func(t *testing.T) {
		// The positive control, and it is what keeps the mutation below from
		// passing vacuously: an implementation that refused everything would
		// satisfy the mutated case and fail this one.
		path := twoVolumeKeyContainer(t, "binding-control.img", passA, passB)
		_, metadata, err := readHeaderForTest(path)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}

		for _, tc := range []struct{ id, pass string }{{"0", string(passA)}, {"1", string(passB)}} {
			key, err := unlockKeyslot(context.Background(), path, tc.id, []byte(tc.pass), metadata.Keyslots[tc.id], metadata.Digests, testVolumeSys())
			if err != nil {
				t.Fatalf("keyslot %s did not open under its own credential and digest: %v", tc.id, err)
			}
			mustDestroy(t, key)
		}
	})

	t.Run("a keyslot cannot borrow another keyslot's digest", func(t *testing.T) {
		path := twoVolumeKeyContainer(t, "binding-mutated.img", passA, passB)
		hdr, metadata, err := readHeaderForTest(path)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}

		// Digest 0 still holds keyslot 0's master key digest; only the association moves.
		metadata.Digests["0"].Keyslots = []string{"1"}
		if err := writeHeaderUnvalidated(path, hdr, metadata); err != nil {
			t.Fatalf("failed to write the mutated header: %v", err)
		}

		_, mutated, err := readHeaderForTest(path)
		if err != nil {
			t.Fatalf("ReadHeader after mutation failed: %v", err)
		}

		key, err := unlockKeyslot(context.Background(), path, "0", passA, mutated.Keyslots["0"], mutated.Digests, testVolumeSys())
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
		if errors.Is(err, ErrWrongKey) {
			t.Fatalf("a keyslot no digest names was reported as a failed verification: %v", err)
		}

		// And keyslot 1 is unaffected: the refusal above is scoped to the slot
		// whose association was removed, not applied to the whole container.
		key, err = unlockKeyslot(context.Background(), path, "1", passB, mutated.Keyslots["1"], mutated.Digests, testVolumeSys())
		if err != nil {
			t.Fatalf("keyslot 1 stopped opening after keyslot 0 lost its digest: %v", err)
		}
		mustDestroy(t, key)
	})
}
