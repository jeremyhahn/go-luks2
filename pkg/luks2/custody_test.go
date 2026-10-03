// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"hash"
	"testing"

	"github.com/jeremyhahn/go-enclave"
	"golang.org/x/crypto/xts"
)

// Custody tests.
//
// These do not check that the code runs -- the rest of the suite does that.
// They check WHERE key material lives: that a function hands back a handle to
// locked memory rather than a slice, that a borrow window is closed when the
// borrow returns, that material is released on the failure path as well as the
// success path, and that the locked pages actually go back to the kernel.
//
// A second group pins the rewrites that the enclave work required, against
// reference implementations of the code they replaced. Those rewrites are on
// paths that decide whether a container can be read back at all, so "it still
// round-trips through this package" is not sufficient evidence: the reference
// implementations here are what make a behavioral drift visible.

// legacyDiffuse is the allocating formulation diffuse replaced: accumulate the
// hashed blocks in a fresh slice, then copy it over the input. It is kept here,
// and only here, as the oracle for the in-place rewrite.
func legacyDiffuse(data []byte, hashFunc func() hash.Hash, blockSize int) {
	h := hashFunc()
	digestSize := h.Size()
	numBlocks := blockSize / digestSize

	result := make([]byte, 0, blockSize)

	for i := 0; i < numBlocks; i++ {
		block := data[i*digestSize : (i+1)*digestSize]
		result = append(result, legacyHashBlock(block, h, i)...)
	}

	if remainder := blockSize % digestSize; remainder != 0 {
		lastBlock := data[blockSize-remainder:]
		hashed := legacyHashBlock(lastBlock, h, numBlocks)
		result = append(result, hashed[:remainder]...)
	}

	copy(data, result)
}

// legacyHashBlock is the allocating hashBlock the in-place version replaced.
func legacyHashBlock(block []byte, h hash.Hash, iv int) []byte {
	h.Reset()

	ivBytes := make([]byte, 4)
	ivBytes[0] = byte(iv >> 24)
	ivBytes[1] = byte(iv >> 16)
	ivBytes[2] = byte(iv >> 8)
	ivBytes[3] = byte(iv)
	h.Write(ivBytes)
	h.Write(block)

	return h.Sum(nil)
}

// TestDiffuseInPlaceMatchesTheAllocatingFormulation is the guard on the
// rewrite that removed ~4000 heap copies of diffusion state per operation.
//
// Diffusion feeds every stripe of the AF split, so a single differing byte here
// produces containers this library writes and cannot read -- and, worse,
// containers cryptsetup cannot read either. Round-tripping through this package
// would not catch it, because both directions would drift together.
func TestDiffuseInPlaceMatchesTheAllocatingFormulation(t *testing.T) {
	cases := []struct {
		name      string
		blockSize int
		hashAlgo  string
	}{
		{"sha256 over a 32-byte block", 32, "sha256"},
		{"sha256 over a 64-byte block", 64, "sha256"},
		{"sha512 over a 64-byte block", 64, "sha512"},
		{"sha512 over a 128-byte block", 128, "sha512"},
		// A block that is NOT a multiple of the digest size exercises the
		// remainder path, which is the one branch a real LUKS2 key size never
		// reaches and therefore the one nothing else covers.
		{"sha256 over a 40-byte block", 40, "sha256"},
		{"sha512 over a 100-byte block", 100, "sha512"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hashFunc, err := getHashFunc(tc.hashAlgo)
			if err != nil {
				t.Fatalf("getHashFunc failed: %v", err)
			}

			seed := make([]byte, tc.blockSize)
			if _, err := rand.Read(seed); err != nil {
				t.Fatalf("failed to seed the block: %v", err)
			}

			got := append([]byte(nil), seed...)
			want := append([]byte(nil), seed...)

			diffuse(got, hashFunc, tc.blockSize)
			legacyDiffuse(want, hashFunc, tc.blockSize)

			if !bytes.Equal(got, want) {
				t.Fatalf("in-place diffuse differs from the allocating one:\n got %x\nwant %x", got, want)
			}
			if bytes.Equal(got, seed) {
				t.Fatal("diffuse left the block unchanged, so the comparison above proves nothing")
			}
		})
	}
}

// legacyXtsSectors is the per-sector scratch-buffer loop that xtsSectors
// replaced, kept as the oracle for the in-place rewrite.
func legacyXtsSectors(dst, src, key []byte, sectorSize int, decrypt bool) error {
	xtsCipher, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return err
	}

	numSectors := (len(src) + sectorSize - 1) / sectorSize
	for i := 0; i < numSectors; i++ {
		start := i * sectorSize
		end := start + sectorSize
		if end > len(src) {
			end = len(src)
		}

		sector := make([]byte, sectorSize)
		copy(sector, src[start:end])

		out := make([]byte, sectorSize)
		if decrypt {
			xtsCipher.Decrypt(out, sector, uint64(i))
		} else {
			xtsCipher.Encrypt(out, sector, uint64(i))
		}

		copy(dst[start:end], out[:end-start])
	}

	return nil
}

// TestXtsSectorsMatchesThePerSectorScratchFormulation pins the transform that
// stopped copying every sector through two fresh heap buffers.
//
// The lengths deliberately include one that is NOT a whole number of sectors,
// because that is the only case where the two formulations do anything
// different: the rewrite transforms whole sectors between the caller's buffers
// and keeps the zero-padded scratch path only for a trailing partial sector.
func TestXtsSectorsMatchesThePerSectorScratchFormulation(t *testing.T) {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate a key: %v", err)
	}

	for _, length := range []int{512, 1024, 4096, 100, 600, 1500} {
		t.Run(formatSize(int64(length))+" bytes", func(t *testing.T) {
			src := make([]byte, length)
			if _, err := rand.Read(src); err != nil {
				t.Fatalf("failed to generate plaintext: %v", err)
			}

			got := make([]byte, length)
			want := make([]byte, length)

			if err := xtsSectors(got, src, key, "aes", 512, false); err != nil {
				t.Fatalf("xtsSectors failed: %v", err)
			}
			if err := legacyXtsSectors(want, src, key, 512, false); err != nil {
				t.Fatalf("legacyXtsSectors failed: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("encryption differs from the formulation it replaced")
			}

			// Decryption is checked against the same oracle rather than by
			// round trip, because a round trip is not something this transform
			// can promise for every length -- see
			// TestKeyMaterialTransformDoesNotRoundTripAPartialSector.
			gotBack := make([]byte, length)
			wantBack := make([]byte, length)

			if err := xtsSectors(gotBack, got, key, "aes", 512, true); err != nil {
				t.Fatalf("xtsSectors decrypt failed: %v", err)
			}
			if err := legacyXtsSectors(wantBack, want, key, 512, true); err != nil {
				t.Fatalf("legacyXtsSectors decrypt failed: %v", err)
			}
			if !bytes.Equal(gotBack, wantBack) {
				t.Fatal("decryption differs from the formulation it replaced")
			}

			if length%512 == 0 && !bytes.Equal(gotBack, src) {
				t.Fatal("a whole-sector round trip did not recover the plaintext")
			}
		})
	}
}

// TestKeyMaterialTransformDoesNotRoundTripAPartialSector records a PRE-EXISTING
// limitation rather than asserting a desirable property.
//
// A final sector shorter than 512 bytes is zero-padded to a whole sector before
// the transform, in both directions. On the way out only the first n ciphertext
// bytes are kept; on the way back those n bytes are padded with zeros again,
// which is not the ciphertext that was produced. XTS decrypts each 16-byte
// block independently, so everything past the last whole AES block inside that
// final sector comes back as garbage.
//
// This is not reachable from any LUKS2 path: keyslot material is
// keySize*stripes bytes -- 128000 or 256000 -- both whole numbers of sectors,
// and unlockKeyslot rounds its decryption length UP to a sector boundary
// precisely so it stays that way. It is pinned here so that the limitation is
// recorded where someone reusing these helpers will meet it, and so that a
// future fix is visible as a change in behavior rather than an accident.
func TestKeyMaterialTransformDoesNotRoundTripAPartialSector(t *testing.T) {
	key := mustRandom(t, 64)
	src := mustRandom(t, 600) // one whole sector plus 88 bytes

	enc, err := encryptKeyMaterial(src, key, "aes")
	if err != nil {
		t.Fatalf("encryptKeyMaterial failed: %v", err)
	}

	back, err := decryptKeyMaterial(enc, key, "aes", 512)
	if err != nil {
		t.Fatalf("decryptKeyMaterial failed: %v", err)
	}

	if bytes.Equal(back, src) {
		t.Fatal("the partial-sector round trip now succeeds; this limitation was fixed and the note above is stale")
	}

	// The damage is confined to the tail of the final partial sector: whole AES
	// blocks within it still decrypt correctly.
	const intact = 512 + 80 // 88 bytes of tail, of which 5 whole 16-byte blocks
	if !bytes.Equal(back[:intact], src[:intact]) {
		t.Fatal("the corruption reaches further than the incomplete AES block at the end")
	}
}

func TestXtsSectorsRefusesMismatchedBuffers(t *testing.T) {
	key := make([]byte, 64)

	if err := xtsSectors(make([]byte, 512), make([]byte, 1024), key, "aes", 512, false); err == nil {
		t.Fatal("xtsSectors accepted buffers of different lengths")
	}
	if err := xtsSectors(make([]byte, 512), make([]byte, 512), key, "aes", 0, false); err == nil {
		t.Fatal("xtsSectors accepted a zero sector size")
	}
	if err := xtsSectors(make([]byte, 512), make([]byte, 512), key, "twofish", 512, false); err == nil {
		t.Fatal("xtsSectors accepted an unsupported cipher")
	}
}

func TestDeriveKeyEnclaveAgreesWithTheUnprotectedDerivation(t *testing.T) {
	iterations := 1000
	kdf := &KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       encodeBase64([]byte("a-sixteen-byte!!")),
		Iterations: &iterations,
	}
	passphrase := []byte("custody-test-passphrase")

	held, err := DeriveKeyEnclave(passphrase, kdf, 64)
	if err != nil {
		t.Fatalf("DeriveKeyEnclave failed: %v", err)
	}
	defer mustDestroy(t, held)

	plain, err := deriveKeyPlain(passphrase, kdf, 64)
	if err != nil {
		t.Fatalf("deriveKeyPlain failed: %v", err)
	}
	defer clearBytes(plain)

	// Constant-time comparison inside the enclave: the derived key is never
	// copied out to be checked.
	if !held.EqualTo(plain) {
		t.Fatal("the enclave derivation and the plain one produced different keys")
	}
	if held.Size() != 64 {
		t.Fatalf("derived key holds %d bytes, want 64", held.Size())
	}
}

// TestDeriveKeyEnclaveHandsBackAnEnclaveNotASlice asserts the custody property
// itself rather than the value: what comes back can be DESTROYED, and reading
// it afterwards fails. A []byte return has neither property -- a caller who
// forgets to wipe one gets no error, just a live copy of the key.
func TestDeriveKeyEnclaveHandsBackAnEnclaveNotASlice(t *testing.T) {
	iterations := 1000
	kdf := &KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       encodeBase64([]byte("a-sixteen-byte!!")),
		Iterations: &iterations,
	}

	held, err := DeriveKeyEnclave([]byte("custody-test-passphrase"), kdf, 64)
	if err != nil {
		t.Fatalf("DeriveKeyEnclave failed: %v", err)
	}

	if !held.IsAlive() {
		t.Fatal("the derived key is not in live protected memory")
	}

	mustDestroy(t, held)

	if held.IsAlive() {
		t.Fatal("the derived key survived Destroy")
	}
	if err := held.WithBytes(func([]byte) error { return nil }); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("a destroyed derived key is still readable: %v", err)
	}
	if held.EqualTo(make([]byte, 64)) {
		t.Fatal("a destroyed enclave compared equal to something")
	}
}

func TestDeriveKeySecretKeepsTheInputInsideItsEnclave(t *testing.T) {
	iterations := 1000
	kdf := &KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       encodeBase64([]byte("a-sixteen-byte!!")),
		Iterations: &iterations,
	}

	secret := []byte("a master key that never leaves protected memory!")
	source := enclaveFrom(t, secret)

	derived, err := deriveKeySecret(source, kdf, 32)
	if err != nil {
		t.Fatalf("deriveKeySecret failed: %v", err)
	}
	defer mustDestroy(t, derived)

	// Same answer as deriving from the raw bytes, so routing through the
	// enclave changed custody and nothing else.
	want, err := deriveKeyPlain(secret, kdf, 32)
	if err != nil {
		t.Fatalf("deriveKeyPlain failed: %v", err)
	}
	defer clearBytes(want)

	if !derived.EqualTo(want) {
		t.Fatal("deriving from an enclave produced a different key")
	}

	// The source enclave is untouched: deriveKeySecret borrows, it does not
	// consume.
	if !source.IsAlive() {
		t.Fatal("deriveKeySecret destroyed the enclave it was given")
	}
}

func TestDeriveKeySecretRefusesADestroyedInput(t *testing.T) {
	iterations := 1000
	kdf := &KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       encodeBase64([]byte("a-sixteen-byte!!")),
		Iterations: &iterations,
	}

	source, err := randomSecret("master key", 64)
	if err != nil {
		t.Fatalf("randomSecret failed: %v", err)
	}
	mustDestroy(t, source)

	derived, err := deriveKeySecret(source, kdf, 32)
	if err == nil {
		mustDestroy(t, derived)
		t.Fatal("deriveKeySecret derived from a destroyed enclave")
	}
	if !errors.Is(err, ErrProtectedMemory) {
		t.Fatalf("error does not match ErrProtectedMemory: %v", err)
	}
}

func TestAFSplitEnclaveRoundTripsWithoutLeavingProtectedMemory(t *testing.T) {
	for _, hashAlgo := range []string{"sha256", "sha512"} {
		t.Run(hashAlgo, func(t *testing.T) {
			const stripes = 64

			secret := make([]byte, 64)
			if _, err := rand.Read(secret); err != nil {
				t.Fatalf("failed to generate a secret: %v", err)
			}

			held := enclaveFrom(t, secret)

			split, err := afSplitEnclave(held, stripes, hashAlgo)
			if err != nil {
				t.Fatalf("afSplitEnclave failed: %v", err)
			}
			defer mustDestroy(t, split)

			if split.Size() != len(secret)*stripes {
				t.Fatalf("split holds %d bytes, want %d", split.Size(), len(secret)*stripes)
			}

			// The stripes must not simply be the key repeated or appended: they
			// are the key spread across random material, so no stripe-aligned
			// window may equal it.
			raw := openSecret(t, split)
			for i := 0; i+len(secret) <= len(raw); i += len(secret) {
				if bytes.Equal(raw[i:i+len(secret)], secret) {
					t.Fatalf("the master key appears verbatim at stripe offset %d", i)
				}
			}

			merged, err := afMergeEnclave(split, split.Size(), stripes, len(secret), hashAlgo)
			if err != nil {
				t.Fatalf("afMergeEnclave failed: %v", err)
			}
			defer mustDestroy(t, merged)

			if !merged.EqualTo(secret) {
				t.Fatal("the enclave AF round trip did not recover the secret")
			}
		})
	}
}

// TestAFMergeEnclaveAgreesWithTheUnprotectedMerge pins afMergeEnclave against
// afMergeInto -- the same merge core, run directly over plain slices -- over
// the SAME stripes, which is the only way to compare them: a split draws
// fresh randomness every time, so two splits of one key never match. This
// proves the enclave plumbing (borrowSecret, the locked diffusion buffer)
// does not change the answer relative to computing over ordinary memory.
func TestAFMergeEnclaveAgreesWithTheUnprotectedMerge(t *testing.T) {
	const (
		stripes   = 32
		blockSize = 64
	)

	stripeBytes := make([]byte, blockSize*stripes)
	if _, err := rand.Read(stripeBytes); err != nil {
		t.Fatalf("failed to generate stripes: %v", err)
	}

	hashFunc, err := getHashFunc("sha256")
	if err != nil {
		t.Fatalf("getHashFunc failed: %v", err)
	}

	want := make([]byte, blockSize)
	buffer := make([]byte, blockSize)
	defer clearBytes(buffer)
	afMergeInto(want, stripeBytes, buffer, stripes, blockSize, hashFunc)
	defer clearBytes(want)

	held := enclaveFrom(t, stripeBytes)
	got, err := afMergeEnclave(held, len(stripeBytes), stripes, blockSize, "sha256")
	if err != nil {
		t.Fatalf("afMergeEnclave failed: %v", err)
	}
	defer mustDestroy(t, got)

	if !got.EqualTo(want) {
		t.Fatal("the enclave merge and the plain merge disagree")
	}
}

func TestAFMergeEnclaveRefusesASizeThatIsNotTheSplit(t *testing.T) {
	held := enclaveFrom(t, make([]byte, 64*32))

	// splitLen must be exactly blockSize*stripes; anything else would merge
	// alignment padding into the key.
	if merged, err := afMergeEnclave(held, 64*32, 32, 63, "sha256"); err == nil {
		mustDestroy(t, merged)
		t.Fatal("afMergeEnclave accepted a length that is not blockSize*stripes")
	}
	if merged, err := afMergeEnclave(held, 64*31, 32, 64, "sha256"); err == nil {
		mustDestroy(t, merged)
		t.Fatal("afMergeEnclave accepted a short split length")
	}
}

func TestAFSplitEnclaveRefusesADestroyedSecret(t *testing.T) {
	secret, err := randomSecret("master key", 64)
	if err != nil {
		t.Fatalf("randomSecret failed: %v", err)
	}
	mustDestroy(t, secret)

	split, err := afSplitEnclave(secret, 16, "sha256")
	if err == nil {
		mustDestroy(t, split)
		t.Fatal("afSplitEnclave split a destroyed secret")
	}
	if !errors.Is(err, ErrProtectedMemory) {
		t.Fatalf("error does not match ErrProtectedMemory: %v", err)
	}
}

func TestEncryptAndDecryptKeyMaterialEnclaveRoundTrip(t *testing.T) {
	key := enclaveFrom(t, mustRandom(t, 64))

	plaintext := mustRandom(t, 2048)
	held := enclaveFrom(t, plaintext)

	ciphertext, err := encryptKeyMaterialEnclave(held, key, "aes")
	if err != nil {
		t.Fatalf("encryptKeyMaterialEnclave failed: %v", err)
	}
	defer clearBytes(ciphertext)

	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("the ciphertext equals the plaintext")
	}

	recovered, err := decryptKeyMaterialEnclave(ciphertext, key, "aes", 512)
	if err != nil {
		t.Fatalf("decryptKeyMaterialEnclave failed: %v", err)
	}
	defer mustDestroy(t, recovered)

	// The plaintext comes back INSIDE an enclave -- it is the AF-split master
	// key on a real volume, so it must never be produced as a slice.
	if !recovered.EqualTo(plaintext) {
		t.Fatal("the enclave round trip did not recover the key material")
	}
}

func TestDecryptKeyMaterialEnclaveReleasesOnFailure(t *testing.T) {
	key := enclaveFrom(t, mustRandom(t, 64))

	if _, err := decryptKeyMaterialEnclave(nil, key, "aes", 512); err == nil {
		t.Fatal("decryptKeyMaterialEnclave accepted empty ciphertext")
	}

	before := lockedKiB(t)

	// An unsupported cipher fails AFTER the destination enclave has been
	// allocated, which is exactly the path on which a missed Destroy would leak
	// locked pages that nobody holds a handle to any more.
	for i := 0; i < 32; i++ {
		if _, err := decryptKeyMaterialEnclave(make([]byte, 64<<10), key, "twofish", 512); err == nil {
			t.Fatal("decryptKeyMaterialEnclave accepted an unsupported cipher")
		}
	}

	if after := lockedKiB(t); after > before+lockedSlackKiB {
		t.Fatalf("locked memory grew from %d KiB to %d KiB across 32 failed decryptions", before, after)
	}
}

// TestUnlockKeyslotHoldsTheMasterKeyInProtectedMemory is the end-to-end custody
// assertion: a real container, opened through the real path, must hand back a
// live enclave and nothing else.
func TestUnlockKeyslotHoldsTheMasterKeyInProtectedMemory(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "custody.img")
	formatWithLibrary(t, path)

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	masterKey, err := getMasterKey(path, []byte(conformancePassphrase), metadata)
	if err != nil {
		t.Fatalf("getMasterKey failed: %v", err)
	}

	if !masterKey.IsAlive() {
		t.Fatal("the master key is not in live protected memory")
	}
	if masterKey.Size() != 64 {
		t.Fatalf("master key holds %d bytes, want 64", masterKey.Size())
	}
	// String must not spill the key if the handle is ever logged.
	if s := masterKey.String(); s != "MemoryEnclave(redacted)" {
		t.Fatalf("the master key handle renders as %q", s)
	}

	mustDestroy(t, masterKey)

	if err := masterKey.WithBytes(func([]byte) error { return nil }); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("the master key is still readable after Destroy: %v", err)
	}
}

// TestFailedUnlocksReleaseEveryLockedRegion is the failure-path half.
//
// A wrong passphrase runs the whole of unlockKeyslot -- derivation, a 256 KiB
// locked decryption buffer, an AF merge into another locked region -- and then
// throws all of it away. Nothing returns a handle to the caller on that path,
// so a missed Destroy is invisible except as locked memory that never comes
// back. Sixteen attempts against a real container would strand several
// megabytes if any of them leaked.
func TestFailedUnlocksReleaseEveryLockedRegion(t *testing.T) {
	path := newImage(t, "custody-failure.img")
	formatWithLibrary(t, path)

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	// One warm-up attempt first: the first pass through these paths allocates
	// package-level state that would otherwise be counted as a leak.
	if _, err := getMasterKey(path, []byte(conformanceWrongPassphrase), metadata); err == nil {
		t.Fatal("a wrong passphrase opened the volume")
	}

	before := lockedKiB(t)

	// Four rounds, not sixteen. The signal is the SIZE of a leaked region, not
	// the count: each failed unlock locks a 256 KiB stripe buffer and the
	// tolerance below is one page, so a single leak is sixty-four times the
	// threshold and one round would show it. Sixteen rounds cost 86 seconds on
	// a CI runner and bought nothing the fourth did not.
	const attempts = 4
	for i := 0; i < attempts; i++ {
		key, err := getMasterKey(path, []byte(conformanceWrongPassphrase), metadata)
		if err == nil {
			mustDestroy(t, key)
			t.Fatal("a wrong passphrase opened the volume")
		}
	}

	if after := lockedKiB(t); after > before+lockedSlackKiB {
		t.Fatalf("locked memory grew from %d KiB to %d KiB across %d failed unlocks", before, after, attempts)
	}
}

// TestSuccessfulUnlocksReleaseEveryLockedRegion is the same assertion for the
// path that succeeds: the intermediate stripes and derived keys must be gone
// once the caller destroys the one handle it was given.
func TestSuccessfulUnlocksReleaseEveryLockedRegion(t *testing.T) {
	path := newImage(t, "custody-success.img")
	formatWithLibrary(t, path)

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	key, err := getMasterKey(path, []byte(conformancePassphrase), metadata)
	if err != nil {
		t.Fatalf("getMasterKey failed: %v", err)
	}
	mustDestroy(t, key)

	before := lockedKiB(t)

	// Three rounds, for the reason given in the failed-unlock test above.
	const attempts = 3
	for i := 0; i < attempts; i++ {
		key, err := getMasterKey(path, []byte(conformancePassphrase), metadata)
		if err != nil {
			t.Fatalf("getMasterKey failed: %v", err)
		}
		mustDestroy(t, key)
	}

	if after := lockedKiB(t); after > before+lockedSlackKiB {
		t.Fatalf("locked memory grew from %d KiB to %d KiB across %d unlocks", before, after, attempts)
	}
}

// TestUnlockKeyslotRefusesAnAbsurdKeyslotArea covers the bound that keeps a
// hostile header from asking for an unbounded locked allocation. Locked memory
// is process-wide and rlimited, so an unbounded request would not merely fail
// this unlock -- it would starve every other one in the process.
func TestUnlockKeyslotRefusesAnAbsurdKeyslotArea(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "custody-absurd-area.img")
	formatWithLibrary(t, path)

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	keyslot := metadata.Keyslots["0"]
	if keyslot == nil {
		t.Fatal("fixture precondition: keyslot 0 is missing")
	}

	for _, size := range []string{"0", "-1", formatSize(maxKeyslotAreaSize + 1)} {
		t.Run(size, func(t *testing.T) {
			original := keyslot.Area.Size
			keyslot.Area.Size = size
			defer func() { keyslot.Area.Size = original }()

			key, err := unlockKeyslot(path, "0", []byte(conformancePassphrase), keyslot, metadata.Digests)
			if err == nil {
				mustDestroy(t, key)
				t.Fatalf("unlockKeyslot accepted a keyslot area of %s bytes", size)
			}
			// ErrInvalidKeyslot, not ErrInvalidHeader: damage to one keyslot
			// must let the scan move on to the others.
			if !errors.Is(err, ErrInvalidKeyslot) {
				t.Fatalf("error does not match ErrInvalidKeyslot: %v", err)
			}
		})
	}
}

// TestRecoveryKeyIsHeldInProtectedMemory guards the part of a recovery key that
// is easiest to leave behind: the printable form, which used to be a plain Go
// string that could never be wiped -- and which is now the credential itself.
func TestRecoveryKeyIsHeldInProtectedMemory(t *testing.T) {
	key, err := GenerateRecoveryKey(32, RecoveryKeyFormatDashed)
	if err != nil {
		t.Fatalf("GenerateRecoveryKey failed: %v", err)
	}
	defer key.Clear()

	if !key.Credential.IsAlive() {
		t.Fatal("the credential is not in live protected memory")
	}

	// What is displayed is the credential, byte for byte. Anything else means
	// the string an operator writes down is not the string the keyslot holds.
	rendered, err := key.FormattedString()
	if err != nil {
		t.Fatalf("FormattedString failed: %v", err)
	}
	if !key.Credential.EqualTo([]byte(rendered)) {
		t.Fatal("the displayed string is not the credential")
	}

	typed, err := RecoveryCredential(rendered)
	if err != nil {
		t.Fatalf("RecoveryCredential failed: %v", err)
	}
	defer mustDestroy(t, typed)

	if !key.Credential.EqualTo(openSecret(t, typed)) {
		t.Fatal("typing the displayed string back does not reproduce the credential")
	}
}

func TestRecoveryKeyRenderingRoundTripsInEveryFormat(t *testing.T) {
	for _, format := range []RecoveryKeyFormat{RecoveryKeyFormatHex, RecoveryKeyFormatBase64, RecoveryKeyFormatDashed} {
		t.Run(string(format), func(t *testing.T) {
			key, err := GenerateRecoveryKey(32, format)
			if err != nil {
				t.Fatalf("GenerateRecoveryKey failed: %v", err)
			}
			defer key.Clear()

			if key.Credential.Size() != formattedLen(32, format) {
				t.Fatalf("credential holds %d bytes, want %d", key.Credential.Size(), formattedLen(32, format))
			}

			rendered, err := key.FormattedString()
			if err != nil {
				t.Fatalf("FormattedString failed: %v", err)
			}

			typed, err := RecoveryCredential(rendered)
			if err != nil {
				t.Fatalf("RecoveryCredential(%q) failed: %v", rendered, err)
			}
			defer mustDestroy(t, typed)

			if !key.Credential.EqualTo(openSecret(t, typed)) {
				t.Fatalf("the %s credential does not survive being typed back", format)
			}

			// The credential is still a faithful rendering of 32 random bytes,
			// which is where its strength comes from. Nothing depends on the
			// decode any more, but if it ever stopped decoding to 32 bytes the
			// generator would be producing something other than what it claims.
			decoded, err := ParseRecoveryKey(rendered)
			if err != nil {
				t.Fatalf("ParseRecoveryKey(%q) failed: %v", rendered, err)
			}
			defer mustDestroy(t, decoded)

			if decoded.Size() != 32 {
				t.Fatalf("the %s rendering decodes to %d bytes, want 32", format, decoded.Size())
			}
		})
	}
}

func mustRandom(t *testing.T, n int) []byte {
	t.Helper()

	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("failed to generate %d random bytes: %v", n, err)
	}
	return b
}
