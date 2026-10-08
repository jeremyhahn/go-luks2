// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package af

import (
	"bytes"
	"crypto/rand"
	"errors"
	"hash"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

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
			hashFunc, err := writeHash(tc.hashAlgo)
			if err != nil {
				t.Fatalf("writeHash failed: %v", err)
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

func TestSplitRoundTripsWithoutLeavingProtectedMemory(t *testing.T) {
	for _, hashAlgo := range []string{"sha256", "sha512"} {
		t.Run(hashAlgo, func(t *testing.T) {
			const stripes = 64

			key := make([]byte, 64)
			if _, err := rand.Read(key); err != nil {
				t.Fatalf("failed to generate a key: %v", err)
			}

			held := enclaveFrom(t, key)

			split, err := testCodec.Split(held, Params{Stripes: stripes, Hash: hashAlgo})
			if err != nil {
				t.Fatalf("Split failed: %v", err)
			}
			defer mustDestroy(t, split)

			if split.Size() != len(key)*stripes {
				t.Fatalf("split holds %d bytes, want %d", split.Size(), len(key)*stripes)
			}

			// The stripes must not simply be the key repeated or appended: they
			// are the key spread across random material, so no stripe-aligned
			// window may equal it.
			raw := openSecret(t, split)
			for i := 0; i+len(key) <= len(raw); i += len(key) {
				if bytes.Equal(raw[i:i+len(key)], key) {
					t.Fatalf("the master key appears verbatim at stripe offset %d", i)
				}
			}

			merged, err := testCodec.Merge(split, len(key), Params{Stripes: stripes, Hash: hashAlgo})
			if err != nil {
				t.Fatalf("Merge failed: %v", err)
			}
			defer mustDestroy(t, merged)

			if ok, err := merged.EqualTo(key); err != nil || !ok {
				t.Fatal("the enclave AF round trip did not recover the key")
			}
		})
	}
}

// TestMergeAgreesWithTheUnprotectedMerge pins Merge against mergeInto -- the
// same merge core, run directly over plain slices -- over the SAME stripes,
// which is the only way to compare them: a split draws fresh randomness every
// time, so two splits of one key never match. This proves the enclave
// plumbing (secret.Borrow, the locked diffusion buffer) does not change the
// answer relative to computing over ordinary memory.
func TestMergeAgreesWithTheUnprotectedMerge(t *testing.T) {
	const (
		stripes   = 32
		blockSize = 64
	)

	stripeBytes := make([]byte, blockSize*stripes)
	if _, err := rand.Read(stripeBytes); err != nil {
		t.Fatalf("failed to generate stripes: %v", err)
	}

	hashFunc, err := writeHash("sha256")
	if err != nil {
		t.Fatalf("writeHash failed: %v", err)
	}

	want := make([]byte, blockSize)
	buffer := make([]byte, blockSize)
	defer clear(buffer)
	mergeInto(want, stripeBytes, buffer, stripes, blockSize, hashFunc)
	defer clear(want)

	held := enclaveFrom(t, stripeBytes)
	got, err := testCodec.Merge(held, blockSize, Params{Stripes: stripes, Hash: "sha256"})
	if err != nil {
		t.Fatalf("Merge failed: %v", err)
	}
	defer mustDestroy(t, got)

	if ok, err := got.EqualTo(want); err != nil || !ok {
		t.Fatal("the enclave merge and the plain merge disagree")
	}
}

func TestSplitRefusesADestroyedKey(t *testing.T) {
	key, err := secret.System().Random("master key", 64, rand.Reader)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}
	mustDestroy(t, key)

	split, err := testCodec.Split(key, Params{Stripes: 16, Hash: "sha256"})
	if err == nil {
		mustDestroy(t, split)
		t.Fatal("Split split a destroyed key")
	}
	if !errors.Is(err, secret.ErrProtectedMemory) {
		t.Fatalf("error does not match ErrProtectedMemory: %v", err)
	}
}

// TestHashTables: the split writes sha256 and sha512 only; the merge also
// reads sha1, except in FIPS mode, where it refuses with fips.ErrNotApproved
// before any hashing; the structural check accepts sha1 in any mode and
// nothing unknown.
func TestHashTables(t *testing.T) {
	outside := Codec{FIPS: false}
	inFIPS := Codec{FIPS: true}
	for _, name := range []string{"sha256", "sha512"} {
		if err := ValidateWriteHash(name); err != nil {
			t.Fatalf("split %s: %v", name, err)
		}
		if _, err := inFIPS.mergeHash(name); err != nil {
			t.Fatalf("merge %s: %v", name, err)
		}
	}
	if err := ValidateWriteHash("sha1"); !errors.Is(err, errs.ErrUnsupportedHash) || !errors.Is(err, errs.ErrSHA1NotWritten) {
		t.Fatalf("split sha1: got %v, want ErrUnsupportedHash carrying ErrSHA1NotWritten", err)
	}
	for _, name := range []string{"md5", "sha384", ""} {
		if err := ValidateReadHash(name); !errors.Is(err, errs.ErrUnsupportedHash) {
			t.Fatalf("readable %q: got %v, want ErrUnsupportedHash", name, err)
		}
		if _, err := outside.mergeHash(name); !errors.Is(err, errs.ErrUnsupportedHash) {
			t.Fatalf("merge %q: got %v, want ErrUnsupportedHash", name, err)
		}
	}
	if err := ValidateReadHash("sha1"); err != nil {
		t.Fatalf("readable sha1: %v", err)
	}
	if h, err := outside.mergeHash("sha1"); err != nil || h().Size() != 20 {
		t.Fatalf("merge sha1 outside FIPS mode: %v", err)
	}
	if _, err := inFIPS.mergeHash("sha1"); !errors.Is(err, fips.ErrNotApproved) {
		t.Fatalf("merge sha1 in FIPS mode: got %v, want fips.ErrNotApproved", err)
	}
	if err := RequireApprovedHash(true, "sha1"); !errors.Is(err, fips.ErrNotApproved) {
		t.Fatalf("RequireApprovedHash(sha1) in FIPS mode = %v", err)
	}
	if err := RequireApprovedHash(false, "sha1"); err != nil {
		t.Fatalf("RequireApprovedHash(sha1) outside FIPS mode = %v", err)
	}
}

// TestSplitReportsAFailedDraw: a split whose randomness fails leaves no
// stripes behind.
func TestSplitReportsAFailedDraw(t *testing.T) {
	broken := errors.New("entropy source unavailable")
	c := testCodec
	c.Rand = failingReader{broken}
	split, err := c.Split(enclaveFrom(t, make([]byte, 32)), Params{Stripes: 4, Hash: "sha256"})
	if err == nil {
		mustDestroy(t, split)
		t.Fatal("Split succeeded from a reader that fails")
	}
	if !errors.Is(err, broken) {
		t.Fatalf("Split = %v, want the reader's failure", err)
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }
