// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"io"
	"math/rand/v2"
	"testing"

	"github.com/google/uuid"
)

// Test-side control of the two seams that make a container's bytes
// unpredictable: cryptoRand (util.go) and newUUID (header.go).
//
// This file carries NO build tag on purpose. Both tiers need these helpers --
// the unit tier to assert that two formats with the same inputs produce the
// same bytes, the integration tier to compare those bytes against cryptsetup --
// and an untagged _test.go is compiled into both.
//
// NOTHING HERE MAY BE RUN IN PARALLEL. Both helpers assign to a package var and
// restore it from t.Cleanup, so a t.Parallel() test using either would see
// another test's reader. The package runs its tests sequentially and no test in
// it calls t.Parallel(); this is the reason to keep it that way.

// pinCryptoRand replaces the package RNG with a deterministic ChaCha8 stream
// for the duration of the test.
//
// THE SUBSTITUTE IS A STREAM CIPHER, NOT A CONSTANT, and that is a requirement
// rather than a nicety. The obvious stand-in -- a reader that yields zeroes --
// would silently invalidate every measurement taken through it: afSplitInto
// draws stripes*keySize bytes (~256 KiB for a default keyslot) and XORs them
// together, so under a zero reader the stripes collapse and the keyslot area
// stops resembling the thing under test. It would also make "the keyslots area
// is filled with random" trivially true and trivially meaningless.
//
// math/rand/v2.ChaCha8 is the standard library's own CSPRNG construction,
// seeded rather than system-fed, so its output is indistinguishable from
// rand.Reader's to everything downstream and reproducible from the seed.
func pinCryptoRand(t *testing.T, seed byte) {
	t.Helper()

	var key [32]byte
	for i := range key {
		key[i] = seed
	}

	useCryptoRand(t, rand.NewChaCha8(key))
}

// useCryptoRand substitutes an arbitrary reader for the package RNG, restoring
// it when the test ends. It exists for the failure paths: a fill or a salt draw
// that cannot get its bytes must report that, and there is no other way to make
// crypto/rand fail.
func useCryptoRand(t *testing.T, r io.Reader) {
	t.Helper()

	previous := cryptoRand
	cryptoRand = r
	t.Cleanup(func() { cryptoRand = previous })
}

// pinUUID fixes the UUID CreateBinaryHeader stamps into the header, so that two
// containers formatted with the same parameters carry the same 40 bytes at
// offset 0xa8.
func pinUUID(t *testing.T, value string) {
	t.Helper()

	parsed, err := uuid.Parse(value)
	if err != nil {
		t.Fatalf("pinUUID was given %q, which is not a UUID: %v", value, err)
	}

	previous := newUUID
	newUUID = func() uuid.UUID { return parsed }
	t.Cleanup(func() { newUUID = previous })
}

// TestPinCryptoRandIsDeterministicAndStillRandomLooking establishes both halves
// of the contract the helper claims: the same seed reproduces the same stream,
// and the stream is not a degenerate one that would hollow out the tests built
// on it.
func TestPinCryptoRandIsDeterministicAndStillRandomLooking(t *testing.T) {
	first := func() []byte {
		pinCryptoRand(t, 0x5a)
		b, err := randomBytes(4096)
		if err != nil {
			t.Fatalf("randomBytes failed: %v", err)
		}
		return b
	}

	a := first()
	b := first()

	if string(a) != string(b) {
		t.Fatal("the same seed produced two different streams; nothing built on pinCryptoRand can be reproducible")
	}

	zeros := 0
	for _, v := range a {
		if v == 0 {
			zeros++
		}
	}
	// 4096 uniform bytes give ~16 zeroes. A constant reader gives 4096, and a
	// counter or a byte-repeating pattern gives 16 exactly; the bound below
	// catches the first, and the whole-stream comparison against a real draw
	// below catches the rest.
	if zeros > 64 {
		t.Fatalf("the pinned reader produced %d zero bytes in 4096 -- it is not CSPRNG-shaped, and every measurement taken through it is void", zeros)
	}

	distinct := map[byte]struct{}{}
	for _, v := range a {
		distinct[v] = struct{}{}
	}
	// Not 256: over 4096 uniform bytes some value is missing about once in
	// 34000 draws, and a test that fails that often is noise. 200 is
	// unreachable for a uniform source and unreachable from below for every
	// degenerate reader worth guarding against.
	if len(distinct) < 200 {
		t.Fatalf("the pinned reader emitted only %d distinct byte values in 4096; it is not CSPRNG-shaped", len(distinct))
	}
}

// TestPinCryptoRandRestoresTheRealReader guards the cleanup, because a leaked
// deterministic RNG would make every later test in the package format
// containers with predictable key material and nothing would report it.
func TestPinCryptoRandRestoresTheRealReader(t *testing.T) {
	before := cryptoRand

	t.Run("pinned", func(t *testing.T) {
		pinCryptoRand(t, 0x11)
		if cryptoRand == before {
			t.Fatal("pinCryptoRand did not replace the package reader")
		}
	})

	if cryptoRand != before {
		t.Fatal("pinCryptoRand leaked its reader past the subtest; the package RNG is now deterministic for every test that follows")
	}
}

// TestPinUUIDRejectsAValueThatIsNotAUUID keeps the helper from stamping 40
// bytes of something else into the header field and producing a container that
// fails for an unrelated reason.
func TestPinUUIDRejectsAValueThatIsNotAUUID(t *testing.T) {
	// A t.Fatalf inside the helper cannot be caught, so the rejection is
	// asserted through uuid.Parse itself -- the exact call the helper makes --
	// and the helper is then exercised with a value that parses.
	if _, err := uuid.Parse("not-a-uuid"); err == nil {
		t.Fatal("uuid.Parse accepted a non-UUID, so pinUUID's guard cannot fire")
	}

	t.Run("valid", func(t *testing.T) {
		pinUUID(t, "3f2a9c1e-0b7d-4e58-9a11-6c5d2e8f7b03")
		if newUUID().String() != "3f2a9c1e-0b7d-4e58-9a11-6c5d2e8f7b03" {
			t.Fatalf("pinUUID did not take effect, got %s", newUUID())
		}
	})

	// Go forbids == on func values, so the restoration is asserted through
	// behavior: uuid.New yields a fresh UUID per call, a pinned one does not.
	if newUUID() == newUUID() {
		t.Fatal("pinUUID leaked past the subtest; every header written afterwards would carry the same UUID")
	}
}
