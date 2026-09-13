// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strconv"
)

// cryptoRand is the source every secret and every random fill in this package
// draws from.
//
// It is a package var rather than a direct rand.Reader reference for one
// reason: without it there is NO way to write a test that formats the same
// container twice and compares the bytes, so "the header this library writes is
// byte-for-byte what cryptsetup writes" cannot be asserted at all -- the salts,
// the UUID and the AF stripes differ on every run. crypto/tls solves the same
// problem the same way with Config.Rand.
//
// It is unexported and has no setter. Nothing outside this package can weaken
// the RNG through it, and the only code that substitutes a reader is this
// package's own tests -- which must supply a CSPRNG-shaped one (a seeded stream
// cipher, not a zero reader): AF-split consumes ~256 KiB per keyslot, and
// feeding it a constant changes the very property under measurement.
var cryptoRand io.Reader = rand.Reader

// clearBytes securely zeros a byte slice
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// randomBytes generates cryptographically secure random bytes
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(cryptoRand, b); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

// randomBase64 generates a base64-encoded random string
// -tags=integration, so `unused` fires on a function the default build exercises.
//
//nolint:unused // Test-only helper: the tests that call it are excluded under
func randomBase64(byteCount int) (string, error) {
	b, err := randomBytes(byteCount)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// parseSize parses a size string (e.g., "512", "4096") to int64
func parseSize(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}

// formatSize formats an int64 size as a string
func formatSize(size int64) string {
	return strconv.FormatInt(size, 10)
}

// alignTo aligns a value to the nearest multiple of alignment
func alignTo(value, alignment int64) int64 {
	if value%alignment == 0 {
		return value
	}
	return ((value / alignment) + 1) * alignment
}

// isPowerOf2 checks if a number is a power of 2
func isPowerOf2(n int) bool {
	return n > 0 && (n&(n-1)) == 0
}

// randomFillChunk is how much random data is generated and written per call in
// writeRandom. It is keyslotWipeChunk (wipe.go), not a second copy of the same
// number, so the two fill loops cannot drift apart.
const randomFillChunk = keyslotWipeChunk

// writeRandom writes size bytes of CSPRNG output at the file's current
// position, in fixed-size chunks.
//
// It is the counterpart of writeZeros and exists for the same reason that one
// chunks: size is derived from a header, and a single make([]byte, size) hands
// an attacker-influenced number to the allocator. Here the argument is stronger
// still -- the largest caller fills the whole unallocated keyslots region, ~16
// MiB on a default container, which is not an allocation worth making at once.
func writeRandom(f *os.File, size int64) error {
	if size <= 0 {
		return nil
	}

	// The buffer is not wiped afterwards. What it holds is the fill that was
	// just written to the device in the clear; it is not key material and
	// clearing it would protect a copy of something already on disk.
	buf := make([]byte, randomFillChunk)

	for remaining := size; remaining > 0; {
		n := int64(len(buf))
		if remaining < n {
			n = remaining
		}
		if _, err := io.ReadFull(cryptoRand, buf[:n]); err != nil {
			return fmt.Errorf("failed to generate random fill: %w", err)
		}
		if _, err := f.Write(buf[:n]); err != nil {
			return err
		}
		remaining -= n
	}
	return nil
}
