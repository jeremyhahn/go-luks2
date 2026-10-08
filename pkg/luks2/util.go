// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/jeremyhahn/go-luks2/internal/af"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/kdf"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// custody is where this package's key material is allocated and released:
// secret.System, every enclave admitted through go-enclave's process
// Allocator. It is a variable only so the fail-closed tests can stand in a
// custody that refuses, or one that measures; nothing in the package changes
// it.
var custody = secret.System()

// afCodec is the anti-forensic codec this package splits and merges with: its
// custody, its randomness and its FIPS mode, read at the call so a test that
// substitutes one of them is honored.
func afCodec(sys volumeSys) af.Codec {
	return af.Codec{Custody: custody, Rand: sys.cryptoRand, FIPS: sys.fipsMode()}
}

// kdfDeriver builds the internal/kdf.Deriver each KDF call runs through,
// reading the same custody and FIPS seams afCodec does.
func kdfDeriver(sys volumeSys) kdf.Deriver {
	return kdf.Deriver{Custody: sys.custody, FIPS: sys.fipsMode()}
}

// clearBytes securely zeros a byte slice. The clear builtin is a memclr the
// compiler cannot drop: the slice's memory outlives the call.
func clearBytes(b []byte) {
	clear(b)
}

// randomBytes generates cryptographically secure random bytes
func randomBytes(n int, cryptoRand io.Reader) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(cryptoRand, b); err != nil {
		return nil, &errs.Error{Kind: errs.ErrIO, Detail: "failed to generate random bytes", Err: err}
	}
	return b, nil
}

// randomBase64 generates a base64-encoded random string
// -tags=integration, so `unused` fires on a function the default build exercises.
//
//nolint:unused // Test-only helper: the tests that call it are excluded under
func randomBase64(byteCount int, cryptoRand io.Reader) (string, error) {
	b, err := randomBytes(byteCount, cryptoRand)
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
// It is the counterpart of zeroRange (wipe.go) and exists for the same reason that one
// chunks: size is derived from a header, and a single make([]byte, size) hands
// an attacker-influenced number to the allocator. Here the argument is stronger
// still -- the largest caller fills the whole unallocated keyslots region, ~16
// MiB on a default container, which is not an allocation worth making at once.
func writeRandom(ctx context.Context, f *os.File, size int64, cryptoRand io.Reader) error {
	if size <= 0 {
		return nil
	}

	// The buffer is not wiped afterwards. What it holds is the fill that was
	// just written to the device in the clear; it is not key material and
	// clearing it would protect a copy of something already on disk.
	buf := make([]byte, randomFillChunk)

	var written int64
	for remaining := size; remaining > 0; {
		// Checked per chunk (DESIGN.md §D.2), so a cancellation is observed
		// between writes rather than only before the first or after the last.
		if err := ctx.Err(); err != nil {
			return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: fmt.Sprintf("canceled after writing %d of %d bytes", written, size), Err: err}
		}
		n := int64(len(buf))
		if remaining < n {
			n = remaining
		}
		if _, err := io.ReadFull(cryptoRand, buf[:n]); err != nil {
			return &errs.Error{Kind: errs.ErrIO, Detail: "failed to generate random fill", Err: err}
		}
		if _, err := f.Write(buf[:n]); err != nil {
			return err
		}
		written += n
		remaining -= n
	}
	return nil
}
