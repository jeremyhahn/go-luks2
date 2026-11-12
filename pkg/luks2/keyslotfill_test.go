// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// Tests for what occupies the keyslots area where no key material does.
//
// The property under test is INDISTINGUISHABILITY, not secrecy. Encrypted
// AF-split key material is indistinguishable from random; a zeroed region is
// distinguishable from all of it at a glance. So a container whose unused and
// freed keyslot ranges are zero publishes, to anyone holding the drive, how
// many credentials it has, where they sit and which slots were destroyed --
// none of which any keyslot's encryption was ever asked to hide. cryptsetup
// fills both ranges with random; so does this package now.
//
// These tests measure the FILL, not the RNG. The population statistics they
// assert on are the ones a zero fill, a constant fill or a truncated fill all
// fail; they are not a randomness test and are not offered as one.

// entropyOf reports the distinct-byte count and the longest run of zeroes in b.
// Both are cheap and both separate "random" from every failure mode that
// actually occurs here -- a zero fill, a repeated byte, a short write that left
// the tail untouched.
func entropyOf(b []byte) (distinct, longestZeroRun int) {
	var seen [256]bool
	run := 0
	for _, v := range b {
		seen[v] = true
		if v == 0 {
			run++
			if run > longestZeroRun {
				longestZeroRun = run
			}
		} else {
			run = 0
		}
	}
	for _, ok := range seen {
		if ok {
			distinct++
		}
	}
	return distinct, longestZeroRun
}

// minRandomFillBytes is the smallest range requireRandomFill will judge. Below
// it the population statistics stop separating a real fill from an unlucky one.
const minRandomFillBytes = 2048

// minDistinctBytes is the alphabet a filled range must use.
//
// It is 200 and not 256 ON PURPOSE. Over n uniform bytes the expected number of
// values NEVER drawn is 256*(255/256)^n -- 0.086 at n = 2048 -- so "all 256
// appeared" is a coin flip at these sizes and a test asserting it is a flake
// waiting to happen (it flaked on the 2048-byte keyslot tail the first time it
// ran). 200 is far enough below the mean that a uniform source cannot reach it,
// and far enough above the alphabets the real defects produce -- 1 for a zero
// or constant fill, a handful for a pattern -- to catch every one of them.
const minDistinctBytes = 200

// requireRandomFill fails when b does not look like CSPRNG output.
//
// The zero-run bound is the load-bearing one. 4096 consecutive zeroes have
// probability 256^-4096 under a uniform source, so the bound never fires by
// chance, while it fires immediately on a region the fill never reached -- and
// a short write is the realistic defect, not a weak RNG.
func requireRandomFill(t *testing.T, what string, b []byte) {
	t.Helper()

	if len(b) < minRandomFillBytes {
		t.Fatalf("%s: %d bytes is too short to judge; requireRandomFill needs at least %d", what, len(b), minRandomFillBytes)
	}

	distinct, longestZeroRun := entropyOf(b)
	if distinct < minDistinctBytes {
		t.Errorf("%s: only %d distinct byte values across %d bytes, want at least %d", what, distinct, len(b), minDistinctBytes)
	}
	if longestZeroRun >= 4096 {
		t.Errorf("%s: a run of %d zero bytes; that range was never filled", what, longestZeroRun)
	}
}

func TestWriteRandomFillsExactlyTheRequestedRange(t *testing.T) {
	const (
		prefix = 512
		fill   = 128 * 1024 // spans several randomFillChunk writes
		suffix = 512
	)

	path := filepath.Join(t.TempDir(), "fill.img")
	image := bytes.Repeat([]byte{0xa5}, prefix+fill+suffix)
	if err := os.WriteFile(path, image, 0600); err != nil {
		t.Fatalf("failed to create the image: %v", err)
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0600) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the image: %v", err)
	}
	if _, err := f.Seek(prefix, 0); err != nil {
		t.Fatalf("seek failed: %v", err)
	}
	if err := writeRandom(context.Background(), f, fill, testVolumeSys().cryptoRand); err != nil {
		t.Fatalf("writeRandom failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	got, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to read the image back: %v", err)
	}
	if len(got) != len(image) {
		t.Fatalf("the file is now %d bytes, was %d; writeRandom wrote past its range", len(got), len(image))
	}
	if !bytes.Equal(got[:prefix], image[:prefix]) {
		t.Error("writeRandom overwrote bytes before the seek position")
	}
	if !bytes.Equal(got[prefix+fill:], image[prefix+fill:]) {
		t.Error("writeRandom overwrote bytes past the requested size")
	}
	requireRandomFill(t, "the filled range", got[prefix:prefix+fill])
}

func TestWriteRandomWritesNothingForANonPositiveSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.img")
	original := bytes.Repeat([]byte{0x5a}, 1024)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatalf("failed to create the image: %v", err)
	}

	for _, size := range []int64{0, -1, -4096} {
		f, err := os.OpenFile(path, os.O_RDWR, 0600) // #nosec G304 -- path is under t.TempDir()
		if err != nil {
			t.Fatalf("failed to open the image: %v", err)
		}
		err = writeRandom(context.Background(), f, size, testVolumeSys().cryptoRand)
		_ = f.Close()
		if err != nil {
			t.Fatalf("writeRandom(%d) returned %v, want nil", size, err)
		}

		got, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir()
		if err != nil {
			t.Fatalf("failed to read the image back: %v", err)
		}
		if !bytes.Equal(got, original) {
			t.Fatalf("writeRandom(%d) modified the file", size)
		}
	}
}

// TestWriteRandomCancelledBeforeTheFirstChunkWritesNothing pins that a
// random fill checks ctx per 1 MiB chunk: ctx is checked before every chunk,
// including the first, so a ctx already canceled leaves the file untouched
// and reports ctx.Err()'s kind with how many bytes were written (zero).
func TestWriteRandomCancelledBeforeTheFirstChunkWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "canceled.img")
	original := bytes.Repeat([]byte{0x5a}, 256*1024)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatalf("failed to create the image: %v", err)
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0600) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the image: %v", err)
	}
	defer func() { _ = f.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = writeRandom(ctx, f, int64(len(original)), testVolumeSys().cryptoRand)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("writeRandom with an already-canceled ctx = %v, want context.Canceled", err)
	}
	if !strings.Contains(err.Error(), "0 of") {
		t.Errorf("writeRandom canceled before any chunk = %q, want it to say 0 bytes were written", err)
	}

	got, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to read the image back: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("writeRandom with an already-canceled ctx modified the file")
	}
}

// cancelAfterChecks is a context whose Err reports context.Canceled from its
// (n+1)th call on, so a loop that checks ctx once per chunk is cancelled
// after exactly n chunks.
type cancelAfterChecks struct {
	context.Context
	n, calls int
}

func (c *cancelAfterChecks) Err() error {
	c.calls++
	if c.calls > c.n {
		return context.Canceled
	}
	return nil
}

// TestFormatFillAndHeaderWipeObserveCancellationPerChunk pins the last row of
// the cancellation table: the random fill and the header wipe check ctx per
// 64 KiB chunk, so a cancellation after the first chunk stops both with one
// chunk written and the rest untouched, and the cancelled fill names the
// bytes it wrote in Detail.
func TestFormatFillAndHeaderWipeObserveCancellationPerChunk(t *testing.T) {
	const size = 4 * keyslotWipeChunk
	open := func(t *testing.T) *os.File {
		path := filepath.Join(t.TempDir(), "chunks.img")
		if err := os.WriteFile(path, bytes.Repeat([]byte{0x5a}, size), 0600); err != nil {
			t.Fatalf("failed to create the image: %v", err)
		}
		f, err := os.OpenFile(path, os.O_RDWR, 0600) // #nosec G304 -- path is under t.TempDir()
		if err != nil {
			t.Fatalf("failed to open the image: %v", err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	untouchedFrom := func(t *testing.T, f *os.File, from int) {
		got, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatalf("failed to read the image back: %v", err)
		}
		if !bytes.Equal(got[from:], bytes.Repeat([]byte{0x5a}, size-from)) {
			t.Fatalf("the cancelled write went past byte %d", from)
		}
		if bytes.Equal(got[:from], bytes.Repeat([]byte{0x5a}, from)) {
			t.Fatal("the first chunk was not written before the cancellation")
		}
	}

	t.Run("writeRandom", func(t *testing.T) {
		f := open(t)
		ctx := &cancelAfterChecks{Context: context.Background(), n: 1}
		err := writeRandom(ctx, f, size, testVolumeSys().cryptoRand)
		var e *Error
		if !errors.As(err, &e) || e.Kind != context.Canceled {
			t.Fatalf("writeRandom cancelled after one chunk = %v, want an *Error of Kind context.Canceled", err)
		}
		if want := fmt.Sprintf("canceled after writing %d of %d bytes", keyslotWipeChunk, size); e.Detail != want {
			t.Errorf("Detail = %q, want %q", e.Detail, want)
		}
		untouchedFrom(t, f, keyslotWipeChunk)
	})
	t.Run("zeroRange", func(t *testing.T) {
		f := open(t)
		ctx := &cancelAfterChecks{Context: context.Background(), n: 1}
		if err := zeroRange(ctx, f, 0, size); !errors.Is(err, context.Canceled) {
			t.Fatalf("zeroRange cancelled after one chunk = %v, want context.Canceled", err)
		}
		untouchedFrom(t, f, keyslotWipeChunk)
	})
}

// TestWriteRandomReportsAWriteFailure covers the error path. A fill that
// silently stops short leaves exactly the zeroed range the fill exists to
// prevent, so the failure has to reach the caller.
func TestWriteRandomReportsAWriteFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "readonly.img")
	if err := os.WriteFile(path, make([]byte, 1024), 0600); err != nil {
		t.Fatalf("failed to create the image: %v", err)
	}

	f, err := os.Open(path) // #nosec G304 -- path is under t.TempDir(); opened read-only on purpose
	if err != nil {
		t.Fatalf("failed to open the image: %v", err)
	}
	defer func() { _ = f.Close() }()

	if err := writeRandom(context.Background(), f, 1024, testVolumeSys().cryptoRand); err == nil {
		t.Fatal("writeRandom reported success writing to a read-only file handle")
	}
}

// deadRNG is an io.Reader that never yields a byte. It stands in for the
// package RNG so the paths that draw from it can be observed failing.
type deadRNG struct{ err error }

func (r deadRNG) Read([]byte) (int, error) { return 0, r.err }

// TestWriteRandomReportsAnRNGFailure covers the other error path. A fill that
// cannot get random bytes must NOT fall back to zeroes: the zeroes are the
// disclosure the fill exists to remove, and a silent fallback would reinstate
// it at exactly the moment nobody is watching.
func TestWriteRandomReportsAnRNGFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "norng.img")
	original := bytes.Repeat([]byte{0x77}, 8192)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatalf("failed to create the image: %v", err)
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0600) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the image: %v", err)
	}
	err = writeRandom(context.Background(), f, int64(len(original)), deadRNG{err: errors.New("the entropy source is unavailable")})
	_ = f.Close()

	if err == nil {
		t.Fatal("writeRandom reported success with no entropy available")
	}
	if !strings.Contains(err.Error(), "the entropy source is unavailable") {
		t.Errorf("the error does not carry the cause: %v", err)
	}

	got, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to read the image back: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("writeRandom modified the file before failing; a partial fill leaves a range it cannot report")
	}
}

// TestRandomBytesReportsAnRNGFailure is the same contract one level down: every
// salt and every key in this package comes through randomBytes, so a swallowed
// failure here would produce a container with predictable material.
func TestRandomBytesReportsAnRNGFailure(t *testing.T) {
	b, err := randomBytes(32, deadRNG{err: errors.New("the entropy source is unavailable")})
	if err == nil {
		t.Fatalf("randomBytes returned %x with no entropy available", b)
	}
	if b != nil {
		t.Errorf("randomBytes returned %d bytes alongside its error", len(b))
	}
	if !strings.Contains(err.Error(), "the entropy source is unavailable") {
		t.Errorf("the error does not carry the cause: %v", err)
	}
}

// TestCreateBinaryHeaderReportsAnRNGFailure closes the same path on the header
// salt: a header whose checksum salt is not random is a header whose checksum
// can be precomputed.
func TestCreateBinaryHeaderReportsAnRNGFailure(t *testing.T) {
	sys := testVolumeSys()
	sys.cryptoRand = deadRNG{err: errors.New("the entropy source is unavailable")}

	hdr, err := createBinaryHeader(formatOptionsForTest{}, sys)
	if err == nil {
		t.Fatalf("CreateBinaryHeader returned a header with salt %x and no entropy available", hdr.Salt)
	}
	if hdr != nil {
		t.Error("CreateBinaryHeader returned a header alongside its error")
	}
}

// TestFormatFillsTheWholeKeyslotsAreaWithRandom is the format-side half of the
// disclosure fix, over the two ranges that were zero before it:
// the tail of keyslot 0's own declared area, and the ~15.7 MiB of keyslots area
// that no keyslot occupies yet.
func TestFormatFillsTheWholeKeyslotsAreaWithRandom(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "filled.img")
	if err := formatForTest(standardFormatOptions(path)); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	image, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to read the image back: %v", err)
	}

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	areaOffset, err := parseSize(metadata.Keyslots["0"].Area.Offset)
	if err != nil {
		t.Fatalf("keyslot 0 has an unparseable area offset: %v", err)
	}
	areaSize, err := parseSize(metadata.Keyslots["0"].Area.Size)
	if err != nil {
		t.Fatalf("keyslot 0 has an unparseable area size: %v", err)
	}
	dataOffset, err := parseSize(metadata.Segments["0"].Offset)
	if err != nil {
		t.Fatalf("segment 0 has an unparseable offset: %v", err)
	}

	// The material itself is keySize*header.AFStripes bytes; the rest of the declared
	// area is padding, and it used to be zero.
	material := int64(metadata.Keyslots["0"].KeySize) * header.AFStripes
	requireRandomFill(t, "the tail of keyslot 0's declared area", image[areaOffset+material:areaOffset+areaSize])
	requireRandomFill(t, "the unallocated keyslots region", image[areaOffset+areaSize:dataOffset])

	// The DATA SEGMENT must not have been touched. Format encrypts nothing
	// below dataOffset and filling past the keyslots area would be a
	// catastrophic bug rather than a hardening measure.
	for i, b := range image[dataOffset:] {
		if b != 0 {
			t.Fatalf("Format wrote %q into the data segment at offset %d", b, dataOffset+int64(i))
		}
	}

	// And the container must still be one: a fill that ran over the headers or
	// the key material would show up here and nowhere else in this test.
	if err := testKeyForTest(path, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("the passphrase no longer opens the container after the fill: %v", err)
	}
}

// TestWipeKeyslotAreaLeavesRandomNotZeroes is the removal-side half. Zeroing a
// freed area announces that a credential was revoked; the whole point of the
// removal is that it leaves no trace.
func TestWipeKeyslotAreaLeavesRandomNotZeroes(t *testing.T) {
	defer parallel(t)()

	const (
		areaOffset = 0x8000
		// The declared area must hold a full complement of AF stripes --
		// header.ValidateKeyslot refuses anything smaller -- so this is the size
		// Format lays out for a 512-bit volume key.
		areaSize = 258048
	)

	path := filepath.Join(t.TempDir(), "wipe.img")
	image := bytes.Repeat([]byte{0xc3}, areaOffset+areaSize+4096)
	if err := os.WriteFile(path, image, 0600); err != nil {
		t.Fatalf("failed to create the image: %v", err)
	}

	keyslot := &header.Keyslot{
		Type:    "luks2",
		KeySize: 64,
		Area: &header.KeyslotArea{
			Type:       "raw",
			KeySize:    64,
			Offset:     formatSize(areaOffset),
			Size:       formatSize(areaSize),
			Encryption: keyslotAreaEncryption,
		},
		KDF: &header.KDF{Type: "pbkdf2", Hash: "sha512", Salt: "AAAA", Iterations: intPtr(210000)},
		AF:  &header.AntiForensic{Type: "luks1", Stripes: header.AFStripes, Hash: "sha512"},
	}

	hdr, metadata := bareKeyslotsGeometry(areaOffset + areaSize)
	if err := wipeKeyslotArea(context.Background(), lockedDevice(t, path), hdr, metadata, "0", keyslot); err != nil {
		t.Fatalf("wipeKeyslotArea failed: %v", err)
	}

	got, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to read the image back: %v", err)
	}

	if bytes.Equal(got[areaOffset:areaOffset+areaSize], image[areaOffset:areaOffset+areaSize]) {
		t.Fatal("wipeKeyslotArea left the area untouched; the key material survived")
	}
	requireRandomFill(t, "the freed keyslot area", got[areaOffset:areaOffset+areaSize])

	if !bytes.Equal(got[:areaOffset], image[:areaOffset]) {
		t.Error("wipeKeyslotArea wrote before the area's offset")
	}
	if !bytes.Equal(got[areaOffset+areaSize:], image[areaOffset+areaSize:]) {
		t.Error("wipeKeyslotArea wrote past the area's size")
	}
}

// TestWipeKeyslotAreaRefusesAKeyslotItCannotLocate is the error half: a keyslot
// whose geometry does not parse must be refused before anything is overwritten,
// because the range that would be filled is unknown.
func TestWipeKeyslotAreaRefusesAKeyslotItCannotLocate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.img")
	image := bytes.Repeat([]byte{0xc3}, 64*1024)
	if err := os.WriteFile(path, image, 0600); err != nil {
		t.Fatalf("failed to create the image: %v", err)
	}

	tests := []struct {
		name    string
		keyslot *header.Keyslot
	}{
		{"no area", &header.Keyslot{Type: "luks2", KeySize: 64}},
		{
			"unparseable offset",
			&header.Keyslot{Type: "luks2", KeySize: 64, Area: &header.KeyslotArea{
				Type: "raw", KeySize: 64, Offset: "not-a-number", Size: "4096",
				Encryption: keyslotAreaEncryption,
			}},
		},
		{
			"area beyond the end of the device",
			&header.Keyslot{Type: "luks2", KeySize: 64, Area: &header.KeyslotArea{
				Type: "raw", KeySize: 64, Offset: "0", Size: "1073741824",
				Encryption: keyslotAreaEncryption,
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr, metadata := bareKeyslotsGeometry(1 << 30)
			if err := wipeKeyslotArea(context.Background(), lockedDevice(t, path), hdr, metadata, "0", tt.keyslot); err == nil {
				t.Fatal("wipeKeyslotArea accepted a keyslot whose area it cannot locate")
			}

			got, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir()
			if err != nil {
				t.Fatalf("failed to read the image back: %v", err)
			}
			if !bytes.Equal(got, image) {
				t.Fatal("wipeKeyslotArea modified the device before refusing")
			}
		})
	}
}

// bareKeyslotsGeometry is the header geometry the bare-image wipe tests stand for: a
// 16 KiB header area, so the keyslots area starts at 0x8000, running up to end,
// and no data segment. wipeKeyslotArea confines every wipe to that area
// (#249, A2), so a test that wipes outside a container still has to say where
// the keyslots area is.
func bareKeyslotsGeometry(end int64) (*header.BinaryHeader, *header.Metadata) {
	hdr := &header.BinaryHeader{HeaderSize: header.HeaderMinSize}
	metadata := &header.Metadata{
		Config:   &header.Config{KeyslotsSize: formatSize(end - 2*header.HeaderMinSize)},
		Segments: map[string]*header.Segment{},
	}
	return hdr, metadata
}
