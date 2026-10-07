// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package wipe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestVerifyWriteAcceptsWhatThePassWrote, for every pattern, and reports
// verification progress.
func TestVerifyWriteAcceptsWhatThePassWrote(t *testing.T) {
	for _, pattern := range []Pattern{Zeros, Ones, Random} {
		size := chunk + 4096 + 100
		path := writeFixture(t, size, 0xAA)
		f, err := os.OpenFile(path, os.O_RDWR, 0o600) // #nosec G304 -- under t.TempDir()
		if err != nil {
			t.Fatal(err)
		}
		s, err := newPassStream(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if err := writePass(context.Background(), f, path, int64(size), s, nil, 1, 1); err != nil {
			t.Fatal(err)
		}
		if err := f.Sync(); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()

		var verified int64
		progress := func(p Progress) {
			if p.Verifying {
				verified = p.Written
			}
		}
		if err := verifyWrite(context.Background(), path, path, int64(size), s, progress, 1, baseSys()); err != nil {
			t.Fatalf("verifyWrite(%s) refused what the pass wrote: %v", pattern, err)
		}
		if verified != int64(size) {
			t.Fatalf("verification progress reached %d bytes, want %d", verified, size)
		}
	}
}

// TestVerifyWriteDetectsADifferenceInARandomPass is #246 D1. The DoD
// sequences end with a random pass, and a verification that returns nil for
// a random pass without reading a byte verifies nothing.
func TestVerifyWriteDetectsADifferenceInARandomPass(t *testing.T) {
	size := 64 * 1024
	path := writeFixture(t, size, 0)
	f, err := os.OpenFile(path, os.O_RDWR, 0o600) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	s, err := newPassStream(Random)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePass(context.Background(), f, path, int64(size), s, nil, 1, 1); err != nil {
		t.Fatal(err)
	}
	// One byte of the medium is not what the pass wrote.
	one := make([]byte, 1)
	if _, err := f.ReadAt(one, 40000); err != nil {
		t.Fatal(err)
	}
	one[0] ^= 0x01
	if _, err := f.WriteAt(one, 40000); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	err = verifyWrite(context.Background(), path, path, int64(size), s, nil, 1, baseSys())
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("verifyWrite = %v, want ErrVerification", err)
	}
	if !strings.Contains(err.Error(), "byte 40000") {
		t.Fatalf("the error does not name the first differing byte: %v", err)
	}
}

// TestVerifyWriteDetectsAShortMedium: a medium that ends early is not
// verified, and verifying nothing always succeeds.
func TestVerifyWriteDetectsAShortMedium(t *testing.T) {
	path := writeFixture(t, 4096, 0)
	s, _ := newPassStream(Zeros)
	if err := verifyWrite(context.Background(), path, path, 8192, s, nil, 1, baseSys()); !errors.Is(err, ErrVerification) {
		t.Fatalf("verifyWrite past the end = %v, want ErrVerification", err)
	}
	if err := verifyWrite(context.Background(), path, path, 0, s, nil, 1, baseSys()); err != nil {
		t.Fatalf("verifyWrite of nothing = %v, want nil", err)
	}
}

// TestVerifyWriteStopsAtTheChunkBoundaryOnCancellation mirrors writePass's
// per-chunk ctx check (DESIGN.md D.2).
func TestVerifyWriteStopsAtTheChunkBoundaryOnCancellation(t *testing.T) {
	size := 3 * chunk
	path := writeFixture(t, size, 0)
	s, _ := newPassStream(Zeros)

	ctx, cancel := context.WithCancel(context.Background())
	chunks := 0
	err := verifyWrite(ctx, path, path, int64(size), s, func(Progress) {
		chunks++
		if chunks == 1 {
			cancel()
		}
	}, 1, baseSys())

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("verifyWrite after cancellation = %v, want context.Canceled", err)
	}
	if chunks != 1 {
		t.Fatalf("verifyWrite verified %d chunks after cancellation, want exactly 1", chunks)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%d of %d bytes verified", chunk, size)) {
		t.Fatalf("the error does not state how far verification got: %v", err)
	}
}

// TestVerifyWritePropagatesAMediumReadFailure: a device that cannot be found
// is not reported as verified.
func TestVerifyWritePropagatesAMediumReadFailure(t *testing.T) {
	s, _ := newPassStream(Zeros)
	if err := verifyWrite(context.Background(), "/nonexistent", "/nonexistent", 4096, s, nil, 1, baseSys()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("verifyWrite(absent) = %v, want ErrNotExist", err)
	}
}
