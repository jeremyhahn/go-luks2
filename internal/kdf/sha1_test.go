// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package kdf

import (
	"context"
	"crypto/sha1" // #nosec G505 -- sized, never derived with: a test fixture for the cost-conversion model
	"crypto/sha256"
	"errors"
	"hash"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/fips"
)

// modelTimer returns a Timer whose reported cost per HMAC comes from
// sha1Cost/sha256Cost (indexed by call count), so the cost-conversion math
// can be checked without running real derivations.
func modelTimer(sha1Cost, sha256Cost func(call int) float64) Timer {
	calls := map[int]int{}
	return func(hashFunc func() hash.Hash, iterations, keySize int) (time.Duration, error) {
		size := hashFunc().Size()
		cost := sha256Cost
		if size == sha1.Size {
			cost = sha1Cost
		}
		blocks := (keySize + size - 1) / size
		perHMAC := cost(calls[size])
		calls[size]++
		return time.Duration(float64(iterations*blocks) * perHMAC * float64(time.Microsecond)), nil
	}
}

func TestSHA1Iterations(t *testing.T) {
	if testDeriver.FIPS {
		t.Skip("PBKDF2-SHA1 is not measured in FIPS mode")
	}

	constant := func(c float64) func(int) float64 { return func(int) float64 { return c } }
	cases := []struct {
		name               string
		n, keySize         int
		sha1Cost, sha2Cost func(int) float64
		want               int
	}{
		// 64-byte key: 4 SHA-1 blocks, 2 SHA-256 blocks.
		{"slower SHA-256: the work bound", 1_000_000, 64, constant(1), constant(2), 2_000_000},
		{"equal HMAC cost: work and time agree", 1_000_000, 64, constant(1), constant(1), 2_000_000},
		{"faster SHA-256 (SHA extensions): the time bound", 1_000_000, 64, constant(1), constant(0.9), 2_222_223},
		// 32-byte key: 2 SHA-1 blocks, 1 SHA-256 block.
		{"32-byte key", 500_000, 32, constant(1), constant(2), 1_000_000},
		{"noisy samples, conservatively", 300_000, 64,
			func(i int) float64 { return []float64{100, 120, 110}[i%3] },
			func(i int) float64 { return []float64{90, 95, 100}[i%3] }, 800_000},
		{"past the ceiling", MaxKDFIterations, 64, constant(1), constant(1), MaxKDFIterations + 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			timer := modelTimer(tc.sha1Cost, tc.sha2Cost)
			got, err := testDeriver.SHA1Iterations(tc.n, tc.keySize, timer)
			if err != nil || got < tc.want || got > tc.want+1 {
				t.Fatalf("SHA1Iterations(%d, %d) = %d, %v; want %d (or one more)", tc.n, tc.keySize, got, err, tc.want)
			}
			if got > MaxKDFIterations {
				return
			}
			sha1HMACs := tc.n * ((tc.keySize + sha1.Size - 1) / sha1.Size)
			if sha256HMACs := got * ((tc.keySize + sha256.Size - 1) / sha256.Size); sha256HMACs < sha1HMACs {
				t.Fatalf("%d SHA-256 HMACs is fewer than the %d SHA-1 HMACs the keyslot took", sha256HMACs, sha1HMACs)
			}
		})
	}
}

func TestSHA1IterationsRefusals(t *testing.T) {
	if testDeriver.FIPS {
		t.Skip("PBKDF2-SHA1 is not measured in FIPS mode")
	}
	for _, args := range [][2]int{{0, 64}, {-1, 64}, {1000, 0}} {
		if _, err := testDeriver.SHA1Iterations(args[0], args[1], WallClockPBKDF2); !errors.Is(err, errs.ErrInvalidKeyslot) {
			t.Fatalf("SHA1Iterations(%d, %d): got %v, want ErrInvalidKeyslot", args[0], args[1], err)
		}
	}

	errTimer := errors.New("injected: the timer failed")
	failingTimer := func(func() hash.Hash, int, int) (time.Duration, error) { return 0, errTimer }
	if _, err := testDeriver.SHA1Iterations(1000, 64, failingTimer); !errors.Is(err, errTimer) {
		t.Fatalf("a failing timer: got %v", err)
	}

	stuckTimer := func(func() hash.Hash, int, int) (time.Duration, error) { return 0, nil }
	if _, err := testDeriver.SHA1Iterations(1000, 64, stuckTimer); !errors.Is(err, ErrKDFCalibration) {
		t.Fatalf("a clock that never advances: got %v, want ErrKDFCalibration", err)
	}
}

// TestFIPSDeriverRefusesTheUnapproved needs no skip: the Deriver's FIPS field
// is set explicitly, so the refusals are exercised in every process mode.
func TestFIPSDeriverRefusesTheUnapproved(t *testing.T) {
	d := Deriver{Custody: testDeriver.Custody, FIPS: true}

	timer := func(func() hash.Hash, int, int) (time.Duration, error) {
		t.Fatal("the timer ran: the refusal must come before any measurement")
		return 0, nil
	}
	if _, err := d.SHA1Iterations(1000, 64, timer); !errors.Is(err, fips.ErrNotApproved) {
		t.Fatalf("SHA1Iterations under FIPS: got %v, want fips.ErrNotApproved", err)
	}

	timeVal, memory, cpus := 1, 64, 1
	for _, typ := range []string{"argon2i", "argon2id"} {
		p := Params{Type: typ, Salt: b64("saltsaltsaltsalt"), Time: &timeVal, Memory: &memory, CPUs: &cpus}
		if _, err := d.DerivePlain(context.Background(), []byte("passphrase"), p, 32); !errors.Is(err, fips.ErrNotApproved) {
			t.Fatalf("DerivePlain(%s) under FIPS: got %v, want fips.ErrNotApproved", typ, err)
		}
	}
}
