// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package kdf

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

var testDeriver = Deriver{Custody: secret.System(), FIPS: fips.Probe()}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func intPtr(n int) *int { return &n }

func mustDestroy(t *testing.T, e interface{ Destroy() error }) {
	t.Helper()
	if err := e.Destroy(); err != nil {
		t.Errorf("releasing a test enclave was reported: %v", err)
	}
}

func TestDerivePlainPBKDF2(t *testing.T) {
	iterations := 1000
	p := Params{Type: "pbkdf2", Hash: "sha256", Salt: b64("saltsaltsaltsalt"), Iterations: &iterations}

	key1, err := testDeriver.DerivePlain(context.Background(), []byte("passphrase"), p, 32)
	if err != nil {
		t.Fatalf("DerivePlain: %v", err)
	}
	key2, err := testDeriver.DerivePlain(context.Background(), []byte("passphrase"), p, 32)
	if err != nil {
		t.Fatalf("DerivePlain: %v", err)
	}
	if string(key1) != string(key2) {
		t.Fatal("the same parameters derived different keys")
	}
	key3, err := testDeriver.DerivePlain(context.Background(), []byte("different"), p, 32)
	if err != nil {
		t.Fatalf("DerivePlain: %v", err)
	}
	if string(key1) == string(key3) {
		t.Fatal("a different passphrase derived the same key")
	}
}

func TestDerivePlainArgon2(t *testing.T) {
	time, memory, cpus := 1, 64, 1
	for _, typ := range []string{"argon2i", "argon2id"} {
		t.Run(typ, func(t *testing.T) {
			p := Params{Type: typ, Salt: b64("saltsaltsaltsalt"), Time: &time, Memory: &memory, CPUs: &cpus}
			if fips.Probe() {
				if _, err := testDeriver.DerivePlain(context.Background(), []byte("passphrase"), p, 32); !errors.Is(err, fips.ErrNotApproved) {
					t.Fatalf("argon2 in FIPS mode: got %v, want ErrNotApproved", err)
				}
				return
			}
			key1, err := testDeriver.DerivePlain(context.Background(), []byte("passphrase"), p, 32)
			if err != nil {
				t.Fatalf("DerivePlain: %v", err)
			}
			key2, err := testDeriver.DerivePlain(context.Background(), []byte("passphrase"), p, 32)
			if err != nil {
				t.Fatalf("DerivePlain: %v", err)
			}
			if string(key1) != string(key2) {
				t.Fatal("the same parameters derived different keys")
			}
		})
	}
}

func TestDerivePlainRefusesAnUnsupportedType(t *testing.T) {
	p := Params{Type: "scrypt", Salt: b64("salt")}
	_, err := testDeriver.DerivePlain(context.Background(), []byte("passphrase"), p, 32)
	if !errors.Is(err, ErrUnsupportedKDF) {
		t.Fatalf("got %v, want an error wrapping ErrUnsupportedKDF", err)
	}
}

func TestDeriveArgon2CPUsBounds(t *testing.T) {
	timeVal, memory := 1, 64
	for _, cpus := range []int{0, 256, -1} {
		p := Params{Type: "argon2i", Salt: b64("salt"), Time: &timeVal, Memory: &memory, CPUs: &cpus}
		if _, err := testDeriver.DerivePlain(context.Background(), []byte("passphrase"), p, 32); err == nil && !fips.Probe() {
			t.Fatalf("cpus %d: accepted", cpus)
		}
	}
}

func TestDeriveArgon2MemoryBelowFloor(t *testing.T) {
	timeVal, cpus := 1, 1
	for _, memory := range []int{0, -1, MinArgon2Memory - 1} {
		p := Params{Type: "argon2i", Salt: b64("salt"), Time: &timeVal, Memory: &memory, CPUs: &cpus}
		if _, err := testDeriver.DerivePlain(context.Background(), []byte("passphrase"), p, 32); err == nil && !fips.Probe() {
			t.Fatalf("memory %d: accepted", memory)
		}
	}
}

func TestDerive(t *testing.T) {
	iterations := 1000
	p := Params{Type: "pbkdf2", Hash: "sha256", Salt: b64("saltsaltsaltsalt"), Iterations: &iterations}
	e, err := testDeriver.Derive(context.Background(), []byte("passphrase"), p, 32)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	defer mustDestroy(t, e)
	if e.Size() != 32 {
		t.Fatalf("derived enclave holds %d bytes, want 32", e.Size())
	}
}

func TestDeriveFromSecret(t *testing.T) {
	iterations := 1000
	p := Params{Type: "pbkdf2", Hash: "sha256", Salt: b64("saltsaltsaltsalt"), Iterations: &iterations}

	plain, err := testDeriver.DerivePlain(context.Background(), []byte("the master key"), p, 32)
	if err != nil {
		t.Fatalf("DerivePlain: %v", err)
	}

	material, err := testDeriver.Custody.Copied([]byte("the master key"))
	if err != nil {
		t.Fatalf("allocating test material: %v", err)
	}
	defer mustDestroy(t, material)

	derived, err := testDeriver.DeriveFromSecret(context.Background(), material, p, 32)
	if err != nil {
		t.Fatalf("DeriveFromSecret: %v", err)
	}
	defer mustDestroy(t, derived)

	var got []byte
	if err := secret.Borrow("read derived", derived, func(b []byte) error {
		got = append(got, b...)
		return nil
	}); err != nil {
		t.Fatalf("Borrow: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatal("DeriveFromSecret and DerivePlain disagree on the same input")
	}
}

func TestPBKDF2Hash(t *testing.T) {
	for _, tc := range []struct {
		name string
		want crypto.Hash
	}{
		{"sha1", crypto.SHA1}, {"SHA256", crypto.SHA256}, {"sha384", crypto.SHA384}, {"sha512", crypto.SHA512},
	} {
		got, err := PBKDF2Hash(tc.name)
		if err != nil || got != tc.want {
			t.Fatalf("PBKDF2Hash(%q) = %v, %v; want %v", tc.name, got, err, tc.want)
		}
	}
	if _, err := PBKDF2Hash("md5"); err == nil {
		t.Fatal("an unsupported hash was accepted")
	} else {
		var e *errs.Error
		if !errors.As(err, &e) || e.Kind != errs.ErrUnsupportedHash {
			t.Fatalf("got %v, want an *errs.Error with Kind ErrUnsupportedHash", err)
		}
	}
}

func TestPBKDF2HashFuncFIPSGate(t *testing.T) {
	if _, err := PBKDF2HashFunc(fips.Mode(true), "sha1"); !errors.Is(err, fips.ErrNotApproved) {
		t.Fatalf("PBKDF2-SHA1 under FIPS: got %v, want ErrNotApproved", err)
	}
	if _, err := PBKDF2HashFunc(fips.Mode(true), "sha256"); err != nil {
		t.Fatalf("PBKDF2-SHA256 under FIPS: %v", err)
	}
	if _, err := PBKDF2HashFunc(fips.Mode(false), "sha1"); err != nil {
		t.Fatalf("PBKDF2-SHA1 outside FIPS: %v", err)
	}
}

func TestU32(t *testing.T) {
	if _, err := u32("op", "field", -1); err == nil {
		t.Fatal("a negative value was accepted")
	}
	over := int64(math.MaxUint32) + 1
	if _, err := u32("op", "field", int(over)); err == nil {
		t.Fatal("a value past uint32 was accepted")
	}
	got, err := u32("op", "field", 5)
	if err != nil || got != 5 {
		t.Fatalf("u32(5) = %d, %v", got, err)
	}
}

func TestDeriveFromSecretErrorPath(t *testing.T) {
	material, err := testDeriver.Custody.Copied([]byte("the master key"))
	if err != nil {
		t.Fatalf("allocating test material: %v", err)
	}
	defer mustDestroy(t, material)

	p := Params{Type: "scrypt", Salt: b64("salt")}
	if _, err := testDeriver.DeriveFromSecret(context.Background(), material, p, 32); err == nil {
		t.Fatal("DeriveFromSecret accepted an unsupported type")
	}
}

// TestDerivePlainCancelledBeforeDerivationReturnsCtxErr is D.2's KDF row: a
// ctx canceled before the derivation starts is checked before any work is
// done, and no key material is produced.
func TestDerivePlainCancelledBeforeDerivationReturnsCtxErr(t *testing.T) {
	iterations := 1000
	p := Params{Type: "pbkdf2", Hash: "sha256", Salt: b64("saltsaltsaltsalt"), Iterations: &iterations}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	key, err := testDeriver.DerivePlain(ctx, []byte("passphrase"), p, 32)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("DerivePlain with an already-canceled ctx = %v, want context.Canceled", err)
	}
	if key != nil {
		t.Fatal("DerivePlain with an already-canceled ctx returned key bytes")
	}
}

// TestDeriveCancelledBeforeDerivationReturnsNoEnclave is Derive's half of the
// same row: a canceled ctx produces no enclave for Custody to leak.
func TestDeriveCancelledBeforeDerivationReturnsNoEnclave(t *testing.T) {
	iterations := 1000
	p := Params{Type: "pbkdf2", Hash: "sha256", Salt: b64("saltsaltsaltsalt"), Iterations: &iterations}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	e, err := testDeriver.Derive(ctx, []byte("passphrase"), p, 32)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Derive with an already-canceled ctx = %v, want context.Canceled", err)
	}
	if e != nil {
		t.Fatal("Derive with an already-canceled ctx returned a non-nil enclave")
	}
}

// TestDerivePlainCancelledDuringDerivationDestroysOutput is D.2's KDF row's
// other half: a derivation already in flight when its ctx is canceled is
// NOT interrupted (crypto/pbkdf2.Key has no interruption point), but once it
// finishes, the output is destroyed rather than handed back, and ctx.Err()'s
// kind is returned. The iteration count is large enough, against the 1ms
// deadline, that the derivation is still running when the deadline fires.
func TestDerivePlainCancelledDuringDerivationDestroysOutput(t *testing.T) {
	iterations := 100_000
	p := Params{Type: "pbkdf2", Hash: "sha256", Salt: b64("saltsaltsaltsalt"), Iterations: &iterations}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()

	key, err := testDeriver.DerivePlain(ctx, []byte("passphrase"), p, 32)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DerivePlain canceled mid-derivation = %v, want context.DeadlineExceeded", err)
	}
	if key != nil {
		t.Fatal("DerivePlain canceled mid-derivation handed back key bytes instead of destroying them")
	}
}

func TestHashOutputLen(t *testing.T) {
	for _, tc := range []struct {
		name string
		want int
	}{
		{"sha1", 20}, {"sha256", 32}, {"sha384", 48}, {"sha512", 64},
	} {
		got, err := HashOutputLen(fips.Mode(false), tc.name)
		if err != nil || got != tc.want {
			t.Fatalf("HashOutputLen(%q) = %d, %v; want %d", tc.name, got, err, tc.want)
		}
	}
	if _, err := HashOutputLen(fips.Mode(false), "unknown"); err == nil {
		t.Fatal("an unsupported hash was accepted")
	}
}
