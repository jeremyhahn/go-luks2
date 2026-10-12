// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package kdf derives keys from passphrases, calibrates and bounds the cost
// of doing so, and converts a legacy PBKDF2-SHA1 cost into its SHA-256
// equivalent for a rewrite.
//
// # Params and the single conversion
//
// Params is the on-disk KDF object with its hash algorithm and cost fields
// carried as given. Salt stays the base64 string LUKS2 stores it as: only the
// derive path ever needs the decoded bytes, and decoding it there -- rather
// than in whatever builds a Params -- means a cost-only caller (ValidateCost,
// DerivationWork) can never fail on a salt it never reads.
package kdf

import (
	"context"
	"crypto"
	"crypto/pbkdf2"
	_ "crypto/sha512" // registers SHA-384/SHA-512 for crypto.Hash.New, resolved below
	"encoding/base64"
	"fmt"
	"hash"
	"math"
	"strings"

	"github.com/jeremyhahn/go-enclave"
	"golang.org/x/crypto/argon2"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// Params is the derivation parameter set: the on-disk KDF object, with cost
// fields left as the optional pointers the JSON gives them as.
type Params struct {
	// Type is the on-disk KDF type string ("pbkdf2", "argon2i", "argon2id",
	// ...), exactly as stored. Callers that dispatch on it normalize their own
	// copy; this field is never mutated.
	Type string

	// Hash is the PBKDF2 hash algorithm name, as stored. Unused for argon2.
	Hash string

	// Salt is the base64-encoded salt, as stored. Decoded only where actual
	// bytes are needed.
	Salt string

	Iterations *int
	Time       *int
	Memory     *int
	CPUs       *int
}

// Deriver runs derivations with the custody and FIPS policy it is given, as
// af.Codec carries its seams.
type Deriver struct {
	Custody secret.Custody
	FIPS    fips.Mode
}

// Derive runs the KDF named by p against passphrase and adopts the result
// into an enclave. custody.Adopt wipes the intermediate key on every path, so
// there is no window in which the derived key outlives this call in the
// clear.
func (d Deriver) Derive(ctx context.Context, passphrase []byte, p Params, keySize int) (*enclave.MemoryEnclave, error) {
	key, err := d.DerivePlain(ctx, passphrase, p, keySize)
	if err != nil {
		return nil, err
	}
	return d.Custody.Adopt("derived key", key)
}

// DeriveFromSecret runs Derive with passphrase material borrowed from an
// enclave, for the two callers whose "passphrase" is the volume master key
// (digest verification and digest creation).
func (d Deriver) DeriveFromSecret(ctx context.Context, material *enclave.MemoryEnclave, p Params, keySize int) (*enclave.MemoryEnclave, error) {
	var derived *enclave.MemoryEnclave
	err := secret.Borrow("derive from secret", material, func(b []byte) error {
		var err error
		derived, err = d.Derive(ctx, b, p, keySize)
		return err
	})
	if err != nil {
		return nil, err
	}
	return derived, nil
}

// DerivePlain runs the KDF named by p against passphrase and returns the raw
// derived bytes, before any enclave custody. Most callers want Derive;
// DerivePlain exists for the callers that compare or test the bytes directly.
func (d Deriver) DerivePlain(ctx context.Context, passphrase []byte, p Params, keySize int) ([]byte, error) {
	// A PANIC GUARD, not a policy ceiling: crypto/pbkdf2 refuses a
	// non-positive keyLength with an error x/crypto used to turn into a
	// panic, and argon2 dereferences nil on one. The ceiling a header must
	// respect is applied where headers are read, not here: this function
	// also serves Format/AddKey/ChangeKey, deriving from a size the CALLER
	// chose.
	if keySize <= 0 {
		return nil, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "requested key length must be positive"}
	}

	if err := d.FIPS.RequireKDF(p.Type); err != nil {
		return nil, err
	}

	salt, err := base64.StdEncoding.DecodeString(p.Salt)
	if err != nil {
		return nil, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "invalid salt", Err: err}
	}

	// ctx is checked before each derivation: a PBKDF2/argon2 run in
	// flight cannot be interrupted, so cancellation is observed here, at the
	// one point before the derivation starts, rather than attempted inside it.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var key []byte
	switch p.Type {
	case "pbkdf2":
		key, err = derivePBKDF2(passphrase, salt, p, keySize, d.FIPS)
	case "argon2i":
		key, err = DeriveArgon2i(passphrase, salt, p, keySize)
	case "argon2id":
		key, err = DeriveArgon2id(passphrase, salt, p, keySize)
	default:
		return nil, &errs.Error{Kind: ErrUnsupportedKDF, Detail: p.Type}
	}
	if err != nil {
		return nil, err
	}

	// A derivation that finished while its ctx was being canceled is not
	// handed back: the output is destroyed and the cancellation is reported,
	// exactly as if the derivation had never been allowed to start.
	if err := ctx.Err(); err != nil {
		clear(key)
		return nil, err
	}
	return key, nil
}

func derivePBKDF2(passphrase, salt []byte, p Params, keySize int, mode fips.Mode) ([]byte, error) {
	if p.Iterations == nil {
		return nil, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "crypto pbkdf2: PBKDF2 requires iterations"}
	}

	hashFunc, err := PBKDF2HashFunc(mode, p.Hash)
	if err != nil {
		return nil, err
	}

	// string(passphrase) is the unwipeable copy exposure 2 in internal/secret
	// records. It is made HERE now rather than inside the x/crypto wrapper,
	// which changes who makes it and not whether it is made: crypto/pbkdf2
	// takes a string, and the module copies it again into the HMAC state
	// regardless. The ruling above is what settles that.
	key, err := pbkdf2.Key(hashFunc, string(passphrase), salt, *p.Iterations, keySize)
	if err != nil {
		return nil, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "crypto pbkdf2", Err: err}
	}
	return key, nil
}

// DeriveArgon2i and DeriveArgon2id run Argon2 directly against an
// already-decoded salt, for a caller that wants to compare or probe bytes
// without going through a stored, base64 KDF object (DerivePlain's dispatch
// decodes p.Salt itself; these two do not read it at all).
func DeriveArgon2i(passphrase, salt []byte, p Params, keySize int) ([]byte, error) {
	return deriveArgon2(p, "argon2i", "Argon2i", argon2.Key, passphrase, salt, keySize)
}

func DeriveArgon2id(passphrase, salt []byte, p Params, keySize int) ([]byte, error) {
	return deriveArgon2(p, "argon2id", "Argon2id", argon2.IDKey, passphrase, salt, keySize)
}

func deriveArgon2(
	p Params,
	op, name string,
	keyFn func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte,
	passphrase, salt []byte, keySize int,
) ([]byte, error) {
	if p.Time == nil || p.Memory == nil || p.CPUs == nil {
		return nil, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: fmt.Sprintf("%s requires time, memory, and cpus parameters", name)}
	}

	// Validate CPUs fits in uint8 (Argon2 parallelism is 1-255)
	cpus := *p.CPUs
	if cpus < 1 || cpus > 255 {
		return nil, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "crypto " + op + ": cpus must be between 1 and 255"}
	}

	// The round count, which x/crypto/argon2 PANICS on rather than refusing:
	// "argon2: number of rounds too small" for time < 1.
	if *p.Time < 1 {
		return nil, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "crypto " + op + ": time cost must be at least 1"}
	}

	// AND THE MEMORY COST: these are signed ints out of JSON converted with
	// uint32 below, so -1 becomes 4294967295 KiB and argon2 is asked for a
	// FOUR TERABYTE matrix. Not an error -- an allocation. Only the floor is
	// enforced here; the ceiling is the read path's job (ValidateCost), so a
	// foreign volume that currently unlocks is not newly refused.
	if *p.Memory < MinArgon2Memory {
		return nil, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: fmt.Sprintf("crypto %s: memory cost %d is below the %d KiB floor; "+
			"a negative value becomes ~4 TiB after the uint32 conversion", op, *p.Memory, MinArgon2Memory)}
	}

	t32, err := u32(op, "time cost", *p.Time)
	if err != nil {
		return nil, err
	}
	m32, err := u32(op, "memory cost", *p.Memory)
	if err != nil {
		return nil, err
	}
	k32, err := u32(op, "key length", keySize)
	if err != nil {
		return nil, err
	}

	return keyFn(passphrase, salt, t32, m32, uint8(cpus), k32), nil
}

// u32 converts a validated, non-negative int cost into the uint32 the argon2
// interface takes, refusing a value too large to represent rather than
// silently truncating it.
func u32(op, field string, v int) (uint32, error) {
	if v < 0 {
		return 0, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: fmt.Sprintf("crypto %s: %s must not be negative (got %d); "+
			"the conversion below would turn it into a very large one", op, field, v)}
	}
	if uint64(v) > math.MaxUint32 {
		return 0, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: fmt.Sprintf("crypto %s: %s %d exceeds what the argon2 interface can "+
			"represent (uint32); the conversion would silently truncate it rather than fail", op, field, v)}
	}
	return uint32(v), nil
}

// PBKDF2Hash resolves a PBKDF2 hash algorithm name to its crypto.Hash, with no
// FIPS gate: pure name resolution.
func PBKDF2Hash(hashAlgo string) (crypto.Hash, error) {
	switch strings.ToLower(hashAlgo) {
	case "sha1":
		return crypto.SHA1, nil
	case "sha256":
		return crypto.SHA256, nil
	case "sha384":
		return crypto.SHA384, nil
	case "sha512":
		return crypto.SHA512, nil
	default:
		return 0, &errs.Error{Kind: errs.ErrUnsupportedHash, Detail: hashAlgo + " (supported: sha1, sha256, sha384, sha512)"}
	}
}

// PBKDF2HashFunc resolves a PBKDF2 hash algorithm name to its constructor,
// refusing one the FIPS policy in mode does not approve.
//
// PBKDF2-HMAC-SHA1 is needed to open LUKS headers written by cryptsetup
// releases that defaulted to SHA-1, but the Go Cryptographic Module permits
// PBKDF2 only with SHA-2/SHA-3 and panics on SHA-1 under GODEBUG=fips140=only.
// Refuse it here so a FIPS build reports a typed error instead of crashing,
// and so the call never reaches the module. See docs/fips/architecture.md.
func PBKDF2HashFunc(mode fips.Mode, hashAlgo string) (func() hash.Hash, error) {
	h, err := PBKDF2Hash(hashAlgo)
	if err != nil {
		return nil, err
	}
	if err := mode.RequireHash("pbkdf2-hmac-"+strings.ToLower(hashAlgo), h); err != nil {
		return nil, err
	}
	return h.New, nil
}

// HashOutputLen is the output size, in bytes, of a PBKDF2 hash algorithm.
func HashOutputLen(mode fips.Mode, hashAlgo string) (int, error) {
	hashFunc, err := PBKDF2HashFunc(mode, hashAlgo)
	if err != nil {
		return 0, err
	}
	return hashFunc().Size(), nil
}
