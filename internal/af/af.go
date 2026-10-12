// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package af is LUKS's anti-forensic split and merge, and the custody of what
// they produce.
//
// AF STRIPES ARE MASTER KEY MATERIAL. It is easy to read the split as an
// obfuscation step and treat its output as less sensitive than its input, and
// that is backwards: the split is reversible with nothing but the stripes
// themselves -- Merge takes no key -- so holding the stripes is holding the
// master key, spread over keySize*stripes bytes instead of keySize. For the
// default 512-bit key and 4000 stripes that is 256 KiB of key material, four
// thousand times the surface of the key it encodes, which is precisely why it
// must not sit on the ordinary heap.
//
// The diffusion buffer carries the same weight. It is the running XOR of the
// stripes, and combined with the final stripe it yields the key directly.
package af

import (
	"crypto"
	"crypto/sha1" // #nosec G505 -- legacy LUKS interop only: SHA-1 AF keyslots are read, never written, and refused in FIPS mode (docs/fips/architecture.md)
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"hash"
	"io"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// Params is a keyslot's anti-forensic object: how many stripes the key is
// split into, and the hash that diffuses them.
type Params struct {
	Stripes int
	Hash    string
}

// Codec runs the split and the merge with the custody, randomness and FIPS
// policy it is given. Rand is crypto/rand.Reader on every production path; it
// is a field so a test can make a split deterministic.
type Codec struct {
	Custody secret.Custody
	Rand    io.Reader
	FIPS    fips.Mode
}

// Split performs anti-forensic splitting entirely inside protected memory: the
// key is borrowed from its enclave, the stripes are generated into locked
// pages, and the diffusion state lives in a locked page of its own.
//
// The returned enclave holds key.Size()*p.Stripes bytes and is the caller's to
// destroy. p.Hash must be one a new keyslot may be written with (ValidateWriteHash).
func (c Codec) Split(key *enclave.Memory, p Params) (*enclave.Memory, error) {
	if p.Stripes <= 0 {
		return nil, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "stripes must be positive"}
	}

	hashFunc, err := writeHash(p.Hash)
	if err != nil {
		return nil, err
	}

	blockSize := key.Size()
	if blockSize == 0 {
		return nil, &errs.Error{Kind: secret.ErrProtectedMemory, Detail: "af split input", Err: enclave.ErrEnclaveDestroyed}
	}

	result, err := c.Custody.New("af stripes", blockSize*p.Stripes)
	if err != nil {
		return nil, err
	}

	// The diffusion buffer is allocated and destroyed here rather than left to
	// the caller: it is as sensitive as the stripes and its lifetime is exactly
	// this call.
	buffer, err := c.Custody.New("af diffusion state", blockSize)
	if err != nil {
		c.Custody.Release(result)
		return nil, err
	}
	defer c.Custody.Release(buffer)

	err = secret.Borrow("af stripes", result, func(dst []byte) error {
		return secret.Borrow("af diffusion state", buffer, func(buf []byte) error {
			return secret.Borrow("af split input", key, func(data []byte) error {
				return splitInto(dst, data, buf, p.Stripes, hashFunc, c.Rand)
			})
		})
	})
	if err != nil {
		c.Custody.Release(result)
		return nil, err
	}

	return result, nil
}

// Merge reverses Split for a keySize-byte key without either the stripes or
// the recovered key leaving protected memory.
//
// split may be LARGER than keySize*p.Stripes -- a keyslot area on disk is 4
// KiB-aligned, so the decrypted area usually is -- and only that many bytes
// are consumed: merging the trailing alignment padding into the key would
// corrupt it. A split shorter than that is refused as ErrInvalidKeyslot.
func (c Codec) Merge(split *enclave.Memory, keySize int, p Params) (*enclave.Memory, error) {
	if keySize <= 0 || p.Stripes <= 0 {
		return nil, &errs.Error{Kind: errs.ErrInvalidKeyslot, Detail: "the anti-forensic material is not the size its stripes and key size declare"}
	}
	splitLen := keySize * p.Stripes

	hashFunc, err := c.mergeHash(p.Hash)
	if err != nil {
		return nil, err
	}

	result, err := c.Custody.New("merged master key", keySize)
	if err != nil {
		return nil, err
	}

	buffer, err := c.Custody.New("af diffusion state", keySize)
	if err != nil {
		c.Custody.Release(result)
		return nil, err
	}
	defer c.Custody.Release(buffer)

	err = secret.Borrow("merged master key", result, func(dst []byte) error {
		return secret.Borrow("af diffusion state", buffer, func(buf []byte) error {
			return secret.Borrow("af stripes", split, func(splitData []byte) error {
				if len(splitData) < splitLen {
					return &errs.Error{Kind: errs.ErrInvalidKeyslot, Detail: "the anti-forensic material is not the size its stripes and key size declare"}
				}
				mergeInto(dst, splitData[:splitLen], buf, p.Stripes, keySize, hashFunc)
				return nil
			})
		})
	})
	if err != nil {
		c.Custody.Release(result)
		return nil, err
	}

	return result, nil
}

// splitInto is the split itself, writing into caller-provided storage so
// that every split runs the SAME code regardless of where dst and buffer
// live.
//
// dst must be len(data)*stripes bytes and buffer must be len(data) bytes; both
// are the caller's to protect and to clear.
func splitInto(dst, data, buffer []byte, stripes int, hashFunc func() hash.Hash, rand io.Reader) error {
	blockSize := len(data)

	// Generate random data for all blocks except the last, straight into dst --
	// which for the enclave path is locked memory, so the stripes are never
	// anywhere else.
	randomSize := blockSize * (stripes - 1)
	if _, err := io.ReadFull(rand, dst[:randomSize]); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "failed to generate random data", Err: err}
	}

	for i := 0; i < stripes-1; i++ {
		block := dst[i*blockSize : (i+1)*blockSize]
		xorBytes(block, buffer, buffer)
		diffuse(buffer, hashFunc, blockSize)
	}

	// XOR with input data to get final block
	xorBytes(data, buffer, dst[randomSize:])

	return nil
}

// mergeInto is the merge itself, writing the recovered value into dst.
func mergeInto(dst, splitData, buffer []byte, stripes, blockSize int, hashFunc func() hash.Hash) {
	for i := 0; i < stripes-1; i++ {
		block := splitData[i*blockSize : (i+1)*blockSize]
		xorBytes(block, buffer, buffer)
		diffuse(buffer, hashFunc, blockSize)
	}

	// XOR with final block to recover data
	lastBlock := splitData[(stripes-1)*blockSize:]
	xorBytes(lastBlock, buffer, dst)
}

// maxDigestSize is the largest digest writeHash can return (SHA-512). It
// bounds the one stack scratch buffer diffuse still needs.
const maxDigestSize = sha512.Size

// diffuse performs diffusion using the hash function, IN PLACE.
//
// In place is not a micro-optimization here, it is custody. The previous form
// accumulated the result in a fresh heap slice and copied it back, so every
// call left a heap copy of the diffusion state -- which is master key material,
// see the file comment -- for the collector to move around and eventually
// release unzeroed. diffuse is called stripes-1 times per split or merge, which
// is 3999 times for a default container, so that was ~4000 unreachable copies
// of key-derived state per operation, on memory this package had already gone
// to some trouble to lock.
//
// Rewriting in place is exactly equivalent because output block i depends only
// on input block i: the blocks are disjoint, each is fully consumed by h.Write
// before h.Sum writes the digest back over it, and the remainder block is the
// tail past the last whole block, so it overlaps none of them.
func diffuse(data []byte, hashFunc func() hash.Hash, blockSize int) {
	h := hashFunc()
	digestSize := h.Size()
	numBlocks := blockSize / digestSize

	for i := 0; i < numBlocks; i++ {
		start := i * digestSize
		block := data[start : start+digestSize]
		// dst has length 0 and capacity digestSize over the block just read, so
		// h.Sum appends the digest exactly over it without allocating.
		hashBlockInto(block[:0:digestSize], block, h, i)
	}

	// Handle remaining bytes if blockSize isn't a multiple of digestSize. This
	// does not arise for any LUKS2 key size in practice -- 32 and 64 are both
	// multiples of both digest sizes -- but a header names its own hash and its
	// own key size, so the case is handled rather than assumed away.
	if remainder := blockSize % digestSize; remainder != 0 {
		lastBlock := data[blockSize-remainder:]
		// The destination cannot be the block itself here: it is shorter than
		// one digest, so h.Sum would allocate past its capacity and put the
		// state on the heap. A stack array is used and cleared instead.
		var scratch [maxDigestSize]byte
		hashed := hashBlockInto(scratch[:0], lastBlock, h, numBlocks)
		copy(data[blockSize-remainder:], hashed[:remainder])
		clear(hashed)
	}
}

// hashBlockInto hashes block with an IV and APPENDS the digest to dst,
// returning the extended slice. Appending into caller-provided storage is what
// lets diffuse keep the diffusion state in the memory it already owns; the
// digest is never returned on a fresh heap allocation.
func hashBlockInto(dst, block []byte, h hash.Hash, iv int) []byte {
	h.Reset()

	// Write IV as big-endian uint32. The IV is a stripe counter, not key
	// material, and lives on the stack.
	var ivBytes [4]byte
	binary.BigEndian.PutUint32(ivBytes[:], uint32(iv)) // #nosec G115 - iv bounded by stripe count (max ~4000)
	h.Write(ivBytes[:])

	// Write block data
	h.Write(block)

	return h.Sum(dst)
}

// xorBytes XORs the first len(dest) bytes of a and b into dest.
//
// crypto/subtle's word-at-a-time XOR rather than a byte loop: an AF split or
// merge calls this 3999 times per keyslot, and a byte loop in this package is
// also a coverage counter per byte under the instrumented test build (#92).
func xorBytes(a, b, dest []byte) {
	n := len(dest)
	subtle.XORBytes(dest, a[:n], b[:n])
}

// writeHash returns the anti-forensic hash a NEW keyslot may be written with:
// sha256 or sha512. It is the split's table, and SHA-1 is deliberately absent
// from it -- this module reads SHA-1 keyslots (Merge) and never creates one
// (#236).
func writeHash(name string) (func() hash.Hash, error) {
	switch name {
	case "sha256":
		return sha256.New, nil
	case "sha512":
		return sha512.New, nil
	case "sha1":
		return nil, &errs.Error{Kind: errs.ErrUnsupportedHash, Err: errs.ErrSHA1NotWritten, Detail: "sha1: an anti-forensic hash this package reads in legacy keyslots and never writes; use sha256 or sha512"}
	default:
		return nil, &errs.Error{Kind: errs.ErrUnsupportedHash, Detail: name + " (supported: sha256, sha512)"}
	}
}

// ValidateWriteHash reports whether name is an anti-forensic hash a new
// keyslot may be written with.
func ValidateWriteHash(name string) error {
	_, err := writeHash(name)
	return err
}

// mergeHash returns the anti-forensic hash an EXISTING keyslot is read with:
// writeHash's, plus SHA-1.
//
// SHA-1 is what LUKS1 used for the AF split by default, so every LUKS1 volume
// converted to LUKS2 carries it, as does any `cryptsetup luksFormat --hash
// sha1`; cryptsetup opens them and so must this module (#236). In FIPS 140-3
// mode it is refused before any hashing runs; see RequireApprovedHash.
func (c Codec) mergeHash(name string) (func() hash.Hash, error) {
	if err := RequireApprovedHash(c.FIPS, name); err != nil {
		return nil, err
	}
	if name == "sha1" {
		return sha1.New, nil
	}
	return writeHash(name)
}

// ValidateReadHash reports whether name is an anti-forensic hash an existing
// keyslot can be read with, whatever the FIPS policy: the structural question,
// as opposed to RequireApprovedHash's policy one.
func ValidateReadHash(name string) error {
	if name == "sha1" {
		return nil
	}
	return ValidateWriteHash(name)
}

// RequireApprovedHash refuses a non-approved anti-forensic hash -- SHA-1 -- in
// FIPS 140-3 mode, naming it. SHA-1 is not an approved diffuser for key
// material, and under GODEBUG=fips140=only the Go module makes sha1's Write
// return an error that hash.Hash callers discard, so the merge would otherwise
// complete with wrong bytes rather than fail.
func RequireApprovedHash(mode fips.Mode, name string) error {
	if name != "sha1" {
		return nil
	}
	return mode.RequireHash("anti-forensic merge with sha1", crypto.SHA1)
}
