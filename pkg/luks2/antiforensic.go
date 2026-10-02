// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"github.com/jeremyhahn/go-enclave"
)

// Anti-forensic splitting and the custody of what it produces.
//
// AF STRIPES ARE MASTER KEY MATERIAL. It is easy to read afSplitEnclave as an
// obfuscation step and treat its output as less sensitive than its input, and
// that is backwards: the split is reversible with nothing but the stripes
// themselves -- afMergeEnclave takes no key -- so holding the stripes is
// holding the master key, spread over keySize*stripes bytes instead of
// keySize. For the default 512-bit key and 4000 stripes that is 256 KiB of
// key material, four thousand times the surface of the key it encodes, which
// is precisely why it must not sit on the ordinary heap.
//
// The diffusion buffer carries the same weight. It is the running XOR of the
// stripes, and combined with the final stripe it yields the key directly.

// afSplitEnclave performs anti-forensic splitting entirely inside protected
// memory: the secret is borrowed from its enclave, the stripes are generated
// into locked pages, and the diffusion state lives in a locked page of its own.
//
// The returned enclave holds blockSize*stripes bytes and is the caller's to
// destroy.
func afSplitEnclave(secret *enclave.MemoryEnclave, stripes int, hashAlgo string) (*enclave.MemoryEnclave, error) {
	if stripes <= 0 {
		return nil, fmt.Errorf("stripes must be positive")
	}

	hashFunc, err := getHashFunc(hashAlgo)
	if err != nil {
		return nil, err
	}

	blockSize := secret.Size()
	if blockSize == 0 {
		return nil, &ProtectedMemoryError{Op: "af split input", Err: enclave.ErrEnclaveDestroyed}
	}

	result, err := newSecretEnclave("af stripes", blockSize*stripes)
	if err != nil {
		return nil, err
	}

	// The diffusion buffer is allocated and destroyed here rather than left to
	// the caller: it is as sensitive as the stripes and its lifetime is exactly
	// this call.
	buffer, err := newSecretEnclave("af diffusion state", blockSize)
	if err != nil {
		releaseSecret(result)
		return nil, err
	}
	defer releaseSecret(buffer)

	err = borrowSecret("af stripes", result, func(dst []byte) error {
		return borrowSecret("af diffusion state", buffer, func(buf []byte) error {
			return borrowSecret("af split input", secret, func(data []byte) error {
				return afSplitInto(dst, data, buf, stripes, hashFunc)
			})
		})
	})
	if err != nil {
		releaseSecret(result)
		return nil, err
	}

	return result, nil
}

// afMergeEnclave reverses afSplitEnclave without either the stripes or the
// recovered secret leaving protected memory.
//
// splitLen bounds how much of the split enclave is consumed, because a keyslot
// area on disk is 4 KiB-aligned and therefore usually LARGER than the
// blockSize*stripes the merge needs. Passing the whole enclave would merge
// trailing alignment padding into the key.
func afMergeEnclave(split *enclave.MemoryEnclave, splitLen, stripes, blockSize int, hashAlgo string) (*enclave.MemoryEnclave, error) {
	if splitLen != blockSize*stripes {
		return nil, fmt.Errorf("invalid split data size")
	}

	hashFunc, err := getHashFunc(hashAlgo)
	if err != nil {
		return nil, err
	}

	result, err := newSecretEnclave("merged master key", blockSize)
	if err != nil {
		return nil, err
	}

	buffer, err := newSecretEnclave("af diffusion state", blockSize)
	if err != nil {
		releaseSecret(result)
		return nil, err
	}
	defer releaseSecret(buffer)

	err = borrowSecret("merged master key", result, func(dst []byte) error {
		return borrowSecret("af diffusion state", buffer, func(buf []byte) error {
			return borrowSecret("af stripes", split, func(splitData []byte) error {
				if len(splitData) < splitLen {
					return fmt.Errorf("invalid split data size")
				}
				afMergeInto(dst, splitData[:splitLen], buf, stripes, blockSize, hashFunc)
				return nil
			})
		})
	})
	if err != nil {
		releaseSecret(result)
		return nil, err
	}

	return result, nil
}

// afSplitInto is the split itself, writing into caller-provided storage so
// that afSplitEnclave's callers all run the SAME code regardless of where dst
// and buffer live.
//
// dst must be len(data)*stripes bytes and buffer must be len(data) bytes; both
// are the caller's to protect and to clear.
func afSplitInto(dst, data, buffer []byte, stripes int, hashFunc func() hash.Hash) error {
	blockSize := len(data)

	// Generate random data for all blocks except the last, straight into dst --
	// which for the enclave path is locked memory, so the stripes are never
	// anywhere else.
	randomSize := blockSize * (stripes - 1)
	if _, err := io.ReadFull(cryptoRand, dst[:randomSize]); err != nil {
		return fmt.Errorf("failed to generate random data: %w", err)
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

// afMergeInto is the merge itself, writing the recovered value into dst.
func afMergeInto(dst, splitData, buffer []byte, stripes, blockSize int, hashFunc func() hash.Hash) {
	for i := 0; i < stripes-1; i++ {
		block := splitData[i*blockSize : (i+1)*blockSize]
		xorBytes(block, buffer, buffer)
		diffuse(buffer, hashFunc, blockSize)
	}

	// XOR with final block to recover data
	lastBlock := splitData[(stripes-1)*blockSize:]
	xorBytes(lastBlock, buffer, dst)
}

// maxDigestSize is the largest digest getHashFunc can return (SHA-512). It
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
		clearBytes(hashed)
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

// xorBytes XORs two byte slices into dest
func xorBytes(a, b, dest []byte) {
	for i := range dest {
		dest[i] = a[i] ^ b[i]
	}
}

// getHashFunc returns a hash function by name
func getHashFunc(name string) (func() hash.Hash, error) {
	switch name {
	case "sha256":
		return sha256.New, nil
	case "sha512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedHash, name)
	}
}
