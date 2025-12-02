// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
)

// AFSplit performs anti-forensic information splitting
// Splits the input data into stripes using the specified hash algorithm
// This is the LUKS standard AF splitter (AFSplit)
func AFSplit(data []byte, stripes int, hashAlgo string) ([]byte, error) {
	if stripes <= 0 {
		return nil, fmt.Errorf("stripes must be positive")
	}

	blockSize := len(data)
	totalSize := blockSize * stripes
	result := make([]byte, totalSize)

	// Generate random data for all blocks except the last
	randomSize := blockSize * (stripes - 1)
	if _, err := rand.Read(result[:randomSize]); err != nil {
		return nil, fmt.Errorf("failed to generate random data: %w", err)
	}

	// Calculate the last block using diffusion
	hashFunc, err := getHashFunc(hashAlgo)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, blockSize)
	defer clearBytes(buffer)
	for i := 0; i < stripes-1; i++ {
		block := result[i*blockSize : (i+1)*blockSize]
		xorBytes(block, buffer, buffer)
		diffuse(buffer, hashFunc, blockSize)
	}

	// XOR with input data to get final block
	xorBytes(data, buffer, result[randomSize:])

	return result, nil
}

// AFMerge performs anti-forensic information merging
// Recovers the original data from the split stripes
func AFMerge(splitData []byte, stripes int, blockSize int, hashAlgo string) ([]byte, error) {
	if len(splitData) != blockSize*stripes {
		return nil, fmt.Errorf("invalid split data size")
	}

	hashFunc, err := getHashFunc(hashAlgo)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, blockSize)
	defer clearBytes(buffer)
	for i := 0; i < stripes-1; i++ {
		block := splitData[i*blockSize : (i+1)*blockSize]
		xorBytes(block, buffer, buffer)
		diffuse(buffer, hashFunc, blockSize)
	}

	// XOR with final block to recover data
	result := make([]byte, blockSize)
	lastBlock := splitData[(stripes-1)*blockSize:]
	xorBytes(lastBlock, buffer, result)

	return result, nil
}

// diffuse performs diffusion using the hash function
func diffuse(data []byte, hashFunc func() hash.Hash, blockSize int) {
	h := hashFunc()
	digestSize := h.Size()
	numBlocks := blockSize / digestSize

	result := make([]byte, 0, blockSize)

	for i := 0; i < numBlocks; i++ {
		block := data[i*digestSize : (i+1)*digestSize]
		result = append(result, hashBlock(block, h, i)...)
	}

	// Handle remaining bytes if blockSize isn't a multiple of digestSize
	if remainder := blockSize % digestSize; remainder != 0 {
		lastBlock := data[blockSize-remainder:]
		hashed := hashBlock(lastBlock, h, numBlocks)
		result = append(result, hashed[:remainder]...)
	}

	copy(data, result)
	clearBytes(result)
}

// hashBlock hashes a block with an IV
func hashBlock(block []byte, h hash.Hash, iv int) []byte {
	h.Reset()

	// Write IV as big-endian uint32
	ivBytes := make([]byte, 4)
	defer clearBytes(ivBytes)
	binary.BigEndian.PutUint32(ivBytes, uint32(iv)) // #nosec G115 - iv bounded by stripe count (max ~4000)
	h.Write(ivBytes)

	// Write block data
	h.Write(block)

	return h.Sum(nil)
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
		return nil, fmt.Errorf("unsupported hash algorithm: %s", name)
	}
}
