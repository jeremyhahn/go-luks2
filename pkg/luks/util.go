// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
)

// nextPowerOf2 returns the next power of 2 >= n
func nextPowerOf2(n int) int {
	if n <= 0 {
		return 1
	}
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n++
	return n
}

// clearBytes securely zeros a byte slice
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// randomBytes generates cryptographically secure random bytes
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

// randomBase64 generates a base64-encoded random string
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
