// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

// ChangeKey rewrites a PBKDF2-SHA1 keyslot as PBKDF2-SHA256 at the larger of equal-work and equal-time iteration counts (RFC 8018 section 5.2); the math is in internal/kdf.

// sha256IterationsForSHA1 returns the PBKDF2-SHA256 count costing at least sha1Iterations of PBKDF2-SHA1 for keySize bytes; above the ceiling it returns header.MaxKDFIterations+1.
func sha256IterationsForSHA1(sha1Iterations, keySize int, sys volumeSys) (int, error) {
	return kdfDeriver(sys).SHA1Iterations(sha1Iterations, keySize, sys.sha1CostTimer)
}
