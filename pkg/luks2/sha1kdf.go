// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

// Rewriting a PBKDF2-SHA1 keyslot as PBKDF2-SHA256 at no lower cost (#239).
//
// ChangeKey never writes SHA-1, so a PBKDF2-SHA1 keyslot -- a converted LUKS1
// one -- is rewritten as PBKDF2-SHA256. Its iteration count cannot simply be
// copied. PBKDF2 derives its output in blocks of the hash's length, and each
// block is a full chain of the iteration count's HMACs (RFC 8018 section 5.2):
// a 64-byte XTS key is four SHA-1 blocks but two SHA-256 blocks, so the same
// count is HALF the HMACs. Nor is an HMAC of either hash a fixed multiple of
// the other's: on CPUs with SHA extensions an HMAC-SHA256 can cost less than
// an HMAC-SHA1. So the count is converted from cost, by two bounds, and the
// larger is taken:
//
//   - equal work: as many SHA-256 HMACs as the SHA-1 keyslot took, which the
//     block counts fix exactly;
//   - equal time on this machine: the SHA-1 count scaled by the measured cost
//     of an iteration of each, measured conservatively -- the slowest SHA-1
//     sample against the fastest SHA-256 sample -- so measurement noise can
//     only raise the count.
//
// The caller then raises the result to the SHA-256 floor, and a count past
// the ceiling is refused by CreateKDF before anything is written.
//
// The measurement and the cost math live in internal/kdf
// (Deriver.SHA1Iterations); this file keeps the seam the measurement runs
// through.

// sha256IterationsForSHA1 returns the PBKDF2-SHA256 iteration count whose
// derivation of keySize bytes costs at least what sha1Iterations of
// PBKDF2-SHA1 to keySize bytes cost, by work and by measured time. A result
// past header.MaxKDFIterations is returned as header.MaxKDFIterations+1, for the caller's
// range check to refuse rather than for this to wrap.
func sha256IterationsForSHA1(sha1Iterations, keySize int, sys volumeSys) (int, error) {
	return kdfDeriver(sys).SHA1Iterations(sha1Iterations, keySize, sys.sha1CostTimer)
}
