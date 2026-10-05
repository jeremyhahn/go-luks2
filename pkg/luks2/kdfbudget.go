// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"fmt"
	"math"

	"github.com/jeremyhahn/go-enclave"
)

// The aggregate key-derivation budget of one operation (#26).
//
// Every derivation is bounded on its own (validateKDFCost), but an unlock
// derives once per keyslot it tries and once per digest attesting that
// keyslot, and the header chooses how many of those there are. A header that
// declares each of them at the per-derivation ceiling makes one unlock attempt
// do that ceiling's work many times over before it refuses the passphrase.
//
// The budget is the work of the most expensive header cryptsetup can write:
// LUKS2MaxKeyslots keyslots (cryptsetup creates no more, and the scan tries
// no other ids), each attested by exactly one digest (cryptsetup refuses any
// other header, measured), every derivation at the per-derivation ceiling.
// So no container cryptsetup can produce is ever refused by it, and a crafted
// one that asks for more is refused before the first derivation.
//
// Work is counted in two units, because the two KDFs spend different things:
// PBKDF2 in PRF blocks (iterations times output blocks), Argon2 in KiB-passes
// (time cost times memory). Neither is converted into the other.

// kdfWork is an amount of key-derivation work.
type kdfWork struct {
	pbkdf2Blocks    uint64
	argon2KiBPasses uint64
}

// add is a saturating sum, so a crafted header cannot wrap the total.
func (w kdfWork) add(o kdfWork) kdfWork {
	return kdfWork{
		pbkdf2Blocks:    saturatingAdd(w.pbkdf2Blocks, o.pbkdf2Blocks),
		argon2KiBPasses: saturatingAdd(w.argon2KiBPasses, o.argon2KiBPasses),
	}
}

// exceeds reports whether w is more than budget in either unit.
func (w kdfWork) exceeds(budget kdfWork) bool {
	return w.pbkdf2Blocks > budget.pbkdf2Blocks || w.argon2KiBPasses > budget.argon2KiBPasses
}

func saturatingAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

func saturatingMul(a, b uint64) uint64 {
	if a != 0 && b > math.MaxUint64/a {
		return math.MaxUint64
	}
	return a * b
}

// maxDerivedKeyLen is the longest output any derivation in an unlock asks
// for: an area key (at most 64 bytes, XTS) or a digest (at most 64, sha512).
const maxDerivedKeyLen = 64

// minPRFOutputLen is the shortest PBKDF2 PRF output: SHA-1's 20 bytes, which
// needs the most blocks for a given output length.
const minPRFOutputLen = 20

// derivationWork is what one derivation of kdf to outLen bytes costs. The KDF
// has passed the screen, so its parameters are present and bounded.
func derivationWork(kdf *KDF, outLen int) kdfWork {
	if kdf == nil || outLen <= 0 {
		return kdfWork{}
	}
	switch normalizeKDFType(kdf.Type) {
	case KDFTypeArgon2i, KDFTypeArgon2id:
		if kdf.Time == nil || kdf.Memory == nil || *kdf.Time < 0 || *kdf.Memory < 0 {
			return kdfWork{}
		}
		return kdfWork{argon2KiBPasses: saturatingMul(uint64(*kdf.Time), uint64(*kdf.Memory))} // #nosec G115 -- non-negative, checked above
	default:
		if kdf.Iterations == nil || *kdf.Iterations < 0 {
			return kdfWork{}
		}
		hashLen := minPRFOutputLen
		if h, err := pbkdf2Hash(kdf.Hash); err == nil {
			hashLen = h.Size()
		}
		blocks := (outLen + hashLen - 1) / hashLen
		return kdfWork{pbkdf2Blocks: saturatingMul(uint64(*kdf.Iterations), uint64(blocks))} // #nosec G115 -- non-negative, checked above
	}
}

// ceilingWork is one derivation at the per-derivation ceilings, of either KDF.
var ceilingWork = kdfWork{
	pbkdf2Blocks:    uint64(maxKDFIterations) * ((maxDerivedKeyLen + minPRFOutputLen - 1) / minPRFOutputLen),
	argon2KiBPasses: uint64(maxArgon2Time) * uint64(maxArgon2Memory),
}

// operationKDFBudget is the work one unlock, verify or authorize operation may
// do: a keyslot derivation and a digest derivation, at the ceilings, for each
// of LUKS2MaxKeyslots keyslots.
var operationKDFBudget = kdfWork{
	pbkdf2Blocks:    2 * LUKS2MaxKeyslots * ceilingWork.pbkdf2Blocks,
	argon2KiBPasses: 2 * LUKS2MaxKeyslots * ceilingWork.argon2KiBPasses,
}

// scanPlan is what a keyslot scan over order would cost at most, were every
// keyslot tried: the derivations it would make, and the most locked memory
// one keyslot holds at a time.
type scanPlan struct {
	work       kdfWork
	peakLocked int64
}

// planKeyslotScan prices the scan getMasterKeySlot would make over order. It
// counts only what the scan would derive -- keyslots it would try, which the
// screen passes, and the digests that attest each of them and pass theirs --
// so a damaged entry costs nothing here, as it costs nothing there.
func planKeyslotScan(metadata *LUKS2Metadata, order []string) scanPlan {
	var plan scanPlan
	for _, id := range order {
		keyslot := metadata.Keyslots[id]
		if keyslot == nil || keyslot.Type != "luks2" {
			continue
		}
		if _, ok := canonicalKeyslotID(id); !ok {
			continue
		}
		kp, err := screenKeyslot(id, keyslot, metadata.Digests)
		if err != nil {
			continue
		}
		plan.work = plan.work.add(derivationWork(keyslot.KDF, kp.areaKeySize))
		digestWork, longestDigest := planDigests(metadata.Digests, func(d *Digest) bool { return digestCovers(d, id) })
		plan.work = plan.work.add(digestWork)
		plan.peakLocked = max(plan.peakLocked, keyslotOpenPeakLocked(kp, keyslot.KeySize, longestDigest))
	}
	return plan
}

// keyslotOpenPeakLocked is the most locked memory opening one keyslot holds at
// once: unlockKeyslotFrom and recoverKeyslotKey, allocation by allocation.
//
//	area key            passphraseKDF -> adoptSecret          areaKeySize   held to the end
//	decrypted stripes   decryptKeyMaterialEnclave             decryptLen    held to the end
//	merged key          afMergeEnclave, result                keySize       held to the end
//	diffusion state     afMergeEnclave, buffer                keySize       freed after the merge
//	derived digest      evaluateDigest -> deriveKeySecret     digest length one at a time, after the merge
//
// decryptLen is whole sectors, so the transform needs no partial-sector
// scratch (xtsPartialSector). TestKeyslotOpenPeakIsWhatTheUnlockAllocates
// measures the real sequence against this for each keyslot geometry, so the
// two cannot drift apart silently.
func keyslotOpenPeakLocked(kp keyslotPlan, keySize, longestDigest int) int64 {
	held := enclave.LockedSize(kp.areaKeySize) + enclave.LockedSize(int(kp.decryptLen)) + enclave.LockedSize(keySize) // #nosec G115 -- decryptLen is bounded by validateKeyslot
	merge := enclave.LockedSize(keySize)
	verify := int64(0)
	if longestDigest > 0 {
		verify = enclave.LockedSize(longestDigest)
	}
	return held + max(merge, verify)
}

// planDigests prices deriving every digest covers selects that passes its
// screen, and reports the longest of them.
func planDigests(digests map[string]*Digest, covers func(*Digest) bool) (work kdfWork, longest int) {
	for _, id := range sortedIDs(digests) {
		digest := digests[id]
		if !covers(digest) {
			continue
		}
		expected, kdf, err := screenDigest(digest)
		n := len(expected)
		clearBytes(expected)
		if err != nil {
			continue
		}
		work = work.add(derivationWork(kdf, n))
		longest = max(longest, n)
	}
	return work, longest
}

// checkKDFBudget refuses, before any derivation, an operation whose plan is
// over the aggregate budget, or whose single keyslot needs more locked memory
// than the process allocator could ever admit.
func checkKDFBudget(op string, plan scanPlan) error {
	if plan.work.exceeds(operationKDFBudget) {
		return &KDFBudgetError{Op: op, Need: plan.work, Budget: operationKDFBudget}
	}
	if plan.peakLocked > 0 {
		allocator, err := lockedMemoryAllocator()
		if err != nil {
			return &ProtectedMemoryError{Op: op, Err: err}
		}
		if limit := allocator.Limit(); plan.peakLocked > limit {
			return &ProtectedMemoryError{Op: op, Err: &enclave.BudgetError{Requested: plan.peakLocked, Limit: limit}}
		}
	}
	return nil
}

// KDFBudgetError reports an operation refused because the header would have it
// derive more than operationKDFBudget allows. Nothing was derived. It matches
// ErrKDFBudgetExceeded, and ErrInvalidHeader: no header cryptsetup can write
// asks for this much, so the header is the defect.
type KDFBudgetError struct {
	Op string
	// Need and Budget are in PBKDF2 PRF blocks and Argon2 KiB-passes; see
	// kdfWork. They are diagnostic, not contract.
	Need, Budget kdfWork
}

func (e *KDFBudgetError) Error() string {
	return fmt.Sprintf("%s: %s: the header asks for %d PBKDF2 blocks and %d Argon2 KiB-passes; one operation may spend %d and %d, the most any header cryptsetup writes can ask for",
		ErrKDFBudgetExceeded.Error(), e.Op, e.Need.pbkdf2Blocks, e.Need.argon2KiBPasses, e.Budget.pbkdf2Blocks, e.Budget.argon2KiBPasses)
}

// Is reports the error as both sentinels it stands for.
func (e *KDFBudgetError) Is(target error) bool {
	return target == ErrKDFBudgetExceeded || target == ErrInvalidHeader
}
