// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"fmt"
	"github.com/jeremyhahn/go-luks2/internal/fips"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/internal/kdf"
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
// MaxKeyslots keyslots (cryptsetup creates no more, and the scan tries
// no other ids), each attested by exactly one digest (cryptsetup refuses any
// other header, measured), every derivation at the per-derivation ceiling.
// So no container cryptsetup can produce is ever refused by it, and a crafted
// one that asks for more is refused before the first derivation.
//
// Work is counted in two units, because the two KDFs spend different things:
// PBKDF2 in PRF blocks (iterations times output blocks), Argon2 in KiB-passes
// (time cost times memory). Neither is converted into the other.

// kdfWork is an amount of key-derivation work. Add is a saturating sum, so a
// crafted header cannot wrap the total, and Exceeds reports whether one
// amount is more than a budget in either unit; both live on kdf.Work, which
// this is an alias of.
type kdfWork = kdf.Work

// derivationWork is what one derivation of k to outLen bytes costs. The KDF
// has passed the screen, so its parameters are present and bounded.
func derivationWork(k *rawKDF, outLen int) kdfWork {
	if k == nil || outLen <= 0 {
		return kdfWork{}
	}
	return kdf.DerivationWork(toKDFParams(k), outLen)
}

// operationKDFBudget is the work one unlock, verify or authorize operation may
// do: a keyslot derivation and a digest derivation, at the per-derivation
// ceilings, for each of MaxKeyslots keyslots.
var operationKDFBudget = kdf.OperationBudget(MaxKeyslots)

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
func planKeyslotScan(metadata *header.Metadata, order []string) scanPlan {
	var plan scanPlan
	for _, id := range order {
		keyslot := metadata.Keyslots[id]
		if keyslot == nil || keyslot.Type != "luks2" {
			continue
		}
		if _, ok := canonicalKeyslotID(id); !ok {
			continue
		}
		kp, err := screenKeyslot(id, keyslot, metadata.Digests, fips.Probe)
		if err != nil {
			continue
		}
		plan.work = plan.work.Add(derivationWork(keyslot.KDF, kp.areaKeySize))
		digestWork, longestDigest := planDigests(metadata.Digests, func(d *rawDigest) bool { return digestCovers(d, id) })
		plan.work = plan.work.Add(digestWork)
		plan.peakLocked = max(plan.peakLocked, keyslotOpenPeakLocked(kp, keyslot.KeySize, longestDigest))
	}
	return plan
}

// keyslotOpenPeakLocked is the most locked memory opening one keyslot holds at
// once: unlockKeyslotFrom and recoverKeyslotKey, allocation by allocation.
//
//	area key            passphraseKDF -> custody.Adopt          areaKeySize   held to the end
//	decrypted stripes   areacipher DecryptEnclave             decryptLen    held to the end
//	merged key          af.Codec.Merge, result                keySize       held to the end
//	diffusion state     af.Codec.Merge, buffer                keySize       freed after the merge
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
func planDigests(digests map[string]*rawDigest, covers func(*rawDigest) bool) (work kdfWork, longest int) {
	for _, id := range sortedIDs(digests) {
		digest := digests[id]
		if !covers(digest) {
			continue
		}
		expected, kdf, err := screenDigest(digest, fips.Probe)
		n := len(expected)
		clearBytes(expected)
		if err != nil {
			continue
		}
		work = work.Add(derivationWork(kdf, n))
		longest = max(longest, n)
	}
	return work, longest
}

// checkKDFBudget refuses, before any derivation, an operation whose plan is
// over the aggregate budget, or whose single keyslot needs more locked memory
// than the process allocator could ever admit.
func checkKDFBudget(op string, plan scanPlan) error {
	if plan.work.Exceeds(operationKDFBudget) {
		return &errs.Error{Kind: ErrInvalidHeader, Detail: fmt.Sprintf(
			"%s: the header asks for %d PBKDF2 blocks and %d Argon2 KiB-passes; one operation may spend %d and %d, the most any header cryptsetup writes can ask for",
			op, plan.work.PBKDF2Blocks, plan.work.Argon2KiBPasses, operationKDFBudget.PBKDF2Blocks, operationKDFBudget.Argon2KiBPasses)}
	}
	if plan.peakLocked > 0 {
		return custody.Admissible(op, plan.peakLocked)
	}
	return nil
}

// An operation refused because the header would have it derive more than
// operationKDFBudget allows -- nothing was derived -- is an *errs.Error
// with Kind ErrInvalidHeader: no header cryptsetup can write asks for this
// much, so the header is the defect.
