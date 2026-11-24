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

// One operation's aggregate KDF budget: the most expensive header cryptsetup can write, counted in PBKDF2 PRF blocks and Argon2 KiB-passes.

// kdfWork is an amount of key-derivation work (alias of kdf.Work) with a saturating Add and Exceeds.
type kdfWork = kdf.Work

// derivationWork is what one derivation of k to outLen bytes costs. The KDF
// has passed the screen, so its parameters are present and bounded.
func derivationWork(k *header.KDF, outLen int) kdfWork {
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

// planKeyslotScan prices only what getMasterKeySlot's scan over order would derive.
func planKeyslotScan(metadata *header.Metadata, order []string) scanPlan {
	var plan scanPlan
	for _, id := range order {
		keyslot := metadata.Keyslots[id]
		if keyslot == nil || keyslot.Type != "luks2" {
			continue
		}
		if _, ok := header.CanonicalKeyslotID(id); !ok {
			continue
		}
		kp, err := screenKeyslot(id, keyslot, metadata.Digests, fips.Probe)
		if err != nil {
			continue
		}
		plan.work = plan.work.Add(derivationWork(keyslot.KDF, kp.areaKeySize))
		digestWork, longestDigest := planDigests(metadata.Digests, func(d *header.Digest) bool { return digestCovers(d, id) })
		plan.work = plan.work.Add(digestWork)
		plan.peakLocked = max(plan.peakLocked, keyslotOpenPeakLocked(kp, keyslot.KeySize, longestDigest))
	}
	return plan
}

// keyslotOpenPeakLocked is the most locked memory opening one keyslot holds at once; TestKeyslotOpenPeakIsWhatTheUnlockAllocates checks it.
func keyslotOpenPeakLocked(kp keyslotPlan, keySize, longestDigest int) int64 {
	held := enclave.LockedSize(kp.areaKeySize) + enclave.LockedSize(int(kp.decryptLen)) + enclave.LockedSize(keySize) // #nosec G115 -- decryptLen is bounded by header.ValidateKeyslot
	merge := enclave.LockedSize(keySize)
	verify := int64(0)
	if longestDigest > 0 {
		verify = enclave.LockedSize(longestDigest)
	}
	return held + max(merge, verify)
}

// planDigests prices deriving every digest covers selects that passes its
// screen, and reports the longest of them.
func planDigests(digests map[string]*header.Digest, covers func(*header.Digest) bool) (work kdfWork, longest int) {
	for _, id := range header.SortedIDs(digests) {
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

// An operation over operationKDFBudget is refused before deriving, as ErrInvalidHeader.
