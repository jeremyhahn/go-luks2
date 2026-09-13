// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"math"
	"testing"
)

// TestChangeKeyRaisesABelowFloorCostRatherThanRefusing is the asymmetry between
// the pbkdf2 and argon2 halves of ChangeKey's cost preservation, and it is
// deliberate.
//
// # Why this needs cryptsetup
//
// The fixture is a container carrying a pbkdf2 count BELOW this package's
// floor, and no caller of this package can create one -- that is what the floor
// means. Nor can it be faked by rewriting the header: the iteration count is an
// input to the derivation, so changing the number in the JSON leaves key
// material no passphrase derives, and ChangeKey then fails at the unlock for an
// unrelated reason. (That is what the first draft of this test did, and it
// failed with "master key verification failed".)
//
// cryptsetup's --pbkdf-force-iterations writes both the count and the material
// consistently, which is exactly what an imported container looks like.
//
// # What it establishes
//
// Argon2 costs are preserved unconditionally, because argon2 has no floor here.
// PBKDF2 costs are preserved but RAISED to the floor when they sit under it.
// Refusing instead would mean an imported container could never have its
// passphrase changed -- this package declining to let an operator rotate a
// credential, which is a worse outcome than a keyslot stronger than the one
// asked for.
//
// Raising is also closer to the behavior it replaces: recalibration already
// turned a low count into a much larger one. What changes is that the increase
// stops at the floor rather than at whatever this machine benchmarks.
func TestChangeKeyRaisesABelowFloorCostRatherThanRefusing(t *testing.T) {
	requireCryptsetupDeclared(t)

	path := canonicalImage(t, "imported-weak.img")
	formatWithCryptsetupForced(t, path, minPBKDF2Iterations)

	floor := int(math.Ceil(pbkdf2IterationFloor("sha512", pbkdf2ReferenceTargetMs)))

	_, before, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if got := before.Keyslots["0"].KDF.Iterations; got == nil || *got != minPBKDF2Iterations {
		t.Fatalf("the fixture does not carry the below-floor count: %v", got)
	}
	if minPBKDF2Iterations >= floor {
		t.Fatalf("the fixture's %d iterations are not below the sha512 floor of %d; this test measures nothing",
			minPBKDF2Iterations, floor)
	}

	updated := []byte("the-replacement-credential")
	if err := ChangeKey(path, []byte(canonicalPassphrase), updated, 0); err != nil {
		t.Fatalf("ChangeKey refused a container carrying a below-floor cost: %v", err)
	}

	_, after, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	got := after.Keyslots["0"].KDF.Iterations
	if got == nil {
		t.Fatal("the keyslot has no iteration count after ChangeKey")
	}
	if *got != floor {
		t.Fatalf("ChangeKey wrote %d iterations, want the sha512 floor %d", *got, floor)
	}

	// Raising the cost must not have broken the keyslot: the rewritten material
	// has to be derivable at the count now recorded beside it.
	if err := TestKey(path, updated); err != nil {
		t.Fatalf("the new passphrase does not open the volume after the cost was raised: %v", err)
	}
	if err := TestKey(path, []byte(canonicalPassphrase)); err == nil {
		t.Fatal("the old passphrase still opens the volume")
	}
}
