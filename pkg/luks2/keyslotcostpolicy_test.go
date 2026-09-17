// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Tests for the PBKDF2 floor exemption granted to credentials THIS LIBRARY
// GENERATED.
//
// The tests that matter here are the ones that fail if the exemption becomes
// reachable from outside. A test showing that the exempt path can write 1000
// proves the feature works; it does not prove it is safe, and safety is the
// entire question. So the first three below are boundary tests and the happy
// path comes last.

// TestTheExemptionIsUnreachableFromOutsideThePackage is the structural
// assertion, and it is deliberately about the TYPE SYSTEM rather than about
// behavior.
//
// keyslotCostPolicy is unexported and its zero value is the strict policy, so a
// caller cannot select the exemption, cannot construct the value, and cannot
// reach it by leaving a field unset. If someone later adds a Force or SkipFloor
// bool to AddKeyOptions, this test is what notices.
func TestTheExemptionIsUnreachableFromOutsideThePackage(t *testing.T) {
	// The zero value must be the STRICT policy. Everything downstream relies on
	// a forgotten argument failing closed.
	var unset keyslotCostPolicy
	if unset != callerSuppliedCredential {
		t.Fatal("the zero keyslotCostPolicy is not callerSuppliedCredential; a forgotten argument would grant the exemption")
	}

	// No exported field may offer it. The exemption travels as an unexported
	// argument on an unexported function, and an options struct is exactly
	// where a well-meaning change would put a bool instead.
	for _, field := range reflect.VisibleFields(reflect.TypeOf(AddKeyOptions{})) {
		name := strings.ToLower(field.Name)
		for _, forbidden := range []string{"force", "skip", "bypass", "unsafe", "weak", "policy"} {
			if strings.Contains(name, forbidden) {
				t.Errorf("AddKeyOptions.%s looks like a caller-facing floor override; "+
					"the exemption must be reachable only because the library generated the credential", field.Name)
			}
		}
	}
}

// TestCallerSuppliedCredentialsKeepTheFullFloor is the property the exemption
// must not erode. systemd's 1000 is legitimate for a 256-bit generated key and
// catastrophic for a passphrase, and nothing about the mechanism may blur that.
func TestCallerSuppliedCredentialsKeepTheFullFloor(t *testing.T) {
	tests := []struct {
		hash    string
		wantMin int
	}{
		{"sha1", 1_300_000},
		{"sha256", 600_000},
		{"sha512", 210_000},
	}

	for _, tt := range tests {
		t.Run(tt.hash, func(t *testing.T) {
			got, err := forcedPBKDF2Iterations(tt.hash, minPBKDF2Iterations, callerSuppliedCredential)
			if err == nil {
				t.Fatalf("a caller-supplied %s credential was accepted at %d iterations (%d)",
					tt.hash, minPBKDF2Iterations, got)
			}
			if !errors.Is(err, ErrPBKDFIterationsTooLow) {
				t.Fatalf("error = %v, want ErrPBKDFIterationsTooLow", err)
			}
			var refusal *PBKDFIterationsError
			if !errors.As(err, &refusal) {
				t.Fatalf("error %v is not a *PBKDFIterationsError", err)
			}
			if refusal.Minimum != tt.wantMin {
				t.Fatalf("reported minimum %d, want %d", refusal.Minimum, tt.wantMin)
			}
		})
	}
}

// TestTheExemptPathStillHasAFloor is the other half of "exempt": the
// hash-dependent floor stops applying, the absolute one does not.
func TestTheExemptPathStillHasAFloor(t *testing.T) {
	for _, iterations := range []int{0, -1, -1000, minPBKDF2Iterations - 1} {
		got, err := forcedPBKDF2Iterations("sha512", iterations, libraryGeneratedCredential)
		if err == nil {
			t.Fatalf("the exempt path accepted %d iterations and returned %d", iterations, got)
		}
		if !errors.Is(err, ErrPBKDFIterationsTooLow) {
			t.Fatalf("forcedPBKDF2Iterations(%d) error = %v, want ErrPBKDFIterationsTooLow", iterations, err)
		}
		var refusal *PBKDFIterationsError
		if !errors.As(err, &refusal) {
			t.Fatalf("error %v is not a *PBKDFIterationsError; both paths must refuse the same way", err)
		}
		if refusal.Minimum != minPBKDF2Iterations {
			t.Fatalf("the exempt floor is reported as %d, want %d", refusal.Minimum, minPBKDF2Iterations)
		}
	}

	// The ceiling is not relaxed either.
	if _, err := forcedPBKDF2Iterations("sha512", maxKDFIterations+1, libraryGeneratedCredential); !errors.Is(err, ErrPBKDFIterationsTooHigh) {
		t.Fatalf("the exempt path accepted a count above the ceiling: %v", err)
	}
}

// TestTheExemptPathAcceptsSystemdsParameters is the happy path, and the reason
// the exemption exists: systemd enrolls pbkdf2/sha512/1000 for recovery keys
// and FIDO2 tokens, so a package that cannot write that cannot reproduce a
// systemd-enrolled header.
func TestTheExemptPathAcceptsSystemdsParameters(t *testing.T) {
	for _, hash := range []string{"sha1", "sha256", "sha512"} {
		got, err := forcedPBKDF2Iterations(hash, minPBKDF2Iterations, libraryGeneratedCredential)
		if err != nil {
			t.Fatalf("the exempt path refused systemd's %s/%d: %v", hash, minPBKDF2Iterations, err)
		}
		if got != minPBKDF2Iterations {
			t.Fatalf("got %d iterations, want %d written unchanged", got, minPBKDF2Iterations)
		}
	}
}

// TestPublicEntryPointsCannotReachTheExemption drives the exported API rather
// than the validator, because the validator is not where a bypass would appear.
// AddKey and Format are the two ways a caller reaches keyslot creation, and
// both must refuse systemd's count for a credential they did not generate.
func TestPublicEntryPointsCannotReachTheExemption(t *testing.T) {
	t.Run("Format", func(t *testing.T) {
		opts := standardFormatOptions(newImage(t, "exempt-format.img"))
		opts.PBKDFIterations = minPBKDF2Iterations
		if err := Format(opts); !errors.Is(err, ErrPBKDFIterationsTooLow) {
			t.Fatalf("Format = %v, want ErrPBKDFIterationsTooLow", err)
		}
	})

	t.Run("AddKey", func(t *testing.T) {
		path := newImage(t, "exempt-addkey.img")
		formatWithLibrary(t, path)

		_, err := AddKey(path, []byte(conformancePassphrase), []byte("a-second-credential"), &AddKeyOptions{
			KDFType:         KDFTypePBKDF2,
			Hash:            "sha512",
			PBKDFIterations: minPBKDF2Iterations,
		})
		if !errors.Is(err, ErrPBKDFIterationsTooLow) {
			t.Fatalf("AddKey = %v, want ErrPBKDFIterationsTooLow", err)
		}
	})

	t.Run("CreateKDF", func(t *testing.T) {
		_, err := CreateKDF(FormatOptions{
			KDFType:         KDFTypePBKDF2,
			HashAlgo:        "sha512",
			PBKDFIterations: minPBKDF2Iterations,
		}, 64)
		if !errors.Is(err, ErrPBKDFIterationsTooLow) {
			t.Fatalf("CreateKDF = %v, want ErrPBKDFIterationsTooLow", err)
		}
	})
}

// TestTheInternalSeamWritesSystemdsCountToTheHeader is the end-to-end form of
// the exemption, through the same unexported entry point AddRecoveryKey and
// EnrollKeyProvider will call.
func TestTheInternalSeamWritesSystemdsCountToTheHeader(t *testing.T) {
	path := newImage(t, "generated-credential.img")
	formatWithLibrary(t, path)

	// A credential this package generated: 256 CSPRNG bits, which is what makes
	// the iteration count irrelevant. Nothing about the mechanism depends on
	// that being true, which is exactly why the seam is unexported.
	generated, err := randomBase64(32)
	if err != nil {
		t.Fatalf("randomBase64 failed: %v", err)
	}

	assigned, err := addKeyWithPolicy(path, []byte(conformancePassphrase), []byte(generated), &AddKeyOptions{
		KDFType:         KDFTypePBKDF2,
		Hash:            "sha512",
		PBKDFIterations: minPBKDF2Iterations,
	}, libraryGeneratedCredential)
	if err != nil {
		t.Fatalf("addKeyWithPolicy with a generated credential: %v", err)
	}

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	kdf := metadata.Keyslots[strconv.Itoa(assigned)].KDF
	if kdf == nil || kdf.Iterations == nil {
		t.Fatalf("keyslot %d has no PBKDF2 iteration count", assigned)
	}
	if *kdf.Iterations != minPBKDF2Iterations {
		t.Fatalf("keyslot %d records %d iterations, want systemd's %d",
			assigned, *kdf.Iterations, minPBKDF2Iterations)
	}

	if err := TestKey(path, []byte(generated)); err != nil {
		t.Fatalf("the generated credential does not open the volume: %v", err)
	}
	// And the strict path is unchanged by its presence.
	if err := TestKey(path, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("the original passphrase no longer opens the volume: %v", err)
	}
}

// TestAddRecoveryKeyReachesTheExemption is the PRODUCTION form of the
// exemption, and the one the seam test above cannot stand in for.
//
// The seam test calls addKeyWithPolicy directly, so it proves the mechanism
// works when something selects it. It says nothing about whether anything in
// the shipped API ever does -- and for a while nothing did: AddRecoveryKey
// called AddKey, which hardcodes callerSuppliedCredential, so the relaxed branch
// was reachable only from that test. A policy no exported path can select is
// indistinguishable from one that does not exist.
//
// This test goes through AddRecoveryKey, the way a consumer does, and asserts
// the systemd-compatible count lands in the header. It fails if the wiring is
// removed, if RecoveryKeyOptions stops forwarding the count, or if the policy
// reverts to strict -- each of which returns ErrPBKDFIterationsTooLow here.
func TestAddRecoveryKeyReachesTheExemption(t *testing.T) {
	path := newImage(t, "recovery-exemption.img")
	formatWithLibrary(t, path)

	// systemd's own parameters: pbkdf2/sha512/1000. The sha512 floor is 210000,
	// so this is exactly the header the strict policy cannot write.
	recoveryKey, err := AddRecoveryKey(path, []byte(conformancePassphrase), &RecoveryKeyOptions{
		KDFType:         KDFTypePBKDF2,
		Hash:            "sha512",
		PBKDFIterations: minPBKDF2Iterations,
	})
	if err != nil {
		t.Fatalf("AddRecoveryKey at systemd's parameters: %v", err)
	}
	defer recoveryKey.Clear()

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	// The slot AddRecoveryKey chose, not any pbkdf2 slot: the container was
	// formatted with one already, at its own calibrated count.
	ks := metadata.Keyslots[strconv.Itoa(recoveryKey.Keyslot)]
	if ks == nil || ks.KDF == nil || ks.KDF.Iterations == nil {
		t.Fatalf("keyslot %d has no PBKDF2 iteration count", recoveryKey.Keyslot)
	}
	if *ks.KDF.Iterations != minPBKDF2Iterations {
		t.Fatalf("keyslot %d records %d iterations, want systemd's %d",
			recoveryKey.Keyslot, *ks.KDF.Iterations, minPBKDF2Iterations)
	}

	// And it opens the volume, so the exemption produced a usable keyslot
	// rather than merely a well-formed header.
	if err := borrowSecret("recovery key", recoveryKey.Credential, func(raw []byte) error {
		return TestKey(path, raw)
	}); err != nil {
		t.Fatalf("the recovery key does not open the volume: %v", err)
	}
}

// TestAddKeyKeepsTheFullFloorForTheSameCount is the other half of the pair: the
// exemption belongs to the credential's ORIGIN, not to the number. The exact
// count AddRecoveryKey just wrote is refused when a caller supplies the bytes.
func TestAddKeyKeepsTheFullFloorForTheSameCount(t *testing.T) {
	path := newImage(t, "recovery-exemption-negative.img")
	formatWithLibrary(t, path)

	_, err := AddKey(path, []byte(conformancePassphrase), []byte("a-caller-supplied-credential"), &AddKeyOptions{
		KDFType:         KDFTypePBKDF2,
		Hash:            "sha512",
		PBKDFIterations: minPBKDF2Iterations,
	})
	if !errors.Is(err, ErrPBKDFIterationsTooLow) {
		t.Fatalf("AddKey = %v, want ErrPBKDFIterationsTooLow", err)
	}
}

// TestAddKeyInheritsTheContainersArgon2Cost is the owner-facing defect: a
// volume deliberately formatted at 512 MiB -- chosen so it stays openable from
// a rescue USB or a small recovery box -- used to gain keyslots at this
// package's hardcoded 1 GiB default, inconsistently with every neighbor and
// precisely on the credential added for a recovery scenario.
func TestAddKeyInheritsTheContainersArgon2Cost(t *testing.T) {
	const containerMemory = 512_000

	container := &LUKS2Metadata{Keyslots: map[string]*Keyslot{
		"0": {Type: "luks2", KDF: &KDF{
			Type: KDFTypeArgon2id, Salt: "AAAA",
			Time: intPtr(4), Memory: intPtr(containerMemory), CPUs: intPtr(2),
		}},
	}}

	opts, inherited := addKeyFormatOptions(&AddKeyOptions{}, container)
	if inherited == nil {
		t.Fatal("AddKey did not report inheriting the container's cost")
	}
	if opts.Argon2Memory != containerMemory {
		t.Fatalf("Argon2Memory = %d, want the container's %d -- the 1 GiB default is back",
			opts.Argon2Memory, containerMemory)
	}
	if opts.Argon2Time != 4 || opts.Argon2Parallel != 2 {
		t.Fatalf("time/parallel = %d/%d, want the container's 4/2", opts.Argon2Time, opts.Argon2Parallel)
	}
}

// TestAddKeyInheritsABelowFloorArgon2CostExactly encodes the invariant: every
// keyslot in a volume should be derivable by the hardware that owns the volume.
//
// The inherited cost is NOT clamped up to MinArgon2MemoryKB. The machine adding
// a key need not be the machine using the volume, so a clamp succeeds on a
// roomy workstation and writes a keyslot the 32 MiB target cannot derive at
// all -- a lockout discovered later, by whoever needed that credential. And it
// buys nothing: a volume's resistance is bounded by its weakest slot, which on
// this container is already 32 MiB.
func TestAddKeyInheritsABelowFloorArgon2CostExactly(t *testing.T) {
	const containerMemory = 32768

	container := &LUKS2Metadata{Keyslots: map[string]*Keyslot{
		"0": {Type: "luks2", KDF: &KDF{
			Type: KDFTypeArgon2id, Salt: "AAAA",
			Time: intPtr(4), Memory: intPtr(containerMemory), CPUs: intPtr(1),
		}},
	}}

	opts, inherited := addKeyFormatOptions(&AddKeyOptions{}, container)
	if inherited == nil {
		t.Fatal("AddKey did not report inheriting the container's cost")
	}
	if containerMemory >= MinArgon2MemoryKB {
		t.Fatalf("the fixture's %d KiB is not below the floor of %d; this test measures nothing",
			containerMemory, MinArgon2MemoryKB)
	}
	if opts.Argon2Memory != containerMemory {
		t.Fatalf("Argon2Memory = %d, want the container's %d preserved exactly",
			opts.Argon2Memory, containerMemory)
	}
	if opts.Argon2Memory == MinArgon2MemoryKB {
		t.Fatal("the inherited cost was clamped to the create floor; a keyslot the owning " +
			"hardware cannot derive is not hardening")
	}
	// The report carries the same value, so an operator can see a below-floor
	// cost was carried rather than discovering it from a dump.
	if inherited.Memory == nil || *inherited.Memory != containerMemory {
		t.Fatalf("the report says memory %v, want %d", inherited.Memory, containerMemory)
	}
}

// TestAddKeyDoesNotInheritWhenTheCallerChose is the control: inheritance is a
// better default, not an override of the caller.
func TestAddKeyDoesNotInheritWhenTheCallerChose(t *testing.T) {
	container := &LUKS2Metadata{Keyslots: map[string]*Keyslot{
		"0": {Type: "luks2", KDF: &KDF{
			Type: KDFTypeArgon2id, Salt: "AAAA",
			Time: intPtr(4), Memory: intPtr(512_000), CPUs: intPtr(2),
		}},
	}}

	opts, inherited := addKeyFormatOptions(&AddKeyOptions{Argon2Memory: 2_000_000}, container)
	if inherited != nil {
		t.Fatal("AddKey reported inheriting a cost the caller supplied")
	}
	if opts.Argon2Memory != 2_000_000 {
		t.Fatalf("Argon2Memory = %d, want the caller's 2000000", opts.Argon2Memory)
	}
}

// TestAddKeyFallsBackToDefaultsForANonArgon2Container covers the shape with
// nothing to inherit: a pbkdf2 container carries no Argon2 cost, so the
// package defaults stand and nothing is reported.
func TestAddKeyFallsBackToDefaultsForANonArgon2Container(t *testing.T) {
	container := &LUKS2Metadata{Keyslots: map[string]*Keyslot{
		"0": {Type: "luks2", KDF: &KDF{Type: KDFTypePBKDF2, Hash: "sha512", Salt: "AAAA", Iterations: intPtr(210000)}},
	}}

	for _, metadata := range []*LUKS2Metadata{container, {Keyslots: map[string]*Keyslot{}}, nil} {
		opts, inherited := addKeyFormatOptions(&AddKeyOptions{}, metadata)
		if inherited != nil {
			t.Fatalf("reported inheriting %+v from a container with no Argon2 cost", inherited)
		}
		if opts.Argon2Memory != 1048576 {
			t.Fatalf("Argon2Memory = %d, want the package default 1048576", opts.Argon2Memory)
		}
	}
}

// TestAddKeyReportsTheInheritedCostToTheCaller is the visibility requirement.
// The value must reach the caller at the point of decision rather than be left
// to be inferred from the header afterwards.
func TestAddKeyReportsTheInheritedCostToTheCaller(t *testing.T) {
	path := newImage(t, "inherited-report.img")
	if err := Format(FormatOptions{
		Device:         path,
		Passphrase:     []byte(conformancePassphrase),
		Cipher:         "aes",
		CipherMode:     "xts-plain64",
		KeySize:        512,
		HashAlgo:       "sha512",
		SectorSize:     512,
		KDFType:        KDFTypeArgon2id,
		Argon2Time:     1,
		Argon2Memory:   MinArgon2MemoryKB,
		Argon2Parallel: 1,
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	opts := &AddKeyOptions{}
	if _, err := AddKey(path, []byte(conformancePassphrase), []byte("a-second-credential"), opts); err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}

	if opts.InheritedArgon2Cost == nil {
		t.Fatal("AddKey did not report the inherited cost; an operator cannot tell it came from the container")
	}
	if got := opts.InheritedArgon2Cost.Memory; got == nil || *got != MinArgon2MemoryKB {
		t.Fatalf("reported memory %v, want the container's %d", got, MinArgon2MemoryKB)
	}

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	for id, keyslot := range metadata.Keyslots {
		if keyslot.KDF.Memory == nil || *keyslot.KDF.Memory != MinArgon2MemoryKB {
			t.Fatalf("keyslot %s has memory %v; every slot should share the container's cost",
				id, keyslot.KDF.Memory)
		}
	}
}

// TestListKeyslotsReportsTheKDFCost is the visibility requirement for a cost
// that was PRESERVED rather than inherited.
//
// ChangeKey has no options struct, so there is no call-site field to write the
// preserved value back to the way AddKey reports InheritedArgon2Cost. The
// listing is the surface an operator would look at instead, and until now it
// did not carry costs at all -- so a slot deliberately left below
// MinArgon2MemoryKB was invisible without parsing the header by hand.
func TestListKeyslotsReportsTheKDFCost(t *testing.T) {
	metadata := &LUKS2Metadata{Keyslots: map[string]*Keyslot{
		"0": {Type: "luks2", KeySize: 64, KDF: &KDF{
			Type: KDFTypeArgon2id, Salt: "AAAA",
			Time: intPtr(4), Memory: intPtr(32768), CPUs: intPtr(1),
		}},
		"1": {Type: "luks2", KeySize: 64, KDF: &KDF{
			Type: KDFTypePBKDF2, Hash: "sha512", Salt: "AAAA", Iterations: intPtr(210000),
		}},
	}}

	slots, err := listKeyslotsFrom(metadata)
	if err != nil {
		t.Fatalf("listKeyslotsFrom failed: %v", err)
	}
	if len(slots) != 2 {
		t.Fatalf("got %d slots, want 2", len(slots))
	}

	argon2, pbkdf2 := slots[0], slots[1]

	// The argon2 slot reports its costs, INCLUDING a memory cost below the
	// create floor -- which is exactly the case that has to be observable.
	if argon2.Argon2MemoryKB != 32768 || argon2.Argon2Time != 4 || argon2.Argon2Parallel != 1 {
		t.Fatalf("argon2 slot reports time/memory/parallel %d/%d/%d, want 4/32768/1",
			argon2.Argon2Time, argon2.Argon2MemoryKB, argon2.Argon2Parallel)
	}
	if argon2.Argon2MemoryKB >= MinArgon2MemoryKB {
		t.Fatalf("the fixture's %d KiB is not below the create floor of %d; this test measures nothing",
			argon2.Argon2MemoryKB, MinArgon2MemoryKB)
	}
	if argon2.PBKDF2Iterations != 0 {
		t.Errorf("argon2 slot reports %d PBKDF2 iterations; it has none", argon2.PBKDF2Iterations)
	}

	// And the pbkdf2 slot the other way round.
	if pbkdf2.PBKDF2Iterations != 210000 {
		t.Fatalf("pbkdf2 slot reports %d iterations, want 210000", pbkdf2.PBKDF2Iterations)
	}
	if pbkdf2.Argon2MemoryKB != 0 || pbkdf2.Argon2Time != 0 || pbkdf2.Argon2Parallel != 0 {
		t.Errorf("pbkdf2 slot reports Argon2 costs %d/%d/%d; it has none",
			pbkdf2.Argon2Time, pbkdf2.Argon2MemoryKB, pbkdf2.Argon2Parallel)
	}
}

// TestListKeyslotsReportsNoCostForAKeyslotWithoutAKDF is the error-shaped half.
// A "reencrypt" keyslot has no kdf object at all, and listing is the operation
// an operator reaches for when a container is in a state nothing else handles,
// so it must report what is there rather than dereference what is not.
func TestListKeyslotsReportsNoCostForAKeyslotWithoutAKDF(t *testing.T) {
	metadata := &LUKS2Metadata{Keyslots: map[string]*Keyslot{
		"0": {Type: "reencrypt", KeySize: 64},
		"1": {Type: "luks2", KeySize: 64, KDF: &KDF{Type: KDFTypePBKDF2, Hash: "sha512", Salt: "AAAA"}},
	}}

	slots, err := listKeyslotsFrom(metadata)
	if err != nil {
		t.Fatalf("listKeyslotsFrom failed: %v", err)
	}
	for _, slot := range slots {
		if slot.PBKDF2Iterations != 0 || slot.Argon2Time != 0 || slot.Argon2MemoryKB != 0 || slot.Argon2Parallel != 0 {
			t.Fatalf("keyslot %d reports a cost it does not carry: %+v", slot.ID, slot)
		}
	}
}
