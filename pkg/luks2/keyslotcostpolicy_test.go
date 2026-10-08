// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"crypto"
	"crypto/fips140"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/header"
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
	for _, field := range reflect.VisibleFields(reflect.TypeOf(addKeyOptionsForTest{})) {
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
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("error = %v, want ErrInvalidArgument", err)
			}
			var refusal *KDFCostError
			if !errors.As(err, &refusal) {
				t.Fatalf("error %v is not a *KDFCostError", err)
			}
			if refusal.Min != tt.wantMin {
				t.Fatalf("reported minimum %d, want %d", refusal.Min, tt.wantMin)
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
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("forcedPBKDF2Iterations(%d) error = %v, want ErrInvalidArgument", iterations, err)
		}
		var refusal *KDFCostError
		if !errors.As(err, &refusal) {
			t.Fatalf("error %v is not a *KDFCostError; both paths must refuse the same way", err)
		}
		if refusal.Min != minPBKDF2Iterations {
			t.Fatalf("the exempt floor is reported as %d, want %d", refusal.Min, minPBKDF2Iterations)
		}
	}

	// The ceiling is not relaxed either.
	if _, err := forcedPBKDF2Iterations("sha512", header.MaxKDFIterations+1, libraryGeneratedCredential); !errors.Is(err, ErrInvalidArgument) {
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
	defer parallel(t)()

	t.Run("Format", func(t *testing.T) {
		opts := standardFormatOptions(newImage(t, "exempt-format.img"))
		opts.PBKDFIterations = minPBKDF2Iterations
		if err := formatForTest(opts); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("Format = %v, want ErrInvalidArgument", err)
		}
	})

	t.Run("AddKey", func(t *testing.T) {
		path := newImage(t, "exempt-addkey.img")
		formatWithLibrary(t, path)

		_, err := addKeyForTest(path, []byte(conformancePassphrase), []byte("a-second-credential"), &addKeyOptionsForTest{
			KDFType:         kdfTypePBKDF2,
			Hash:            "sha512",
			PBKDFIterations: minPBKDF2Iterations,
		})
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("AddKey = %v, want ErrPBKDFIterationsTooLow", err)
		}
	})

	t.Run("CreateKDF", func(t *testing.T) {
		_, err := createKDFStrictAtProductionFloor(formatOptionsForTest{
			KDFType:         kdfTypePBKDF2,
			HashAlgo:        "sha512",
			PBKDFIterations: minPBKDF2Iterations,
		}, 64)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("CreateKDF = %v, want ErrPBKDFIterationsTooLow", err)
		}
	})
}

// TestTheInternalSeamWritesSystemdsCountToTheHeader is the end-to-end form of
// the exemption, through the same unexported entry point (*Volume).AddRecoveryKey
// and (*Volume).Enroll will call.
func TestTheInternalSeamWritesSystemdsCountToTheHeader(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "generated-credential.img")
	formatWithLibrary(t, path)

	// A credential this package generated: 256 CSPRNG bits, which is what makes
	// the iteration count irrelevant. Nothing about the mechanism depends on
	// that being true, which is exactly why the seam is unexported.
	generated, err := randomBase64(32, testVolumeSys().cryptoRand)
	if err != nil {
		t.Fatalf("randomBase64 failed: %v", err)
	}

	assigned, err := addKeyWithPolicy(context.Background(), path, []byte(conformancePassphrase), []byte(generated), &addKeyOptionsForTest{
		KDFType:         kdfTypePBKDF2,
		Hash:            "sha512",
		PBKDFIterations: minPBKDF2Iterations,
	}, libraryGeneratedCredential, testVolumeSys())
	if err != nil {
		t.Fatalf("addKeyWithPolicy with a generated credential: %v", err)
	}

	_, metadata, err := readHeaderForTest(path)
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

	if err := testKeyForTest(path, []byte(generated)); err != nil {
		t.Fatalf("the generated credential does not open the volume: %v", err)
	}
	// And the strict path is unchanged by its presence.
	if err := testKeyForTest(path, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("the original passphrase no longer opens the volume: %v", err)
	}
}

// TestAddRecoveryKeyReachesTheExemption is the PRODUCTION form of the
// exemption, and the one the seam test above cannot stand in for.
//
// The seam test calls addKeyWithPolicy directly, so it proves the mechanism
// works when something selects it. It says nothing about whether anything in
// the shipped API ever does -- and for a while nothing did: AddRecoveryKey
// called AddKey, which hardcoded callerSuppliedCredential, so the relaxed branch
// was reachable only from that test. A policy no exported path can select is
// indistinguishable from one that does not exist.
//
// This test goes through (*Volume).AddRecoveryKey, the way a consumer does,
// and asserts the systemd-compatible count lands in the header. It fails if
// the wiring is removed, if KeyslotParams stops forwarding the count, or if
// the policy reverts to strict -- each of which returns
// ErrPBKDFIterationsTooLow here.
func TestAddRecoveryKeyReachesTheExemption(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "recovery-exemption.img")
	formatWithLibrary(t, path)

	// systemd's own parameters: pbkdf2/sha512/1000. The sha512 floor is 210000,
	// so this is exactly the header the strict policy cannot write.
	ctx := context.Background()
	v, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy([]byte(conformancePassphrase))
	if err != nil {
		t.Fatalf("could not build a test passphrase enclave: %v", err)
	}
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(ctx, pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	rk, err := NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey failed: %v", err)
	}
	defer rk.Destroy()

	enrollment, err := v.AddRecoveryKey(ctx, key, rk, KeyslotParams{KDF: KDFParams{
		Type:       KDFPBKDF2,
		Hash:       crypto.SHA512,
		Iterations: minPBKDF2Iterations,
	}})
	if err != nil {
		t.Fatalf("AddRecoveryKey at systemd's parameters: %v", err)
	}

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	// The slot AddRecoveryKey chose, not any pbkdf2 slot: the container was
	// formatted with one already, at its own calibrated count.
	ks := metadata.Keyslots[strconv.Itoa(enrollment.Keyslot.ID)]
	if ks == nil || ks.KDF == nil || ks.KDF.Iterations == nil {
		t.Fatalf("keyslot %d has no PBKDF2 iteration count", enrollment.Keyslot.ID)
	}
	if *ks.KDF.Iterations != minPBKDF2Iterations {
		t.Fatalf("keyslot %d records %d iterations, want systemd's %d",
			enrollment.Keyslot.ID, *ks.KDF.Iterations, minPBKDF2Iterations)
	}

	// And it opens the volume, so the exemption produced a usable keyslot
	// rather than merely a well-formed header.
	var buf bytes.Buffer
	if _, err := rk.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	if err := testKeyForTest(path, buf.Bytes()); err != nil {
		t.Fatalf("the recovery key does not open the volume: %v", err)
	}
}

// TestAddKeyKeepsTheFullFloorForTheSameCount is the other half of the pair: the
// exemption belongs to the credential's ORIGIN, not to the number. The exact
// count AddRecoveryKey just wrote is refused when a caller supplies the bytes.
func TestAddKeyKeepsTheFullFloorForTheSameCount(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "recovery-exemption-negative.img")
	formatWithLibrary(t, path)

	_, err := addKeyForTest(path, []byte(conformancePassphrase), []byte("a-caller-supplied-credential"), &addKeyOptionsForTest{
		KDFType:         kdfTypePBKDF2,
		Hash:            "sha512",
		PBKDFIterations: minPBKDF2Iterations,
	})
	if !errors.Is(err, ErrInvalidArgument) {
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

	container := &header.Metadata{Keyslots: map[string]*header.Keyslot{
		"0": {Type: "luks2", KDF: &header.KDF{
			Type: kdfTypeArgon2id, Salt: "AAAA",
			Time: intPtr(4), Memory: intPtr(containerMemory), CPUs: intPtr(2),
		}},
	}}

	// Argon2id is named because inheritance is what an Argon2id keyslot does
	// with no cost chosen, in either mode; with no KDF named at all, FIPS mode
	// defaults to PBKDF2 and there is no Argon2 cost to inherit
	// (TestAddKeyWithNoKDFNamedInheritsOnlyInTheArgon2Default).
	opts, inherited := addKeyFormatOptions(&addKeyOptionsForTest{KDFType: kdfTypeArgon2id}, container, fips.Probe)
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

	container := &header.Metadata{Keyslots: map[string]*header.Keyslot{
		"0": {Type: "luks2", KDF: &header.KDF{
			Type: kdfTypeArgon2id, Salt: "AAAA",
			Time: intPtr(4), Memory: intPtr(containerMemory), CPUs: intPtr(1),
		}},
	}}

	// Argon2id is named because inheritance is what an Argon2id keyslot does
	// with no cost chosen, in either mode; with no KDF named at all, FIPS mode
	// defaults to PBKDF2 and there is no Argon2 cost to inherit
	// (TestAddKeyWithNoKDFNamedInheritsOnlyInTheArgon2Default).
	opts, inherited := addKeyFormatOptions(&addKeyOptionsForTest{KDFType: kdfTypeArgon2id}, container, fips.Probe)
	if inherited == nil {
		t.Fatal("AddKey did not report inheriting the container's cost")
	}
	if containerMemory >= minArgon2MemoryKB {
		t.Fatalf("the fixture's %d KiB is not below the floor of %d; this test measures nothing",
			containerMemory, minArgon2MemoryKB)
	}
	if opts.Argon2Memory != containerMemory {
		t.Fatalf("Argon2Memory = %d, want the container's %d preserved exactly",
			opts.Argon2Memory, containerMemory)
	}
	if opts.Argon2Memory == minArgon2MemoryKB {
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
	container := &header.Metadata{Keyslots: map[string]*header.Keyslot{
		"0": {Type: "luks2", KDF: &header.KDF{
			Type: kdfTypeArgon2id, Salt: "AAAA",
			Time: intPtr(4), Memory: intPtr(512_000), CPUs: intPtr(2),
		}},
	}}

	opts, inherited := addKeyFormatOptions(&addKeyOptionsForTest{Argon2Memory: 2_000_000}, container, fips.Probe)
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
	container := &header.Metadata{Keyslots: map[string]*header.Keyslot{
		"0": {Type: "luks2", KDF: &header.KDF{Type: kdfTypePBKDF2, Hash: "sha512", Salt: "AAAA", Iterations: intPtr(210000)}},
	}}

	for _, metadata := range []*header.Metadata{container, {Keyslots: map[string]*header.Keyslot{}}, nil} {
		opts, inherited := addKeyFormatOptions(&addKeyOptionsForTest{}, metadata, fips.Probe)
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
//
// The container is written by cryptsetup, so the cost being inherited is one
// this package did not choose -- the case the visibility requirement exists
// for -- and so the fixture can exist in a FIPS 140-3 mode process, which
// refuses to create Argon2 keyslots itself (#235). In FIPS mode the inheriting
// AddKey must be refused with the typed error and leave the container exactly
// as it was; without FIPS it must inherit the cost and report it.
func TestAddKeyReportsTheInheritedCostToTheCaller(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)
	path := newImage(t, "inherited-report.img")
	code, out := runCryptsetup(t, conformancePassphrase,
		"luksFormat", "--type", "luks2",
		"--cipher", "aes-xts-plain64", "--key-size", "512", "--hash", "sha512",
		"--pbkdf", "argon2id", "--pbkdf-force-iterations", "4",
		"--pbkdf-memory", strconv.Itoa(minArgon2MemoryKB), "--pbkdf-parallel", "1",
		"--batch-mode", path)
	if code != 0 {
		t.Fatalf("cryptsetup luksFormat exited %d\n%s", code, out)
	}
	before := readAreaBytes(t, path, 0, goldenPrefixBytes)

	opts := &addKeyOptionsForTest{}
	_, err := addKeyForTest(path, []byte(conformancePassphrase), []byte("a-second-credential"), opts)

	if fips140.Enabled() {
		if !errors.Is(err, ErrFIPSNotApproved) {
			t.Fatalf("in FIPS mode AddKey on an Argon2 container = %v, want ErrFIPSNotApproved", err)
		}
		if !bytes.Equal(before, readAreaBytes(t, path, 0, goldenPrefixBytes)) {
			t.Fatal("the refused AddKey changed the container")
		}
		return
	}

	if err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}
	if opts.InheritedArgon2Cost == nil {
		t.Fatal("AddKey did not report the inherited cost; an operator cannot tell it came from the container")
	}
	if got := opts.InheritedArgon2Cost.Memory; got == nil || *got != minArgon2MemoryKB {
		t.Fatalf("reported memory %v, want the container's %d", got, minArgon2MemoryKB)
	}

	_, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if len(metadata.Keyslots) != 2 {
		t.Fatalf("the container has %d keyslots after AddKey, want 2", len(metadata.Keyslots))
	}
	for id, keyslot := range metadata.Keyslots {
		if keyslot.KDF.Memory == nil || *keyslot.KDF.Memory != minArgon2MemoryKB {
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
	metadata := &header.Metadata{Keyslots: map[string]*header.Keyslot{
		"0": {Type: "luks2", KeySize: 64, KDF: &header.KDF{
			Type: kdfTypeArgon2id, Salt: "AAAA",
			Time: intPtr(4), Memory: intPtr(32768), CPUs: intPtr(1),
		}},
		"1": {Type: "luks2", KeySize: 64, KDF: &header.KDF{
			Type: kdfTypePBKDF2, Hash: "sha512", Salt: "AAAA", Iterations: intPtr(210000),
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
	if argon2.KDF.MemoryKiB != 32768 || argon2.KDF.Time != 4 || argon2.KDF.Parallel != 1 {
		t.Fatalf("argon2 slot reports time/memory/parallel %d/%d/%d, want 4/32768/1",
			argon2.KDF.Time, argon2.KDF.MemoryKiB, argon2.KDF.Parallel)
	}
	if argon2.KDF.MemoryKiB >= minArgon2MemoryKB {
		t.Fatalf("the fixture's %d KiB is not below the create floor of %d; this test measures nothing",
			argon2.KDF.MemoryKiB, minArgon2MemoryKB)
	}
	if argon2.KDF.Iterations != 0 {
		t.Errorf("argon2 slot reports %d PBKDF2 iterations; it has none", argon2.KDF.Iterations)
	}

	// And the pbkdf2 slot the other way round.
	if pbkdf2.KDF.Iterations != 210000 {
		t.Fatalf("pbkdf2 slot reports %d iterations, want 210000", pbkdf2.KDF.Iterations)
	}
	if pbkdf2.KDF.MemoryKiB != 0 || pbkdf2.KDF.Time != 0 || pbkdf2.KDF.Parallel != 0 {
		t.Errorf("pbkdf2 slot reports Argon2 costs %d/%d/%d; it has none",
			pbkdf2.KDF.Time, pbkdf2.KDF.MemoryKiB, pbkdf2.KDF.Parallel)
	}
}

// TestListKeyslotsReportsNoCostForAKeyslotWithoutAKDF is the error-shaped half.
// A "reencrypt" keyslot has no kdf object at all, and listing is the operation
// an operator reaches for when a container is in a state nothing else handles,
// so it must report what is there rather than dereference what is not.
func TestListKeyslotsReportsNoCostForAKeyslotWithoutAKDF(t *testing.T) {
	metadata := &header.Metadata{Keyslots: map[string]*header.Keyslot{
		"0": {Type: "reencrypt", KeySize: 64},
		"1": {Type: "luks2", KeySize: 64, KDF: &header.KDF{Type: kdfTypePBKDF2, Hash: "sha512", Salt: "AAAA"}},
	}}

	slots, err := listKeyslotsFrom(metadata)
	if err != nil {
		t.Fatalf("listKeyslotsFrom failed: %v", err)
	}
	for _, slot := range slots {
		if slot.KDF.Iterations != 0 || slot.KDF.Time != 0 || slot.KDF.MemoryKiB != 0 || slot.KDF.Parallel != 0 {
			t.Fatalf("keyslot %d reports a cost it does not carry: %+v", slot.ID, slot)
		}
	}
}
