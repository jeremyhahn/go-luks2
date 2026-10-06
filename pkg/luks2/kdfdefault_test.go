// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"crypto/fips140"
	"errors"
	"math"
	"strconv"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/fips"
)

// The tests in this file hold #237: the KDF a keyslot gets when the caller
// names none depends on the mode the process runs in -- PBKDF2-SHA512 in FIPS
// 140-3 mode, Argon2id otherwise -- and a FIPS-mode process can therefore
// create and enroll keyslots without naming one.
//
// The mode is fixed for the life of a process, so the resolution itself is
// tested through its mode-parameterized form (defaultKDFTypeFor,
// resolveKDFTypeFor) and both answers are checked in every run. The tests that
// go through the public entry points assert what they do in THIS process's
// mode; the nightly FIPS lane runs them in the other one.

// e2eIterTimeMs is the PBKDF2 budget the end-to-end tests below calibrate to.
// What they assert is the KDF TYPE and HASH a keyslot gets, not its cost, and
// the default 2000 ms budget would make each derivation take two seconds.
const e2eIterTimeMs = 50

func TestDefaultKDFTypeForEachMode(t *testing.T) {
	tests := []struct {
		name     string
		fipsMode fips.Mode
		want     string
	}{
		{"FIPS 140-3 mode", true, KDFTypePBKDF2SHA512},
		{"outside FIPS mode", false, KDFTypeArgon2id},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := defaultKDFTypeFor(tt.fipsMode); got != tt.want {
				t.Fatalf("defaultKDFTypeFor(%v) = %q, want %q", tt.fipsMode, got, tt.want)
			}
		})
	}
}

func TestDefaultKDFTypeFollowsTheProcessMode(t *testing.T) {
	want := KDFTypeArgon2id
	if fips140.Enabled() {
		want = KDFTypePBKDF2SHA512
	}
	if got := DefaultKDFType(); got != want {
		t.Fatalf("DefaultKDFType() = %q with fips140.Enabled() = %v, want %q", got, fips140.Enabled(), want)
	}
	// The default is approved in exactly the mode that requires it.
	if fips140.Enabled() && !IsFIPSCompliantKDF(DefaultKDFType()) {
		t.Fatalf("the FIPS-mode default %q is not FIPS-approved", DefaultKDFType())
	}
}

func TestResolveKDFTypeFor(t *testing.T) {
	tests := []struct {
		name            string
		kdfType         string
		argon2CostGiven bool
		fipsMode        fips.Mode
		want            string
	}{
		{"a named type is kept in FIPS mode", KDFTypePBKDF2SHA256, false, true, KDFTypePBKDF2SHA256},
		{"a named type is kept outside FIPS mode", KDFTypePBKDF2, false, false, KDFTypePBKDF2},
		{"a named type wins over an Argon2 cost", KDFTypePBKDF2, true, true, KDFTypePBKDF2},
		{"a named Argon2 type is kept in FIPS mode, for the refusal to see", KDFTypeArgon2id, false, true, KDFTypeArgon2id},
		{"an Argon2 cost selects Argon2id in FIPS mode", "", true, true, KDFTypeArgon2id},
		{"an Argon2 cost selects Argon2id outside FIPS mode", "", true, false, KDFTypeArgon2id},
		{"nothing named is PBKDF2-SHA512 in FIPS mode", "", false, true, KDFTypePBKDF2SHA512},
		{"nothing named is Argon2id outside FIPS mode", "", false, false, KDFTypeArgon2id},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveKDFTypeFor(tt.kdfType, tt.argon2CostGiven, tt.fipsMode); got != tt.want {
				t.Fatalf("resolveKDFTypeFor(%q, %v, %v) = %q, want %q",
					tt.kdfType, tt.argon2CostGiven, tt.fipsMode, got, tt.want)
			}
		})
	}
}

func TestFormatArgon2CostGiven(t *testing.T) {
	tests := []struct {
		name string
		opts FormatOptions
		want bool
	}{
		{"no cost", FormatOptions{PBKDFIterTime: 5}, false},
		{"time", FormatOptions{Argon2Time: 1}, true},
		{"memory", FormatOptions{Argon2Memory: MinArgon2MemoryKB}, true},
		{"parallelism", FormatOptions{Argon2Parallel: 1}, true},
		{"a negative is still a choice", FormatOptions{Argon2Memory: -1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatArgon2CostGiven(tt.opts); got != tt.want {
				t.Fatalf("formatArgon2CostGiven(%+v) = %v, want %v", tt.opts, got, tt.want)
			}
		})
	}
}

// TestCreateKDFDefaultFollowsTheMode replaces the test that held the FIPS-mode
// default as a refusal. CreateKDF only calibrates -- it derives nothing -- so
// the default budget is affordable here and the floor asserted is the real one.
func TestCreateKDFDefaultFollowsTheMode(t *testing.T) {
	kdf, err := CreateKDF(FormatOptions{}, 64)
	if err != nil {
		t.Fatalf("CreateKDF with no KDF named failed: %v", err)
	}

	if !fips140.Enabled() {
		if kdf.Type != KDFTypeArgon2id {
			t.Fatalf("outside FIPS mode the default KDF is %q, want %q", kdf.Type, KDFTypeArgon2id)
		}
		return
	}

	if kdf.Type != KDFTypePBKDF2 || kdf.Hash != "sha512" {
		t.Fatalf("in FIPS mode the default KDF is %s/%s, want pbkdf2/sha512", kdf.Type, kdf.Hash)
	}
	floor := int(math.Ceil(pbkdf2IterationFloor("sha512", pbkdf2ReferenceTargetMs)))
	if kdf.Iterations == nil || *kdf.Iterations < floor {
		t.Fatalf("in FIPS mode the default iteration count is %v, want at least the SHA-512 floor %d",
			kdf.Iterations, floor)
	}
}

// TestCreateKDFDefaultUnderTheFIPSPolicy runs the FIPS-mode default through
// the public CreateKDF in every run, with the package's FIPS policy forced on
// (forceFIPSPolicy): PBKDF2-SHA512 at no less than the SHA-512 floor, and an
// Argon2 cost with no type refused rather than dropped.
func TestCreateKDFDefaultUnderTheFIPSPolicy(t *testing.T) {
	forceFIPSPolicy(t)

	if got := DefaultKDFType(); got != KDFTypePBKDF2SHA512 {
		t.Fatalf("DefaultKDFType under the FIPS policy = %q, want %q", got, KDFTypePBKDF2SHA512)
	}

	kdf, err := CreateKDF(FormatOptions{}, 64)
	if err != nil {
		t.Fatalf("CreateKDF with no KDF named under the FIPS policy failed: %v", err)
	}
	if kdf.Type != KDFTypePBKDF2 || kdf.Hash != "sha512" {
		t.Fatalf("the default KDF under the FIPS policy is %s/%s, want pbkdf2/sha512", kdf.Type, kdf.Hash)
	}
	floor := int(math.Ceil(pbkdf2IterationFloor("sha512", pbkdf2ReferenceTargetMs)))
	if kdf.Iterations == nil || *kdf.Iterations < floor {
		t.Fatalf("iterations = %v, want at least the SHA-512 floor %d", kdf.Iterations, floor)
	}

	_, err = CreateKDF(FormatOptions{Argon2Memory: MinArgon2MemoryKB}, 64)
	if !errors.Is(err, ErrFIPSNotApproved) {
		t.Fatalf("CreateKDF with an Argon2 cost and no type under the FIPS policy = %v, want ErrFIPSNotApproved", err)
	}

	if got := baseAddKeyFormatOptions(nil); got.KDFType != KDFTypePBKDF2SHA512 || got.HashAlgo != "sha512" {
		t.Fatalf("AddKey's default under the FIPS policy = %s/%s, want pbkdf2-sha512/sha512", got.KDFType, got.HashAlgo)
	}
}

// TestCreateKDFWithAnArgon2CostAndNoTypeIsArgon2id: the cost names the KDF. In
// FIPS mode that is refused, rather than the cost being dropped for a PBKDF2
// keyslot the caller did not ask for.
func TestCreateKDFWithAnArgon2CostAndNoTypeIsArgon2id(t *testing.T) {
	opts := FormatOptions{Argon2Time: 1, Argon2Memory: MinArgon2MemoryKB, Argon2Parallel: 1}
	assertCreateKDFInThisMode(t, opts, func(t *testing.T, kdf *KDF) {
		if kdf.Type != KDFTypeArgon2id {
			t.Fatalf("type = %q, want %q", kdf.Type, KDFTypeArgon2id)
		}
		if kdf.Memory == nil || *kdf.Memory != MinArgon2MemoryKB {
			t.Fatalf("memory = %v, want the caller's %d", kdf.Memory, MinArgon2MemoryKB)
		}
	})
}

// TestValidateArgon2CreateCostJudgesTheResolvedKDF: a sub-floor Argon2 cost
// with no KDF named resolves to Argon2id and is refused. The check used to look
// at the spelling, and an empty KDFType passed it.
func TestValidateArgon2CreateCostJudgesTheResolvedKDF(t *testing.T) {
	err := validateArgon2CreateCost(FormatOptions{Argon2Memory: 32})
	if !errors.Is(err, ErrInvalidArgon2Memory) {
		t.Fatalf("validateArgon2CreateCost with memory 32 and no KDF named = %v, want ErrInvalidArgon2Memory", err)
	}

	// The case-insensitive spelling resolves the same way.
	err = validateArgon2CreateCost(FormatOptions{KDFType: "Argon2ID", Argon2Memory: 32})
	if !errors.Is(err, ErrInvalidArgon2Memory) {
		t.Fatalf("validateArgon2CreateCost with KDFType Argon2ID = %v, want ErrInvalidArgon2Memory", err)
	}

	// A PBKDF2 keyslot carries no Argon2 cost to judge.
	if err := validateArgon2CreateCost(FormatOptions{KDFType: KDFTypePBKDF2, Argon2Memory: 32}); err != nil {
		t.Fatalf("validateArgon2CreateCost on a PBKDF2 keyslot = %v, want nil", err)
	}
}

// TestFormatHonorsTheHashAKDFAliasNames: Format defaulted HashAlgo before it
// created the keyslot's KDF, and HashAlgo overrides the hash an alias names,
// so "pbkdf2-sha512" -- the FIPS-mode default -- was written as PBKDF2-SHA256.
// The digest keeps the default hash; only the KDF follows the alias.
func TestFormatHonorsTheHashAKDFAliasNames(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "alias-hash.img")
	if err := Format(FormatOptions{
		Device:        path,
		Passphrase:    []byte(conformancePassphrase),
		KDFType:       KDFTypePBKDF2SHA512,
		PBKDFIterTime: e2eIterTimeMs,
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	kdf := metadata.Keyslots["0"].KDF
	if kdf.Type != KDFTypePBKDF2 || kdf.Hash != "sha512" {
		t.Fatalf("keyslot 0 KDF = %s/%s, want pbkdf2/sha512", kdf.Type, kdf.Hash)
	}
	if got := metadata.Digests["0"].Hash; got != DefaultHashAlgo {
		t.Fatalf("digest hash = %q, want the default %q", got, DefaultHashAlgo)
	}
}

// TestFormatWithNoKDFNamedWritesTheModeDefault formats with no KDF named. In
// FIPS mode the keyslot is PBKDF2-SHA512 and cryptsetup opens it; outside
// FIPS mode the default is Argon2id at 1 GiB, which this suite does not pay
// for, so the same call is made with an Argon2 cost and must still be
// Argon2id there -- and refused in FIPS mode, with nothing written.
func TestFormatWithNoKDFNamedWritesTheModeDefault(t *testing.T) {
	defer parallel(t)()

	if fips140.Enabled() {
		requireCryptsetup(t)
		path := newImage(t, "fips-default.img")
		if err := Format(FormatOptions{
			Device:        path,
			Passphrase:    []byte(conformancePassphrase),
			PBKDFIterTime: e2eIterTimeMs,
		}); err != nil {
			t.Fatalf("Format with no KDF named in FIPS mode failed: %v", err)
		}
		assertPBKDF2SHA512Keyslot(t, path, 0, conformancePassphrase)
		return
	}

	path := newImage(t, "argon2-default.img")
	if err := Format(FormatOptions{
		Device:         path,
		Passphrase:     []byte(conformancePassphrase),
		Argon2Time:     1,
		Argon2Memory:   MinArgon2MemoryKB,
		Argon2Parallel: 1,
	}); err != nil {
		t.Fatalf("Format with no KDF named failed: %v", err)
	}
	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if got := metadata.Keyslots["0"].KDF.Type; got != KDFTypeArgon2id {
		t.Fatalf("keyslot 0 KDF = %q, want %q", got, KDFTypeArgon2id)
	}
}

// TestFormatRefusesAnArgon2CostWithNoKDFNamedInFIPSMode is the other half of
// the case above: what the cost selects is refused in FIPS mode before
// anything reaches the device.
func TestFormatRefusesAnArgon2CostWithNoKDFNamedInFIPSMode(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "argon2-cost.img")
	before := readAreaBytes(t, path, 0, goldenPrefixBytes)
	err := Format(FormatOptions{
		Device:         path,
		Passphrase:     []byte(conformancePassphrase),
		Argon2Time:     1,
		Argon2Memory:   MinArgon2MemoryKB,
		Argon2Parallel: 1,
	})

	if !fips140.Enabled() {
		if err != nil {
			t.Fatalf("Format with an Argon2 cost outside FIPS mode failed: %v", err)
		}
		return
	}
	if !errors.Is(err, ErrFIPSNotApproved) {
		t.Fatalf("Format with an Argon2 cost in FIPS mode = %v, want ErrFIPSNotApproved", err)
	}
	if !bytes.Equal(before, readAreaBytes(t, path, 0, goldenPrefixBytes)) {
		t.Fatal("the refused Format wrote to the device")
	}
}

// TestBaseAddKeyFormatOptionsResolvesTheKDFAndItsHash: the hash is the
// caller's, else the one the KDF type names; and an Argon2 cost with no type
// is Argon2id in either mode.
func TestBaseAddKeyFormatOptionsResolvesTheKDFAndItsHash(t *testing.T) {
	tests := []struct {
		name     string
		opts     *AddKeyOptions
		wantKDF  string
		wantHash string
	}{
		{"an alias names its hash", &AddKeyOptions{KDFType: KDFTypePBKDF2SHA512}, KDFTypePBKDF2SHA512, "sha512"},
		{"another alias names its hash", &AddKeyOptions{KDFType: KDFTypePBKDF2SHA384}, KDFTypePBKDF2SHA384, "sha384"},
		{"the caller's hash wins over the alias", &AddKeyOptions{KDFType: KDFTypePBKDF2SHA512, Hash: "sha256"}, KDFTypePBKDF2SHA512, "sha256"},
		{"plain pbkdf2 is SHA-256", &AddKeyOptions{KDFType: KDFTypePBKDF2}, KDFTypePBKDF2, DefaultHashAlgo},
		{"an Argon2 cost with no type is Argon2id", &AddKeyOptions{Argon2Memory: MinArgon2MemoryKB}, KDFTypeArgon2id, DefaultHashAlgo},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := baseAddKeyFormatOptions(tt.opts)
			if got.KDFType != tt.wantKDF || got.HashAlgo != tt.wantHash {
				t.Fatalf("baseAddKeyFormatOptions(%+v) = %s/%s, want %s/%s",
					tt.opts, got.KDFType, got.HashAlgo, tt.wantKDF, tt.wantHash)
			}
		})
	}
}

// TestAddKeyWithNoKDFNamedInheritsOnlyInTheArgon2Default: on an Argon2
// container, a key added with nothing named inherits the container's Argon2
// cost outside FIPS mode. In FIPS mode the default is PBKDF2, which has no
// Argon2 cost to inherit, and none is reported.
func TestAddKeyWithNoKDFNamedInheritsOnlyInTheArgon2Default(t *testing.T) {
	container := &LUKS2Metadata{Keyslots: map[string]*Keyslot{
		"0": {Type: "luks2", KDF: &KDF{
			Type: KDFTypeArgon2id, Salt: "AAAA",
			Time: intPtr(3), Memory: intPtr(512_000), CPUs: intPtr(2),
		}},
	}}

	opts, inherited := addKeyFormatOptions(&AddKeyOptions{}, container)

	if fips140.Enabled() {
		if opts.KDFType != KDFTypePBKDF2SHA512 || inherited != nil {
			t.Fatalf("in FIPS mode: KDF %q, inherited %+v; want pbkdf2-sha512 and nothing inherited",
				opts.KDFType, inherited)
		}
		return
	}
	if opts.KDFType != KDFTypeArgon2id || inherited == nil || opts.Argon2Memory != 512_000 {
		t.Fatalf("outside FIPS mode: KDF %q, memory %d, inherited %+v; want argon2id inheriting 512000",
			opts.KDFType, opts.Argon2Memory, inherited)
	}
}

// TestAddKeyHonorsTheHashAKDFAliasNames is the end-to-end half: AddKey with
// "pbkdf2-sha512" wrote a PBKDF2-SHA256 keyslot.
func TestAddKeyHonorsTheHashAKDFAliasNames(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "addkey-alias.img")
	formatWithLibrary(t, path)
	slot, err := AddKey(path, []byte(conformancePassphrase), []byte("a-second-credential"),
		&AddKeyOptions{KDFType: KDFTypePBKDF2SHA384, PBKDFIterTime: e2eIterTimeMs})
	if err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}
	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	kdf := metadata.Keyslots[strconv.Itoa(slot)].KDF
	if kdf.Type != KDFTypePBKDF2 || kdf.Hash != "sha384" {
		t.Fatalf("keyslot %d KDF = %s/%s, want pbkdf2/sha384", slot, kdf.Type, kdf.Hash)
	}
}

// TestAddKeyWithNoKDFNamedWritesTheModeDefault: in FIPS mode a second
// passphrase lands in a PBKDF2-SHA512 keyslot that cryptsetup opens. Outside
// it the default is still Argon2id, inheriting the cost of an Argon2
// container written by cryptsetup.
func TestAddKeyWithNoKDFNamedWritesTheModeDefault(t *testing.T) {
	defer parallel(t)()
	requireCryptsetup(t)

	const added = "a-second-credential"

	if fips140.Enabled() {
		path := newImage(t, "fips-addkey.img")
		formatWithLibrary(t, path)
		slot, err := AddKey(path, []byte(conformancePassphrase), []byte(added),
			&AddKeyOptions{PBKDFIterTime: e2eIterTimeMs})
		if err != nil {
			t.Fatalf("AddKey with no KDF named in FIPS mode failed: %v", err)
		}
		assertPBKDF2SHA512Keyslot(t, path, slot, added)
		return
	}

	path := cryptsetupArgon2Container(t, "argon2-addkey.img")
	slot, err := AddKey(path, []byte(conformancePassphrase), []byte(added), &AddKeyOptions{})
	if err != nil {
		t.Fatalf("AddKey with no KDF named failed: %v", err)
	}
	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if got := metadata.Keyslots[strconv.Itoa(slot)].KDF.Type; got != KDFTypeArgon2id {
		t.Fatalf("keyslot %d KDF = %q, want %q", slot, got, KDFTypeArgon2id)
	}
}

// TestAddRecoveryKeyWithNoKDFNamedWritesTheModeDefault is the library half of
// `luks2 recovery add` under FIPS: before #237 it defaulted to Argon2id and
// was refused even on a container whose keyslots are all PBKDF2.
func TestAddRecoveryKeyWithNoKDFNamedWritesTheModeDefault(t *testing.T) {
	defer parallel(t)()
	requireCryptsetup(t)

	var path string
	if fips140.Enabled() {
		path = newImage(t, "fips-recovery.img")
		formatWithLibrary(t, path)
	} else {
		path = cryptsetupArgon2Container(t, "argon2-recovery.img")
	}

	recovery, err := AddRecoveryKey(path, []byte(conformancePassphrase),
		&RecoveryKeyOptions{PBKDFIterTime: e2eIterTimeMs})
	if err != nil {
		t.Fatalf("AddRecoveryKey with no KDF named failed: %v", err)
	}
	defer recovery.Clear()

	if fips140.Enabled() {
		credential, err := recovery.FormattedString()
		if err != nil {
			t.Fatalf("FormattedString failed: %v", err)
		}
		assertPBKDF2SHA512Keyslot(t, path, recovery.Keyslot, credential)
		return
	}
	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if got := metadata.Keyslots[strconv.Itoa(recovery.Keyslot)].KDF.Type; got != KDFTypeArgon2id {
		t.Fatalf("recovery keyslot %d KDF = %q, want %q", recovery.Keyslot, got, KDFTypeArgon2id)
	}
}

// TestAddRecoveryKeyPassesTheIterTimeThrough: PBKDFIterTime reaches AddKey.
// An out-of-range budget is refused there, which it could not be if the field
// were dropped on the way.
func TestAddRecoveryKeyPassesTheIterTimeThrough(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "recovery-itertime.img")
	formatWithLibrary(t, path)
	before := readAreaBytes(t, path, 0, goldenPrefixBytes)

	_, err := AddRecoveryKey(path, []byte(conformancePassphrase),
		&RecoveryKeyOptions{KDFType: KDFTypePBKDF2, PBKDFIterTime: maxPBKDF2IterTimeMs + 1})
	if err == nil {
		t.Fatal("AddRecoveryKey accepted a PBKDF2 budget above the maximum; the field did not reach AddKey")
	}
	if !bytes.Equal(before, readAreaBytes(t, path, 0, goldenPrefixBytes)) {
		t.Fatal("the refused AddRecoveryKey changed the container")
	}
}

// cryptsetupArgon2Container writes an Argon2id container with cryptsetup at
// the cheapest cost this package accepts, so the fixture exists in either mode
// and costs nothing to open outside FIPS mode.
func cryptsetupArgon2Container(t *testing.T, name string) string {
	t.Helper()

	requireCryptsetup(t)
	path := newImage(t, name)
	code, out := runCryptsetup(t, conformancePassphrase,
		"luksFormat", "--type", "luks2",
		"--cipher", "aes-xts-plain64", "--key-size", "512", "--hash", "sha512",
		"--pbkdf", "argon2id", "--pbkdf-force-iterations", "4",
		"--pbkdf-memory", strconv.Itoa(MinArgon2MemoryKB), "--pbkdf-parallel", "1",
		"--batch-mode", path)
	if code != 0 {
		t.Fatalf("cryptsetup luksFormat exited %d\n%s", code, out)
	}
	return path
}

// assertPBKDF2SHA512Keyslot checks that keyslot slot of path is PBKDF2-SHA512
// at no less than the floor for the budget the tests calibrate to, and that
// cryptsetup -- a separate implementation, in no FIPS mode of its own -- opens
// it with passphrase.
func assertPBKDF2SHA512Keyslot(t *testing.T, path string, slot int, passphrase string) {
	t.Helper()

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	keyslot, ok := metadata.Keyslots[strconv.Itoa(slot)]
	if !ok {
		t.Fatalf("keyslot %d is not in the header", slot)
	}
	kdf := keyslot.KDF
	if kdf.Type != KDFTypePBKDF2 || kdf.Hash != "sha512" {
		t.Fatalf("keyslot %d KDF = %s/%s, want pbkdf2/sha512", slot, kdf.Type, kdf.Hash)
	}
	floor := int(math.Ceil(pbkdf2IterationFloor("sha512", e2eIterTimeMs)))
	if kdf.Iterations == nil || *kdf.Iterations < floor {
		t.Fatalf("keyslot %d iterations = %v, want at least %d", slot, kdf.Iterations, floor)
	}

	code, out := runCryptsetup(t, passphrase,
		"open", "--test-passphrase", "--key-slot", strconv.Itoa(slot), path)
	if code != 0 {
		t.Fatalf("cryptsetup could not open keyslot %d (exit %d)\n%s", slot, code, out)
	}
}
