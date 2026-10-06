// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"crypto/fips140"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// The end-to-end proof for #84, against a volume this package did not write.
//
// A default `cryptsetup luksFormat` -- Argon2id, whatever cost cryptsetup
// calibrates -- is migrated in a process that is NOT in FIPS mode and then
// opened in one that IS, under GODEBUG=fips140=only. cryptsetup must still open
// the migrated volume, so the migration does not buy FIPS at the price of
// interoperability.
//
// # Why child processes
//
// FIPS mode is fixed when a process starts: crypto/fips140.Enabled() reports
// what GODEBUG said at startup and nothing can change it afterwards. The two
// halves of this test need OPPOSITE modes, so each runs in its own re-execution
// of this test binary with GODEBUG set for it. The parent never derives
// anything; it formats with cryptsetup, inspects headers, and judges exit codes
// -- so the test behaves identically whether the parent is the ordinary unit
// run or the nightly FIPS lane, which runs this package with
// GODEBUG=fips140=only (.github/workflows/nightly.yml).
//
// This is a TEST seam, and deliberately only that. The owner ruling of
// 2026-09-25 rejected a re-exec seam in the library; the library's own
// verification is the static check and the real open in MigrateToFIPS.

// fipsImportRoleEnv selects the child's role; fipsImportImageEnv names the
// image it acts on. A test binary started without the role runs as normal.
const (
	fipsImportRoleEnv  = "GO_LUKS2_FIPS_IMPORT_ROLE"
	fipsImportImageEnv = "GO_LUKS2_FIPS_IMPORT_IMAGE"
)

// Child roles.
const (
	childRoleOpen    = "open"    // TestKey, in whatever mode the child was started
	childRoleMigrate = "migrate" // MigrateToFIPS, removing non-approved keyslots (the default), at cheapMigration's cost
	childRoleWeaken  = "weaken"  // add a PBKDF2 keyslot, then weakenForStrictFIPS it and digest 0
	// The volume key the normal unlock scan recovers, in hex -- the key Unlock
	// hands to dm-crypt, which TestKey cannot tell apart from an unbound one.
	childRoleVolumeKey = "volumekey"
)

// Child exit codes. Distinct from 0/1/2 so a child that crashed or failed to
// start is never read as an expected outcome.
const (
	childOK             = 0
	childImportRequired = 10 // the open was refused with ErrFIPSImportRequired
	childRefusedFIPS    = 11 // the migration was refused with ErrFIPSMigrationUnderFIPS
	childFailed         = 12 // anything else; the error is on stdout
)

// A child is recognized before the test framework starts, so it runs exactly
// one operation and exits with a code the parent can judge. init rather than
// TestMain because this package's TestMain installs seams the child does not
// need, and because a role check here cannot be forgotten by a later TestMain.
func init() {
	if role := os.Getenv(fipsImportRoleEnv); role != "" {
		useCheapCalibratedCounts()
		os.Exit(runFIPSImportChild(role, os.Getenv(fipsImportImageEnv)))
	}
}

// runFIPSImportChild performs one role and reports its outcome on stdout and in
// the exit code. The FIPS mode it ran in is printed first, so the parent can
// require that GODEBUG actually took effect instead of trusting it did.
func runFIPSImportChild(role, image string) int {
	fmt.Printf("fips140.Enabled=%v\n", fips140.Enabled())

	switch role {
	case childRoleOpen:
		err := TestKey(image, []byte(conformancePassphrase))
		if err == nil {
			return childOK
		}
		fmt.Println(err)
		if errors.Is(err, ErrFIPSImportRequired) {
			return childImportRequired
		}
		return childFailed

	case childRoleMigrate:
		// cheapMigration, not nil: the calibrated default cost is a property of
		// createKDF, covered where it is judged. Here it would only spend the
		// package's -race budget (ci.yml) calibrating and then deriving PBKDF2
		// in this child and in every open after it, and defend nothing this
		// test proves.
		result, err := MigrateToFIPS(image, []byte(conformancePassphrase), cheapMigration())
		if err != nil {
			fmt.Println(err)
			if errors.Is(err, ErrFIPSMigrationUnderFIPS) {
				return childRefusedFIPS
			}
			return childFailed
		}
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			fmt.Println(err)
			return childFailed
		}
		return childOK

	case childRoleVolumeKey:
		_, metadata, err := ReadHeader(image)
		if err != nil {
			fmt.Println(err)
			return childFailed
		}
		key, err := getMasterKey(image, []byte(conformancePassphrase), metadata)
		if err != nil {
			fmt.Println(err)
			if errors.Is(err, ErrFIPSImportRequired) {
				return childImportRequired
			}
			return childFailed
		}
		printErr := secret.Borrow("print the scanned volume key", key, func(b []byte) error {
			fmt.Println(hex.EncodeToString(b))
			return nil
		})
		// A release the enclave reports fails the child: the parent judges
		// the exit code, and a dropped report would read as a clean run.
		if err := errors.Join(printErr, key.Destroy()); err != nil {
			fmt.Println(err)
			return childFailed
		}
		return childOK

	case childRoleWeaken:
		// A second keyslot for the SAME passphrase, PBKDF2 so the migration's
		// approved-first scan reaches it before the Argon2 one, then that
		// keyslot and digest 0 re-written over a salt strict FIPS refuses.
		// Derivations through that salt are what a FIPS parent cannot do,
		// which is why this is a child.
		passphrase := []byte(conformancePassphrase)
		slot, err := AddKey(image, passphrase, passphrase, &AddKeyOptions{KDFType: KDFTypePBKDF2, PBKDFIterTime: 1})
		if err != nil {
			fmt.Println(err)
			return childFailed
		}
		if err := weakenForStrictFIPS(image, passphrase, strconv.Itoa(slot)); err != nil {
			fmt.Println(err)
			return childFailed
		}
		return childOK

	default:
		fmt.Printf("unknown role %q\n", role)
		return childFailed
	}
}

// runChild re-executes this test binary as a child in the given role, with
// GODEBUG set to godebug and nothing else inherited for it, and returns the
// exit code and stdout. It fails the test if the child did not run in the FIPS
// mode asked for.
func runChild(t *testing.T, role, image, godebug string, wantFIPS bool) (int, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0]) // #nosec G204 -- this test binary, re-executed
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "GODEBUG=") ||
			strings.HasPrefix(kv, fipsImportRoleEnv+"=") ||
			strings.HasPrefix(kv, fipsImportImageEnv+"=")
	})
	cmd.Env = append(env, "GODEBUG="+godebug, fipsImportRoleEnv+"="+role, fipsImportImageEnv+"="+image)
	var stderr strings.Builder
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	code := 0
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	default:
		t.Fatalf("child %q could not be run: %v", role, err)
	}

	stdout := string(out)
	wantMode := fmt.Sprintf("fips140.Enabled=%v\n", wantFIPS)
	if !strings.HasPrefix(stdout, wantMode) {
		t.Fatalf("child %q with GODEBUG=%s did not run in the FIPS mode asked for (want %q)\nstdout:\n%s\nstderr:\n%s",
			role, godebug, strings.TrimSpace(wantMode), stdout, stderr.String())
	}
	return code, strings.TrimPrefix(stdout, wantMode)
}

// TestFIPSImportOfACryptsetupArgon2idVolume: a cryptsetup Argon2id volume is
// refused by a FIPS process with the remedy named, cannot be migrated FROM a
// FIPS process, is migrated by a non-FIPS one without its data being touched,
// still opens in cryptsetup, and then opens in a FIPS process.
//
// cryptsetup's defaults in everything but the Argon2 cost, which is its
// minimum. At the default cost -- about a gibibyte, calibrated to two seconds
// of cryptsetup's own time -- the Argon2 unlock runs in a race-instrumented
// child of this binary, and that alone spent a tenth of the package's -race
// budget (ci.yml) on a parameter nothing here is about. The DEFAULT volume is
// proved end to end where that cost is not charged to the budget and where
// more can be checked: the integration suite's
// TestFIPSImportOfADefaultCryptsetupVolumeMapsTheSameData formats with
// cryptsetup's defaults, imports, and reads plaintext back through a mapping a
// GODEBUG=fips140=only process made.
func TestFIPSImportOfACryptsetupArgon2idVolume(t *testing.T) {
	defer parallel(t)()
	requireCryptsetup(t)

	image := newImage(t, "cryptsetup-argon2id.img")

	// cryptsetup's own luksFormat, not a fixture this package wrote. --type
	// luks2 only pins what current cryptsetup defaults to anyway, so a host
	// whose build still defaults to LUKS1 fails loudly here rather than
	// testing something else.
	args := append(append([]string{"luksFormat"}, crashArgon2Args...), "--type", "luks2", image)
	if code, out := runCryptsetup(t, conformancePassphrase, args...); code != 0 {
		t.Fatalf("cryptsetup luksFormat exited %d\n%s", code, out)
	}

	// The fixture is what the test claims: an Argon2id keyslot. Without this
	// the whole test could pass against a volume that never needed importing.
	_, metadata, err := ReadHeader(image)
	if err != nil {
		t.Fatalf("ReadHeader on cryptsetup's volume failed: %v", err)
	}
	keyslots, _ := nonApprovedKDFs(metadata)
	if len(keyslots) != 1 || keyslots[0].Type != KDFTypeArgon2id {
		t.Fatalf("cryptsetup's volume has non-approved keyslots %v, want exactly one argon2id", keyslots)
	}

	fillDataArea(t, image)
	dataBefore := dataAreaDigest(t, image)

	// 1. A FIPS process refuses it -- and says it is intact and how to import it.
	code, out := runChild(t, childRoleOpen, image, "fips140=only", true)
	if code != childImportRequired {
		t.Fatalf("FIPS open of the un-migrated volume exited %d, want %d (ErrFIPSImportRequired)\n%s",
			code, childImportRequired, out)
	}
	for _, want := range []string{"intact", "argon2id", "MigrateToFIPS"} {
		if !strings.Contains(out, want) {
			t.Errorf("the FIPS refusal does not say %q:\n%s", want, out)
		}
	}

	// 2. A FIPS process refuses to migrate, and does not touch the device.
	before := fileDigest(t, image)
	if code, out := runChild(t, childRoleMigrate, image, "fips140=only", true); code != childRefusedFIPS {
		t.Fatalf("migration in a FIPS process exited %d, want %d (ErrFIPSMigrationUnderFIPS)\n%s", code, childRefusedFIPS, out)
	}
	if fileDigest(t, image) != before {
		t.Fatal("the migration refused in a FIPS process still changed the device")
	}

	// 3. The import itself, in a non-FIPS process, removing the originals by default.
	code, out = runChild(t, childRoleMigrate, image, "fips140=off", false)
	if code != childOK {
		t.Fatalf("migration in a non-FIPS process exited %d\n%s", code, out)
	}
	var result FIPSMigrationResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("could not read the migration result %q: %v", out, err)
	}
	if !result.Complete || !result.KeyslotAdded || !slices.Equal(result.RemovedKeyslots, []string{"0"}) {
		t.Fatalf("migration result %+v, want complete, a keyslot added and keyslot 0 removed", result)
	}

	// 4. The header, statically, and the data area, byte for byte.
	assertFIPSReady(t, image)
	if dataAreaDigest(t, image) != dataBefore {
		t.Fatal("the migration changed the data area; it must never re-encrypt")
	}

	// 5. Bidirectional conformance survives: cryptsetup opens what was written.
	if code, out := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", image); code != 0 {
		t.Fatalf("cryptsetup cannot open the migrated volume: exit %d\n%s", code, out)
	}

	// 6. And a FIPS process opens it, never having executed Argon2.
	if code, out := runChild(t, childRoleOpen, image, "fips140=only", true); code != childOK {
		t.Fatalf("FIPS open of the migrated volume exited %d\n%s", code, out)
	}
}

// TestFIPSImportOfACryptsetupVolumeWithShortSalts is the cross-process proof
// that the migration judges what strict FIPS mode will actually RUN, not what
// the header names. A cryptsetup Argon2id volume is given a second keyslot for
// the same passphrase -- PBKDF2-SHA256, so the approved-first scan reaches it
// first -- and that keyslot and digest 0 are rewritten over an eight-byte
// salt. Every name is approved; crypto/pbkdf2 refuses both derivations under
// GODEBUG=fips140=only. The migration must add a fresh keyslot rather than
// reuse that one, migrate the digest, and leave a volume a strict FIPS process
// opens.
//
// This fixture and the unbound-key one are formatted by cryptsetup with an
// explicit, cheap Argon2id cost. Cryptsetup's DEFAULT volume is the headline
// test's job; here what is under test is the salts and the segment binding,
// and a calibrated Argon2 cost would only spend the package's -race budget
// (ci.yml) unlocking it in the children.
func TestFIPSImportOfACryptsetupVolumeWithShortSalts(t *testing.T) {
	defer parallel(t)()
	requireCryptsetup(t)

	image := newImage(t, "cryptsetup-short-salts.img")
	if code, out := runCryptsetup(t, conformancePassphrase, "luksFormat", "--type", "luks2", "--pbkdf", "argon2id",
		"--pbkdf-force-iterations", "4", "--pbkdf-memory", "32", "--batch-mode", image); code != 0 {
		t.Fatalf("cryptsetup luksFormat exited %d\n%s", code, out)
	}
	if code, out := runChild(t, childRoleWeaken, image, "fips140=off", false); code != childOK {
		t.Fatalf("weakening the fixture exited %d\n%s", code, out)
	}

	// The fixture is what the test claims: the Argon2 keyslot, plus a keyslot
	// and a digest whose names are approved and whose salts are not.
	_, metadata, err := ReadHeader(image)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	keyslots, digests := nonApprovedKDFs(metadata)
	if len(keyslots) != 2 || keyslots[0].Type != KDFTypeArgon2id ||
		keyslots[1].Type != KDFTypePBKDF2 || keyslots[1].Hash != "sha256" || keyslots[1].Reason == "" {
		t.Fatalf("fixture keyslots %v, want argon2id and a short-salt pbkdf2-sha256", keyslots)
	}
	if len(digests) != 1 || digests[0].Type != KDFTypePBKDF2 || digests[0].Hash != "sha256" || digests[0].Reason == "" {
		t.Fatalf("fixture digests %v, want one short-salt pbkdf2-sha256", digests)
	}

	fillDataArea(t, image)
	dataBefore := dataAreaDigest(t, image)

	// Strict FIPS cannot open it as it stands: the hazard is real, not
	// theoretical.
	if code, out := runChild(t, childRoleOpen, image, "fips140=only", true); code == childOK {
		t.Fatalf("a strict FIPS process opened the short-salt fixture; the test would measure nothing\n%s", out)
	}

	code, out := runChild(t, childRoleMigrate, image, "fips140=off", false)
	if code != childOK {
		t.Fatalf("migration in a non-FIPS process exited %d\n%s", code, out)
	}
	var result FIPSMigrationResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("could not read the migration result %q: %v", out, err)
	}
	if !result.Complete || !result.KeyslotAdded || result.Keyslot != 2 ||
		!slices.Equal(result.MigratedDigests, []string{"0"}) ||
		!slices.Equal(result.RemovedKeyslots, []string{"0", "1"}) {
		t.Fatalf("migration result %+v, want keyslot 2 added, digest 0 migrated, keyslots 0 and 1 removed, complete", result)
	}

	assertFIPSReady(t, image)
	if dataAreaDigest(t, image) != dataBefore {
		t.Fatal("the migration changed the data area; it must never re-encrypt")
	}
	if code, out := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", image); code != 0 {
		t.Fatalf("cryptsetup cannot open the migrated volume: exit %d\n%s", code, out)
	}
	if code, out := runChild(t, childRoleOpen, image, "fips140=only", true); code != childOK {
		t.Fatalf("strict FIPS open of the migrated volume exited %d\n%s", code, out)
	}
}

// TestFIPSImportOfACryptsetupVolumeWithAnUnboundKey is the cross-process proof
// that the migrated volume maps with the VOLUME key under FIPS, not merely that
// some keyslot opens. cryptsetup adds an unbound PBKDF2-SHA256 keyslot under the
// same passphrase as the Argon2 one; it is approved, so the migration keeps it,
// and it sorts before the keyslot the migration adds. A scan that ignored
// segment binding would find it first and Unlock would hand dm-crypt the wrong
// key -- which TestKey, and opening the migrated keyslot directly, cannot see.
// The key a strict FIPS process's normal scan recovers must be the one
// cryptsetup itself reports as the volume key.
func TestFIPSImportOfACryptsetupVolumeWithAnUnboundKey(t *testing.T) {
	defer parallel(t)()
	requireCryptsetup(t)

	image := newImage(t, "cryptsetup-unbound.img")
	if code, out := runCryptsetup(t, conformancePassphrase, "luksFormat", "--type", "luks2", "--pbkdf", "argon2id",
		"--pbkdf-force-iterations", "4", "--pbkdf-memory", "32", "--batch-mode", image); code != 0 {
		t.Fatalf("cryptsetup luksFormat exited %d\n%s", code, out)
	}
	if code, out := runCryptsetup(t, conformancePassphrase, "luksAddKey", "--unbound", "--key-size", "512",
		"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--batch-mode", image); code != 0 {
		t.Fatalf("cryptsetup luksAddKey --unbound exited %d\n%s", code, out)
	}
	volumeKey := cryptsetupVolumeKey(t, image)

	// The fixture is what the test claims: an Argon2 keyslot 0 bound to the
	// data, and an approved keyslot 1 bound to nothing.
	_, metadata, err := ReadHeader(image)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	keyslots, _ := nonApprovedKDFs(metadata)
	if len(keyslots) != 1 || keyslots[0].ID != "0" || keyslots[0].Type != KDFTypeArgon2id {
		t.Fatalf("fixture non-approved keyslots %v, want exactly argon2id keyslot 0", keyslots)
	}
	if !keyslotFIPSApproved(metadata.Keyslots["1"]) || keyslotDeclaredForAllSegments(metadata, "1") {
		t.Fatal("fixture keyslot 1 is not an approved unbound keyslot")
	}

	fillDataArea(t, image)
	dataBefore := dataAreaDigest(t, image)

	code, out := runChild(t, childRoleMigrate, image, "fips140=off", false)
	if code != childOK {
		t.Fatalf("migration in a non-FIPS process exited %d\n%s", code, out)
	}
	var result FIPSMigrationResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("could not read the migration result %q: %v", out, err)
	}
	if !result.Complete || !result.KeyslotAdded || result.Keyslot != 2 ||
		!slices.Equal(result.RemovedKeyslots, []string{"0"}) {
		t.Fatalf("migration result %+v, want keyslot 2 added, keyslot 0 removed, complete", result)
	}

	assertFIPSReady(t, image)
	if dataAreaDigest(t, image) != dataBefore {
		t.Fatal("the migration changed the data area; it must never re-encrypt")
	}
	if got := cryptsetupVolumeKey(t, image); got != volumeKey {
		t.Fatal("cryptsetup reports a different volume key after the migration")
	}

	code, out = runChild(t, childRoleVolumeKey, image, "fips140=only", true)
	if code != childOK {
		t.Fatalf("strict FIPS unlock scan of the migrated volume exited %d\n%s", code, out)
	}
	if strings.TrimSpace(out) != volumeKey {
		t.Fatal("the strict FIPS unlock scan recovers a key other than cryptsetup's volume key; Unlock would map the wrong key")
	}
}

// cryptsetupVolumeKey returns, in hex, the volume key cryptsetup recovers from
// image with the conformance passphrase -- cryptsetup's own answer to which key
// the data segment uses.
func cryptsetupVolumeKey(t *testing.T, image string) string {
	t.Helper()

	path := image + ".vk"
	if code, out := runCryptsetup(t, conformancePassphrase, "luksDump", "--dump-volume-key",
		"--volume-key-file", path, "--batch-mode", image); code != 0 {
		t.Fatalf("cryptsetup luksDump --dump-volume-key exited %d\n%s", code, out)
	}
	key, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("reading the dumped volume key failed: %v", err)
	}
	defer clearBytes(key)
	if err := os.Remove(path); err != nil {
		t.Fatalf("removing the dumped volume key failed: %v", err)
	}
	return hex.EncodeToString(key)
}
