package luks2

// Conformance tests for docs/fips/engineering.md: each test names the
// requirement it holds and fails if the code stops meeting it.

import (
	"context"
	"crypto/fips140"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/internal/fips"
)

// openEngVolume opens an Argon2id volume image for the engineering.md
// conformance tests and returns it with its passphrase.
func openEngVolume(t *testing.T, name string) (string, *Volume) {
	t.Helper()
	path := argon2VolumeImage(t, name)
	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return path, v
}

// Error semantics: "Calling MigrateToFIPS from a FIPS process ... is reported
// this way [*FIPSMigrationError], at the precondition ... stage", and a
// precondition failure maps to StagePreflight, which implies nothing was
// written.
func TestEngMigrateToFIPSFromAFIPSProcessFailsAtPreflight(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}
	path, v := openEngVolume(t, "eng-preflight.img")
	before := fileDigest(t, path)

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()
	v.sys.fipsMode = func() fips.Mode { return true }

	m, err := v.MigrateToFIPS(context.Background(), pass, MigrateParams{KDF: cheapMigrationParams()})
	if m != nil {
		t.Errorf("MigrateToFIPS in a FIPS process returned a Migration %+v, want nil", m)
	}
	var merr *FIPSMigrationError
	if !errors.As(err, &merr) {
		t.Fatalf("MigrateToFIPS in a FIPS process = %v, want *FIPSMigrationError", err)
	}
	if merr.Stage != "precondition" || merr.MigrationStage() != StagePreflight {
		t.Errorf("Stage = %q (%v), want \"precondition\" (StagePreflight)", merr.Stage, merr.MigrationStage())
	}
	if !errors.Is(err, ErrFIPSMigration) || !errors.Is(err, errFIPSMigrationUnderFIPS) {
		t.Errorf("errors.Is(%v, ErrFIPSMigration and the cause) = false, want both", err)
	}
	if merr.State != fipsStateUntouched {
		t.Errorf("State = %q, want %q", merr.State, fipsStateUntouched)
	}
	if fileDigest(t, path) != before {
		t.Fatal("a migration refused at preflight changed the device")
	}
}

// Error semantics: a passphrase whose key matches no digest is reported as
// *FIPSMigrationError at a verify-phase stage, and the volume is untouched.
func TestEngMigrateToFIPSWithAWrongPassphraseFailsAtVerify(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}
	path, v := openEngVolume(t, "eng-wrongpass.img")
	before := fileDigest(t, path)

	wrong, err := enclave.NewMemoryCopy([]byte("not the passphrase of this volume"))
	if err != nil {
		t.Fatalf("NewMemoryCopy: %v", err)
	}
	defer func() { _ = wrong.Destroy() }()

	_, err = v.MigrateToFIPS(context.Background(), wrong, MigrateParams{KDF: cheapMigrationParams()})
	var merr *FIPSMigrationError
	if !errors.As(err, &merr) {
		t.Fatalf("MigrateToFIPS with a wrong passphrase = %v, want *FIPSMigrationError", err)
	}
	if merr.MigrationStage() != StageVerify {
		t.Errorf("Stage = %q (%v), want a StageVerify stage", merr.Stage, merr.MigrationStage())
	}
	if !errors.Is(err, ErrFIPSMigration) {
		t.Errorf("errors.Is(%v, ErrFIPSMigration) = false", err)
	}
	if merr.State != fipsStateUntouched {
		t.Errorf("State = %q, want %q", merr.State, fipsStateUntouched)
	}
	if fileDigest(t, path) != before {
		t.Fatal("a migration refused for a wrong passphrase changed the device")
	}
}
