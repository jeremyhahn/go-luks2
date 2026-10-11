// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"crypto/fips140"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// cheapMigrationParams keeps the new PBKDF2 keyslot's calibration short:
// MigrateParams{}'s zero IterTime targets 2s, which is real cost this test
// does not need (the subject is the migration's bookkeeping, not the KDF).
func cheapMigrationParams() KDFParams {
	return KDFParams{IterTime: time.Millisecond}
}

// argon2VolumeImage formats a fresh temp image with an Argon2id keyslot at
// the floor DECISIONS.md asks for (m=64MiB t=1 p=1), the shape
// MigrateToFIPS exists to import away from.
func argon2VolumeImage(t *testing.T, name string) string {
	t.Helper()
	path := newImage(t, name)
	if err := formatForTest(formatOptionsForTest{
		Device:       path,
		Passphrase:   []byte(testPassphraseText),
		Cipher:       "aes",
		CipherMode:   "xts-plain64",
		KeySize:      512,
		HashAlgo:     "sha256",
		SectorSize:   512,
		KDFType:      kdfTypeArgon2id,
		Argon2Time:   1,
		Argon2Memory: 64 * 1024,
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}
	return path
}

func TestVolumeMigrateToFIPSImportsAnArgon2Volume(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	path := argon2VolumeImage(t, "migratefips.img")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	migration, err := v.MigrateToFIPS(context.Background(), pass, MigrateParams{KDF: cheapMigrationParams()})
	if err != nil {
		t.Fatalf("MigrateToFIPS failed: %v", err)
	}
	if !migration.KeyslotAdded {
		t.Error("KeyslotAdded = false, want true (the original keyslot is Argon2id)")
	}
	if !migration.Complete {
		t.Errorf("Complete = false, want true: retained %v", migration.RetainedNonApproved)
	}
	if len(migration.RemovedKeyslots) != 1 {
		t.Errorf("RemovedKeyslots = %v, want exactly the original Argon2id slot", migration.RemovedKeyslots)
	}

	// The passphrase must still open the volume, now through the new
	// PBKDF2 keyslot.
	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock after migration failed: %v", err)
	}
	defer key.Destroy()
	if key.Keyslot() != migration.Keyslot {
		t.Errorf("Unlock after migration opened keyslot %d, want %d", key.Keyslot(), migration.Keyslot)
	}
}

func TestVolumeMigrateToFIPSKeepsNonApprovedWhenAsked(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	path := argon2VolumeImage(t, "migratefipskeep.img")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	migration, err := v.MigrateToFIPS(context.Background(), pass, MigrateParams{KeepNonApproved: true, KDF: cheapMigrationParams()})
	if err != nil {
		t.Fatalf("MigrateToFIPS failed: %v", err)
	}
	if migration.Complete {
		t.Error("Complete = true, want false: the Argon2id keyslot was kept")
	}
	if len(migration.RetainedNonApproved) != 1 {
		t.Errorf("RetainedNonApproved = %v, want exactly the original Argon2id slot", migration.RetainedNonApproved)
	}
	if len(migration.RemovedKeyslots) != 0 {
		t.Errorf("RemovedKeyslots = %v, want none", migration.RemovedKeyslots)
	}
}

func TestVolumeMigrateToFIPSRefusesUnderFIPSMode(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	path := argon2VolumeImage(t, "migratefipsunderfips.img")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	v.sys.fipsMode = func() fips.Mode { return true }

	if _, err := v.MigrateToFIPS(context.Background(), pass, MigrateParams{}); !errors.Is(err, errFIPSMigrationUnderFIPS) {
		t.Fatalf("MigrateToFIPS under FIPS mode = %v, want ErrFIPSMigrationUnderFIPS", err)
	}
}

// TestVolumeMigrateToFIPSErrorSaysEachThingOnce pins the rendering of a
// migration failure: the package, the operation, the device and
// ErrFIPSMigration each once, in the head, then the stage, the cause and the
// state, for a refusal and for a stage that failed on a cause from below.
// The classification survives the shorter text.
func TestVolumeMigrateToFIPSErrorSaysEachThingOnce(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	path := argon2VolumeImage(t, "migratefipsmessage.img")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	classified := func(t *testing.T, err error, stage string) {
		t.Helper()
		if !errors.Is(err, ErrFIPSMigration) {
			t.Errorf("errors.Is(%v, ErrFIPSMigration) = false", err)
		}
		var migration *FIPSMigrationError
		if !errors.As(err, &migration) || migration.Stage != stage || migration.Device != path {
			t.Errorf("errors.As(*FIPSMigrationError) = %+v, want stage %q on %s", migration, stage, path)
		}
		var e *errs.Error
		if !errors.As(err, &e) || e.Kind != ErrFIPSMigration || e.Op != "Volume.MigrateToFIPS" || e.Path != path {
			t.Errorf("errors.As(*errs.Error) = %+v, want Kind ErrFIPSMigration, Op Volume.MigrateToFIPS, Path %s", e, path)
		}
		msg := err.Error()
		for _, once := range []string{"luks2: ", "FIPS 140-3 migration failed", path, "at " + stage} {
			if n := strings.Count(msg, once); n != 1 {
				t.Errorf("%q appears %d times in %q, want once", once, n, msg)
			}
		}
	}

	t.Run("a stage failure", func(t *testing.T) {
		wrong := secretOf(t, []byte("not-the-passphrase"))
		_, err := v.MigrateToFIPS(context.Background(), wrong, MigrateParams{KDF: cheapMigrationParams()})
		classified(t, err, "unlock")
		if !errors.Is(err, ErrWrongKey) {
			t.Errorf("errors.Is(%v, ErrWrongKey) = false, want the cause reachable", err)
		}
	})

	t.Run("a refusal", func(t *testing.T) {
		pass := newTestPassphrase(t)
		defer func() { _ = pass.Destroy() }()

		v.sys.fipsMode = func() fips.Mode { return true }
		_, err := v.MigrateToFIPS(context.Background(), pass, MigrateParams{})
		classified(t, err, "precondition")
		want := "luks2: Volume.MigrateToFIPS " + path + ": FIPS 140-3 migration failed: at precondition: " +
			"the FIPS import must run in a process that is not in FIPS 140-3 mode; nothing was written and the volume is unchanged"
		if err == nil || err.Error() != want {
			t.Errorf("MigrateToFIPS under FIPS mode = %v,\nwant %s", err, want)
		}
	})
}

// TestVolumeMigrateToFIPSCanceledInAStageIsAMigrationFailure: a context
// canceled while a migration stage runs is still classified ErrFIPSMigration,
// with the cancellation reachable through errors.Is and the stage through
// *FIPSMigrationError. The context kind must not win over the migration's.
func TestVolumeMigrateToFIPSCanceledInAStageIsAMigrationFailure(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	path := argon2VolumeImage(t, "migratefipscanceled.img")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	// The first derivation is the unlock; the second is the new keyslot's,
	// in the "add keyslot" stage, and it is where the context is canceled.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	real := v.sys
	calls := 0
	v.sys.passphraseKDFOverride = func(ctx context.Context, p []byte, k *header.KDF, size int) (*enclave.MemoryEnclave, error) {
		calls++
		if calls == 2 {
			cancel()
			return nil, ctx.Err()
		}
		return real.passphraseKDF(ctx, p, k, size)
	}

	_, err = v.MigrateToFIPS(ctx, pass, MigrateParams{KDF: cheapMigrationParams()})
	if !errors.Is(err, ErrFIPSMigration) {
		t.Errorf("errors.Is(%v, ErrFIPSMigration) = false", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(%v, context.Canceled) = false, want the cause reachable", err)
	}
	var migration *FIPSMigrationError
	if !errors.As(err, &migration) || migration.Stage != "add keyslot" {
		t.Errorf("errors.As(*FIPSMigrationError) = %+v, want stage %q", migration, "add keyslot")
	}
	var e *errs.Error
	if !errors.As(err, &e) || e.Kind != ErrFIPSMigration {
		t.Errorf("errors.As(*errs.Error) = %+v, want Kind ErrFIPSMigration", e)
	}
}

// TestVolumeDerivationFollowsTheVolumeFIPSMode: a Volume's keyslot derivation
// and PBKDF2 calibration run under the Volume's own sys, not the process's
// mode. An injected FIPS-on sys refuses Argon2id and SHA-1 calibration, and
// the same Argon2id derivation succeeds under an injected FIPS-off sys, in
// any process.
func TestVolumeDerivationFollowsTheVolumeFIPSMode(t *testing.T) {
	path := newImage(t, "volume-derivation-fips.img")

	timeCost, memory, cpus := 1, minArgon2MemoryKB, 1
	argon2 := &header.KDF{
		Type:   kdfTypeArgon2id,
		Salt:   encodeBase64(make([]byte, 32)),
		Time:   &timeCost,
		Memory: &memory,
		CPUs:   &cpus,
	}

	for _, mode := range []fips.Mode{true, false} {
		sys := testVolumeSys()
		sys.fipsMode = func() fips.Mode { return mode }
		v, err := Open(context.Background(), path, withTestSys(sys))
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}

		key, err := v.sys.passphraseKDF(context.Background(), []byte("a passphrase"), argon2, 32)
		_, calErr := benchmarkPBKDF2(v.sys.fipsMode(), "sha1", 20, 1)
		_ = v.Close()

		if mode {
			if !errors.Is(err, ErrFIPSNotApproved) || key != nil {
				t.Errorf("Argon2id derivation under a FIPS-mode Volume = (%v, %v), want ErrFIPSNotApproved", key, err)
			}
			if !errors.Is(calErr, ErrFIPSNotApproved) {
				t.Errorf("SHA-1 calibration under a FIPS-mode Volume = %v, want ErrFIPSNotApproved", calErr)
			}
			continue
		}
		if err != nil {
			t.Fatalf("Argon2id derivation under a non-FIPS Volume failed: %v", err)
		}
		mustDestroy(t, key)
	}
}

func TestVolumeMigrateToFIPSOnAReadOnlyVolumeFailsWithErrReadOnly(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	path := argon2VolumeImage(t, "migratefipsreadonly.img")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()), WithReadOnly())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	if _, err := v.MigrateToFIPS(context.Background(), pass, MigrateParams{}); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("MigrateToFIPS on a read-only Volume = %v, want ErrReadOnly", err)
	}
}
