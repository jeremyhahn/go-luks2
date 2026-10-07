// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/internal/fips"
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

func TestVolumeMigrateToFIPSOnAReadOnlyVolumeFailsWithErrReadOnly(t *testing.T) {
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
