// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// MigrateParams configures MigrateToFIPS. Its zero value is the library's
// policy: remove every non-approved keyslot, and migrate the new PBKDF2
// keyslot and every rewritten digest at KDFParams{}'s own policy (SHA-256,
// calibrated).
type MigrateParams struct {
	// KeepNonApproved keeps the original Argon2 (or PBKDF2-SHA1) keyslots
	// instead of removing them. Keeping them is a HALF-MIGRATION -- the
	// volume still opens in a non-FIPS process through a KDF FIPS mode
	// cannot execute -- and Migration.Complete says so.
	KeepNonApproved bool

	// KDF is the new PBKDF2 keyslot's cost, and the cost any migrated
	// digest is rewritten at. Only KDFPBKDF2 and its Hash are consulted;
	// Hash's zero value is SHA-256. A KDF naming Argon2 -- KDFArgon2id or
	// KDFArgon2i, or any of Time, MemoryKiB or Parallel non-zero -- is refused
	// with ErrFIPSNotApproved before anything is written.
	KDF KDFParams
}

// Migration is the result of a completed MigrateToFIPS run.
type Migration struct {
	// Keyslot is the FIPS-approved keyslot the passphrase now opens.
	Keyslot int

	// KeyslotAdded is false when the passphrase already opened an approved
	// keyslot, which was then used as it stands.
	KeyslotAdded bool

	// MigratedDigests are the digests whose KDF was rewritten to PBKDF2.
	MigratedDigests []int

	// RemovedKeyslots are the non-approved keyslots that were removed.
	RemovedKeyslots []int

	// RetainedNonApproved are the non-approved keyslots kept because the
	// caller set KeepNonApproved. Non-empty means the migration is
	// incomplete.
	RetainedNonApproved []int

	// Complete is true when no keyslot or digest the volume carries uses a
	// KDF FIPS mode cannot execute.
	Complete bool
}

// FIPSMigrationStage names where in a MigrateToFIPS run a failure happened,
// coarser than FIPSMigrationError's own Stage string (fipsmigrate.go has
// ten; this groups them into five phases -- see
// FIPSMigrationError.MigrationStage for the mapping).
type FIPSMigrationStage uint8

const (
	// StagePreflight covers every check made before the device is touched:
	// mode, path, credential, KDF approval, keyslot area confinement.
	StagePreflight FIPSMigrationStage = iota
	// StageVerify covers unlocking, planning which digests migrate, and the
	// post-write opens that prove the result.
	StageVerify
	// StageWrite covers adding the PBKDF2 keyslot and rewriting digests.
	StageWrite
	// StageRemove covers removing the non-approved keyslots.
	StageRemove
	// StageVerifyWritten covers the final check against the header as
	// written, after removal.
	StageVerifyWritten
)

// atoiIDs converts canonical keyslot or digest IDs (small decimal strings,
// as every metadata map key in this package is) to ints, for Migration's
// fields.
func atoiIDs(ids []string) []int {
	if ids == nil {
		return nil
	}
	out := make([]int, 0, len(ids))
	for _, id := range ids {
		n, _ := strconv.Atoi(id)
		out = append(out, n)
	}
	return out
}

// MigrateToFIPS imports the volume into a FIPS 140-3 deployment: it adds a
// PBKDF2 keyslot for pass holding the same volume key, migrates every digest
// whose KDF is not approved, verifies the volume opens through approved
// KDFs alone, and then removes the keyslots FIPS mode cannot execute (or
// keeps them, per p.KeepNonApproved). No data is re-encrypted.
//
// It must be called from a process that is NOT in FIPS mode, because
// unlocking the volume may need to execute its Argon2 keyslot; from a FIPS
// process it returns an error matching ErrFIPSMigration, a
// *FIPSMigrationError at Stage "precondition", without touching the device.
//
// The migration runs on the descriptor Open pinned, under this Volume's own
// exclusive lock -- its lock wait, clock and lock directory -- as AddKeyslot
// does: a path re-pointed since Open cannot send it to another device.
func (v *Volume) MigrateToFIPS(ctx context.Context, pass enclave.ByteAccess, p MigrateParams) (*Migration, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.checkOpen("Volume.MigrateToFIPS"); err != nil {
		return nil, err
	}
	if err := v.checkWritable("Volume.MigrateToFIPS"); err != nil {
		return nil, err
	}

	const op = "Volume.MigrateToFIPS"
	// An Argon2 KDF is refused, not dropped: the migration writes PBKDF2 only,
	// and a caller who named Argon2 must hear that rather than get a PBKDF2
	// keyslot it did not ask for. Refused here, before anything is written,
	// as the precondition failure migrateToFIPS would report it as.
	if err := refuseArgon2MigrateKDF(p.KDF); err != nil {
		return nil, errAt(op, v.path, &FIPSMigrationError{Device: v.path, Stage: "precondition", State: fipsStateUntouched, Err: err})
	}
	opts := &fipsMigrationOptionsForTest{
		KeepNonApprovedKeyslots: p.KeepNonApproved,
		Hash:                    hashAlgoName(p.KDF.Hash),
		PBKDFIterTime:           int(p.KDF.IterTime / time.Millisecond),
		PBKDFIterations:         p.KDF.Iterations,
	}

	lockDevice := func() (*keyslotDevice, func(), error) {
		locked, err := v.lockFor(ctx, device.LockExclusive)
		if err != nil {
			return nil, nil, err
		}
		dev, err := v.keyslotDeviceFor(locked)
		if err != nil {
			_ = locked.Unlock()
			return nil, nil, err
		}
		return dev, func() { _ = locked.Unlock() }, nil
	}

	var result *fipsMigrationResultForTest
	err := secret.Borrow(op, pass, func(raw []byte) error {
		var merr error
		result, merr = migrateToFIPS(ctx, v.path, raw, opts, v.sys, lockDevice)
		return merr
	})
	if err != nil {
		return nil, errAt(op, v.path, err)
	}

	return &Migration{
		Keyslot:             result.Keyslot,
		KeyslotAdded:        result.KeyslotAdded,
		MigratedDigests:     atoiIDs(result.MigratedDigests),
		RemovedKeyslots:     atoiIDs(result.RemovedKeyslots),
		RetainedNonApproved: atoiIDs(result.RetainedNonApprovedKeyslots),
		Complete:            result.Complete,
	}, nil
}

// refuseArgon2MigrateKDF refuses a MigrateParams.KDF that names Argon2 -- by
// Type, or by any Argon2 cost field -- with ErrFIPSNotApproved, naming the
// field. MigrateToFIPS writes PBKDF2 only, so such a KDF cannot be honored.
func refuseArgon2MigrateKDF(k KDFParams) error {
	var field string
	switch {
	case k.Type == KDFArgon2id || k.Type == KDFArgon2i:
		field = "MigrateParams.KDF.Type " + string(k.Type)
	case k.Time != 0:
		field = "MigrateParams.KDF.Time"
	case k.MemoryKiB != 0:
		field = "MigrateParams.KDF.MemoryKiB"
	case k.Parallel != 0:
		field = "MigrateParams.KDF.Parallel"
	default:
		return nil
	}
	return &errs.Error{Kind: ErrFIPSNotApproved,
		Detail: field + ": MigrateToFIPS writes PBKDF2 keyslots only; Argon2 is not FIPS-approved"}
}
