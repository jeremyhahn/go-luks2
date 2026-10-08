// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// testVolumeSys is defaultVolumeSys with the cost floor and the digest count
// lowered to LUKS2's own minimum, so keyslots whose cost is not under test stay as cheap as they were
// before a calibrated count was held to the OWASP floor (#249, A8). Tests
// about the floor use defaultVolumeSys explicitly.
func testVolumeSys() volumeSys {
	sys := defaultVolumeSys()
	sys.calibratedCountFloor = func(string, keyslotCostPolicy) int { return minPBKDF2Iterations }
	sys.digestIterationsFor = pinDigestIterations(minPBKDF2Iterations)
	return sys
}

// createKDFStrict is createKDF under the caller-supplied policy, which is the
// only one a public entry point can select, at the cheap floor.
func createKDFStrict(opts formatOptionsForTest, keySize int) (*header.KDF, error) {
	return createKDFStrictOn(testVolumeSys(), opts, keySize)
}

// createKDFStrictAtProductionFloor is createKDFStrict at the production floor,
// for tests whose subject is that floor.
func createKDFStrictAtProductionFloor(opts formatOptionsForTest, keySize int) (*header.KDF, error) {
	return createKDFStrictOn(defaultVolumeSys(), opts, keySize)
}

func createKDFStrictOn(sys volumeSys, opts formatOptionsForTest, keySize int) (*header.KDF, error) {
	return createKDF(opts, keySize, callerSuppliedCredential, sys.fipsMode, sys.calibratedCountFloor, sys.cryptoRand)
}

// deriveKeyPlain is the derivation with its result left in an ordinary
// slice, under the production sys's FIPS mode: the shape a test compares
// against a known answer. The package itself never derives outside an
// enclave.
func deriveKeyPlain(passphrase []byte, k *header.KDF, keySize int) ([]byte, error) {
	if k == nil {
		return nil, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "no KDF object"}
	}
	key, err := kdfDeriver(defaultVolumeSys()).DerivePlain(context.Background(), passphrase, toKDFParams(k), keySize)
	return key, reclassifyUnsupportedKDF(err)
}

// cheapOpts puts testVolumeSys ahead of opts, so an option in opts that sets its
// own sys still wins.
func cheapOpts(opts []Option) []Option {
	return append([]Option{withTestSys(testVolumeSys())}, opts...)
}

// addKeyForTest adds a keyslot, as a caller-supplied credential, and returns
// the slot it used (-1 on error).
func addKeyForTest(device string, existingPassphrase, newPassphrase []byte, opts *addKeyOptionsForTest) (int, error) {
	return addKeyWithPolicy(context.Background(), device, existingPassphrase, newPassphrase, opts, callerSuppliedCredential, testVolumeSys())
}

func changeKeyForTest(device string, oldPassphrase, newPassphrase []byte, keyslot int) error {
	return changeKeyWithSys(device, oldPassphrase, newPassphrase, keyslot, testVolumeSys())
}

func migrateToFIPSForTest(device string, passphrase []byte, opts *fipsMigrationOptionsForTest) (*fipsMigrationResultForTest, error) {
	return migrateToFIPSAt(context.Background(), device, passphrase, opts, testVolumeSys())
}

// migrateToFIPSAt runs migrateToFIPS on a device path, locked and pinned by
// lockKeyslotDevice: the path-based shape the migration suites drive, where
// (*Volume).MigrateToFIPS locks the descriptor its Open pinned.
func migrateToFIPSAt(ctx context.Context, device string, passphrase []byte, opts *fipsMigrationOptionsForTest, sys volumeSys) (*fipsMigrationResultForTest, error) {
	return migrateToFIPS(ctx, device, passphrase, opts, sys, func() (*keyslotDevice, func(), error) {
		if err := validateDevicePath(device); err != nil {
			return nil, nil, err
		}
		lock, dev, err := lockKeyslotDevice(ctx, device, sys)
		if err != nil {
			return nil, nil, err
		}
		return dev, func() { _ = lock.Release() }, nil
	})
}

// formatForTest formats with testVolumeSys.
func formatForTest(opts formatOptionsForTest) error {
	return formatWithSys(opts, testVolumeSys())
}
