// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/fips"
)

// foreignDigestVolume is TestMigrateToFIPSRefusesADigestThatDoesNotAttestTheKey's
// fixture: a second, PBKDF2-SHA1 digest that attests some other key.
func foreignDigestVolume(t *testing.T) string {
	t.Helper()
	device := newImage(t, "foreign-digest.img")
	formatWithLibrary(t, device)
	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	stray := *metadata.Digests["0"]
	stray.Hash = "sha1"
	stray.Iterations = 1000
	stray.Digest = encodeBase64(bytes.Repeat([]byte{0x5a}, 20))
	metadata.Digests["1"] = &stray
	hdr.SequenceID++
	if err := writeHeaderUnvalidated(device, hdr, metadata); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}
	return device
}

// unboundDataSegmentVolume is TestMigrateToFIPSRefusesWhenNoKeyslotHoldsTheVolumeKey's
// fixture: the data segment is attested only by a digest no keyslot is bound to.
func unboundDataSegmentVolume(t *testing.T) string {
	t.Helper()
	device := argon2Volume(t, "unbound-all.img", false)
	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	unbound := *metadata.Digests["0"]
	unbound.Keyslots = []string{}
	metadata.Digests["1"] = &unbound
	metadata.Digests["0"].Segments = []string{}
	hdr.SequenceID++
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}
	return device
}

// TestMigrateToFIPSRefusalsAreClassified: a migration the policy refuses is
// ErrFIPSMigration, never ErrIO. Its causes were bare sentinels, or the Kind
// of an *errs.Error, that errAt did not recognize, so a refusal to run in a
// FIPS process read as an I/O failure.
func TestMigrateToFIPSRefusalsAreClassified(t *testing.T) {
	defer parallel(t)()
	for _, tc := range []struct {
		name  string
		image func(t *testing.T) string
		fips  bool
		cause error
	}{
		{name: "in a FIPS process", image: func(t *testing.T) string { return argon2Volume(t, "underfips.img", false) }, fips: true, cause: errFIPSMigrationUnderFIPS},
		{name: "a digest that does not attest the key", image: foreignDigestVolume, cause: errFIPSMigrationDigest},
		{name: "no keyslot holds the volume key", image: unboundDataSegmentVolume, cause: errFIPSMigrationUnboundKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.image(t)
			sys := testVolumeSys()
			if tc.fips {
				sys.fipsMode = func() fips.Mode { return true }
			}
			// A FIPS process refuses every migration before it reads anything.
			cause := tc.cause
			if sys.fipsMode() {
				cause = errFIPSMigrationUnderFIPS
			}

			v, err := Open(context.Background(), path, withTestSys(sys))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer func() { _ = v.Close() }()
			pass := newPassphraseEnclave(t, string(migrationPassphrase))
			defer func() { _ = pass.Destroy() }()
			_, err = v.MigrateToFIPS(context.Background(), pass, MigrateParams{})

			requireKindAndOp(t, tc.name, err, ErrFIPSMigration, "Volume.MigrateToFIPS", path)
			if errors.Is(err, ErrIO) {
				t.Errorf("%s: %v is ErrIO", tc.name, err)
			}
			var merr *FIPSMigrationError
			if !errors.Is(err, cause) || !errors.As(err, &merr) {
				t.Errorf("%s: %v is not a *FIPSMigrationError for %v", tc.name, err, cause)
			}
		})
	}
}
