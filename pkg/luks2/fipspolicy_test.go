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
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// The FIPS 140-3 policy branches, run in-process.
//
// FIPS mode is fixed at process start, so in the ordinary unit run every branch
// behind fipsMode would otherwise execute only in the child processes of
// fipsimport_cryptsetup_test.go and in CI's full-tier FIPS job: a regression in how
// a refusal is CLASSIFIED -- import needed, or damage -- would go unseen until
// then. These tests force the policy on, by passing a forced fipsMode into the
// sys-accepting core the operation under test wraps, and pin each
// classification. What the Go Cryptographic Module itself enforces under
// GODEBUG=fips140=only is not simulated here; the child-process tests prove it.
// In a process already in FIPS mode, forcing is a no-op and the tests assert the
// same thing.

// forceFIPSPolicy returns a fipsMode func that reports the package's FIPS
// policy as on.
func forceFIPSPolicy(t *testing.T) func() fips.Mode {
	t.Helper()

	return func() fips.Mode { return true }
}

// forceNonFIPSPolicy is the policy source of a process outside FIPS mode,
// whatever mode the test process is in, for tests of the parameter checks that
// sit behind the FIPS gate (the argon2 cost floors) and so are unreachable
// when the process itself is in FIPS mode.
func forceNonFIPSPolicy(t *testing.T) func() fips.Mode {
	t.Helper()

	return func() fips.Mode { return false }
}

// writeFixture rewrites device's header after mutate has changed its metadata.
func writeFixture(t *testing.T, device string, mutate func(*header.Metadata)) {
	t.Helper()

	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	mutate(metadata)
	hdr.SequenceID++
	if err := writeHeaderUnvalidated(device, hdr, metadata); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}
}

// sha1Digest relabels digest 0 as PBKDF2-SHA1 over a value it never has to
// compute: under FIPS the refusal comes before any derivation.
func sha1Digest(m *header.Metadata) {
	d := m.Digests["0"]
	d.Hash, d.Iterations = "sha1", 1000
	d.Digest = encodeBase64(bytes.Repeat([]byte{0x5a}, 20))
}

// argon2DigestLabel relabels digest 0 as Argon2id, likewise never derived.
func argon2DigestLabel(m *header.Metadata) {
	cost, memory, cpus := header.MinArgon2Time, minArgon2MemoryKB, 1
	d := m.Digests["0"]
	d.Type, d.Hash, d.Iterations = kdfTypeArgon2id, "", 0
	d.Time, d.Memory, d.CPUs = &cost, &memory, &cpus
	d.Digest = encodeBase64(bytes.Repeat([]byte{0x5a}, argon2DigestLen))
}

// TestFIPSPolicyClassifiesWhatItRefuses: under the FIPS policy, a volume that
// is unopenable ONLY because of its KDFs is reported as needing the import,
// naming each keyslot and digest; one that is also damaged, or whose digest is
// malformed, is reported as damaged.
func TestFIPSPolicyClassifiesWhatItRefuses(t *testing.T) {
	cases := []struct {
		name     string
		build    func(t *testing.T, device string)
		keyslots []NonApprovedKDF
		digests  []NonApprovedKDF
		// damaged: the refusal must NOT be an import; wantErr is what it is.
		damaged bool
		wantErr error
	}{
		{
			name: "argon2 keyslot",
			build: func(t *testing.T, device string) {
				writeFixture(t, device, func(m *header.Metadata) {
					cost, memory, cpus := header.MinArgon2Time, minArgon2MemoryKB, 1
					kdf := m.Keyslots["0"].KDF
					kdf.Type, kdf.Hash, kdf.Iterations = kdfTypeArgon2id, "", nil
					kdf.Time, kdf.Memory, kdf.CPUs = &cost, &memory, &cpus
				})
			},
			keyslots: []NonApprovedKDF{{ID: 0, Type: kdfTypeArgon2id}},
		},
		{
			name:    "pbkdf2-sha1 digest",
			build:   func(t *testing.T, device string) { writeFixture(t, device, sha1Digest) },
			digests: []NonApprovedKDF{{ID: 0, Type: kdfTypePBKDF2, Hash: "sha1"}},
		},
		{
			name:    "argon2 digest",
			build:   func(t *testing.T, device string) { writeFixture(t, device, argon2DigestLabel) },
			digests: []NonApprovedKDF{{ID: 0, Type: kdfTypeArgon2id}},
		},
		{
			name: "sha1 digest that is not base64",
			build: func(t *testing.T, device string) {
				writeFixture(t, device, func(m *header.Metadata) {
					sha1Digest(m)
					m.Digests["0"].Digest = "!!! not base64 !!!"
				})
			},
			damaged: true,
			wantErr: ErrInvalidHeader,
		},
		{
			name: "argon2 keyslot with a salt that is not base64",
			build: func(t *testing.T, device string) {
				writeFixture(t, device, func(m *header.Metadata) {
					cost, memory, cpus := header.MinArgon2Time, minArgon2MemoryKB, 1
					kdf := m.Keyslots["0"].KDF
					kdf.Type, kdf.Hash, kdf.Iterations = kdfTypeArgon2id, "", nil
					kdf.Time, kdf.Memory, kdf.CPUs = &cost, &memory, &cpus
					kdf.Salt = "!!! not base64 !!!"
				})
			},
			damaged: true,
			wantErr: ErrKeyslotNotFound,
		},
		{
			name: "argon2 keyslot beside a damaged pbkdf2 keyslot",
			build: func(t *testing.T, device string) {
				writeFixture(t, device, func(m *header.Metadata) {
					damaged := *m.Keyslots["0"]
					area := *damaged.Area
					area.Encryption = "serpent-xts-plain64"
					damaged.Area = &area
					m.Keyslots["1"] = &damaged
					m.Digests["0"].Keyslots = append(m.Digests["0"].Keyslots, "1")
					cost, memory, cpus := header.MinArgon2Time, minArgon2MemoryKB, 1
					kdf := *m.Keyslots["0"].KDF
					kdf.Type, kdf.Hash, kdf.Iterations = kdfTypeArgon2id, "", nil
					kdf.Time, kdf.Memory, kdf.CPUs = &cost, &memory, &cpus
					m.Keyslots["0"].KDF = &kdf
				})
			},
			damaged: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			device := newImage(t, "fips-policy.img")
			formatWithLibrary(t, device)
			tc.build(t, device)
			sys := testVolumeSys()
			sys.fipsMode = forceFIPSPolicy(t)

			err := testKeyForTestWithSys(device, migrationPassphrase, sys)
			if tc.damaged {
				if err == nil || errors.Is(err, ErrFIPSImportRequired) {
					t.Fatalf("a damaged volume was reported as %v, want a damage error and not the import", err)
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Fatalf("got %v, want %v", err, tc.wantErr)
				}
				return
			}
			assertImportRequired(t, err, device, tc.keyslots, tc.digests)
		})
	}
}

// TestFIPSPolicyRefusesTheMigration: MigrateToFIPS refuses under the FIPS
// policy before touching the device.
func TestFIPSPolicyRefusesTheMigration(t *testing.T) {
	device := newImage(t, "fips-refusal-forced.img")
	formatWithLibrary(t, device)
	before := fileDigest(t, device)

	sys := testVolumeSys()
	sys.fipsMode = forceFIPSPolicy(t)

	_, err := migrateToFIPSAt(context.Background(), device, migrationPassphrase, cheapMigration(), sys)
	if !errors.Is(err, errFIPSMigrationUnderFIPS) {
		t.Fatalf("MigrateToFIPS under the forced FIPS policy: got %v, want errFIPSMigrationUnderFIPS", err)
	}
	var merr *FIPSMigrationError
	if !errors.As(err, &merr) || merr.State != fipsStateUntouched {
		t.Fatalf("the refusal must be a *FIPSMigrationError stating the volume is untouched, got %#v", err)
	}
	if after := fileDigest(t, device); after != before {
		t.Fatal("MigrateToFIPS refused under the forced policy and still changed the device")
	}
}

// TestFIPSPolicyGates: the two KDF gates refuse under the policy and pass
// outside it.
func TestFIPSPolicyGates(t *testing.T) {
	if _, err := getPBKDF2HashFunc("sha1", fips.Probe); err != nil && !fips.Probe() {
		t.Fatalf("outside FIPS mode PBKDF2-SHA1 is available for legacy headers, got %v", err)
	}
	if err := fips.Probe().RequireKDF(kdfTypeArgon2id); err != nil && !fips.Probe() {
		t.Fatalf("outside FIPS mode Argon2id is allowed, got %v", err)
	}

	forced := forceFIPSPolicy(t)
	if _, err := getPBKDF2HashFunc("sha1", forced); !errors.Is(err, ErrFIPSNotApproved) {
		t.Fatalf("PBKDF2-SHA1 under the FIPS policy: got %v, want ErrFIPSNotApproved", err)
	}
	if err := forced().RequireKDF(kdfTypeArgon2id); !errors.Is(err, ErrFIPSNotApproved) {
		t.Fatalf("Argon2id under the FIPS policy: got %v, want ErrFIPSNotApproved", err)
	}
	if _, err := getPBKDF2HashFunc("sha256", forced); err != nil {
		t.Fatalf("PBKDF2-SHA256 under the FIPS policy: %v", err)
	}
}

// TestKeyslotRefusedByFIPSIsComputed pins the predicate's every outcome: it is
// true only when substituting approved stand-ins for exactly the refused KDFs
// makes the screen pass.
func TestKeyslotRefusedByFIPSIsComputed(t *testing.T) {
	device := newImage(t, "fips-predicate.img")
	formatWithLibrary(t, device)
	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	approved := metadata.Keyslots["0"]
	digests := metadata.Digests

	argon2 := func(salt string) *header.Keyslot {
		ks := *approved
		cost, memory, cpus := header.MinArgon2Time, minArgon2MemoryKB, 1
		ks.KDF = &header.KDF{Type: kdfTypeArgon2id, Salt: salt, Time: &cost, Memory: &memory, CPUs: &cpus}
		return &ks
	}
	withDigest := func(mutate func(*header.Digest)) map[string]*header.Digest {
		d := *digests["0"]
		mutate(&d)
		return map[string]*header.Digest{"0": &d}
	}
	badCipher := *approved
	area := *approved.Area
	area.Encryption = "serpent-xts-plain64"
	badCipher.Area = &area
	reencrypt := *approved
	reencrypt.Type = "reencrypt"

	cases := []struct {
		name    string
		keyslot *header.Keyslot
		digests map[string]*header.Digest
		want    bool
	}{
		{"nil keyslot", nil, digests, false},
		{"not a luks2 keyslot", &reencrypt, digests, false},
		{"approved and well formed: refused later, not by FIPS", approved, digests, false},
		{"argon2 keyslot", argon2(approved.KDF.Salt), digests, true},
		{"argon2 keyslot with a malformed salt", argon2("!!! not base64 !!!"), digests, false},
		{"approved keyslot, sha1 digest", approved, withDigest(func(d *header.Digest) { sha1Digest(&header.Metadata{Digests: map[string]*header.Digest{"0": d}}) }), true},
		{"approved keyslot, sha1 digest not base64", approved, withDigest(func(d *header.Digest) {
			sha1Digest(&header.Metadata{Digests: map[string]*header.Digest{"0": d}})
			d.Digest = "!!! not base64 !!!"
		}), false},
		{"approved keyslot with a cipher nothing implements", &badCipher, digests, false},
	}

	forced := forceFIPSPolicy(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := keyslotRefusedByFIPS("0", tc.keyslot, tc.digests, forced); got != tc.want {
				t.Fatalf("keyslotRefusedByFIPS = %v, want %v", got, tc.want)
			}
		})
	}

	// Outside the policy nothing is a FIPS refusal.
	notFIPS := func() fips.Mode { return false }
	if keyslotRefusedByFIPS("0", argon2(approved.KDF.Salt), digests, notFIPS) {
		t.Fatal("outside FIPS mode an Argon2 keyslot was classified as a FIPS refusal")
	}
}
