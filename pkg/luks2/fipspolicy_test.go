// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"crypto/fips140"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/errs"
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
	defer parallel(t)()
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
	// Eight bytes: the name is approved, the salt is under strict mode's
	// 128-bit floor, so derivation is refused although the screen passes.
	const shortSalt = "c2hvcnRzYWw="
	shortSaltKeyslot := *approved
	shortKDF := *approved.KDF
	shortKDF.Salt = shortSalt
	shortSaltKeyslot.KDF = &shortKDF

	shortSaltDigests := withDigest(func(d *header.Digest) { d.Salt = shortSalt })
	mixed := &header.Metadata{Digests: map[string]*header.Digest{"0": func() *header.Digest { d := *digests["0"]; return &d }()}}
	mixedShortSaltAndMalformedDigests(mixed)
	mixedDigests := mixed.Digests
	// The failures strict mode raises for a short salt: the passphrase
	// derivation's invalid argument, and the digest check finding nothing it
	// could evaluate. errIO is a failure no FIPS gate raises.
	derivationRefused := &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "crypto pbkdf2", Err: errors.New("salt shorter than 128 bits")}
	digestsUnusable := unverifiableKeyslotError("0", 1)
	errIO := errors.New("injected: input/output error")

	cases := []struct {
		name    string
		keyslot *header.Keyslot
		digests map[string]*header.Digest
		failure error
		want    bool
	}{
		{"nil keyslot", nil, digests, errIO, false},
		{"not a luks2 keyslot", &reencrypt, digests, errIO, false},
		{"approved and well formed: refused later, not by FIPS", approved, digests, errIO, false},
		{"argon2 keyslot", argon2(approved.KDF.Salt), digests, nil, true},
		{"argon2 keyslot with a malformed salt", argon2("!!! not base64 !!!"), digests, nil, false},
		{"approved keyslot, sha1 digest", approved, withDigest(func(d *header.Digest) { sha1Digest(&header.Metadata{Digests: map[string]*header.Digest{"0": d}}) }), nil, true},
		{"approved keyslot, sha1 digest not base64", approved, withDigest(func(d *header.Digest) {
			sha1Digest(&header.Metadata{Digests: map[string]*header.Digest{"0": d}})
			d.Digest = "!!! not base64 !!!"
		}), nil, false},
		{"approved keyslot with a cipher nothing implements", &badCipher, digests, nil, false},
		{"pbkdf2 keyslot with a short salt", &shortSaltKeyslot, digests, derivationRefused, true},
		{"pbkdf2 keyslot with a short salt, failed for another reason", &shortSaltKeyslot, digests, errIO, false},
		{"approved keyslot, pbkdf2 digest with a short salt", approved, shortSaltDigests, digestsUnusable, true},
		{"approved keyslot, pbkdf2 digest with a short salt, area read failed", approved, shortSaltDigests, errIO, false},
		{"approved keyslot, pbkdf2 digest with a short salt, derivation-shaped failure", approved, shortSaltDigests, derivationRefused, false},
		{"approved keyslot, short-salt digest beside a malformed one", approved, mixedDigests, unverifiableKeyslotError("0", 2), false},
	}

	forced := forceFIPSPolicy(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := keyslotRefusedByFIPS("0", tc.keyslot, tc.digests, forced, tc.failure); got != tc.want {
				t.Fatalf("keyslotRefusedByFIPS = %v, want %v", got, tc.want)
			}
		})
	}

	// Outside the policy nothing is a FIPS refusal.
	notFIPS := func() fips.Mode { return false }
	if keyslotRefusedByFIPS("0", argon2(approved.KDF.Salt), digests, notFIPS, nil) {
		t.Fatal("outside FIPS mode an Argon2 keyslot was classified as a FIPS refusal")
	}
}

// areaReadFailure is a device whose every read fails: the header is already
// parsed, so the first read it sees is the keyslot area's.
type areaReadFailure struct{ err error }

func (r areaReadFailure) ReadAt([]byte, int64) (int, error) { return 0, r.err }

// A keyslot whose only FIPS shortfall is a short-salt digest, and whose area
// cannot be read, failed on the read: strict mode never reached the digest.
// The read failure is what the caller gets, not an import request that says
// the volume is intact.
func TestShortSaltDigestKeepsTheAreaReadFailure(t *testing.T) {
	device := newImage(t, "fips-short-salt-eio.img")
	formatWithLibrary(t, device)
	writeFixture(t, device, func(m *header.Metadata) { m.Digests["0"].Salt = "c2hvcnRzYWw=" })
	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	sys := testVolumeSys()
	sys.fipsMode = forceFIPSPolicy(t)
	errInjected := errors.New("injected: the keyslot area read failed")
	_, _, err = getMasterKeySlot(context.Background(), areaReadFailure{errInjected}, device, migrationPassphrase, metadata, []string{"0"}, sys)
	if !errors.Is(err, errInjected) {
		t.Fatalf("a failed area read behind a short-salt digest: got %v, want the read failure", err)
	}
	var importRequired *FIPSImportRequiredError
	if errors.Is(err, ErrFIPSImportRequired) || errors.As(err, &importRequired) {
		t.Fatalf("a failed area read was reported as a FIPS import: %v", err)
	}
}

// malformedDigestCopy adds digest 1: a copy of digest 0, covering the same
// keyslots and segments, whose value is not base64.
func malformedDigestCopy(m *header.Metadata) {
	malformed := *m.Digests["0"]
	malformed.Keyslots = append([]string(nil), m.Digests["0"].Keyslots...)
	malformed.Segments = append([]string(nil), m.Digests["0"].Segments...)
	malformed.Digest = "!!! not base64 !!!"
	m.Digests["1"] = &malformed
}

// mixedShortSaltAndMalformedDigests gives keyslot 0 two covering digests: the
// original with a salt under strict mode's 128-bit floor, which is well formed,
// and a copy whose value is not base64, which is damage.
func mixedShortSaltAndMalformedDigests(m *header.Metadata) {
	malformedDigestCopy(m)
	m.Digests["0"].Salt = "c2hvcnRzYWw="
}

// A short-salt digest is a FIPS refusal only while it is all that stands
// between the keyslot and a verdict. Beside a covering digest that is
// malformed, the header is damaged, and that is what unlock reports: an import
// could not repair it, and the migration it would recommend refuses the volume.
func TestMalformedDigestBesideShortSaltKeepsTheHeaderError(t *testing.T) {
	device := newImage(t, "fips-short-salt-malformed.img")
	formatWithLibrary(t, device)
	if fips140.Enabled() {
		// Strict mode refuses the short salt before any comparison, so the
		// value digest 0 carries is never read.
		writeFixture(t, device, mixedShortSaltAndMalformedDigests)
	} else {
		// A short-salt digest that attests the volume key, as a volume
		// cryptsetup wrote would carry, so the import path gets past unlock.
		if err := weakenForStrictFIPS(device, migrationPassphrase, ""); err != nil {
			t.Fatalf("weakening the fixture failed: %v", err)
		}
		writeFixture(t, device, malformedDigestCopy)
	}
	if _, _, err := readHeaderForTest(device); err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	sys := testVolumeSys()
	sys.fipsMode = forceFIPSPolicy(t)
	err := testKeyForTestWithSys(device, migrationPassphrase, sys)
	if !fips140.Enabled() {
		// Outside strict mode the short-salt digest is evaluated, and it
		// attests the key.
		if err != nil {
			t.Fatalf("unlock outside strict mode through the short-salt digest: %v", err)
		}
	} else {
		var importRequired *FIPSImportRequiredError
		if errors.Is(err, ErrFIPSImportRequired) || errors.As(err, &importRequired) {
			t.Fatalf("a malformed digest beside a short-salt one was reported as a FIPS import: %v", err)
		}
		if !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("unlock under the forced FIPS policy: got %v, want ErrInvalidHeader", err)
		}
		// The import it would have recommended cannot run in this process.
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	// The import path refuses the same volume with the header fault, and
	// leaves it untouched.
	before := fileDigest(t, device)
	sys = testVolumeSys()
	sys.fipsMode = forceNonFIPSPolicy(t)
	_, err = migrateToFIPSAt(context.Background(), device, migrationPassphrase, cheapMigration(), sys)
	if !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("MigrateToFIPS on the same volume: got %v, want ErrInvalidHeader", err)
	}
	if after := fileDigest(t, device); after != before {
		t.Fatal("MigrateToFIPS refused a damaged header and still changed the device")
	}
}

// TestMalformedDigestBesideRefusedKeyslotKDFKeepsTheHeaderError pins the
// classification of a keyslot the policy refuses at its OWN KDF -- Argon2 under
// the FIPS policy, a PBKDF2 salt too short for strict mode -- while one of the
// two digests attesting it is malformed. The keyslot refusal is not damage, but
// the malformed digest is, and it is what unlock reports: ErrInvalidHeader, not
// the policy's sentinel. MigrateToFIPS refuses the same volume at planning with
// the same error and writes nothing.
func TestMalformedDigestBesideRefusedKeyslotKDFKeepsTheHeaderError(t *testing.T) {
	cases := []struct {
		name string
		kdf  func(m *header.Metadata) *header.KDF
		// strictOnly: the keyslot KDF is refused only by strict mode, so
		// outside it the forced FIPS policy opens the volume.
		strictOnly bool
	}{
		{
			name: "argon2 keyslot",
			kdf: func(m *header.Metadata) *header.KDF {
				cost, memory, cpus := header.MinArgon2Time, minArgon2MemoryKB, 1
				return &header.KDF{Type: kdfTypeArgon2id, Salt: m.Keyslots["0"].KDF.Salt, Time: &cost, Memory: &memory, CPUs: &cpus}
			},
		},
		{
			name:       "short-salt keyslot",
			kdf:        func(*header.Metadata) *header.KDF { return shortSaltKDF() },
			strictOnly: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			device := newImage(t, "fips-refused-keyslot-malformed.img")
			formatWithLibrary(t, device)
			hdr, metadata, err := readHeaderForTest(device)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			kdf := tc.kdf(metadata)
			if fips140.Enabled() {
				// Strict mode refuses the keyslot KDF before a byte of the
				// area is decrypted, so the area need not match it.
				metadata.Keyslots["0"].KDF = kdf
			} else {
				// Outside strict mode the keyslot is re-wrapped under the
				// refused KDF, as a volume cryptsetup wrote would be, so the
				// import path gets past unlock to its planning.
				masterKey, err := getMasterKey(device, migrationPassphrase, metadata, testVolumeSys())
				if err != nil {
					t.Fatalf("opening the fixture failed: %v", err)
				}
				err = rewrapKeyslotInPlace(device, metadata.Keyslots["0"], masterKey, migrationPassphrase, kdf)
				if destroyErr := masterKey.Destroy(); destroyErr != nil {
					t.Fatalf("releasing the volume key failed: %v", destroyErr)
				}
				if err != nil {
					t.Fatalf("re-wrapping the keyslot failed: %v", err)
				}
			}
			// Keyslot 0 is now attested by a well-formed digest and a
			// malformed copy of it.
			malformedDigestCopy(metadata)
			hdr.SequenceID++
			if err := writeHeaderUnvalidated(device, hdr, metadata); err != nil {
				t.Fatalf("writing the fixture failed: %v", err)
			}

			sys := testVolumeSys()
			sys.fipsMode = forceFIPSPolicy(t)
			err = testKeyForTestWithSys(device, migrationPassphrase, sys)
			switch {
			case tc.strictOnly && !fips140.Enabled():
				// The salt is derived outside strict mode, and the
				// well-formed digest attests the key.
				if err != nil {
					t.Fatalf("unlock outside strict mode through the short-salt keyslot: %v", err)
				}
			default:
				var importRequired *FIPSImportRequiredError
				if errors.Is(err, ErrFIPSImportRequired) || errors.As(err, &importRequired) {
					t.Fatalf("a malformed digest beside a refused keyslot KDF was reported as a FIPS import: %v", err)
				}
				if !errors.Is(err, ErrInvalidHeader) {
					t.Fatalf("unlock under the forced FIPS policy: got %v, want ErrInvalidHeader", err)
				}
			}

			if fips140.Enabled() {
				// The import it would have recommended cannot run in this
				// process.
				assertMigrationRefusedUnderFIPS(t)
				return
			}
			// The import path refuses the same volume at planning with the
			// header fault, and leaves it untouched.
			before := fileDigest(t, device)
			sys = testVolumeSys()
			sys.fipsMode = forceNonFIPSPolicy(t)
			_, err = migrateToFIPSAt(context.Background(), device, migrationPassphrase, cheapMigration(), sys)
			if !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("MigrateToFIPS on the same volume: got %v, want ErrInvalidHeader", err)
			}
			if after := fileDigest(t, device); after != before {
				t.Fatal("MigrateToFIPS refused a damaged header and still changed the device")
			}
		})
	}
}

// TestMalformedKeyslotKDFIsHeaderDamageUnderFIPS pins that a keyslot KDF
// whose salt is not base64 is reported as the header damage it is under the
// FIPS policy, as outside it, whichever KDF it names: an Argon2 KDF the policy
// refuses is screened for structure before the policy judges it, so the
// unlock error is ErrInvalidHeader and never ErrFIPSNotApproved.
func TestMalformedKeyslotKDFIsHeaderDamageUnderFIPS(t *testing.T) {
	cases := []struct {
		name string
		kdf  func(m *header.Metadata) *header.KDF
	}{
		{
			name: "argon2id keyslot",
			kdf: func(*header.Metadata) *header.KDF {
				cost, memory, cpus := header.MinArgon2Time, minArgon2MemoryKB, 1
				return &header.KDF{Type: kdfTypeArgon2id, Salt: "!!! not base64 !!!", Time: &cost, Memory: &memory, CPUs: &cpus}
			},
		},
		{
			name: "argon2i keyslot",
			kdf: func(*header.Metadata) *header.KDF {
				cost, memory, cpus := header.MinArgon2Time, minArgon2MemoryKB, 1
				return &header.KDF{Type: kdfTypeArgon2i, Salt: "!!! not base64 !!!", Time: &cost, Memory: &memory, CPUs: &cpus}
			},
		},
		{
			name: "sha1 pbkdf2 keyslot",
			kdf: func(m *header.Metadata) *header.KDF {
				kdf := *m.Keyslots["0"].KDF
				kdf.Hash, kdf.Salt = "sha1", "!!! not base64 !!!"
				return &kdf
			},
		},
		{
			name: "approved pbkdf2 keyslot",
			kdf: func(m *header.Metadata) *header.KDF {
				kdf := *m.Keyslots["0"].KDF
				kdf.Salt = "!!! not base64 !!!"
				return &kdf
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			device := newImage(t, "fips-malformed-keyslot-kdf.img")
			formatWithLibrary(t, device)
			hdr, metadata, err := readHeaderForTest(device)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			// The screen refuses the KDF before any derivation, so the area
			// need not match it.
			metadata.Keyslots["0"].KDF = tc.kdf(metadata)
			hdr.SequenceID++
			if err := writeHeaderUnvalidated(device, hdr, metadata); err != nil {
				t.Fatalf("writing the fixture failed: %v", err)
			}

			sys := testVolumeSys()
			sys.fipsMode = forceFIPSPolicy(t)
			err = testKeyForTestWithSys(device, migrationPassphrase, sys)
			if errors.Is(err, ErrFIPSNotApproved) || errors.Is(err, ErrFIPSImportRequired) {
				t.Fatalf("a malformed keyslot KDF was reported as a FIPS refusal: %v", err)
			}
			if !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("unlock under the forced FIPS policy: got %v, want ErrInvalidHeader", err)
			}

			if fips140.Enabled() {
				assertMigrationRefusedUnderFIPS(t)
				return
			}
			// Outside the policy it is the same damage, and the import path
			// refuses it without writing.
			sys = testVolumeSys()
			sys.fipsMode = forceNonFIPSPolicy(t)
			if err := testKeyForTestWithSys(device, migrationPassphrase, sys); !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("unlock outside the FIPS policy: got %v, want ErrInvalidHeader", err)
			}
			before := fileDigest(t, device)
			_, err = migrateToFIPSAt(context.Background(), device, migrationPassphrase, cheapMigration(), sys)
			if !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("MigrateToFIPS on the same volume: got %v, want ErrInvalidHeader", err)
			}
			if after := fileDigest(t, device); after != before {
				t.Fatal("MigrateToFIPS refused a damaged header and still changed the device")
			}
		})
	}
}
