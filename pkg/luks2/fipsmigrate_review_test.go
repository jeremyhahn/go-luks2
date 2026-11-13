// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"crypto/fips140"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// Regressions for the review of #84's first round: a genuine Argon2 digest is
// evaluated and migrated, a malformed digest is reported as damage rather than
// as a volume needing import, and the migration never wipes an area that is
// not keyslot space.

// argon2Digest replaces digest "0" of device with an Argon2id digest over the
// volume key passphrase recovers: the shape a foreign writer that put Argon2
// in its digest would leave. hash is the digest's declared hash, "" for none.
func argon2Digest(t *testing.T, device string, hash string) {
	t.Helper()

	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	mk, err := getMasterKey(device, migrationPassphrase, metadata, testVolumeSys())
	if err != nil {
		t.Fatalf("getMasterKey failed: %v", err)
	}
	defer mustDestroy(t, mk)

	// The lowest Argon2 cost the reader accepts: this is a foreign header's
	// digest, which nothing here writes, and every unlock of the fixture
	// derives through it -- under -race, at the package's budget (ci.yml).
	cost, memory, cpus := header.MinArgon2Time, fixtureArgon2MemoryKB, 1
	digest := metadata.Digests["0"]
	kdf := &header.KDF{Type: kdfTypeArgon2id, Salt: digest.Salt, Time: &cost, Memory: &memory, CPUs: &cpus}
	derived, err := deriveKeySecret(context.Background(), mk, kdf, argon2DigestLen, testVolumeSys())
	if err != nil {
		t.Fatalf("deriving the argon2 digest failed: %v", err)
	}
	defer mustDestroy(t, derived)

	digest.Type, digest.Hash, digest.Iterations = kdfTypeArgon2id, hash, 0
	digest.Time, digest.Memory, digest.CPUs = &cost, &memory, &cpus
	if err := secret.Borrow("test digest", derived, func(b []byte) error {
		digest.Digest = encodeBase64(b)
		return nil
	}); err != nil {
		t.Fatalf("borrow: %v", err)
	}
	hdr.SequenceID++
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		t.Fatalf("writing the argon2 digest failed: %v", err)
	}

	// The fixture must be what it claims: an Argon2 digest on disk, with its
	// cost members, that attests the key.
	raw := readJSONArea(t, device)
	for _, member := range []string{`"type":"argon2id"`, `"time":`, `"memory":`, `"cpus":`} {
		if !bytes.Contains(raw, []byte(member)) {
			t.Fatalf("the fixture's JSON lacks %s: %s", member, raw)
		}
	}
}

// fixtureArgon2MemoryKB is the Argon2 memory of foreign fixtures this package
// derives through but never writes: cryptsetup's own minimum, 32 KiB, which
// the reader accepts (header.MinArgon2Memory) and Format would refuse.
const fixtureArgon2MemoryKB = 32

// readJSONArea returns the primary header's JSON area, trimmed of padding.
func readJSONArea(t *testing.T, device string) []byte {
	t.Helper()

	hdr, _, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	area, err := header.HeaderAreaSize(hdr)
	if err != nil {
		t.Fatalf("header area size: %v", err)
	}
	// The JSON area alone, not the 64 MiB image it sits in.
	f, err := os.Open(device) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("read %s: %v", device, err)
	}
	defer func() { _ = f.Close() }()
	b := make([]byte, area-header.HeaderSize)
	if _, err := f.ReadAt(b, header.HeaderSize); err != nil {
		t.Fatalf("read %s: %v", device, err)
	}
	return bytes.TrimRight(b, "\x00")
}

// TestMigrateToFIPSMigratesAnArgon2Digest is the digest trap in its sharpest
// form, which #84 names explicitly: a foreign volume whose Argon2 reaches past
// its keyslots into the digest. Both have to be migrated -- a volume whose
// keyslots are PBKDF2 and whose digest is Argon2 fails under FIPS exactly as an
// unmigrated one does -- and the digest must come out PBKDF2 with no Argon2
// cost left declared on it.
func TestMigrateToFIPSMigratesAnArgon2Digest(t *testing.T) {
	defer parallel(t)()
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	for _, hash := range []string{"", "sha256"} {
		t.Run("hash="+strconv.Quote(hash), func(t *testing.T) {
			device := argon2Volume(t, "argon2-digest.img", false)
			fillDataArea(t, device)
			argon2Digest(t, device, hash)
			keyBefore := volumeKey(t, device, migrationPassphrase)
			dataBefore := dataAreaDigest(t, device)

			result, err := migrateToFIPSForTest(device, migrationPassphrase, cheapMigration())
			if err != nil {
				t.Fatalf("MigrateToFIPS failed: %v", err)
			}
			if !result.KeyslotAdded || !result.Complete {
				t.Fatalf("result %+v: want a keyslot added and a complete import", result)
			}
			if !slices.Equal(result.MigratedDigests, []string{"0"}) {
				t.Fatalf("MigratedDigests = %v, want [0]", result.MigratedDigests)
			}
			if !slices.Equal(result.RemovedKeyslots, []string{"0"}) {
				t.Fatalf("RemovedKeyslots = %v, want [0]", result.RemovedKeyslots)
			}
			assertFIPSReady(t, device)

			_, metadata, err := readHeaderForTest(device)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			digest := metadata.Digests["0"]
			if digest.Type != kdfTypePBKDF2 || digest.Hash != defaultHashAlgo {
				t.Fatalf("digest is %s-%s, want pbkdf2-%s", digest.Type, digest.Hash, defaultHashAlgo)
			}
			if digest.Time != nil || digest.Memory != nil || digest.CPUs != nil {
				t.Fatal("the migrated digest still declares Argon2 cost")
			}
			raw := readJSONArea(t, device)
			for _, member := range []string{`"argon2`, `"time":`, `"memory":`, `"cpus":`} {
				if bytes.Contains(raw, []byte(member)) {
					t.Fatalf("the migrated header's JSON still carries %s: %s", member, raw)
				}
			}
			if got := volumeKey(t, device, migrationPassphrase); !bytes.Equal(got, keyBefore) {
				t.Fatal("the volume key changed")
			}
			if dataAreaDigest(t, device) != dataBefore {
				t.Fatal("the data area changed; a keyslot migration must not touch it")
			}
		})
	}
}

// TestFIPSRefusalNamesAnArgon2Digest: an approved keyslot attested only by an
// Argon2 digest opens outside FIPS mode, and inside it is refused with the
// import remedy naming the digest -- not called a broken header.
func TestFIPSRefusalNamesAnArgon2Digest(t *testing.T) {
	device := newImage(t, "fips-argon2-digest.img")
	formatWithLibrary(t, device)
	if fips140.Enabled() {
		// A FIPS process cannot derive the Argon2 fixture itself, so the
		// digest is written with a value it never has to compute: the refusal
		// comes before any derivation, which is the point.
		hdr, metadata, err := readHeaderForTest(device)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}
		cost, memory, cpus := header.MinArgon2Time, minArgon2MemoryKB, 1
		digest := metadata.Digests["0"]
		digest.Type, digest.Hash, digest.Iterations = kdfTypeArgon2id, "", 0
		digest.Time, digest.Memory, digest.CPUs = &cost, &memory, &cpus
		digest.Digest = encodeBase64(bytes.Repeat([]byte{0x5a}, argon2DigestLen))
		hdr.SequenceID++
		if err := writeHeaderInternal(device, hdr, metadata); err != nil {
			t.Fatalf("writing the fixture failed: %v", err)
		}
		assertImportRequired(t, testKeyForTest(device, migrationPassphrase), device, nil,
			[]NonApprovedKDF{{ID: 0, Type: kdfTypeArgon2id}})
		return
	}

	argon2Digest(t, device, "")
	if err := testKeyForTest(device, migrationPassphrase); err != nil {
		t.Fatalf("outside FIPS mode an Argon2 digest must be evaluated, got %v", err)
	}
}

// TestFIPSRefusalDoesNotCallAMalformedDigestAnImport: a SHA-1 digest whose
// value is not base64 is damage, in any mode. Its algorithm being one FIPS mode
// refuses does not make the volume "intact" -- the import could not fix it --
// so the header fault is what is reported.
func TestFIPSRefusalDoesNotCallAMalformedDigestAnImport(t *testing.T) {
	device := newImage(t, "fips-malformed-digest.img")
	formatWithLibrary(t, device)
	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	digest := metadata.Digests["0"]
	digest.Hash = "sha1"
	digest.Iterations = 1000
	digest.Digest = "!!! not base64 !!!"
	hdr.SequenceID++
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}

	err = testKeyForTest(device, migrationPassphrase)
	if errors.Is(err, ErrFIPSImportRequired) || errors.Is(err, ErrFIPSNotApproved) {
		t.Fatalf("a malformed digest was reported as a FIPS refusal: %v", err)
	}
	if !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("got %v, want ErrInvalidHeader: no digest can authenticate the keyslot", err)
	}
}

// A digest whose name and parameters are approved -- PBKDF2-SHA256 over a
// full-length salt -- but whose value is 48 bytes, a length SHA-256 never
// produces, is damage the header screen rejects. The FIPS policy check alone
// calls it approved, so the migration plan must screen its structure before
// skipping it: the volume is refused at the plan stage as ErrInvalidHeader,
// with nothing written, rather than migrated with the damage kept.
func TestMigrateToFIPSRefusesAnApprovedLookingMalformedDigestAtPlan(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}
	path := argon2VolumeImage(t, "fips-approved-malformed-digest.img")
	hdr, metadata, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Digests["1"] = &header.Digest{
		Type:       kdfTypePBKDF2,
		Keyslots:   []string{},
		Segments:   []string{"0"},
		Hash:       "sha256",
		Iterations: 1000,
		Salt:       base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32)),
		Digest:     base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, 48)),
	}
	if _, ok := digestFIPSRefusal("1", metadata.Digests["1"]); !ok {
		t.Fatal("fixture digest is not approved by the FIPS policy check; the case needs one it approves")
	}
	if _, _, err := screenDigestStructure(metadata.Digests["1"]); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("fixture digest passes the header screen (%v); the case needs one it rejects", err)
	}
	hdr.SequenceID++
	if err := writeHeaderInternal(path, hdr, metadata); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	before := fileDigest(t, path)
	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	m, err := v.MigrateToFIPS(context.Background(), pass, MigrateParams{})
	if err == nil {
		t.Fatalf("MigrateToFIPS of a volume with a malformed approved-looking digest succeeded (%+v), want ErrInvalidHeader", m)
	}
	if !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("MigrateToFIPS: %v, want ErrInvalidHeader", err)
	}
	var migration *FIPSMigrationError
	if !errors.As(err, &migration) {
		t.Fatalf("MigrateToFIPS: %v is not a *FIPSMigrationError", err)
	}
	if migration.Stage != "plan" || migration.State != fipsStateUntouched {
		t.Errorf("stage %q, state %q; want plan, %q", migration.Stage, migration.State, fipsStateUntouched)
	}
	if fileDigest(t, path) != before {
		t.Fatal("a MigrateToFIPS refused at plan changed the device")
	}
}

// A volume with a valid migration source -- an Argon2 keyslot whose digest is
// well formed -- and one more digest that is malformed, which no keyslot the
// unlock tries consults: one covering no keyslot, bound to the data segment,
// and one bound to nothing. FIPS-mode unlock must not answer
// FIPSImportRequiredError, which says MigrateToFIPS would open the volume:
// MigrateToFIPS refuses it at the plan stage with ErrInvalidHeader, writing
// nothing. Damage is reported as damage, by unlock and import alike.
func TestMalformedUnconsultedDigestIsAHeaderFaultAtUnlockAndImport(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}
	salt := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))
	cases := []struct {
		name     string
		segments []string
		value    string
	}{
		{"bound, covering no keyslot, 48-byte sha256 value", []string{"0"}, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, 48))},
		{"bound to no segment, value not base64", []string{}, "!!! not base64 !!!"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := argon2VolumeImage(t, fmt.Sprintf("fips-unconsulted-malformed-digest-%d.img", i))
			hdr, metadata, err := readHeaderForTest(path)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			metadata.Digests["1"] = &header.Digest{
				Type:       kdfTypePBKDF2,
				Keyslots:   []string{},
				Segments:   tc.segments,
				Hash:       "sha256",
				Iterations: 1000,
				Salt:       salt,
				Digest:     tc.value,
			}
			if _, _, err := screenDigestStructure(metadata.Digests["1"]); !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("fixture digest passes the header screen (%v); the case needs one it rejects", err)
			}
			hdr.SequenceID++
			if err := writeHeaderInternal(path, hdr, metadata); err != nil {
				t.Fatalf("writing the fixture failed: %v", err)
			}
			pass := newTestPassphrase(t)
			defer func() { _ = pass.Destroy() }()

			sys := testVolumeSys()
			sys.fipsMode = forceFIPSPolicy(t)
			fipsVolume, err := Open(context.Background(), path, withTestSys(sys))
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			t.Cleanup(func() { _ = fipsVolume.Close() })
			unlocks := map[string]func() error{
				"Unlock": func() error {
					_, err := fipsVolume.Unlock(context.Background(), pass)
					return err
				},
				"UnlockKeyslot": func() error {
					_, err := fipsVolume.UnlockKeyslot(context.Background(), 0, pass)
					return err
				},
			}
			for name, unlock := range unlocks {
				err := unlock()
				var importRequired *FIPSImportRequiredError
				if errors.Is(err, ErrFIPSImportRequired) || errors.As(err, &importRequired) {
					t.Fatalf("%s under the FIPS policy reported a malformed digest as a FIPS import: %v", name, err)
				}
				if !errors.Is(err, ErrInvalidHeader) {
					t.Fatalf("%s under the FIPS policy: got %v, want ErrInvalidHeader", name, err)
				}
			}

			v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			t.Cleanup(func() { _ = v.Close() })
			before := fileDigest(t, path)
			_, err = v.MigrateToFIPS(context.Background(), pass, MigrateParams{})
			if !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("MigrateToFIPS: %v, want ErrInvalidHeader", err)
			}
			var migration *FIPSMigrationError
			if !errors.As(err, &migration) || migration.Stage != "plan" || migration.State != fipsStateUntouched {
				t.Fatalf("MigrateToFIPS: %v; want a plan-stage FIPSMigrationError leaving the volume %q", err, fipsStateUntouched)
			}
			if fileDigest(t, path) != before {
				t.Fatal("a MigrateToFIPS refused at plan changed the device")
			}
		})
	}
}

// TestMigrateToFIPSRefusesToWipeOutsideTheKeyslotsArea: a non-approved keyslot
// is removed by randomizing its declared area, and that area comes off the
// device. One pointing into the data segment or the header must be refused
// before anything is written -- the volume already opens through an approved
// keyslot, so nothing downstream would notice the damage.
func TestMigrateToFIPSRefusesToWipeOutsideTheKeyslotsArea(t *testing.T) {
	defer parallel(t)()
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	cases := []struct {
		name   string
		offset func(metadata *header.Metadata) string
	}{
		{"into the data segment", func(metadata *header.Metadata) string { return metadata.Segments["0"].Offset }},
		{"into the header", func(*header.Metadata) string { return "4096" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			device := newImage(t, "wipe-outside.img")
			formatWithLibrary(t, device)
			fillDataArea(t, device)

			hdr, metadata, err := readHeaderForTest(device)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			stray := *metadata.Keyslots["0"]
			area := *stray.Area
			area.Offset = tc.offset(metadata)
			stray.Area = &area
			cost, memory, cpus := header.MinArgon2Time, minArgon2MemoryKB, 1
			stray.KDF = &header.KDF{Type: kdfTypeArgon2id, Salt: stray.KDF.Salt, Time: &cost, Memory: &memory, CPUs: &cpus}
			metadata.Keyslots["1"] = &stray
			hdr.SequenceID++
			if err := writeHeaderUnvalidated(device, hdr, metadata); err != nil {
				t.Fatalf("writing the fixture failed: %v", err)
			}
			before := fileDigest(t, device)

			_, err = migrateToFIPSForTest(device, migrationPassphrase, cheapMigration())
			if !errors.Is(err, ErrKeyslotAreaOverlap) {
				t.Fatalf("got %v, want ErrKeyslotAreaOverlap", err)
			}
			var merr *FIPSMigrationError
			if !errors.As(err, &merr) || merr.Stage != "precondition" || merr.State != fipsStateUntouched {
				t.Fatalf("the refusal must come before any keyslot is read, with the volume untouched, got %#v", err)
			}
			if fileDigest(t, device) != before {
				t.Fatal("the refused migration changed the device")
			}
		})
	}
}

// TestMigrateToFIPSReadsNoKeyslotOutsideKeyslotSpace: the keyslot that opens
// the volume declares an area running past the keyslots area into the data
// segment -- its material, at the start, intact, so an unlock would succeed
// after reading every declared byte. The import refuses before reading any
// keyslot: no keyslot key is ever derived, and the unlock derives before it
// reads the area. Whether the non-approved keyslots are to be kept or not.
func TestMigrateToFIPSReadsNoKeyslotOutsideKeyslotSpace(t *testing.T) {
	defer parallel(t)()
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	for _, keep := range []bool{false, true} {
		t.Run(fmt.Sprintf("keep=%v", keep), func(t *testing.T) {
			device := argon2Volume(t, "oversized-area.img", false)
			hdr, metadata, err := readHeaderForTest(device)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			dataOffset, err := parseSize(metadata.Segments["0"].Offset)
			if err != nil {
				t.Fatalf("segment offset: %v", err)
			}
			keyslot := metadata.Keyslots["0"]
			offset, err := parseSize(keyslot.Area.Offset)
			if err != nil {
				t.Fatalf("area offset: %v", err)
			}
			area := *keyslot.Area
			area.Size = formatSize(dataOffset + 4096 - offset)
			keyslot.Area = &area
			hdr.SequenceID++
			if err := writeHeaderUnvalidated(device, hdr, metadata); err != nil {
				t.Fatalf("writing the fixture failed: %v", err)
			}
			before := fileDigest(t, device)

			derivations := 0
			sys := testVolumeSys()
			real := sys.passphraseKDF
			sys.passphraseKDFOverride = func(ctx context.Context, passphrase []byte, kdf *header.KDF, keySize int) (enclave.ByteAccess, error) {
				derivations++
				return real(ctx, passphrase, kdf, keySize)
			}

			opts := cheapMigration()
			opts.KeepNonApprovedKeyslots = keep
			_, err = migrateToFIPSAt(context.Background(), device, migrationPassphrase, opts, sys)
			var merr *FIPSMigrationError
			if !errors.Is(err, ErrKeyslotAreaOverlap) || !errors.As(err, &merr) ||
				merr.Stage != "precondition" || merr.State != fipsStateUntouched {
				t.Fatalf("got %#v, want a precondition-stage ErrKeyslotAreaOverlap with the volume untouched", err)
			}
			if derivations != 0 {
				t.Fatalf("%d keyslot key(s) were derived, so a keyslot area was about to be read; want none", derivations)
			}
			if fileDigest(t, device) != before {
				t.Fatal("the refused import changed the device")
			}
		})
	}
}
