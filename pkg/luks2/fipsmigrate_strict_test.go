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
	"os"
	"slices"
	"strconv"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/af"
	"github.com/jeremyhahn/go-luks2/internal/areacipher"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// Regressions for the second review of #84.
//
// The migration used to decide what to carry across, and what it could leave
// alone, from two things that are not enough on their own: the KDF's NAME, and
// "the passphrase opened this keyslot". A PBKDF2-SHA256 KDF with an eight-byte
// salt has an approved name and is refused by crypto/pbkdf2 under
// GODEBUG=fips140=only. And a keyslot the passphrase opens may hold an UNBOUND
// key -- one no digest binds to the data segment -- beside the keyslot holding
// the key the data is encrypted with.

// shortFIPSSalt is a salt strict FIPS mode refuses: 64 bits, where
// crypto/pbkdf2 requires at least 128 under GODEBUG=fips140=only.
var shortFIPSSalt = []byte("8-bytes!")

// shortSaltKDF is PBKDF2-SHA256 -- an approved name -- over shortFIPSSalt.
func shortSaltKDF() *header.KDF {
	iterations := header.MinKDFIterations
	return &header.KDF{Type: kdfTypePBKDF2, Hash: "sha256", Salt: encodeBase64(shortFIPSSalt), Iterations: &iterations}
}

// weakenForStrictFIPS rewrites device so every KDF the migration might be
// tempted to keep has an approved name and a salt strict FIPS refuses: digest
// "0" is recomputed over shortFIPSSalt, and, when keyslotID is not empty, that
// keyslot is re-wrapped in place under shortSaltKDF. Both still attest and
// hold the same volume key, so the volume opens outside FIPS mode exactly as
// before.
//
// It returns an error rather than taking a *testing.T because the cross-process
// test runs it in a non-FIPS child (fipsimport_cryptsetup_test.go): a FIPS
// parent cannot derive through the salt it writes.
func weakenForStrictFIPS(device string, passphrase []byte, keyslotID string) (err error) {
	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		return err
	}
	masterKey, err := getMasterKey(device, passphrase, metadata, testVolumeSys())
	if err != nil {
		return err
	}
	// No testing.TB here (it also runs in a child process), so a release
	// the enclave reports joins the returned error rather than vanishing.
	defer func() { err = errors.Join(err, masterKey.Destroy()) }()

	digest := metadata.Digests["0"]
	if digest == nil {
		return &errs.Error{Detail: "the fixture has no digest 0"}
	}
	kdf := shortSaltKDF()
	value, err := deriveKeySecret(context.Background(), masterKey, kdf, sha256DigestLen, testVolumeSys())
	if err != nil {
		return err
	}
	// No testing.TB here (it also runs in a child process), so a release
	// the enclave reports joins the returned error rather than vanishing.
	defer func() { err = errors.Join(err, value.Destroy()) }()
	digest.Type, digest.Hash, digest.Salt, digest.Iterations = kdf.Type, kdf.Hash, kdf.Salt, *kdf.Iterations
	digest.Time, digest.Memory, digest.CPUs = nil, nil, nil
	if err := secret.Borrow("fixture digest", value, func(b []byte) error {
		digest.Digest = encodeBase64(b)
		return nil
	}); err != nil {
		return err
	}

	if keyslotID != "" {
		keyslot := metadata.Keyslots[keyslotID]
		if keyslot == nil || keyslot.Area == nil {
			return &errs.Error{Detail: "the fixture has no keyslot " + keyslotID}
		}
		if err := rewrapKeyslotInPlace(device, keyslot, masterKey, passphrase, shortSaltKDF()); err != nil {
			return err
		}
	}

	hdr.SequenceID++
	return writeHeaderInternal(device, hdr, metadata)
}

// rewrapKeyslotInPlace re-wraps masterKey under passphrase through kdf into
// keyslot's existing area, and sets keyslot.KDF. The area is the same size for
// the same key size and stripe count, so nothing else moves.
func rewrapKeyslotInPlace(device string, keyslot *header.Keyslot, masterKey enclave.ByteAccess, passphrase []byte, kdf *header.KDF) (err error) {
	passphraseKey, err := deriveKeyEnclave(context.Background(), passphrase, kdf, keyslot.KeySize, defaultVolumeSys())
	if err != nil {
		return err
	}
	// No testing.TB here (it also runs in a child process), so a release
	// the enclave reports joins the returned error rather than vanishing.
	defer func() { err = errors.Join(err, passphraseKey.Destroy()) }()

	afData, err := afCodec(testVolumeSys()).Split(masterKey, af.Params{Stripes: keyslot.AF.Stripes, Hash: keyslot.AF.Hash})
	if err != nil {
		return err
	}
	// No testing.TB here (it also runs in a child process), so a release
	// the enclave reports joins the returned error rather than vanishing.
	defer func() { err = errors.Join(err, afData.Destroy()) }()

	encrypted, err := areacipher.Default().EncryptEnclave(custody, afData, passphraseKey)
	if err != nil {
		return err
	}
	defer clearBytes(encrypted)

	offset, err := parseSize(keyslot.Area.Offset)
	if err != nil {
		return err
	}
	size, err := parseSize(keyslot.Area.Size)
	if err != nil {
		return err
	}
	if int64(len(encrypted)) > size {
		return &errs.Error{Detail: "the re-wrapped key material does not fit the keyslot's area"}
	}

	f, err := os.OpenFile(device, os.O_WRONLY, 0o600) // #nosec G304 -- a test image
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(encrypted, offset); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	keyslot.KDF = kdf
	return nil
}

// assertStrictRefusal asserts nonApprovedKDFs flags what weakenForStrictFIPS
// wrote, with the salt as the reason: the fixture must be what it claims, or
// the test would measure nothing.
func assertStrictRefusal(t *testing.T, device string, wantKeyslots, wantDigests []string) {
	t.Helper()

	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	keyslots, digests := nonApprovedKDFs(metadata)
	ids := func(list []NonApprovedKDF) []string {
		var out []string
		for _, k := range list {
			out = append(out, strconv.Itoa(k.ID))
		}
		return out
	}
	if !slices.Equal(ids(keyslots), wantKeyslots) || !slices.Equal(ids(digests), wantDigests) {
		t.Fatalf("non-approved keyslots %v and digests %v, want %v and %v", keyslots, digests, wantKeyslots, wantDigests)
	}
	for _, k := range slices.Concat(keyslots, digests) {
		if k.Type == kdfTypePBKDF2 && k.Reason != "salt shorter than 128 bits" {
			t.Fatalf("%s: want the short salt named as the reason", k)
		}
	}
}

// TestMigrateToFIPSMigratesAShortSaltDigest: a PBKDF2-SHA256 digest over an
// eight-byte salt has an approved name, so a check of names alone keeps it,
// passes both verification opens, and reports a complete import that
// GODEBUG=fips140=only then cannot open. It must be migrated like any other
// digest FIPS mode cannot run.
func TestMigrateToFIPSMigratesAShortSaltDigest(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	device := argon2Volume(t, "short-salt-digest.img", false)
	fillDataArea(t, device)
	if err := weakenForStrictFIPS(device, migrationPassphrase, ""); err != nil {
		t.Fatalf("weakening the fixture failed: %v", err)
	}
	assertStrictRefusal(t, device, []string{"0"}, []string{"0"})
	keyBefore := volumeKey(t, device, migrationPassphrase)
	dataBefore := dataAreaDigest(t, device)

	result, err := migrateToFIPSForTest(device, migrationPassphrase, cheapMigration())
	if err != nil {
		t.Fatalf("MigrateToFIPS failed: %v", err)
	}
	if !slices.Equal(result.MigratedDigests, []string{"0"}) || !result.Complete {
		t.Fatalf("result %+v: want digest 0 migrated and a complete import", result)
	}
	assertFIPSReady(t, device)

	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	salt, err := decodeBase64(metadata.Digests["0"].Salt)
	if err != nil || len(salt) < fipsMinSaltLen {
		t.Fatalf("the migrated digest's salt is %d bytes (%v), want at least %d", len(salt), err, fipsMinSaltLen)
	}
	if got := volumeKey(t, device, migrationPassphrase); !bytes.Equal(got, keyBefore) {
		t.Fatal("the volume key changed")
	}
	if dataAreaDigest(t, device) != dataBefore {
		t.Fatal("the data area changed")
	}
}

// TestMigrateToFIPSDoesNotReuseAShortSaltKeyslot: a PBKDF2-SHA256 keyslot over
// an eight-byte salt is found first by the approved-first scan and, judged by
// name, reused as the migrated keyslot -- which strict FIPS mode then cannot
// derive through. It must be treated as non-approved: a fresh keyslot added,
// and it removed.
func TestMigrateToFIPSDoesNotReuseAShortSaltKeyslot(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	device := newImage(t, "short-salt-keyslot.img")
	formatWithLibrary(t, device)
	fillDataArea(t, device)
	keyBefore := volumeKey(t, device, migrationPassphrase)
	if err := weakenForStrictFIPS(device, migrationPassphrase, "0"); err != nil {
		t.Fatalf("weakening the fixture failed: %v", err)
	}
	assertStrictRefusal(t, device, []string{"0"}, []string{"0"})
	if got := volumeKey(t, device, migrationPassphrase); !bytes.Equal(got, keyBefore) {
		t.Fatal("the weakened fixture no longer holds the volume key")
	}

	result, err := migrateToFIPSForTest(device, migrationPassphrase, cheapMigration())
	if err != nil {
		t.Fatalf("MigrateToFIPS failed: %v", err)
	}
	if !result.KeyslotAdded || result.Keyslot != 1 {
		t.Fatalf("result %+v: the short-salt keyslot must not be reused; want a new keyslot 1", result)
	}
	if !slices.Equal(result.RemovedKeyslots, []string{"0"}) || !result.Complete {
		t.Fatalf("result %+v: want the short-salt keyslot removed and a complete import", result)
	}
	assertFIPSReady(t, device)
	if got := volumeKey(t, device, migrationPassphrase); !bytes.Equal(got, keyBefore) {
		t.Fatal("the volume key changed")
	}
}

// unboundKeyslot adds keyslot "1" to device holding a fresh random key -- NOT
// the volume key -- under passphrase, attested by a new digest "1" that binds
// it to no data segment: a LUKS2 unbound key. The keyslot is PBKDF2, so the
// approved-first scan reaches it before the Argon2 keyslot holding the key the
// data needs.
func unboundKeyslot(t *testing.T, device string, passphrase []byte) {
	t.Helper()

	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	reference := metadata.Keyslots["0"]
	raw, err := randomBytes(reference.KeySize, testVolumeSys().cryptoRand)
	if err != nil {
		t.Fatalf("randomBytes failed: %v", err)
	}
	unbound, err := custody.Adopt("fixture unbound key", raw)
	if err != nil {
		t.Fatalf("custody.Adopt failed: %v", err)
	}
	defer mustDestroy(t, unbound)

	writeKeyslot(t, device, hdr, metadata, "1", reference, unbound, passphrase)
	kdf, value, err := createDigest(unbound, "sha256", testVolumeSys())
	if err != nil {
		t.Fatalf("createDigest failed: %v", err)
	}
	metadata.Digests["1"] = &header.Digest{
		Type:       kdfTypePBKDF2,
		Keyslots:   []string{"1"},
		Segments:   []string{},
		Hash:       kdf.Hash,
		Iterations: *kdf.Iterations,
		Salt:       kdf.Salt,
		Digest:     value,
	}
	hdr.SequenceID++
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		t.Fatalf("writing the unbound keyslot failed: %v", err)
	}
}

// TestMigrateToFIPSCarriesTheVolumeKeyNotAnUnboundKey: the passphrase opens an
// approved keyslot holding an unbound key AND the Argon2 keyslot holding the
// volume key. Carrying the unbound key across and removing the Argon2 keyslot
// passes every check that asks only "does the migrated keyslot open to the key
// it was written with" -- and erases the only way to the data. The migration
// must carry the key bound to the data segment.
func TestMigrateToFIPSCarriesTheVolumeKeyNotAnUnboundKey(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	device := argon2Volume(t, "unbound-key.img", false)
	fillDataArea(t, device)
	volumeKeyBefore := volumeKey(t, device, migrationPassphrase)
	unboundKeyslot(t, device, migrationPassphrase)
	dataBefore := dataAreaDigest(t, device)

	result, err := migrateToFIPSForTest(device, migrationPassphrase, cheapMigration())
	if err != nil {
		t.Fatalf("MigrateToFIPS failed: %v", err)
	}
	if !result.KeyslotAdded || result.Keyslot != 2 {
		t.Fatalf("result %+v: the unbound keyslot must not be carried across; want a new keyslot 2", result)
	}
	if !slices.Equal(result.RemovedKeyslots, []string{"0"}) || !result.Complete {
		t.Fatalf("result %+v: want the Argon2 keyslot removed and a complete import", result)
	}

	// The migrated keyslot holds the VOLUME key, and a digest binds it to the
	// data segment.
	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	got, err := unlockKeyslot(context.Background(), device, "2", migrationPassphrase, metadata.Keyslots["2"], metadata.Digests, testVolumeSys())
	if err != nil {
		t.Fatalf("the migrated keyslot does not open: %v", err)
	}
	defer mustDestroy(t, got)
	if ok, err := got.EqualTo(volumeKeyBefore); err != nil || !ok {
		t.Fatal("the migrated keyslot holds a key other than the one the data is encrypted with")
	}
	if missing := unboundSegments(metadata, metadata.Digests, "2", got); len(missing) != 0 {
		t.Fatalf("the migrated key is not bound to data segment(s) %v", missing)
	}
	if dataAreaDigest(t, device) != dataBefore {
		t.Fatal("the data area changed")
	}

	// Opening keyslot 2 directly proves nothing about what Unlock maps: the
	// retained approved keyslot 1 holds the unbound key under the SAME
	// passphrase and sorts first. The normal scan -- the one Unlock hands to
	// dm-crypt -- must recover the volume key, both as this process runs it
	// and as a FIPS process would (approved keyslots and digests only).
	normal, err := getMasterKey(device, migrationPassphrase, metadata, testVolumeSys())
	if err != nil {
		t.Fatalf("the normal unlock scan failed: %v", err)
	}
	defer mustDestroy(t, normal)
	if ok, err := normal.EqualTo(volumeKeyBefore); err != nil || !ok {
		t.Fatal("the normal unlock scan recovered the unbound key, not the volume key the data needs")
	}
	fipsView := fipsApprovedView(metadata)
	underFIPS, err := getMasterKey(device, migrationPassphrase, fipsView, testVolumeSys())
	if err != nil {
		t.Fatalf("the unlock scan over the FIPS-approved view failed: %v", err)
	}
	defer mustDestroy(t, underFIPS)
	if ok, err := underFIPS.EqualTo(volumeKeyBefore); err != nil || !ok {
		t.Fatal("the FIPS unlock scan recovered the unbound key, not the volume key the data needs")
	}
}

// TestMigrateToFIPSRefusesWhenNoKeyslotHoldsTheVolumeKey: when the passphrase
// reaches only an unbound key, there is no volume key to carry across, and
// nothing may be written.
func TestMigrateToFIPSRefusesWhenNoKeyslotHoldsTheVolumeKey(t *testing.T) {
	defer parallel(t)()
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	t.Run("the passphrase opens only the unbound keyslot", func(t *testing.T) {
		device := argon2Volume(t, "unbound-only.img", false)
		unboundKeyslot(t, device, otherPassphrase)
		before := fileDigest(t, device)

		_, err := migrateToFIPSForTest(device, otherPassphrase, cheapMigration())
		var merr *FIPSMigrationError
		if !errors.As(err, &merr) || merr.Stage != "unlock" || merr.State != fipsStateUntouched {
			t.Fatalf("got %v, want a refusal at unlock with the volume untouched", err)
		}
		if fileDigest(t, device) != before {
			t.Fatal("the refused migration changed the device")
		}
	})

	t.Run("no digest binds any keyslot to the data segment", func(t *testing.T) {
		device := argon2Volume(t, "unbound-all.img", false)
		hdr, metadata, err := readHeaderForTest(device)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}
		// The data segment stays attested -- by a digest no keyslot is
		// bound to -- so the header is one cryptsetup accepts and only the
		// binding this test is about is missing.
		unbound := *metadata.Digests["0"]
		unbound.Keyslots = []string{}
		metadata.Digests["1"] = &unbound
		metadata.Digests["0"].Segments = []string{}
		hdr.SequenceID++
		if err := writeHeaderInternal(device, hdr, metadata); err != nil {
			t.Fatalf("writing the fixture failed: %v", err)
		}
		before := fileDigest(t, device)

		_, err = migrateToFIPSForTest(device, migrationPassphrase, cheapMigration())
		if !errors.Is(err, errFIPSMigrationUnboundKey) {
			t.Fatalf("got %v, want ErrFIPSMigrationUnboundKey", err)
		}
		if fileDigest(t, device) != before {
			t.Fatal("the refused migration changed the device")
		}
	})
}

// TestFIPSParameterRefusal pins the floors crypto/pbkdf2 enforces under
// GODEBUG=fips140=only, at their boundaries.
func TestFIPSParameterRefusal(t *testing.T) {
	cases := []struct {
		name      string
		salt      string
		outputLen int
		want      string
	}{
		{"128-bit salt, 112-bit output", encodeBase64(make([]byte, 16)), 14, ""},
		{"120-bit salt", encodeBase64(make([]byte, 15)), 32, "salt shorter than 128 bits"},
		{"104-bit output", encodeBase64(make([]byte, 32)), 13, "output shorter than 112 bits"},
		{"salt not base64", "!!!", 32, "salt is not base64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := fipsParameterRefusal(tc.salt, tc.outputLen); got != tc.want {
				t.Fatalf("fipsParameterRefusal = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestAddKeyJoinsOnlyTheDigestOfTheKeyItWraps: on a header carrying an unbound
// key beside the volume key, a new keyslot must be assigned to the volume key's
// digest alone. It used to be appended to every digest, which cryptsetup
// refuses outright ("header.Keyslot N is not assigned to exactly 1 digest") -- the
// migration adds its keyslot through the same path, so every import of such a
// volume left it unreadable to cryptsetup.
func TestAddKeyJoinsOnlyTheDigestOfTheKeyItWraps(t *testing.T) {
	device := newImage(t, "addkey-digest.img")
	if err := formatForTest(standardFormatOptions(device)); err != nil {
		t.Fatalf("Format failed: %v", err)
	}
	unboundKeyslot(t, device, otherPassphrase)

	slot, err := addKeyForTest(device, migrationPassphrase, []byte("a-third-credential"), &addKeyOptionsForTest{KDFType: kdfTypePBKDF2, PBKDFIterTime: 1})
	if err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}
	id := strconv.Itoa(slot)

	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	var in []string
	for _, digestID := range sortedDigestIDs(metadata.Digests) {
		if digestCovers(metadata.Digests[digestID], id) {
			in = append(in, digestID)
		}
	}
	if !slices.Equal(in, []string{"0"}) {
		t.Fatalf("new keyslot %s is assigned to digests %v, want exactly the volume key's digest 0", id, in)
	}
}
