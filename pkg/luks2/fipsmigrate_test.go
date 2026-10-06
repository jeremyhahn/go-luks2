// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"crypto/fips140"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// In-process tests for MigrateToFIPS (#84). The real-cryptsetup, real-FIPS
// half is in fipsimport_cryptsetup_test.go; these pin the ordering guards, the
// digest migration and the result, on containers built here.
//
// A FIPS 140-3 test process cannot build an Argon2 fixture -- CreateKDF refuses
// it -- and cannot run the migration either, which is the point of the
// refusal. So each test that needs one checks the mode first and, in FIPS mode,
// asserts the refusal instead: nothing is skipped in either mode.

// migrationPassphrase and otherPassphrase are the two credentials the fixtures
// carry.
var (
	migrationPassphrase = []byte(conformancePassphrase)
	otherPassphrase     = []byte("a-second-argon2-credential")
)

// cheapMigration keeps the new keyslot's calibration short; the cost is test
// latency here and defends nothing.
func cheapMigration() *FIPSMigrationOptions {
	return &FIPSMigrationOptions{PBKDFIterTime: 1}
}

// assertMigrationRefusedUnderFIPS is what every fixture-building test asserts
// when the test process itself runs in FIPS mode: the migration is refused,
// typed, and the device is not touched.
func assertMigrationRefusedUnderFIPS(t *testing.T) {
	t.Helper()

	device := newImage(t, "fips-refusal.img")
	formatWithLibrary(t, device)
	before := fileDigest(t, device)

	_, err := MigrateToFIPS(device, migrationPassphrase, cheapMigration())
	if !errors.Is(err, ErrFIPSMigrationUnderFIPS) {
		t.Fatalf("MigrateToFIPS in a FIPS process: got %v, want ErrFIPSMigrationUnderFIPS", err)
	}
	var merr *FIPSMigrationError
	if !errors.As(err, &merr) || merr.State != fipsStateUntouched {
		t.Fatalf("the refusal must be a *FIPSMigrationError stating the volume is untouched, got %#v", err)
	}
	if after := fileDigest(t, device); after != before {
		t.Fatal("MigrateToFIPS refused in a FIPS process and still changed the device")
	}
}

// argon2Volume is a cryptsetup-formatted container whose keyslot 0 is
// Argon2id for migrationPassphrase and, when withSecond is set, whose keyslot 1
// is Argon2id for otherPassphrase: what `cryptsetup luksFormat` followed by
// `luksAddKey` produces -- the foreign volume the import exists for -- at the
// lowest Argon2 cost the reader accepts.
//
// The container is formatted once per process and copied thereafter
// (cryptsetupArgon2Prefix), and the digest cost of anything the migration
// rewrites is pinned at the floor. Both keep these fixtures inside the
// package's -race budget (ci.yml); no caller tests a KDF's cost, only its
// type, hash, salt and what it attests. No caller compares two of these
// volumes, so sharing salts and a UUID loses nothing.
func argon2Volume(t *testing.T, name string, withSecond bool) string {
	t.Helper()

	pinDigestIterations(t, minPBKDF2Iterations)
	device := filepath.Join(t.TempDir(), name)
	placeImage(t, device, cryptsetupArgon2Prefix(t, withSecond))

	_, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	keyslots, _ := nonApprovedKDFs(metadata)
	want := 1
	if withSecond {
		want = 2
	}
	if len(keyslots) != want {
		t.Fatalf("fixture has %d non-approved keyslots, want %d; the test would measure nothing", len(keyslots), want)
	}
	return device
}

// cryptsetupArgon2Cache holds, per process, the metadata region of the two
// cryptsetup Argon2id containers argon2Volume and crashFixture start from.
var cryptsetupArgon2Cache struct {
	sync.Mutex
	prefix map[bool][]byte
}

// cryptsetupArgon2Prefix returns the bytes before the data segment of a
// cryptsetup Argon2id container at crashFormatArgs's cost: keyslot 0 for
// migrationPassphrase, and keyslot 1 for otherPassphrase when withSecond is
// set. cryptsetup runs once per shape per process.
func cryptsetupArgon2Prefix(t *testing.T, withSecond bool) []byte {
	t.Helper()

	cryptsetupArgon2Cache.Lock()
	defer cryptsetupArgon2Cache.Unlock()
	if prefix, ok := cryptsetupArgon2Cache.prefix[withSecond]; ok {
		return prefix
	}

	requireCryptsetup(t)
	image := newImage(t, "cryptsetup-argon2.img")
	args := append(append([]string{"luksFormat"}, crashFormatArgs...), image)
	if code, out := runCryptsetup(t, conformancePassphrase, args...); code != 0 {
		t.Fatalf("cryptsetup luksFormat exited %d\n%s", code, out)
	}
	if withSecond {
		keyFile := filepath.Join(t.TempDir(), "second.key")
		if err := os.WriteFile(keyFile, otherPassphrase, 0o600); err != nil {
			t.Fatalf("writing the second key file failed: %v", err)
		}
		args = append(append([]string{"luksAddKey"}, crashArgon2Args...), image, keyFile)
		if code, out := runCryptsetup(t, conformancePassphrase, args...); code != 0 {
			t.Fatalf("cryptsetup luksAddKey exited %d\n%s", code, out)
		}
	}
	_, metadata, err := ReadHeader(image)
	if err != nil {
		t.Fatalf("ReadHeader on cryptsetup's container failed: %v", err)
	}
	dataOffset, err := parseSize(metadata.Segments["0"].Offset)
	if err != nil {
		t.Fatalf("segment offset: %v", err)
	}
	prefix := readPrefix(t, image, dataOffset)
	if cryptsetupArgon2Cache.prefix == nil {
		cryptsetupArgon2Cache.prefix = map[bool][]byte{}
	}
	cryptsetupArgon2Cache.prefix[withSecond] = prefix
	return prefix
}

// fileDigest hashes a whole image.
func fileDigest(t *testing.T, path string) [32]byte {
	t.Helper()

	b, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return sha256.Sum256(b)
}

// dataAreaDigest hashes everything from the data segment's offset to the end of
// the image -- the bytes a re-encryption would rewrite and a keyslot migration
// must not touch.
func dataAreaDigest(t *testing.T, path string) [32]byte {
	t.Helper()

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	offset, err := parseSize(metadata.Segments["0"].Offset)
	if err != nil {
		t.Fatalf("segment offset: %v", err)
	}
	f, err := os.Open(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		t.Fatalf("seek: %v", err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("read data area: %v", err)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// fillDataArea writes non-zero bytes over the data segment, so "the data area
// did not change" is a statement about content and not about a sparse file
// that stayed zero.
func fillDataArea(t *testing.T, path string) {
	t.Helper()

	_, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	offset, err := parseSize(metadata.Segments["0"].Offset)
	if err != nil {
		t.Fatalf("segment offset: %v", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteAt(bytes.Repeat([]byte("ciphertext-stand-in "), 4096), offset); err != nil {
		t.Fatalf("write data area: %v", err)
	}
}

// volumeKey recovers the volume key with passphrase and returns a copy for
// comparison. Test-only: the point is to prove the migration kept the SAME key.
func volumeKey(t *testing.T, device string, passphrase []byte) []byte {
	t.Helper()

	_, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	mk, err := getMasterKey(device, passphrase, metadata)
	if err != nil {
		t.Fatalf("getMasterKey failed: %v", err)
	}
	defer mustDestroy(t, mk)
	var out []byte
	if err := secret.Borrow("test copy", mk, func(b []byte) error {
		out = bytes.Clone(b)
		return nil
	}); err != nil {
		t.Fatalf("borrow: %v", err)
	}
	return out
}

// assertFIPSReady asserts the header carries no keyslot or digest a FIPS
// process cannot execute.
func assertFIPSReady(t *testing.T, device string) {
	t.Helper()

	_, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	keyslots, digests := nonApprovedKDFs(metadata)
	if len(keyslots) != 0 || len(digests) != 0 {
		t.Fatalf("header still carries non-approved KDFs: keyslots %v, digests %v", keyslots, digests)
	}
}

// TestMigrateToFIPSRewrapsTheVolumeKeyAndRemovesArgon2Keyslots is the default
// import: every Argon2 keyslot gone, one PBKDF2 keyslot holding the SAME volume
// key, and the data area byte-for-byte untouched -- a keyslot migration, not a
// re-encryption.
func TestMigrateToFIPSRewrapsTheVolumeKeyAndRemovesArgon2Keyslots(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	device := argon2Volume(t, "migrate.img", true)
	fillDataArea(t, device)
	keyBefore := volumeKey(t, device, migrationPassphrase)
	dataBefore := dataAreaDigest(t, device)

	result, err := MigrateToFIPS(device, migrationPassphrase, cheapMigration())
	if err != nil {
		t.Fatalf("MigrateToFIPS failed: %v", err)
	}

	if !result.KeyslotAdded || result.Keyslot != 2 {
		t.Errorf("result reports keyslot %d (added %v), want a new keyslot 2", result.Keyslot, result.KeyslotAdded)
	}
	if !slices.Equal(result.RemovedKeyslots, []string{"0", "1"}) {
		t.Errorf("RemovedKeyslots = %v, want [0 1]", result.RemovedKeyslots)
	}
	if len(result.RetainedNonApprovedKeyslots) != 0 || !result.Complete {
		t.Errorf("default migration must be complete, got retained %v complete %v",
			result.RetainedNonApprovedKeyslots, result.Complete)
	}
	if len(result.MigratedDigests) != 0 {
		t.Errorf("this library's digest is already PBKDF2-SHA256, yet MigratedDigests = %v", result.MigratedDigests)
	}

	assertFIPSReady(t, device)

	if got := volumeKey(t, device, migrationPassphrase); !bytes.Equal(got, keyBefore) {
		t.Fatal("the migrated keyslot holds a different volume key; the data would be unreadable")
	}
	if dataAreaDigest(t, device) != dataBefore {
		t.Fatal("the data area changed; a keyslot migration must never touch it")
	}
	if err := TestKey(device, otherPassphrase); err == nil {
		t.Fatal("the removed Argon2 keyslot's credential still opens the volume")
	}
}

// TestMigrateToFIPSKeepsNonApprovedKeyslotsOnlyWhenAskedAndSaysSo pins the
// half-migration: kept Argon2 keyslots are reported, and the result is NOT
// complete.
func TestMigrateToFIPSKeepsNonApprovedKeyslotsOnlyWhenAskedAndSaysSo(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	device := argon2Volume(t, "keep.img", true)
	opts := cheapMigration()
	opts.KeepNonApprovedKeyslots = true

	result, err := MigrateToFIPS(device, migrationPassphrase, opts)
	if err != nil {
		t.Fatalf("MigrateToFIPS failed: %v", err)
	}
	if result.Complete {
		t.Fatal("a migration that kept Argon2 keyslots reported itself complete")
	}
	if !slices.Equal(result.RetainedNonApprovedKeyslots, []string{"0", "1"}) || len(result.RemovedKeyslots) != 0 {
		t.Fatalf("retained %v removed %v, want retained [0 1] and nothing removed",
			result.RetainedNonApprovedKeyslots, result.RemovedKeyslots)
	}
	if err := TestKey(device, otherPassphrase); err != nil {
		t.Fatalf("a kept keyslot no longer opens the volume: %v", err)
	}

	// The staged rollout the option exists for: migrate the second credential,
	// then a final call without the option removes the originals.
	second, err := MigrateToFIPS(device, otherPassphrase, opts)
	if err != nil {
		t.Fatalf("migrating the second credential failed: %v", err)
	}
	if !second.KeyslotAdded {
		t.Fatal("the second credential was not given its own approved keyslot")
	}
	final, err := MigrateToFIPS(device, migrationPassphrase, cheapMigration())
	if err != nil {
		t.Fatalf("the final migration failed: %v", err)
	}
	if final.KeyslotAdded || !final.Complete || !slices.Equal(final.RemovedKeyslots, []string{"0", "1"}) {
		t.Fatalf("final call: added %v complete %v removed %v", final.KeyslotAdded, final.Complete, final.RemovedKeyslots)
	}
	assertFIPSReady(t, device)
	for _, p := range [][]byte{migrationPassphrase, otherPassphrase} {
		if err := TestKey(device, p); err != nil {
			t.Fatalf("a migrated credential does not open the volume: %v", err)
		}
	}
}

// TestMigrateToFIPSOnAMigratedVolumeChangesNothing: re-running a completed
// import must not stack up keyslots, and must not run Argon2 -- there is none.
func TestMigrateToFIPSOnAMigratedVolumeChangesNothing(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	device := argon2Volume(t, "rerun.img", false)
	first, err := MigrateToFIPS(device, migrationPassphrase, cheapMigration())
	if err != nil {
		t.Fatalf("first MigrateToFIPS failed: %v", err)
	}

	again, err := MigrateToFIPS(device, migrationPassphrase, cheapMigration())
	if err != nil {
		t.Fatalf("second MigrateToFIPS failed: %v", err)
	}
	if again.KeyslotAdded || again.Keyslot != first.Keyslot || len(again.RemovedKeyslots) != 0 || !again.Complete {
		t.Fatalf("re-run changed the volume: %+v (first run %+v)", again, first)
	}
	_, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if len(metadata.Keyslots) != 1 {
		t.Fatalf("re-run left %d keyslots, want 1", len(metadata.Keyslots))
	}
}

// sha1DigestVolume is a container whose KEYSLOT is already approved and whose
// DIGEST is PBKDF2-SHA1 -- the shape `cryptsetup convert` leaves on an old
// LUKS1 volume. The digest is recomputed for real, over the real volume key, so
// it verifies outside FIPS mode exactly as the original did.
func sha1DigestVolume(t *testing.T, name string) string {
	t.Helper()

	device := newImage(t, name)
	formatWithLibrary(t, device)

	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	mk, err := getMasterKey(device, migrationPassphrase, metadata)
	if err != nil {
		t.Fatalf("getMasterKey failed: %v", err)
	}
	defer mustDestroy(t, mk)

	iterations := 1000
	kdf := &KDF{Type: KDFTypePBKDF2, Hash: "sha1", Salt: metadata.Digests["0"].Salt, Iterations: &iterations}
	derived, err := deriveKeySecret(mk, kdf, 20)
	if err != nil {
		t.Fatalf("deriving the sha1 digest failed: %v", err)
	}
	defer mustDestroy(t, derived)
	digest := metadata.Digests["0"]
	digest.Hash = "sha1"
	digest.Iterations = iterations
	if err := secret.Borrow("test digest", derived, func(b []byte) error {
		digest.Digest = encodeBase64(b)
		return nil
	}); err != nil {
		t.Fatalf("borrow: %v", err)
	}
	hdr.SequenceID++
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		t.Fatalf("writing the sha1 digest failed: %v", err)
	}
	if err := TestKey(device, migrationPassphrase); err != nil {
		t.Fatalf("the sha1-digest fixture does not open outside FIPS mode: %v", err)
	}
	return device
}

// TestMigrateToFIPSMigratesANonApprovedDigest is the trap the issue names: the
// keyslots can all be PBKDF2 and the volume still not open under FIPS, because
// the DIGEST's KDF runs on every unlock too. It gets its own test rather than
// being assumed to be what this library writes.
func TestMigrateToFIPSMigratesANonApprovedDigest(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	device := sha1DigestVolume(t, "sha1-digest.img")
	keyBefore := volumeKey(t, device, migrationPassphrase)

	result, err := MigrateToFIPS(device, migrationPassphrase, cheapMigration())
	if err != nil {
		t.Fatalf("MigrateToFIPS failed: %v", err)
	}
	if result.KeyslotAdded {
		t.Error("the keyslot was already approved and should have been used as it stands")
	}
	if !slices.Equal(result.MigratedDigests, []string{"0"}) {
		t.Fatalf("MigratedDigests = %v, want [0]", result.MigratedDigests)
	}
	if !result.Complete {
		t.Fatal("result is not complete")
	}
	assertFIPSReady(t, device)

	_, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	digest := metadata.Digests["0"]
	if digest.Type != KDFTypePBKDF2 || digest.Hash != DefaultHashAlgo {
		t.Fatalf("digest is %s-%s, want pbkdf2-%s", digest.Type, digest.Hash, DefaultHashAlgo)
	}
	if !slices.Equal(digest.Keyslots, []string{"0"}) || !slices.Equal(digest.Segments, []string{"0"}) {
		t.Fatalf("the migrated digest lost its associations: keyslots %v segments %v", digest.Keyslots, digest.Segments)
	}
	if got := volumeKey(t, device, migrationPassphrase); !bytes.Equal(got, keyBefore) {
		t.Fatal("the volume key changed")
	}
}

// TestMigrateToFIPSRefusesADigestThatDoesNotAttestTheKey: a non-approved digest
// that does not verify the recovered key is not rewritten into one that does.
// The refusal comes before any write.
func TestMigrateToFIPSRefusesADigestThatDoesNotAttestTheKey(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	device := newImage(t, "foreign-digest.img")
	formatWithLibrary(t, device)
	hdr, metadata, err := ReadHeader(device)
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
	before := fileDigest(t, device)

	_, err = MigrateToFIPS(device, migrationPassphrase, cheapMigration())
	if !errors.Is(err, ErrFIPSMigrationDigest) {
		t.Fatalf("got %v, want ErrFIPSMigrationDigest", err)
	}
	var merr *FIPSMigrationError
	if !errors.As(err, &merr) || merr.Stage != "plan" || merr.State != fipsStateUntouched {
		t.Fatalf("want a plan-stage refusal with the volume untouched, got %#v", err)
	}
	if fileDigest(t, device) != before {
		t.Fatal("the refusal changed the device")
	}
}

// TestMigrateToFIPSRemovesNothingWhenTheKeyslotCannotBeAdded is the ordering
// guard: if the PBKDF2 keyslot cannot be added, no Argon2 keyslot is removed.
func TestMigrateToFIPSRemovesNothingWhenTheKeyslotCannotBeAdded(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	device := argon2Volume(t, "add-fails.img", false)
	before := fileDigest(t, device)

	// Below the iteration floor: createKDF refuses it, after the unlock and
	// before anything is written.
	_, err := MigrateToFIPS(device, migrationPassphrase, &FIPSMigrationOptions{PBKDFIterations: 1000})
	if !errors.Is(err, ErrPBKDFIterationsTooLow) {
		t.Fatalf("got %v, want ErrPBKDFIterationsTooLow", err)
	}
	var merr *FIPSMigrationError
	if !errors.As(err, &merr) || merr.Stage != "add keyslot" || merr.State != fipsStateOriginals {
		t.Fatalf("want an add-keyslot failure reporting the originals intact, got %#v", err)
	}
	if fileDigest(t, device) != before {
		t.Fatal("a failed add changed the device")
	}
	if err := TestKey(device, migrationPassphrase); err != nil {
		t.Fatalf("the volume no longer opens after a failed migration: %v", err)
	}
}

// TestMigrateToFIPSRefusesAHashFIPSModeCannotRun: the new keyslot must itself
// be approved, so sha1 is refused before the device is touched.
func TestMigrateToFIPSRefusesAHashFIPSModeCannotRun(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}

	device := newImage(t, "sha1-option.img")
	formatWithLibrary(t, device)
	before := fileDigest(t, device)

	_, err := MigrateToFIPS(device, migrationPassphrase, &FIPSMigrationOptions{Hash: "sha1", PBKDFIterTime: 1})
	if !errors.Is(err, ErrUnsupportedHash) {
		t.Fatalf("got %v, want ErrUnsupportedHash", err)
	}
	if fileDigest(t, device) != before {
		t.Fatal("the refusal changed the device")
	}
}

// fakeArgon2KeyslotVolume relabels a PBKDF2 container's keyslot as Argon2id.
// The material no longer matches -- nothing will ever derive it -- but the
// header is well-formed, and under FIPS the refusal happens before any
// derivation, which is exactly the path being pinned. It is buildable in a
// FIPS process, which a real Argon2 container is not.
func fakeArgon2KeyslotVolume(t *testing.T, name string) string {
	t.Helper()

	device := newImage(t, name)
	formatWithLibrary(t, device)
	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	cost, memory, cpus := MinArgon2Time, MinArgon2MemoryKB, 1
	kdf := metadata.Keyslots["0"].KDF
	kdf.Type, kdf.Hash, kdf.Iterations = KDFTypeArgon2id, "", nil
	kdf.Time, kdf.Memory, kdf.CPUs = &cost, &memory, &cpus
	hdr.SequenceID++
	if err := writeHeaderUnvalidated(device, hdr, metadata); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}
	return device
}

// TestFIPSRefusalOfAnArgon2VolumeNamesTheImport pins the operator-facing error.
// In FIPS mode the refusal must say the volume is intact, what it uses, and that
// MigrateToFIPS is the remedy -- not "invalid keyslot", which reads as damage.
// Outside FIPS mode the same header is judged normally and must NOT claim a
// FIPS refusal.
func TestFIPSRefusalOfAnArgon2VolumeNamesTheImport(t *testing.T) {
	device := fakeArgon2KeyslotVolume(t, "fips-refusal-message.img")
	err := TestKey(device, migrationPassphrase)

	if !fips140.Enabled() {
		if errors.Is(err, ErrFIPSImportRequired) {
			t.Fatalf("a non-FIPS process reported a FIPS refusal: %v", err)
		}
		if !errors.Is(err, ErrMasterKeyVerification) {
			t.Fatalf("outside FIPS the relabelled keyslot is derived and does not verify; got %v", err)
		}
		return
	}

	assertImportRequired(t, err, device, []NonApprovedKDF{{ID: "0", Type: KDFTypeArgon2id}}, nil)
}

// TestFIPSRefusalNamesANonApprovedDigest is the digest half: an approved
// keyslot attested only by a SHA-1 digest is just as unopenable under FIPS, and
// the error must name the digest rather than call the header broken.
func TestFIPSRefusalNamesANonApprovedDigest(t *testing.T) {
	device := newImage(t, "fips-digest-message.img")
	formatWithLibrary(t, device)
	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	digest := metadata.Digests["0"]
	digest.Hash = "sha1"
	digest.Iterations = 1000
	digest.Digest = encodeBase64(bytes.Repeat([]byte{0x5a}, 20))
	hdr.SequenceID++
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}

	err = TestKey(device, migrationPassphrase)
	if !fips140.Enabled() {
		if errors.Is(err, ErrFIPSImportRequired) {
			t.Fatalf("a non-FIPS process reported a FIPS refusal: %v", err)
		}
		return
	}
	assertImportRequired(t, err, device, nil, []NonApprovedKDF{{ID: "0", Type: KDFTypePBKDF2, Hash: "sha1"}})
}

// TestFIPSRefusalDoesNotMaskDamage: when a keyslot could not be tried for a
// reason OTHER than FIPS, the scan reports that, not the import remedy. A
// migration would not fix a damaged keyslot, and saying "intact" would be false.
func TestFIPSRefusalDoesNotMaskDamage(t *testing.T) {
	device := fakeArgon2KeyslotVolume(t, "fips-and-damage.img")
	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	damaged := *metadata.Keyslots["0"]
	area := *damaged.Area
	area.Encryption = "serpent-xts-plain64"
	damaged.Area = &area
	iterations := 1000
	damaged.KDF = &KDF{Type: KDFTypePBKDF2, Hash: DefaultHashAlgo, Salt: damaged.KDF.Salt, Iterations: &iterations}
	metadata.Keyslots["1"] = &damaged
	metadata.Digests["0"].Keyslots = append(metadata.Digests["0"].Keyslots, "1")
	hdr.SequenceID++
	if err := writeHeaderUnvalidated(device, hdr, metadata); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}

	err = TestKey(device, migrationPassphrase)
	if err == nil {
		t.Fatal("TestKey succeeded on a volume nothing can open")
	}
	if errors.Is(err, ErrFIPSImportRequired) {
		t.Fatalf("a volume with a damaged keyslot was reported as merely needing the FIPS import: %v", err)
	}
}

// assertImportRequired checks the typed error, its matching, and the words an
// operator needs.
func assertImportRequired(t *testing.T, err error, device string, keyslots, digests []NonApprovedKDF) {
	t.Helper()

	var ierr *FIPSImportRequiredError
	if !errors.As(err, &ierr) {
		t.Fatalf("got %v, want a *FIPSImportRequiredError", err)
	}
	if !errors.Is(err, ErrFIPSImportRequired) || !errors.Is(err, ErrFIPSNotApproved) {
		t.Fatal("the error must match ErrFIPSImportRequired and, for existing callers, ErrFIPSNotApproved")
	}
	if errors.Is(err, ErrInvalidKeyslot) || errors.Is(err, ErrInvalidHeader) {
		t.Fatal("the error must not match a damage sentinel; the volume is not damaged")
	}
	if ierr.Device != device || !slices.Equal(ierr.Keyslots, keyslots) || !slices.Equal(ierr.Digests, digests) {
		t.Fatalf("error names device %q keyslots %v digests %v, want %q %v %v",
			ierr.Device, ierr.Keyslots, ierr.Digests, device, keyslots, digests)
	}
	msg := err.Error()
	for _, want := range []string{"intact", "FIPS 140-3 mode", "MigrateToFIPS", "NOT in FIPS mode", "without re-encrypting"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message lacks %q: %s", want, msg)
		}
	}
	for _, k := range append(slices.Clone(keyslots), digests...) {
		if !strings.Contains(msg, k.String()) {
			t.Errorf("error message does not name %s: %s", k, msg)
		}
	}
}

// TestFIPSApprovedKDFIncludesTheHash: on disk PBKDF2 is type "pbkdf2" plus a
// hash, and pbkdf2 over sha1 is not approved even though the type is.
func TestFIPSApprovedKDFIncludesTheHash(t *testing.T) {
	cases := []struct {
		kdfType, hash string
		want          bool
	}{
		{"pbkdf2", "sha256", true},
		{"pbkdf2", "SHA512", true},
		{"pbkdf2", "sha384", true},
		{"pbkdf2", "sha1", false},
		{"pbkdf2", "", false},
		{"argon2id", "", false},
		{"argon2i", "sha256", false},
		{"scrypt", "", false},
	}
	for _, c := range cases {
		if got := fipsApprovedKDF(c.kdfType, c.hash); got != c.want {
			t.Errorf("fipsApprovedKDF(%q, %q) = %v, want %v", c.kdfType, c.hash, got, c.want)
		}
	}
}
