package luks2

// Conformance tests for docs/fips/engineering.md: each test names the
// requirement it holds and fails if the code stops meeting it.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/fips140"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/internal/fips"
)

// openEngVolume opens an Argon2id volume image for the engineering.md
// conformance tests and returns it with its passphrase.
func openEngVolume(t *testing.T, name string) (string, *Volume) {
	t.Helper()
	path := argon2VolumeImage(t, name)
	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return path, v
}

// Error semantics: "Calling MigrateToFIPS from a FIPS process ... is reported
// this way [*FIPSMigrationError], at the precondition ... stage", and a
// precondition failure maps to StagePreflight, which implies nothing was
// written.
func TestEngMigrateToFIPSFromAFIPSProcessFailsAtPreflight(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}
	path, v := openEngVolume(t, "eng-preflight.img")
	before := fileDigest(t, path)

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()
	v.sys.fipsMode = func() fips.Mode { return true }

	m, err := v.MigrateToFIPS(context.Background(), pass, MigrateParams{KDF: cheapMigrationParams()})
	if m != nil {
		t.Errorf("MigrateToFIPS in a FIPS process returned a Migration %+v, want nil", m)
	}
	var merr *FIPSMigrationError
	if !errors.As(err, &merr) {
		t.Fatalf("MigrateToFIPS in a FIPS process = %v, want *FIPSMigrationError", err)
	}
	if merr.Stage != "precondition" || merr.MigrationStage() != StagePreflight {
		t.Errorf("Stage = %q (%v), want \"precondition\" (StagePreflight)", merr.Stage, merr.MigrationStage())
	}
	if !errors.Is(err, ErrFIPSMigration) || !errors.Is(err, errFIPSMigrationUnderFIPS) {
		t.Errorf("errors.Is(%v, ErrFIPSMigration and the cause) = false, want both", err)
	}
	if merr.State != fipsStateUntouched {
		t.Errorf("State = %q, want %q", merr.State, fipsStateUntouched)
	}
	if fileDigest(t, path) != before {
		t.Fatal("a migration refused at preflight changed the device")
	}
}

// Error semantics: a passphrase whose key matches no digest is reported as
// *FIPSMigrationError at a verify-phase stage, and the volume is untouched.
func TestEngMigrateToFIPSWithAWrongPassphraseFailsAtVerify(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}
	path, v := openEngVolume(t, "eng-wrongpass.img")
	before := fileDigest(t, path)

	wrong, err := enclave.NewMemoryCopy([]byte("not the passphrase of this volume"))
	if err != nil {
		t.Fatalf("NewMemoryCopy: %v", err)
	}
	defer func() { _ = wrong.Destroy() }()

	_, err = v.MigrateToFIPS(context.Background(), wrong, MigrateParams{KDF: cheapMigrationParams()})
	var merr *FIPSMigrationError
	if !errors.As(err, &merr) {
		t.Fatalf("MigrateToFIPS with a wrong passphrase = %v, want *FIPSMigrationError", err)
	}
	if merr.MigrationStage() != StageVerify {
		t.Errorf("Stage = %q (%v), want a StageVerify stage", merr.Stage, merr.MigrationStage())
	}
	if !errors.Is(err, ErrFIPSMigration) {
		t.Errorf("errors.Is(%v, ErrFIPSMigration) = false", err)
	}
	if merr.State != fipsStateUntouched {
		t.Errorf("State = %q, want %q", merr.State, fipsStateUntouched)
	}
	if fileDigest(t, path) != before {
		t.Fatal("a migration refused for a wrong passphrase changed the device")
	}
}

// Invariants: "SHA-1 is never written by any code path, in or out of FIPS
// mode", and the Approved KDFs table: PBKDF2 with SHA-1 is "Never written".
// Every public write that takes a KDFParams refuses SHA-1 under either policy
// and leaves the image as it was.
func TestEngSHA1IsNeverWrittenInOrOutOfFIPSMode(t *testing.T) {
	sha1KDF := KDFParams{Type: KDFPBKDF2, Hash: crypto.SHA1, IterTime: time.Millisecond}
	writes := []struct {
		name  string
		write func(v *Volume, key *Key, pass enclave.ByteAccess) error
	}{
		{"AddKeyslot", func(v *Volume, key *Key, pass enclave.ByteAccess) error {
			_, err := v.AddKeyslot(context.Background(), key, pass, KeyslotParams{KDF: sha1KDF})
			return err
		}},
		{"ChangeKeyslot", func(v *Volume, key *Key, pass enclave.ByteAccess) error {
			_, err := v.ChangeKeyslot(context.Background(), key, pass, KeyslotParams{KDF: sha1KDF})
			return err
		}},
		{"Format", func(v *Volume, _ *Key, pass enclave.ByteAccess) error {
			return v.Format(context.Background(), pass, FormatParams{KDF: sha1KDF})
		}},
	}
	for _, mode := range []bool{false, true} {
		for _, w := range writes {
			t.Run(fmt.Sprintf("%s fips=%v", w.name, mode), func(t *testing.T) {
				path := formattedVolumeImage(t, "eng-sha1.img", "", "")
				v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
				if err != nil {
					t.Fatalf("Open failed: %v", err)
				}
				defer func() { _ = v.Close() }()

				pass := newTestPassphrase(t)
				defer func() { _ = pass.Destroy() }()
				key, err := v.Unlock(context.Background(), pass)
				if err != nil {
					t.Fatalf("Unlock failed: %v", err)
				}
				defer key.Destroy()
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("snapshot: %v", err)
				}

				v.sys.fipsMode = func() fips.Mode { return fips.Mode(mode) }
				err = w.write(v, key, pass)
				if !errors.Is(err, ErrInvalidArgument) && !errors.Is(err, ErrFIPSNotApproved) {
					t.Fatalf("%s with PBKDF2-SHA1 = %v, want a refusal", w.name, err)
				}
				after, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("re-read: %v", err)
				}
				if !bytes.Equal(before, after) {
					t.Errorf("a refused %s with PBKDF2-SHA1 changed the image", w.name)
				}
			})
		}
	}
}

// Invariants: SHA-1 is never written. A MigrateParams.KDF naming SHA-1 is
// refused before any write and the volume is untouched.
func TestEngMigrateToFIPSRefusesASHA1TargetHash(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}
	path, v := openEngVolume(t, "eng-target-sha1.img")
	before := fileDigest(t, path)
	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	kdf := KDFParams{Type: KDFPBKDF2, Hash: crypto.SHA1, IterTime: time.Millisecond}
	m, err := v.MigrateToFIPS(context.Background(), pass, MigrateParams{KDF: kdf})
	if err == nil {
		t.Fatalf("MigrateToFIPS with a SHA-1 target hash succeeded (%+v), want a refusal", m)
	}
	if fileDigest(t, path) != before {
		t.Fatal("a refused MigrateToFIPS changed the device")
	}
}

// Invariants and Approved KDFs: MigrateParams.KDF sets only the new PBKDF2
// keyslot's cost and hash, so a caller naming an Argon2 type or cost still
// gets a volume whose every keyslot and digest is approved: the import never
// writes Argon2.
func TestEngMigrateToFIPSWritesOnlyApprovedKDFs(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}
	cases := []struct {
		name string
		kdf  KDFParams
	}{
		{"argon2id named", KDFParams{Type: KDFArgon2id, Time: 1, MemoryKiB: minArgon2MemoryKB, Parallel: 1}},
		{"argon2i named", KDFParams{Type: KDFArgon2i, Time: 1, MemoryKiB: minArgon2MemoryKB, Parallel: 1}},
		{"an argon2 cost and no type", KDFParams{MemoryKiB: minArgon2MemoryKB}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, v := openEngVolume(t, "eng-target-kdf.img")
			pass := newTestPassphrase(t)
			defer func() { _ = pass.Destroy() }()

			m, err := v.MigrateToFIPS(context.Background(), pass, MigrateParams{KDF: tc.kdf})
			if err != nil {
				t.Fatalf("MigrateToFIPS: %v", err)
			}
			if !m.Complete {
				t.Fatalf("Migration = %+v, want Complete", m)
			}
			_, metadata, err := readHeaderForTest(path)
			if err != nil {
				t.Fatalf("ReadHeader: %v", err)
			}
			for id, ks := range metadata.Keyslots {
				if ks.KDF == nil || ks.KDF.Type != kdfTypePBKDF2 || !isApprovedEngHash(ks.KDF.Hash) {
					t.Errorf("keyslot %s after the import has KDF %+v, want PBKDF2 with SHA-2", id, ks.KDF)
				}
			}
			for id, d := range metadata.Digests {
				if d.Type != kdfTypePBKDF2 || !isApprovedEngHash(d.Hash) {
					t.Errorf("digest %s after the import is %s/%s, want PBKDF2 with SHA-2", id, d.Type, d.Hash)
				}
			}
		})
	}
}

func isApprovedEngHash(h string) bool {
	switch h {
	case "sha256", "sha384", "sha512":
		return true
	}
	return false
}
