//go:build !integration

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
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
				// In FIPS mode the refusal is a FIPS one (SHA-1 is not an
				// approved PRF); outside it, an invalid argument.
				want, other := ErrInvalidArgument, ErrFIPSNotApproved
				if mode {
					want, other = ErrFIPSNotApproved, ErrInvalidArgument
				}
				if !errors.Is(err, want) || errors.Is(err, other) {
					t.Fatalf("%s with PBKDF2-SHA1 fips=%v = %v, want %v", w.name, mode, err, want)
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
// keyslot's cost and hash. A caller naming an Argon2 type or cost is refused
// with ErrFIPSNotApproved, the field named and the volume unchanged; a PBKDF2
// KDF migrates to a volume whose every keyslot and digest is approved: the
// import never writes Argon2.
func TestEngMigrateToFIPSWritesOnlyApprovedKDFs(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}
	// An Argon2 target KDF is refused before anything is written, with the
	// field named: the import writes PBKDF2 only and does not drop what the
	// caller asked for.
	refused := []struct {
		name, field string
		kdf         KDFParams
	}{
		{"argon2id named", "MigrateParams.KDF.Type", KDFParams{Type: KDFArgon2id, Time: 1, MemoryKiB: minArgon2MemoryKB, Parallel: 1}},
		{"argon2i named", "MigrateParams.KDF.Type", KDFParams{Type: KDFArgon2i, Time: 1, MemoryKiB: minArgon2MemoryKB, Parallel: 1}},
		{"an argon2 cost and no type", "MigrateParams.KDF.MemoryKiB", KDFParams{MemoryKiB: minArgon2MemoryKB}},
		{"an argon2 time and no type", "MigrateParams.KDF.Time", KDFParams{Time: 1}},
		{"an argon2 parallelism and no type", "MigrateParams.KDF.Parallel", KDFParams{Parallel: 1}},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			path, v := openEngVolume(t, "eng-target-kdf.img")
			pass := newTestPassphrase(t)
			defer func() { _ = pass.Destroy() }()
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("snapshot: %v", err)
			}

			m, err := v.MigrateToFIPS(context.Background(), pass, MigrateParams{KDF: tc.kdf})
			if !errors.Is(err, ErrFIPSNotApproved) || m != nil {
				t.Fatalf("MigrateToFIPS with %+v = %+v, %v; want ErrFIPSNotApproved", tc.kdf, m, err)
			}
			// A migration failure like any other: ErrFIPSMigration, typed,
			// at the precondition stage, with the volume untouched.
			if !errors.Is(err, ErrFIPSMigration) {
				t.Errorf("MigrateToFIPS with %+v: %v is not ErrFIPSMigration", tc.kdf, err)
			}
			var migration *FIPSMigrationError
			if !errors.As(err, &migration) {
				t.Fatalf("MigrateToFIPS with %+v: %v is not a *FIPSMigrationError", tc.kdf, err)
			}
			if migration.Stage != "precondition" || migration.State != fipsStateUntouched {
				t.Errorf("MigrateToFIPS with %+v: stage %q, state %q; want precondition, %q", tc.kdf, migration.Stage, migration.State, fipsStateUntouched)
			}
			if !errors.Is(migration.Err, ErrFIPSNotApproved) {
				t.Errorf("MigrateToFIPS with %+v: cause %v is not ErrFIPSNotApproved", tc.kdf, migration.Err)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("MigrateToFIPS error %q does not name %s", err, tc.field)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("re-read: %v", err)
			}
			if !bytes.Equal(before, after) {
				t.Errorf("a refused MigrateToFIPS (%s) changed the image", tc.name)
			}
		})
	}

	// A PBKDF2 target KDF still migrates, and only approved KDFs are written.
	for _, kdf := range []KDFParams{
		cheapMigrationParams(),
		{Type: KDFPBKDF2, Hash: crypto.SHA512, IterTime: time.Millisecond},
	} {
		t.Run(fmt.Sprintf("pbkdf2 %v", kdf.Hash), func(t *testing.T) {
			path, v := openEngVolume(t, "eng-target-kdf.img")
			pass := newTestPassphrase(t)
			defer func() { _ = pass.Destroy() }()

			m, err := v.MigrateToFIPS(context.Background(), pass, MigrateParams{KDF: kdf})
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

// Observability: "No logging; every failure above is a typed, returned
// error." Neither this package nor internal/fips imports a logger.
func TestEngFIPSCodeDoesNotLog(t *testing.T) {
	for _, dir := range []string{".", filepath.Join("..", "..", "internal", "fips")} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("listing %s: %v (%d files)", dir, err, len(files))
		}
		for _, name := range files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parsing %s: %v", name, err)
			}
			for _, imp := range f.Imports {
				if path := strings.Trim(imp.Path.Value, `"`); path == "log" || path == "log/slog" {
					t.Errorf("%s imports %s; FIPS failures are returned, never logged", name, path)
				}
			}
		}
	}
}

// Edge cases: "Under fips140=only, crypto/pbkdf2 also refuses a salt under
// 128 bits": a volume with no Argon2 at all, every way in through a
// short-salt PBKDF2-SHA256 digest, is classified with the salt as the reason
// and is not opened by a strict FIPS process, which leaves it as it was.
// Without cryptsetup: the fixture is the library's own PBKDF2 format,
// weakened in a fips140=off child.
//
// The open is refused as the *FIPSImportRequiredError the Error semantics
// section names, not as a damaged header: the pre-derivation screen passes
// the approved names, strict mode refuses the short salt at derivation, and
// the unlock classifier counts that keyslot as refused only by FIPS.
func TestEngAShortSaltPBKDF2VolumeIsNotOpenedInStrictMode(t *testing.T) {
	image := newImage(t, "eng-short-salt.img")
	if err := formatForTest(formatOptionsForTest{
		Device:        image,
		Passphrase:    []byte(conformancePassphrase),
		Cipher:        "aes",
		CipherMode:    "xts-plain64",
		KeySize:       512,
		HashAlgo:      "sha256",
		SectorSize:    512,
		KDFType:       kdfTypePBKDF2,
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}
	if code, out := runChild(t, childRoleWeaken, image, "fips140=off", false); code != childOK {
		t.Fatalf("weakening the fixture exited %d\n%s", code, out)
	}

	_, metadata, err := readHeaderForTest(image)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	keyslots, digests := nonApprovedKDFs(metadata)
	for _, k := range slices.Concat(keyslots, digests) {
		if k.Type != kdfTypePBKDF2 || k.Reason != "salt shorter than 128 bits" {
			t.Fatalf("fixture names %s, want only short-salt PBKDF2 with the salt as the reason", k)
		}
	}
	if len(digests) != 1 {
		t.Fatalf("fixture digests %v, want the one digest weakened", digests)
	}

	before := fileDigest(t, image)
	// Not opened, and the caller is told to import: the short salt is a FIPS
	// parameter refusal, so the open fails as *FIPSImportRequiredError, not as
	// a damaged header.
	if code, out := runChild(t, childRoleOpen, image, "fips140=only", true); code != childImportRequired {
		t.Fatalf("a strict FIPS open of a volume whose only digest has a short salt exited %d, want %d (*FIPSImportRequiredError)\n%s", code, childImportRequired, out)
	}
	if fileDigest(t, image) != before {
		t.Fatal("the refused open changed the device")
	}
}

// Edge cases: "A PBKDF2 keyslot or digest below either [a 128-bit salt or a
// 112-bit output] is treated like Argon2, and NonApprovedKDF.Reason names
// the parameter"; and Error semantics: the refusal is a
// *FIPSImportRequiredError that unwraps to both ErrFIPSImportRequired and
// ErrFIPSNotApproved, with the volume intact.
