package cli

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// fipsModeChildEnv names, in the FIPS-mode child, the Argon2 volume the
// non-FIPS parent built for it.
const fipsModeChildEnv = "LUKS2_CLI_FIPS_MODE_VOLUME"

// docs/fips/cli.md: what the commands do in FIPS mode. FIPS mode is fixed at
// process start, so the rows run in a child started under
// GODEBUG=fips140=only, on an Argon2id volume a non-FIPS process built (FIPS
// mode cannot write one). A FIPS-mode test binary first re-runs this test
// with FIPS mode off, to build that volume.
func TestFIPSModeCLIRows(t *testing.T) {
	if path := os.Getenv(fipsModeChildEnv); path != "" {
		if !fipsProcess {
			t.Fatal("the FIPS child did not start in FIPS mode")
		}
		assertFIPSModeCLIRows(t, path)
		return
	}
	if fipsProcess {
		rerunFIPSModeTest(t, "GODEBUG=fips140=off")
		return
	}
	path := newTestVolumeImage(t, "fips-mode-argon2.img")
	rerunFIPSModeTest(t, "GODEBUG=fips140=only", fipsModeChildEnv+"="+path)
}

// rerunFIPSModeTest runs TestFIPSModeCLIRows again in a child with the given
// extra environment, and fails unless the child passed it.
func rerunFIPSModeTest(t *testing.T, extra ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFIPSModeCLIRows$", "-test.v") // #nosec G204 -- this test binary, re-executed
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "GODEBUG=") || strings.HasPrefix(kv, fipsModeChildEnv+"=")
	})
	cmd.Env = append(env, extra...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child (%v) failed: %v\n%s", extra, err, out)
	}
	if !bytes.Contains(out, []byte("--- PASS: TestFIPSModeCLIRows")) {
		t.Fatalf("child (%v) did not run the test:\n%s", extra, out)
	}
}

func assertFIPSModeCLIRows(t *testing.T, argon2Volume string) {
	t.Helper()
	ctx := context.Background()

	// open and testkey unlock the volume, so an Argon2-only volume fails
	// with the FIPS-import error; testkey does not report "opens" and open
	// activates nothing.
	t.Run("testkey refuses an Argon2-only volume", func(t *testing.T) {
		e, _, _, stdout, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
		err := runTestKey(ctx, e, []string{argon2Volume})
		if !errors.Is(err, luks2.ErrFIPSImportRequired) {
			t.Fatalf("runTestKey = %v, want ErrFIPSImportRequired", err)
		}
		if strings.Contains(stdout.String(), "opens") {
			t.Errorf("stdout = %q, want no \"opens\" verdict", stdout.String())
		}
	})
	t.Run("open refuses an Argon2-only volume", func(t *testing.T) {
		e, act, _, _, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
		err := runOpen(ctx, e, []string{argon2Volume, "fips-open"})
		if !errors.Is(err, luks2.ErrFIPSImportRequired) {
			t.Fatalf("runOpen = %v, want ErrFIPSImportRequired", err)
		}
		if len(act.activated) != 0 {
			t.Errorf("activated = %v, want nothing activated", act.activated)
		}
	})

	// isluks, header show and keyslots only read: FIPS mode does not affect
	// them, even on a volume whose keyslots it cannot derive.
	readers := []struct {
		name string
		run  func(context.Context, *env, []string) error
		args []string
	}{
		{"isluks", runIsLUKS, []string{"--luks2", argon2Volume}},
		{"header show", runHeaderShow, []string{argon2Volume}},
		{"keyslots", runKeyslots, []string{argon2Volume}},
	}
	for _, r := range readers {
		t.Run(r.name+" reads an Argon2-only volume", func(t *testing.T) {
			e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})
			if err := r.run(ctx, e, r.args); err != nil {
				t.Fatalf("%s: %v", r.name, err)
			}
			if stdout.Len() == 0 {
				t.Errorf("%s printed nothing", r.name)
			}
		})
	}

	// create with no KDF options works and writes a PBKDF2-SHA512 keyslot.
	t.Run("create with no KDF options writes PBKDF2-SHA512", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "fips-create.luks")
		e, _, _, _, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
		if err := runCreate(ctx, e, []string{path, "24M"}); err != nil {
			t.Fatalf("runCreate: %v", err)
		}
		v, err := luks2.Open(ctx, path, luks2.WithReadOnly())
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer func() { _ = v.Close() }()
		h, err := v.Header(ctx)
		if err != nil {
			t.Fatalf("Header: %v", err)
		}
		slots := h.Keyslots()
		if len(slots) != 1 {
			t.Fatalf("keyslots = %d, want 1", len(slots))
		}
		if kdf := slots[0].KDF; kdf.Type != luks2.KDFPBKDF2 || kdf.Hash != crypto.SHA512 {
			t.Errorf("keyslot 0 KDF = %s/%v, want pbkdf2/SHA-512", kdf.Type, kdf.Hash)
		}
	})
}
