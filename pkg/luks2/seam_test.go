// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2_test

// The seam APIs the Release criteria in docs/SPEC.md name for
// go-trusted-platform, driven the way that consumer drives them: exported
// API only, a volume file under t.TempDir(), no root. Each test is one
// contract a downstream caller relies on; the package's own tests pin the
// internals behind it.
//
// The FIPS cases run in child processes of this test binary with GODEBUG
// set to the mode each step needs, so every one of them runs, and is judged,
// in both a plain `go test` and `make test-fips-mode`.

import (
	"bytes"
	"context"
	"crypto/fips140"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/pkg/keyprovider"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

const (
	seamPassphrase = "seam-passphrase-one"
	seamImageSize  = 32 << 20

	seamRoleEnv  = "LUKS2_SEAM_CHILD_ROLE"
	seamImageEnv = "LUKS2_SEAM_CHILD_IMAGE"

	seamRoleFormatArgon2  = "format-argon2"
	seamRoleArgon2Refused = "argon2-refused"
	seamRoleUnlock        = "unlock"
	seamRoleMigrate       = "migrate"

	seamChildOK     = 0
	seamChildFailed = 1
)

func init() {
	role := os.Getenv(seamRoleEnv)
	if role == "" {
		return
	}
	os.Exit(runSeamChildRole(role, os.Getenv(seamImageEnv)))
}

// seamKDF is the cheapest PBKDF2 cost the caller-supplied policy accepts:
// the floor still applies, so this is the production floor, not a test
// shortcut around it.
func seamKDF() luks2.KDFParams {
	return luks2.KDFParams{Type: luks2.KDFPBKDF2, IterTime: time.Millisecond}
}

func seamSecret(t testing.TB, text string) enclave.ByteAccess {
	t.Helper()
	e, err := enclave.NewMemoryCopy([]byte(text))
	if err != nil {
		t.Fatalf("could not build a credential enclave: %v", err)
	}
	t.Cleanup(func() { _ = e.Destroy() })
	return e
}

func seamImage(t testing.TB) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seam.img")
	if err := createSeamImage(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func createSeamImage(path string) error {
	f, err := os.Create(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		return err
	}
	if err := f.Truncate(seamImageSize); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// seamVolume formats a fresh PBKDF2 volume for seamPassphrase and returns
// it open.
func seamVolume(t *testing.T) *luks2.Volume {
	t.Helper()
	v, err := luks2.Open(context.Background(), seamImage(t))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	if err := v.Format(context.Background(), seamSecret(t, seamPassphrase), luks2.FormatParams{KDF: seamKDF()}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}
	return v
}

func seamUnlock(t *testing.T, v *luks2.Volume, pass string) *luks2.Key {
	t.Helper()
	key, err := v.Unlock(context.Background(), seamSecret(t, pass))
	if err != nil {
		t.Fatalf("Unlock(%q) failed: %v", pass, err)
	}
	t.Cleanup(key.Destroy)
	return key
}

func assertWrongKey(t *testing.T, v *luks2.Volume, pass string) {
	t.Helper()
	key, err := v.Unlock(context.Background(), seamSecret(t, pass))
	if key != nil {
		key.Destroy()
	}
	if !errors.Is(err, luks2.ErrWrongKey) {
		t.Fatalf("Unlock(%q) = %v, want ErrWrongKey", pass, err)
	}
}

// TestSeamAddKeyslotThenUnlock: a passphrase added to a volume opens it,
// through the keyslot AddKeyslot reported, and the original still does.
func TestSeamAddKeyslotThenUnlock(t *testing.T) {
	v := seamVolume(t)
	key := seamUnlock(t, v, seamPassphrase)

	info, err := v.AddKeyslot(context.Background(), key, seamSecret(t, "seam-passphrase-two"), luks2.KeyslotParams{KDF: seamKDF()})
	if err != nil {
		t.Fatalf("AddKeyslot failed: %v", err)
	}
	if info.ID == key.Keyslot() {
		t.Fatalf("AddKeyslot reused keyslot %d, the one the key came from", info.ID)
	}

	if got := seamUnlock(t, v, "seam-passphrase-two").Keyslot(); got != info.ID {
		t.Errorf("the added passphrase opened keyslot %d, want %d", got, info.ID)
	}
	if got := seamUnlock(t, v, seamPassphrase).Keyslot(); got != key.Keyslot() {
		t.Errorf("the original passphrase opened keyslot %d, want %d", got, key.Keyslot())
	}
}

// TestSeamChangeKeyslotRotatesThePassphrase: after ChangeKeyslot the new
// passphrase opens the same slot and the old one opens nothing.
func TestSeamChangeKeyslotRotatesThePassphrase(t *testing.T) {
	v := seamVolume(t)
	key := seamUnlock(t, v, seamPassphrase)

	info, err := v.ChangeKeyslot(context.Background(), key, seamSecret(t, "seam-passphrase-rotated"), luks2.KeyslotParams{KDF: seamKDF()})
	if err != nil {
		t.Fatalf("ChangeKeyslot failed: %v", err)
	}
	if got := seamUnlock(t, v, "seam-passphrase-rotated").Keyslot(); got != info.ID {
		t.Errorf("the rotated passphrase opened keyslot %d, want %d", got, info.ID)
	}
	assertWrongKey(t, v, seamPassphrase)
}

// TestSeamRemoveKeyslotRetiresASlot: a removed slot's passphrase opens
// nothing, the remaining one still opens the volume, and the last slot that
// can open it is refused.
func TestSeamRemoveKeyslotRetiresASlot(t *testing.T) {
	v := seamVolume(t)
	key := seamUnlock(t, v, seamPassphrase)
	info, err := v.AddKeyslot(context.Background(), key, seamSecret(t, "seam-passphrase-retired"), luks2.KeyslotParams{KDF: seamKDF()})
	if err != nil {
		t.Fatalf("AddKeyslot failed: %v", err)
	}

	if err := v.RemoveKeyslot(context.Background(), info.ID); err != nil {
		t.Fatalf("RemoveKeyslot(%d) failed: %v", info.ID, err)
	}
	assertWrongKey(t, v, "seam-passphrase-retired")
	seamUnlock(t, v, seamPassphrase)

	if err := v.RemoveKeyslot(context.Background(), key.Keyslot()); !errors.Is(err, luks2.ErrLastKeyslot) {
		t.Fatalf("RemoveKeyslot of the last slot = %v, want ErrLastKeyslot", err)
	}
	seamUnlock(t, v, seamPassphrase)
}

// TestSeamRecoveryKeyOpensTheVolume: the text NewRecoveryKey prints, enrolled
// with AddRecoveryKey, opens the volume once read back through
// ParseRecoveryKey.
func TestSeamRecoveryKeyOpensTheVolume(t *testing.T) {
	v := seamVolume(t)
	key := seamUnlock(t, v, seamPassphrase)

	rk, err := luks2.NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey failed: %v", err)
	}
	defer rk.Destroy()

	enrollment, err := v.AddRecoveryKey(context.Background(), key, rk, luks2.KeyslotParams{KDF: seamKDF()})
	if err != nil {
		t.Fatalf("AddRecoveryKey failed: %v", err)
	}

	var printed bytes.Buffer
	if _, err := rk.WriteTo(&printed); err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	typed, err := luks2.ParseRecoveryKey(seamSecret(t, printed.String()))
	if err != nil {
		t.Fatalf("ParseRecoveryKey of the printed key failed: %v", err)
	}
	t.Cleanup(func() { _ = typed.Destroy() })

	unlocked, err := v.Unlock(context.Background(), typed)
	if err != nil {
		t.Fatalf("Unlock with the recovery key failed: %v", err)
	}
	defer unlocked.Destroy()
	if unlocked.Keyslot() != enrollment.Keyslot.ID {
		t.Errorf("the recovery key opened keyslot %d, want %d", unlocked.Keyslot(), enrollment.Keyslot.ID)
	}
}

// consumerProvider is a KeyProvider the consumer writes itself, as
// go-trusted-platform does for the TPM.
type consumerProvider struct {
	credential string
	token      luks2.Token
}

func (p consumerProvider) Passphrase(context.Context) (enclave.ByteAccess, error) {
	return enclave.NewMemoryCopy([]byte(p.credential))
}

func (p consumerProvider) Token() luks2.Token { return p.token }

// assertEnrollAndUnlock enrolls p and unlocks with it, and checks that the
// provider's keyslot is the one that opened, and that a token was written
// exactly when the provider names one.
func assertEnrollAndUnlock(t *testing.T, p luks2.KeyProvider, unlockWith func(luks2.Token) (luks2.KeyProvider, error)) {
	t.Helper()
	v := seamVolume(t)
	key := seamUnlock(t, v, seamPassphrase)

	enrollment, err := v.Enroll(context.Background(), key, p, luks2.KeyslotParams{KDF: seamKDF()})
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}

	// The binding as unlock time sees it: the token Enroll recorded on the
	// device, or, for an anonymous provider, the keyslot the caller kept.
	recorded := luks2.Token{Keyslots: []int{enrollment.Keyslot.ID}}
	if p.Token().Type != "" {
		h, err := v.Header(context.Background())
		if err != nil {
			t.Fatalf("Header failed: %v", err)
		}
		tok, ok := h.Tokens()[enrollment.Token]
		if !ok {
			t.Fatalf("Enroll reported token %d, and the header has no such token", enrollment.Token)
		}
		if tok.Type != p.Token().Type || !slices.Equal(tok.Keyslots, []int{enrollment.Keyslot.ID}) {
			t.Fatalf("recorded token %q for keyslots %v, want %q for [%d]", tok.Type, tok.Keyslots, p.Token().Type, enrollment.Keyslot.ID)
		}
		recorded = tok
	} else if enrollment.Token != -1 {
		t.Errorf("Enroll wrote token %d for an anonymous provider, want -1", enrollment.Token)
	}

	provider, err := unlockWith(recorded)
	if err != nil {
		t.Fatalf("could not build the unlock provider: %v", err)
	}
	unlocked, err := v.UnlockWithProvider(context.Background(), provider)
	if err != nil {
		t.Fatalf("UnlockWithProvider failed: %v", err)
	}
	defer unlocked.Destroy()
	if unlocked.Keyslot() != enrollment.Keyslot.ID {
		t.Errorf("UnlockWithProvider opened keyslot %d, want the enrolled %d", unlocked.Keyslot(), enrollment.Keyslot.ID)
	}
}

func TestSeamEnrollAConsumerKeyProvider(t *testing.T) {
	const credential = "consumer-sealed-credential"
	unlockWith := func(tok luks2.Token) (luks2.KeyProvider, error) {
		return consumerProvider{credential: credential, token: tok}, nil
	}
	t.Run("named", func(t *testing.T) {
		assertEnrollAndUnlock(t, consumerProvider{credential: credential, token: luks2.Token{Type: "consumer-tpm2"}}, unlockWith)
	})
	t.Run("anonymous", func(t *testing.T) {
		assertEnrollAndUnlock(t, consumerProvider{credential: credential}, unlockWith)
	})
}

// privateHelperDir is a directory only this user can write, which is what
// keyprovider demands of the path to a helper it runs.
func privateHelperDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeHelper(t *testing.T, name, stdout string) string {
	t.Helper()
	path := filepath.Join(privateHelperDir(t), name)
	script := "#!/bin/sh\ncat > /dev/null\nprintf '%s' '" + stdout + "'\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatal(err)
	}
	return path
}

func TestSeamEnrollACommandKeyProvider(t *testing.T) {
	helper := writeHelper(t, "tpm-helper", "helper-sealed-credential\n")
	p, err := keyprovider.NewCommand(helper, keyprovider.WithLine(1), keyprovider.WithToken(luks2.Token{Type: "consumer-tpm2"}))
	if err != nil {
		t.Fatalf("NewCommand failed: %v", err)
	}
	assertEnrollAndUnlock(t, p, func(tok luks2.Token) (luks2.KeyProvider, error) {
		return keyprovider.NewCommand(helper, keyprovider.WithLine(1), keyprovider.WithToken(tok))
	})
}

func TestSeamEnrollAFIDO2KeyProvider(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5a}, keyprovider.SecretLength)
	assertion := strings.Join([]string{
		base64.StdEncoding.EncodeToString([]byte("client data hash")),
		keyprovider.DefaultRelyingParty,
		base64.StdEncoding.EncodeToString([]byte("authdata")),
		base64.StdEncoding.EncodeToString([]byte("signature")),
		base64.StdEncoding.EncodeToString(secret),
	}, "\n") + "\n"

	salt, err := keyprovider.NewFIDO2Salt()
	if err != nil {
		t.Fatalf("NewFIDO2Salt failed: %v", err)
	}
	tools := keyprovider.WithFIDO2Tools("", writeHelper(t, "fido2-assert", assertion))
	device := keyprovider.WithDevice("/dev/hidraw0")
	p, err := keyprovider.NewFIDO2(keyprovider.FIDO2Params{
		CredentialID: []byte("credential-id"),
		Salt:         salt,
		UserPresence: true,
	}, tools, device)
	if err != nil {
		t.Fatalf("NewFIDO2 failed: %v", err)
	}
	if got := p.Token().Type; got != keyprovider.TokenTypeFIDO2 {
		t.Fatalf("FIDO2 token type = %q, want %q", got, keyprovider.TokenTypeFIDO2)
	}
	// Unlock rebuilds the provider from the token read back from the header,
	// as a boot path does, not from the enrollment options. The rebuilt
	// provider names the token's keyslots, the only ones UnlockWithProvider
	// tries, so the caller unlocks with it as it is.
	assertEnrollAndUnlock(t, p, func(tok luks2.Token) (luks2.KeyProvider, error) {
		return keyprovider.FromToken(tok, tools, device)
	})
}

// TestSeamFIPSArgon2IsRefused: a FIPS process can neither format nor add an
// Argon2 keyslot, and says FIPS refused it.
func TestSeamFIPSArgon2IsRefused(t *testing.T) {
	if out := runSeamChildOK(t, seamRoleArgon2Refused, "", "fips140=only", true); out != "" {
		t.Fatalf("child output: %s", out)
	}
}

// TestSeamFIPSUnlockRefusesAnArgon2VolumeThenMigrateToFIPSImportsIt: in a
// FIPS process Unlock refuses an Argon2 volume with ErrFIPSImportRequired and
// returns no key, so none can reach dmcrypt.Activate; MigrateToFIPS is
// refused there and imports the volume in a non-FIPS process; and a FIPS
// process then unlocks it.
func TestSeamFIPSUnlockRefusesAnArgon2VolumeThenMigrateToFIPSImportsIt(t *testing.T) {
	image := filepath.Join(t.TempDir(), "argon2.img")
	if err := createSeamImage(image); err != nil {
		t.Fatal(err)
	}

	runSeamChildOK(t, seamRoleFormatArgon2, image, "fips140=off", false)

	if code, out := runSeamChild(t, seamRoleUnlock, image, "fips140=only", true); code != seamChildFailed ||
		!strings.Contains(out, "import required") {
		t.Fatalf("FIPS Unlock of the Argon2 volume: exit %d, want a refusal\n%s", code, out)
	}
	if code, out := runSeamChild(t, seamRoleMigrate, image, "fips140=only", true); code != seamChildFailed ||
		!strings.Contains(out, "migration refused") {
		t.Fatalf("FIPS MigrateToFIPS: exit %d, want a refusal\n%s", code, out)
	}

	runSeamChildOK(t, seamRoleMigrate, image, "fips140=off", false)
	runSeamChildOK(t, seamRoleUnlock, image, "fips140=only", true)
}

func runSeamChildOK(t *testing.T, role, image, godebug string, wantFIPS bool) string {
	t.Helper()
	code, out := runSeamChild(t, role, image, godebug, wantFIPS)
	if code != seamChildOK {
		t.Fatalf("child %q with GODEBUG=%s exited %d\n%s", role, godebug, code, out)
	}
	return out
}

// runSeamChild re-executes this test binary in role under godebug, checks
// it ran in the FIPS mode asked for, and returns its exit code and the rest
// of its output.
func runSeamChild(t *testing.T, role, image, godebug string, wantFIPS bool) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0]) // #nosec G204 -- this test binary, re-executed
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "GODEBUG=") || strings.HasPrefix(kv, seamRoleEnv+"=") || strings.HasPrefix(kv, seamImageEnv+"=")
	})
	cmd.Env = append(env, "GODEBUG="+godebug, seamRoleEnv+"="+role, seamImageEnv+"="+image)
	var stderr strings.Builder
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	code := 0
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	default:
		t.Fatalf("child %q could not be run: %v", role, err)
	}

	wantMode := fmt.Sprintf("fips140.Enabled=%v\n", wantFIPS)
	stdout := string(out)
	if !strings.HasPrefix(stdout, wantMode) {
		t.Fatalf("child %q with GODEBUG=%s did not run in the FIPS mode asked for (want %q)\nstdout:\n%s\nstderr:\n%s",
			role, godebug, strings.TrimSpace(wantMode), stdout, stderr.String())
	}
	return code, strings.TrimPrefix(stdout, wantMode)
}

// runSeamChild's other half: the child's body, exported API only. It prints
// nothing on success; on failure it prints why and returns seamChildFailed.
func runSeamChildRole(role, image string) int {
	fmt.Printf("fips140.Enabled=%v\n", fips140.Enabled())
	if err := seamChild(role, image); err != nil {
		fmt.Println(err)
		return seamChildFailed
	}
	return seamChildOK
}

func seamChild(role, image string) error {
	ctx := context.Background()
	pass, err := enclave.NewMemoryCopy([]byte(seamPassphrase))
	if err != nil {
		return err
	}
	defer func() { _ = pass.Destroy() }()

	switch role {
	case seamRoleFormatArgon2:
		v, err := luks2.Open(ctx, image)
		if err != nil {
			return err
		}
		defer func() { _ = v.Close() }()
		return v.Format(ctx, pass, luks2.FormatParams{KDF: seamArgon2KDF()})

	case seamRoleArgon2Refused:
		dir, err := os.MkdirTemp("", "seam-argon2-")
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(dir) }()
		return seamArgon2Refused(ctx, filepath.Join(dir, "argon2.img"), pass)

	case seamRoleUnlock:
		v, err := luks2.Open(ctx, image)
		if err != nil {
			return err
		}
		defer func() { _ = v.Close() }()
		key, err := v.Unlock(ctx, pass)
		if err == nil {
			key.Destroy()
			return nil
		}
		var importErr *luks2.FIPSImportRequiredError
		if key == nil && errors.Is(err, luks2.ErrFIPSImportRequired) && errors.As(err, &importErr) && len(importErr.Keyslots) > 0 {
			return fmt.Errorf("import required, no key returned: %w", err)
		}
		return fmt.Errorf("unlock failed (key returned: %v): %w", key != nil, err)

	case seamRoleMigrate:
		v, err := luks2.Open(ctx, image)
		if err != nil {
			return err
		}
		defer func() { _ = v.Close() }()
		m, err := v.MigrateToFIPS(ctx, pass, luks2.MigrateParams{KDF: seamKDF()})
		if err != nil {
			var merr *luks2.FIPSMigrationError
			if fips140.Enabled() && errors.Is(err, luks2.ErrFIPSMigration) && errors.As(err, &merr) {
				return fmt.Errorf("migration refused: %w", err)
			}
			return err
		}
		if !m.Complete || !m.KeyslotAdded || len(m.RemovedKeyslots) != 1 {
			return fmt.Errorf("migration %+v, want complete with the one Argon2 keyslot replaced", *m)
		}
		return nil

	default:
		return fmt.Errorf("unknown role %q", role)
	}
}

func seamArgon2KDF() luks2.KDFParams {
	return luks2.KDFParams{Type: luks2.KDFArgon2id, Time: 4, MemoryKiB: 64 * 1024, Parallel: 1}
}

// seamArgon2Refused runs in a FIPS process: Format and AddKeyslot with
// Argon2 must both be refused as not approved, and a PBKDF2 volume must
// still be made.
func seamArgon2Refused(ctx context.Context, image string, pass enclave.ByteAccess) error {
	if !fips140.Enabled() {
		return errors.New("not a FIPS process")
	}
	if err := createSeamImage(image); err != nil {
		return err
	}
	v, err := luks2.Open(ctx, image)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	if err := v.Format(ctx, pass, luks2.FormatParams{KDF: seamArgon2KDF()}); !errors.Is(err, luks2.ErrFIPSNotApproved) {
		return fmt.Errorf("Format with Argon2 in FIPS mode = %v, want ErrFIPSNotApproved", err)
	}
	if err := v.Format(ctx, pass, luks2.FormatParams{KDF: seamKDF()}); err != nil {
		return fmt.Errorf("Format with PBKDF2 in FIPS mode: %w", err)
	}
	key, err := v.Unlock(ctx, pass)
	if err != nil {
		return fmt.Errorf("Unlock in FIPS mode: %w", err)
	}
	defer key.Destroy()
	other, err := enclave.NewMemoryCopy([]byte("seam-passphrase-argon2"))
	if err != nil {
		return err
	}
	defer func() { _ = other.Destroy() }()
	if _, err := v.AddKeyslot(ctx, key, other, luks2.KeyslotParams{KDF: seamArgon2KDF()}); !errors.Is(err, luks2.ErrFIPSNotApproved) {
		return fmt.Errorf("AddKeyslot with Argon2 in FIPS mode = %v, want ErrFIPSNotApproved", err)
	}
	return nil
}
