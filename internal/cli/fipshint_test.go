// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// fipsHintChildEnv marks the re-executed test binary that runs the FIPS
// assertions; the value is irrelevant.
const fipsHintChildEnv = "LUKS2_CLI_FIPS_HINT_CHILD"

const fipsHint = "In FIPS 140-3 mode use --pbkdf pbkdf2"

// TestKDFChoiceRefusedInFIPSModeCarriesTheHint proves every command that takes
// the shared KDF options refuses an Argon2 choice under FIPS 140-3 policy with
// ErrFIPSNotApproved and prints the hint that names the approved choice. FIPS
// mode is fixed at process start, so a non-FIPS run re-executes this test
// binary under GODEBUG=fips140=only and judges the child; a FIPS run (the
// full tier's FIPS job) asserts directly.
func TestKDFChoiceRefusedInFIPSModeCarriesTheHint(t *testing.T) {
	if fipsProcess {
		assertFIPSKDFHint(t)
		return
	}
	if os.Getenv(fipsHintChildEnv) != "" {
		t.Fatal("the FIPS child did not start in FIPS mode")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestKDFChoiceRefusedInFIPSModeCarriesTheHint$", "-test.v") // #nosec G204 -- this test binary, re-executed
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "GODEBUG=") || strings.HasPrefix(kv, fipsHintChildEnv+"=")
	})
	cmd.Env = append(env, "GODEBUG=fips140=only", fipsHintChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("FIPS child failed: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("--- PASS: "+t.Name())) {
		t.Fatalf("FIPS child did not run the assertions:\n%s", out)
	}
}

func assertFIPSKDFHint(t *testing.T) {
	t.Helper()

	path := newPlainImage(t, "fips-hint.img")
	cases := []struct {
		name string
		run  func(context.Context, *env, []string) error
		args []string
	}{
		{"create", runCreate, []string{path, "24M"}},
		{"recovery add", runRecoveryAdd, []string{path}},
		{"addkey", runAddKey, []string{path}},
		{"changekey", runChangeKey, []string{path, "0"}},
	}
	for _, c := range cases {
		for _, pbkdf := range []string{"argon2i", "argon2id"} {
			t.Run(c.name+" "+pbkdf, func(t *testing.T) {
				e, _, _, _, stderr := newTestEnv(&bytes.Buffer{})
				args := append([]string{"--pbkdf", pbkdf}, c.args...)
				err := c.run(context.Background(), e, args)
				if !errors.Is(err, luks2.ErrFIPSNotApproved) {
					t.Fatalf("want ErrFIPSNotApproved, got %v", err)
				}
				if !strings.Contains(stderr.String(), fipsHint) {
					t.Errorf("stderr lacks the FIPS hint: %q", stderr.String())
				}
			})
		}
	}
}
