// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package kdf_test

import (
	"context"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/kdf"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

const canonicalPassphrase = "conformance-test-passphrase"

func requireCryptsetupDeclared(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		t.Fatalf("cryptsetup is not installed (%v). This tier DECLARES it.", err)
	}
}

// changeKeyForTest unlocks slot with oldPass and replaces its credential
// with newPass, the way the pre-redesign library's
// luks2.ChangeKey(device, oldPass, newPass, slot) did before B.6 moved it
// behind (*luks2.Volume).ChangeKeyslot.
func changeKeyForTest(device string, oldPass, newPass []byte, slot int) error {
	ctx := context.Background()
	v, err := luks2.Open(ctx, device)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	old, err := enclave.NewMemoryCopy(oldPass)
	if err != nil {
		return err
	}
	defer func() { _ = old.Destroy() }()
	key, err := v.UnlockKeyslot(ctx, slot, old)
	if err != nil {
		return err
	}
	defer key.Destroy()

	newCred, err := enclave.NewMemoryCopy(newPass)
	if err != nil {
		return err
	}
	defer func() { _ = newCred.Destroy() }()

	_, err = v.ChangeKeyslot(ctx, key, newCred, luks2.KeyslotParams{})
	return err
}

func canonicalImage(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	f, err := os.Create(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to create %s: %v", path, err)
	}
	if err := f.Truncate(64 << 20); err != nil {
		_ = f.Close()
		t.Fatalf("failed to size %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close %s: %v", path, err)
	}
	return path
}

func formatWithCryptsetupForced(t *testing.T, path string, iterations int) {
	t.Helper()
	cmd := exec.Command("cryptsetup", "luksFormat", // #nosec G204 -- arguments are test constants
		"--type", "luks2",
		"--cipher", "aes-xts-plain64",
		"--key-size", "512",
		"--hash", "sha512",
		"--sector-size", "512",
		"--pbkdf", "pbkdf2",
		"--pbkdf-force-iterations", strconv.Itoa(iterations),
		"--batch-mode",
		path,
	)
	cmd.Stdin = strings.NewReader(canonicalPassphrase)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cryptsetup luksFormat: %v\n%s", err, out)
	}
}

// TestChangeKeyRaisesABelowFloorCostRatherThanRefusing is the asymmetry
// between the pbkdf2 and argon2 halves of ChangeKey's cost preservation.
// See kdfiterations_integration_test.go (now moved, from pkg/luks2) for the
// full reasoning. internal/kdf.PBKDF2IterationFloor,
// PBKDF2ReferenceTargetMs and MinPBKDF2Iterations are already exported
// (pkg/luks2's own pbkdf2IterationFloor/pbkdf2ReferenceTargetMs/
// minPBKDF2Iterations are thin aliases of them).
func TestChangeKeyRaisesABelowFloorCostRatherThanRefusing(t *testing.T) {
	requireCryptsetupDeclared(t)

	path := canonicalImage(t, "imported-weak.img")
	formatWithCryptsetupForced(t, path, kdf.MinPBKDF2Iterations)

	floor := int(math.Ceil(kdf.PBKDF2IterationFloor("sha512", kdf.PBKDF2ReferenceTargetMs)))

	_, before, err := harness.ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if got := before.Keyslots["0"].KDF.Iterations; got == nil || *got != kdf.MinPBKDF2Iterations {
		t.Fatalf("the fixture does not carry the below-floor count: %v", got)
	}
	if kdf.MinPBKDF2Iterations >= floor {
		t.Fatalf("the fixture's %d iterations are not below the sha512 floor of %d; this test measures nothing",
			kdf.MinPBKDF2Iterations, floor)
	}

	updated := []byte("the-replacement-credential")
	if err := changeKeyForTest(path, []byte(canonicalPassphrase), updated, 0); err != nil {
		t.Fatalf("ChangeKey refused a container carrying a below-floor cost: %v", err)
	}

	_, after, err := harness.ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	got := after.Keyslots["0"].KDF.Iterations
	if got == nil {
		t.Fatal("the keyslot has no iteration count after ChangeKey")
	}
	if *got != floor {
		t.Fatalf("ChangeKey wrote %d iterations, want the sha512 floor %d", *got, floor)
	}

	if err := harness.TestKey(path, updated); err != nil {
		t.Fatalf("the new passphrase does not open the volume after the cost was raised: %v", err)
	}
	if err := harness.TestKey(path, []byte(canonicalPassphrase)); err == nil {
		t.Fatal("the old passphrase still opens the volume")
	}
}
