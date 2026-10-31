// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// TestMissingArgsAcrossCommands drives every new command's "want
// <args>" usage-error branch, which a happy-path test never reaches.
func TestMissingArgsAcrossCommands(t *testing.T) {
	cases := []struct {
		name string
		run  func(context.Context, *env, []string) error
		args []string
	}{
		{"keyslots", runKeyslots, nil},
		{"addkey", runAddKey, nil},
		{"changekey", runChangeKey, []string{"/dev/sdb1"}},
		{"removekey", runRemoveKey, []string{"/dev/sdb1"}},
		{"killslot", runKillSlot, []string{"/dev/sdb1"}},
		{"recovery add", runRecoveryAdd, nil},
		{"recovery verify", runRecoveryVerify, nil},
		{"token list", runTokenList, nil},
		{"token show", runTokenShow, nil},
		{"token export", runTokenExport, []string{"/dev/sdb1"}},
		{"token import", runTokenImport, []string{"/dev/sdb1"}},
		{"token remove", runTokenRemove, []string{"/dev/sdb1"}},
		{"token free", runTokenFree, nil},
		{"token exists", runTokenExists, []string{"/dev/sdb1"}},
		{"token count", runTokenCount, nil},
		{"header show", runHeaderShow, nil},
		{"header secondary", runHeaderSecondary, nil},
		{"info", runInfo, nil},
		{"create", runCreate, nil},
	}
	for _, c := range cases {
		e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
		if err := c.run(context.Background(), e, c.args); err == nil {
			t.Errorf("%s: want a usage error for %v", c.name, c.args)
		}
	}
}

func TestRunCreateDeviceLooksLikePathButIsAbsent(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runCreate(context.Background(), e, []string{"/dev/cli-coverage-does-not-exist"}); err == nil {
		t.Fatal("runCreate: want an error for a /dev path that is not a block device")
	}
}

func TestRunCreatePathAlreadyExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exists.img")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runCreate(context.Background(), e, []string{path, "16M"}); err == nil {
		t.Fatal("runCreate: want an error for a path that already exists")
	}
}

func TestCreatePathKindCharDevice(t *testing.T) {
	kind, err := createPathKind("/dev/null")
	if err != nil {
		t.Fatalf("createPathKind(/dev/null): %v", err)
	}
	if kind != pathOther {
		t.Errorf("createPathKind(/dev/null) = %v, want pathOther", kind)
	}
}

func TestClaimDeviceNonexistentPath(t *testing.T) {
	if _, _, err := claimDevice(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("claimDevice: want an error for a path that does not exist")
	}
}

func TestFindSignatureSecondaryHeaderCopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secondary.img")
	data := make([]byte, 64<<10)
	copy(data[16<<10:], []byte("SKUL\xba\xbe"))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	found, release, err := claimDevice(path)
	if err != nil {
		t.Fatalf("claimDevice: %v", err)
	}
	defer release()
	if found != "a LUKS2 secondary header" {
		t.Errorf("found = %q, want the secondary-header signature", found)
	}
}

func TestRunWipeInvalidStandard(t *testing.T) {
	path := newPlainImage(t, "wipe-badstandard.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("YES\n"))

	if err := runWipe(context.Background(), e, []string{"--standard", "nonsense", path}); err == nil {
		t.Fatal("runWipe: want a usage error for an unknown --standard")
	}
}

func TestUnshownRecoveryKeyRollsBack(t *testing.T) {
	path := newTestVolumeImage(t, "unshown-recovery.img")

	ctx := context.Background()
	v, err := luks2.Open(ctx, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphraseEnclave(t)
	defer pass.Destroy()
	key, err := v.Unlock(ctx, pass)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer key.Destroy()

	rk, err := luks2.NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey: %v", err)
	}
	defer rk.Destroy()

	enrollment, err := v.AddRecoveryKey(ctx, key, rk, luks2.KeyslotParams{Priority: luks2.PriorityNormal, KDF: fastKDF})
	if err != nil {
		t.Fatalf("AddRecoveryKey: %v", err)
	}

	e, _, _, _, stderr := newTestEnv(&bytes.Buffer{})
	cause := errSentinel
	if got := unshownRecoveryKey(ctx, e, v, path, enrollment, cause); got != cause {
		t.Errorf("unshownRecoveryKey returned %v, want the cause back", got)
	}
	if stderr.Len() == 0 {
		t.Error("stderr should explain the rollback")
	}

	// The keyslot should no longer open the volume, and the token should
	// be gone too.
	hdr, err := v.Header(ctx)
	if err != nil {
		t.Fatalf("Header: %v", err)
	}
	if _, ok := hdr.Tokens()[enrollment.Token]; ok {
		t.Error("the recovery token should have been removed")
	}
	for _, s := range hdr.Keyslots() {
		if s.ID == enrollment.Keyslot.ID {
			t.Error("the recovery keyslot should have been removed")
		}
	}
}
