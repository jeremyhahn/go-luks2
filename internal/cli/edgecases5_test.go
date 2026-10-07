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
)

func TestKeyslotCommandsOnNonLUKSDevice(t *testing.T) {
	cases := []struct {
		name  string
		run   func(context.Context, *env, []string) error
		stdin string
		args  []string
	}{
		{"addkey", runAddKey, testPassphrase + "\nnew\n", nil},
		{"changekey", runChangeKey, testPassphrase + "\nnew\n", []string{"0"}},
		{"removekey", runRemoveKey, testPassphrase + "\n", []string{"0"}},
		{"killslot", runKillSlot, testPassphrase + "\n", []string{"0"}},
	}
	for _, c := range cases {
		path := newPlainImage(t, "notluks-"+c.name+".img")
		e, _, _, _, _ := newTestEnv(bytes.NewBufferString(c.stdin))
		args := append([]string{path}, c.args...)
		if err := c.run(context.Background(), e, args); err == nil {
			t.Errorf("%s: want an error for a non-LUKS2 device", c.name)
		}
	}
}

func TestRunWipeHeaderOnlyOnNonLUKSDevice(t *testing.T) {
	// docs/wipe/cli.md: with no valid header copy the keyslots area cannot be
	// located, so the first 32 KiB is zeroed and the wipe still succeeds.
	const headerBytes = 32 << 10
	path := newPlainImage(t, "wipe-header-notluks.img")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0xA5}, 1<<20), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("YES\n"))

	if err := runWipe(context.Background(), e, []string{path}); err != nil {
		t.Fatalf("runWipe on a non-LUKS2 device: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got[:headerBytes], make([]byte, headerBytes)) {
		t.Error("the first 32 KiB was not zeroed")
	}
	if !bytes.Equal(got[headerBytes:], bytes.Repeat([]byte{0xA5}, len(got)-headerBytes)) {
		t.Error("a header-only wipe changed data beyond the header area")
	}
}

func TestRunTokenExportFileWriteFailure(t *testing.T) {
	path := newTestVolumeImage(t, "token-export-writefail.img")
	tokenPath := filepath.Join(t.TempDir(), "token.json")
	if err := os.WriteFile(tokenPath, []byte(`{"type":"user-defined","keyslots":["0"]}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	importE, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runTokenImport(context.Background(), importE, []string{"--file", tokenPath, path, "0"}); err != nil {
		t.Fatalf("runTokenImport: %v", err)
	}

	badExportPath := filepath.Join(t.TempDir(), "nonexistent-dir", "out.json")
	exportE, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runTokenExport(context.Background(), exportE, []string{"--file", badExportPath, path, "0"}); err == nil {
		t.Fatal("runTokenExport: want an error when the output directory does not exist")
	}
}
