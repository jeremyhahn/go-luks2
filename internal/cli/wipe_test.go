// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func TestRunWipeHeaderOnly(t *testing.T) {
	path := newTestVolumeImage(t, "wipe-header.img")
	e, _, _, stdout, _ := newTestEnv(bytes.NewBufferString("YES\n"))

	if err := runWipe(context.Background(), e, []string{path}); err != nil {
		t.Fatalf("runWipe: %v", err)
	}
	if !strings.Contains(stdout.String(), "Volume wiped successfully") {
		t.Errorf("stdout = %q, want confirmation of success", stdout.String())
	}

	v, err := luks2.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open after wipe: %v", err)
	}
	defer func() { _ = v.Close() }()
	if _, err := v.Header(context.Background()); err == nil {
		t.Error("Header after wipe: want an error -- the header is gone")
	}
}

// TestRunWipeHeaderOnlyWarnsThatAHeaderBackupStillOpens: a header-only wipe
// leaves the data in place, so a full header backup (what cryptsetup
// luksHeaderBackup saves: everything before the data segment) restored
// afterwards opens the volume again. The warning must say so, not the
// opposite.
func TestRunWipeHeaderOnlyWarnsThatAHeaderBackupStillOpens(t *testing.T) {
	ctx := context.Background()
	path := newTestVolumeImage(t, "wipe-header-backup.img")

	v, err := luks2.Open(ctx, path, luks2.WithReadOnly())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	hdr, err := v.Header(ctx)
	_ = v.Close()
	if err != nil {
		t.Fatalf("Header: %v", err)
	}
	image, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read image: %v", err)
	}
	backup := bytes.Clone(image[:hdr.Segments()[0].Offset])

	e, _, _, stdout, _ := newTestEnv(bytes.NewBufferString("YES\n"))
	if err := runWipe(ctx, e, []string{path}); err != nil {
		t.Fatalf("runWipe: %v", err)
	}
	warning := stdout.String()
	if strings.Contains(warning, "no\nlonger opens") || !strings.Contains(warning, "luksHeaderBackup") {
		t.Errorf("warning = %q, want it to say a header backup taken before still opens the data", warning)
	}

	// The warning's claim, demonstrated: restore the backup and unlock.
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open image: %v", err)
	}
	if _, err := f.WriteAt(backup, 0); err != nil {
		_ = f.Close()
		t.Fatalf("restore the backup: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close image: %v", err)
	}
	v, err = luks2.Open(ctx, path, luks2.WithReadOnly())
	if err != nil {
		t.Fatalf("Open after restore: %v", err)
	}
	defer func() { _ = v.Close() }()
	pass := newTestPassphraseEnclave(t)
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(ctx, pass)
	if err != nil {
		t.Fatalf("Unlock after restoring a pre-wipe header backup: %v", err)
	}
	key.Destroy()
}

func TestRunWipeHeaderOnlyInvalidPasses(t *testing.T) {
	path := newPlainImage(t, "wipe-badpasses.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("YES\n"))

	err := runWipe(context.Background(), e, []string{"--passes", "0", path})
	var ue *UsageError
	if !errors.As(err, &ue) {
		t.Fatalf("runWipe error = %T, want *UsageError", err)
	}
}

// TestRunWipeRejectsFullOnlyFlagsWithoutFull is S6: a header-only wipe would
// otherwise accept --random, --passes and the rest and silently ignore them,
// leaving the operator believing the data was overwritten.
func TestRunWipeRejectsFullOnlyFlagsWithoutFull(t *testing.T) {
	for _, flag := range [][]string{
		{"--random"}, {"--passes", "1"}, {"--standard", "nist"},
		{"--verify"}, {"--no-verify"}, {"--trim"},
	} {
		path := newPlainImage(t, "wipe-fullonly.img")
		e, _, _, _, _ := newTestEnv(bytes.NewBufferString("YES\n"))

		err := runWipe(context.Background(), e, append(flag, path))
		var ue *UsageError
		if !errors.As(err, &ue) || !strings.Contains(ue.Detail, "--full") {
			t.Errorf("runWipe %v without --full = %v, want a *UsageError naming --full", flag, err)
		}
	}
}

func TestRunWipeFullOverwritesTheDevice(t *testing.T) {
	path := newPlainImage(t, "wipe-full.img")
	e, _, _, stdout, _ := newTestEnv(bytes.NewBufferString("YES\n"))

	if err := runWipe(context.Background(), e, []string{"--full", path}); err != nil {
		t.Fatalf("runWipe --full: %v", err)
	}
	if !strings.Contains(stdout.String(), "wiped successfully") {
		t.Errorf("stdout = %q, want it to report success", stdout.String())
	}
}

func TestRunWipeFullBatchModeSkipsConfirmation(t *testing.T) {
	path := newPlainImage(t, "wipe-batch.img")
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})

	if err := runWipe(context.Background(), e, []string{"--full", "--batch-mode", path}); err != nil {
		t.Fatalf("runWipe: %v", err)
	}
}

func TestRunWipeFullWithStandard(t *testing.T) {
	path := newPlainImage(t, "wipe-nist.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("YES\n"))

	if err := runWipe(context.Background(), e, []string{"--full", "--standard", "nist", path}); err != nil {
		t.Fatalf("runWipe --standard nist: %v", err)
	}
}

func TestRunWipeFullWithRandomAndMultiplePasses(t *testing.T) {
	path := newPlainImage(t, "wipe-random.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("YES\n"))

	if err := runWipe(context.Background(), e, []string{"--full", "--random", "--passes", "2", path}); err != nil {
		t.Fatalf("runWipe --random --passes 2: %v", err)
	}
}

func TestRunWipeUnknownStandard(t *testing.T) {
	path := newPlainImage(t, "wipe-badstd.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("YES\n"))

	if err := runWipe(context.Background(), e, []string{"--full", "--standard", "nope", path}); err == nil {
		t.Fatal("runWipe: want a usage error for an unknown --standard")
	}
}

func TestRunWipeInvalidPasses(t *testing.T) {
	path := newPlainImage(t, "wipe-badpasses.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("YES\n"))

	if err := runWipe(context.Background(), e, []string{"--full", "--passes", "0", path}); err == nil {
		t.Fatal("runWipe: want a usage error for --passes 0")
	}
	if err := runWipe(context.Background(), e, []string{"--full", "--passes", "notanumber", path}); err == nil {
		t.Fatal("runWipe: want a usage error for a non-numeric --passes")
	}
}

func TestRunWipeCanceled(t *testing.T) {
	path := newPlainImage(t, "wipe-cancel.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("no\n"))

	err := runWipe(context.Background(), e, []string{"--full", path})
	var ce *ConfirmationError
	if !errors.As(err, &ce) {
		t.Fatalf("runWipe error = %T, want *ConfirmationError", err)
	}
}

// TestRunWipeHeaderOnlyCanceledReportsWipeCanceled locks docs/wipe/cli.md's
// "Wipe canceled" text on stderr for wipe's default (header-only) mode: the
// pre-rewrite CLI reported a canceled destructive operation this way, for
// both an explicit non-YES answer and no answer at all (EOF).
func TestRunWipeHeaderOnlyCanceledReportsWipeCanceled(t *testing.T) {
	for _, stdin := range []string{"no\n", ""} {
		path := newPlainImage(t, "wipe-header-cancel.img")
		e, _, _, _, stderr := newTestEnv(bytes.NewBufferString(stdin))

		err := runWipe(context.Background(), e, []string{path})
		var ce *ConfirmationError
		if !errors.As(err, &ce) {
			t.Fatalf("runWipe error = %T, want *ConfirmationError", err)
		}
		if !strings.Contains(stderr.String(), "Wipe canceled") {
			t.Errorf("stderr = %q, want it to report 'Wipe canceled'", stderr.String())
		}
	}
}
