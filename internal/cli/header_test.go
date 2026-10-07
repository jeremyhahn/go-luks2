// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func TestRunHeaderRestoreRefusesAnIntactPrimary(t *testing.T) {
	path := newTestVolumeImage(t, "restore.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("YES\n"))

	// A freshly formatted volume's primary is intact and not older than
	// its secondary, so a non-forced restore is refused as a rollback.
	err := runHeaderRestore(context.Background(), e, []string{path})
	if !errors.Is(err, luks2.ErrPrimaryHeaderCurrent) {
		t.Fatalf("runHeaderRestore error = %v, want ErrPrimaryHeaderCurrent", err)
	}
}

func TestRunHeaderRestoreForceSucceeds(t *testing.T) {
	path := newTestVolumeImage(t, "restore-force.img")
	e, _, _, stdout, _ := newTestEnv(bytes.NewBufferString("YES\n"))

	if err := runHeaderRestore(context.Background(), e, []string{"--force", path}); err != nil {
		t.Fatalf("runHeaderRestore --force: %v", err)
	}
	if got := stdout.String(); !strings.Contains(got, "was restored") {
		t.Errorf("stdout = %q, want it to report success", got)
	}
}

func TestRunHeaderRestoreCanceled(t *testing.T) {
	path := newTestVolumeImage(t, "restore-cancel.img")
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("no\n"))

	err := runHeaderRestore(context.Background(), e, []string{"--force", path})
	var ce *ConfirmationError
	if !errors.As(err, &ce) {
		t.Fatalf("runHeaderRestore error = %T, want *ConfirmationError", err)
	}
}

func TestRunHeaderRestoreBatchModeSkipsConfirmation(t *testing.T) {
	path := newTestVolumeImage(t, "restore-batch.img")
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})

	if err := runHeaderRestore(context.Background(), e, []string{"--force", "--batch-mode", path}); err != nil {
		t.Fatalf("runHeaderRestore: %v", err)
	}
}

func TestRunHeaderRestoreMissingArgs(t *testing.T) {
	e, _, _, _, _ := newTestEnv(bytes.NewBufferString("YES\n"))
	if err := runHeaderRestore(context.Background(), e, nil); err == nil {
		t.Fatal("runHeaderRestore: want a usage error with no arguments")
	}
}

func TestRunHeaderShow(t *testing.T) {
	path := newTestVolumeImage(t, "header-show.img")
	e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})

	if err := runHeaderShow(context.Background(), e, []string{path}); err != nil {
		t.Fatalf("runHeaderShow: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"Primary header:", "UUID:", "Header offset:  0", "Keyslots:       1"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout = %q, want it to contain %q", out, want)
		}
	}
}

func TestRunHeaderSecondary(t *testing.T) {
	path := newTestVolumeImage(t, "header-secondary.img")
	e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})

	if err := runHeaderSecondary(context.Background(), e, []string{path}); err != nil {
		t.Fatalf("runHeaderSecondary: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "Secondary header:") {
		t.Errorf("stdout = %q, want it to say Secondary header", out)
	}
	if strings.Contains(out, "Header offset:  0") {
		t.Errorf("stdout = %q, want a nonzero header offset for the secondary copy", out)
	}
}

func TestRunHeaderShowMissingArgs(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runHeaderShow(context.Background(), e, nil); err == nil {
		t.Fatal("runHeaderShow: want a usage error with no arguments")
	}
}
