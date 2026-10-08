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

// TestRunHeaderShowLabelsTheCopyItShows: with the primary copy damaged,
// `header show` prints the secondary (the current copy), and must say so and
// give the secondary's offset rather than "Primary" and 0.
func TestRunHeaderShowLabelsTheCopyItShows(t *testing.T) {
	path := newTestVolumeImage(t, "header-show-secondary.img")

	// Byte 24 is inside the primary's label field, which its checksum
	// covers, so the primary no longer verifies and the secondary is current.
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open image: %v", err)
	}
	if _, err := f.WriteAt([]byte{'X'}, 24); err != nil {
		_ = f.Close()
		t.Fatalf("damage the primary: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close image: %v", err)
	}

	e, _, _, stdout, stderr := newTestEnv(&bytes.Buffer{})
	if err := runHeaderShow(context.Background(), e, []string{path}); err != nil {
		t.Fatalf("runHeaderShow: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "Secondary header:") {
		t.Errorf("stdout = %q, want it labeled Secondary header", out)
	}
	if strings.Contains(out, "Primary header:") || strings.Contains(out, "Header offset:  0\n") {
		t.Errorf("stdout = %q, labels the secondary copy as the primary", out)
	}
	if !strings.Contains(stderr.String(), "showing the secondary") {
		t.Errorf("stderr = %q, want a note that the secondary is shown", stderr.String())
	}
}

func TestRunHeaderShowMissingArgs(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runHeaderShow(context.Background(), e, nil); err == nil {
		t.Fatal("runHeaderShow: want a usage error with no arguments")
	}
}
