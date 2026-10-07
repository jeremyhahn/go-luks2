// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunTokenListEmpty(t *testing.T) {
	path := newTestVolumeImage(t, "token-list-empty.img")
	e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})

	if err := runTokenList(context.Background(), e, []string{path}); err != nil {
		t.Fatalf("runTokenList: %v", err)
	}
	if !strings.Contains(stdout.String(), "no tokens") {
		t.Errorf("stdout = %q, want it to report no tokens", stdout.String())
	}
}

func TestRunTokenImportShowListAndRemove(t *testing.T) {
	path := newTestVolumeImage(t, "token-import.img")
	tokenJSON := `{"type":"user-defined","keyslots":["0"]}`

	importE, _, _, importStdout, _ := newTestEnv(bytes.NewBufferString(tokenJSON))
	if err := runTokenImport(context.Background(), importE, []string{"--file", "-", path, "0"}); err != nil {
		t.Fatalf("runTokenImport: %v", err)
	}
	if !strings.Contains(importStdout.String(), "stored") {
		t.Errorf("stdout = %q, want confirmation", importStdout.String())
	}

	showE, _, _, showStdout, _ := newTestEnv(&bytes.Buffer{})
	if err := runTokenShow(context.Background(), showE, []string{path, "0"}); err != nil {
		t.Fatalf("runTokenShow: %v", err)
	}
	if !strings.Contains(showStdout.String(), "user-defined") {
		t.Errorf("stdout = %q, want the token type", showStdout.String())
	}

	listE, _, _, listStdout, _ := newTestEnv(&bytes.Buffer{})
	if err := runTokenList(context.Background(), listE, []string{path}); err != nil {
		t.Fatalf("runTokenList: %v", err)
	}
	if !strings.Contains(listStdout.String(), "user-defined") {
		t.Errorf("stdout = %q, want the token listed", listStdout.String())
	}

	countE, _, _, countStdout, _ := newTestEnv(&bytes.Buffer{})
	if err := runTokenCount(context.Background(), countE, []string{path}); err != nil {
		t.Fatalf("runTokenCount: %v", err)
	}
	if strings.TrimSpace(countStdout.String()) != "1" {
		t.Errorf("count stdout = %q, want %q", countStdout.String(), "1")
	}

	existsE, _, _, existsStdout, _ := newTestEnv(&bytes.Buffer{})
	if err := runTokenExists(context.Background(), existsE, []string{path, "0"}); err != nil {
		t.Fatalf("runTokenExists: %v", err)
	}
	if !strings.Contains(existsStdout.String(), "is present") {
		t.Errorf("stdout = %q, want it to report presence", existsStdout.String())
	}

	exportE, _, _, exportStdout, _ := newTestEnv(&bytes.Buffer{})
	if err := runTokenExport(context.Background(), exportE, []string{path, "0"}); err != nil {
		t.Fatalf("runTokenExport: %v", err)
	}
	if !strings.Contains(exportStdout.String(), "user-defined") {
		t.Errorf("stdout = %q, want the token JSON", exportStdout.String())
	}

	removeE, _, _, removeStdout, _ := newTestEnv(&bytes.Buffer{})
	if err := runTokenRemove(context.Background(), removeE, []string{path, "0"}); err != nil {
		t.Fatalf("runTokenRemove: %v", err)
	}
	if !strings.Contains(removeStdout.String(), "removed") {
		t.Errorf("stdout = %q, want removal confirmation", removeStdout.String())
	}

	existsAfterE, _, _, existsAfterStdout, _ := newTestEnv(&bytes.Buffer{})
	if err := runTokenExists(context.Background(), existsAfterE, []string{path, "0"}); err == nil {
		t.Fatal("runTokenExists: want an error (exit 1) after the token was removed")
	}
	if !strings.Contains(existsAfterStdout.String(), "not present") {
		t.Errorf("stdout = %q, want it to report absence", existsAfterStdout.String())
	}
}

func TestRunTokenFreeReportsFirstFreeSlot(t *testing.T) {
	path := newTestVolumeImage(t, "token-free.img")
	e, _, _, stdout, _ := newTestEnv(&bytes.Buffer{})

	if err := runTokenFree(context.Background(), e, []string{path}); err != nil {
		t.Fatalf("runTokenFree: %v", err)
	}
	if strings.TrimSpace(stdout.String()) != "0" {
		t.Errorf("stdout = %q, want %q on a volume with no tokens", stdout.String(), "0")
	}
}

func TestRunTokenImportRequiresFile(t *testing.T) {
	path := newTestVolumeImage(t, "token-nofile.img")
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})

	err := runTokenImport(context.Background(), e, []string{path, "0"})
	var ue *UsageError
	if !asUsageError(err, &ue) {
		t.Fatalf("runTokenImport error = %T, want *UsageError", err)
	}
}

func TestParseTokenIDOutOfRange(t *testing.T) {
	if _, err := parseTokenID("token show", "99"); err == nil {
		t.Fatal("parseTokenID: want an error for an out-of-range id")
	}
	if _, err := parseTokenID("token show", "nope"); err == nil {
		t.Fatal("parseTokenID: want an error for a non-numeric id")
	}
}
