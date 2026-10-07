// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile puts content at name under dir and returns the path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

func runGate(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// TestRunIsAGateThatCanFail is the issue's positive and negative control,
// end to end through the command: the same profile passes at a floor it meets
// and fails at one it misses by a single statement.
func TestRunIsAGateThatCanFail(t *testing.T) {
	dir := t.TempDir()
	prof := writeFile(t, dir, "unit.out",
		"mode: atomic\nm/a/f.go:1.1,2.2 9 1\nm/a/f.go:3.1,4.2 1 0\n") // 90.00% exactly

	pass := writeFile(t, dir, "pass.txt", "m/a unit 90\n")
	if code, out, errOut := runGate("-floors", pass, "-tier", "unit", "-profile", prof, "m/a"); code != 0 {
		t.Fatalf("negative control: exit %d, want 0\n%s%s", code, out, errOut)
	}

	fail := writeFile(t, dir, "fail.txt", "m/a unit 90.01\n")
	code, out, _ := runGate("-floors", fail, "-tier", "unit", "-profile", prof, "m/a")
	if code != 1 {
		t.Fatalf("positive control: exit %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "coverage gate FAILED") {
		t.Errorf("positive control did not say it failed:\n%s", out)
	}
}

// TestRunMergesSeveralProfiles is how the combined tier is measured: the
// statement only the integration suite executes counts.
func TestRunMergesSeveralProfiles(t *testing.T) {
	dir := t.TempDir()
	unit := writeFile(t, dir, "unit.out", "mode: atomic\nm/a/f.go:1.1,2.2 9 1\nm/a/f.go:3.1,4.2 1 0\n")
	integration := writeFile(t, dir, "int.out", "mode: atomic\nm/a/f.go:3.1,4.2 1 4\n")
	floors := writeFile(t, dir, "floors.txt", "m/a unit 90\nm/a combined 100\n")

	code, out, errOut := runGate("-floors", floors, "-tier", "combined",
		"-profile", unit, "-profile", integration, "m/a")
	if code != 0 || !strings.Contains(out, "100.00% (10 of 10 statements)") {
		t.Fatalf("exit %d, want the union at 100%%\n%s%s", code, out, errOut)
	}
}

func TestRunRefusesInputsItCannotUse(t *testing.T) {
	dir := t.TempDir()
	prof := writeFile(t, dir, "unit.out", "mode: atomic\nm/a/f.go:1.1,2.2 1 1\n")
	empty := writeFile(t, dir, "empty.out", "\n")
	headerOnly := writeFile(t, dir, "header-only.out", "mode: atomic\n")
	garbage := writeFile(t, dir, "garbage.out", "mode: atomic\nthis is not a profile\n")
	floors := writeFile(t, dir, "floors.txt", "m/a unit 90\n")
	badFloors := writeFile(t, dir, "bad-floors.txt", "m/a sometimes 90\n")
	missing := filepath.Join(dir, "absent")

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"unknown flag", []string{"-strict"}, "flag provided but not defined"},
		{"no floors file named", []string{"-tier", "unit", "-profile", prof, "m/a"}, "-floors is required"},
		{"no tier", []string{"-floors", floors, "-profile", prof, "m/a"}, "-tier must be"},
		{"no profile", []string{"-floors", floors, "-tier", "unit", "m/a"}, "at least one -profile"},
		{"no packages", []string{"-floors", floors, "-tier", "unit", "-profile", prof}, "name the packages"},
		{"unreadable target", []string{"-floors", floors, "-tier", "unit", "-target", "ninety", "-profile", prof, "m/a"}, "-target"},
		{"floors file missing", []string{"-floors", missing, "-tier", "unit", "-profile", prof, "m/a"}, "reading the floors file"},
		{"floors file malformed", []string{"-floors", badFloors, "-tier", "unit", "-profile", prof, "m/a"}, "sometimes"},
		{"profile missing", []string{"-floors", floors, "-tier", "unit", "-profile", missing, "m/a"}, "reading coverage profile"},
		{"profile empty", []string{"-floors", floors, "-tier", "unit", "-profile", empty, "m/a"}, "is empty"},
		{"a leg that measured nothing, beside one that did", []string{"-floors", floors, "-tier", "unit",
			"-profile", prof, "-profile", headerOnly, "m/a"}, "no coverage blocks"},
		{"profile malformed", []string{"-floors", floors, "-tier", "unit", "-profile", garbage, "m/a"}, "malformed coverage profile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := runGate(tc.args...)
			if code != 2 {
				t.Fatalf("exit %d, want 2\nstdout: %s\nstderr: %s", code, out, errOut)
			}
			if !strings.Contains(errOut, tc.want) {
				t.Errorf("stderr %q does not mention %q", errOut, tc.want)
			}
		})
	}
}
