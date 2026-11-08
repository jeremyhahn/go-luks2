// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package labstrings

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The export-ignore attribute is read from the staged .gitattributes, at any
// depth its patterns say, and an unstaged edit to it changes nothing.
func TestIndexEntries_MarksWhatTheStagedGitattributesExportIgnores(t *testing.T) {
	root := gitIndexTree(t, map[string]string{
		GitAttributes:                           "**/CLAUDE.md export-ignore\n**/.claude/** export-ignore\n.github/workflows/code-review.yml export-ignore\n",
		"CLAUDE.md":                             "# agent\n",
		"cmd/x/CLAUDE.md":                       "# agent\n",
		".claude/settings.json":                 "{}\n",
		".github/workflows/code-review.yml":     "on: push\n",
		".github/workflows/ci.yml":              "on: push\n",
		"go.mod":                                "module example.com/x\n",
		"docs/CLAUDE.md.txt":                    "not an agent file\n",
		"sub/.github/workflows/code-review.yml": "on: push\n",
		"pkg/x/claude_settings_example.txt":     "x\n",
	})
	// Unstaged: must not count.
	if err := os.WriteFile(filepath.Join(root, GitAttributes), []byte("go.mod export-ignore\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	entries, err := IndexEntries(root)
	if err != nil {
		t.Fatalf("IndexEntries: %v", err)
	}
	want := map[string]bool{
		"CLAUDE.md": true, "cmd/x/CLAUDE.md": true, ".claude/settings.json": true, ".github/workflows/code-review.yml": true,
	}
	for _, e := range entries {
		if e.ExportIgnored != want[e.Path] {
			t.Errorf("%s: ExportIgnored = %v, want %v", e.Path, e.ExportIgnored, want[e.Path])
		}
	}
}

// Only the committed .gitattributes travel with the tree; a forge's archive
// never sees an attribute file outside it. A rule from .git/info/attributes,
// a core.attributesFile in any config, or the XDG default must not make a
// file the staged rules publish look excluded: that is a false clean.
func TestIndexEntries_AnExportIgnoreRuleOutsideTheStagedTreeDoesNotCount(t *testing.T) {
	outside := "**/CLAUDE.md export-ignore\n"
	for name, plant := range map[string]func(t *testing.T, root string){
		"info/attributes": func(t *testing.T, root string) {
			writeFiles(t, root, map[string]string{".git/info/attributes": outside})
		},
		"global core.attributesFile": func(t *testing.T, root string) {
			dir := t.TempDir()
			writeFiles(t, dir, map[string]string{"attributes": outside,
				"gitconfig": "[core]\n\tattributesFile = " + filepath.Join(dir, "attributes") + "\n"})
			t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(dir, "gitconfig"))
		},
		"repository core.attributesFile": func(t *testing.T, root string) {
			dir := t.TempDir()
			writeFiles(t, dir, map[string]string{"attributes": outside})
			git(t, root, "", "config", "core.attributesFile", filepath.Join(dir, "attributes"))
		},
		"XDG default attributes": func(t *testing.T, root string) {
			dir := t.TempDir()
			writeFiles(t, dir, map[string]string{"git/attributes": outside})
			t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
			t.Setenv("XDG_CONFIG_HOME", dir)
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := gitIndexTree(t, map[string]string{
				GitAttributes: "go.mod export-ignore\n",
				"CLAUDE.md":   "# agent\n",
				"go.mod":      "module example.com/x\n",
			})
			plant(t, root)

			entries, err := IndexEntries(root)
			if err != nil {
				t.Fatalf("IndexEntries: %v", err)
			}
			want := map[string]bool{"go.mod": true}
			for _, e := range entries {
				if e.ExportIgnored != want[e.Path] {
					t.Errorf("%s: ExportIgnored = %v, want %v", e.Path, e.ExportIgnored, want[e.Path])
				}
			}
		})
	}
}

func TestExportIgnored_AGitThatCannotRunFailsRatherThanPasses(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PATH", t.TempDir())
	_, err := exportIgnored(root, map[string][]byte{GitAttributes: []byte("CLAUDE.md export-ignore\n")}, []string{"CLAUDE.md"})
	var attrErr *AttrError
	if !errors.As(err, &attrErr) {
		t.Fatalf("err = %v, want *AttrError", err)
	}
	if attrErr.Root != root || !strings.Contains(err.Error(), root) {
		t.Errorf("AttrError = %+v; want the root", attrErr)
	}
	if !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("AttrError does not unwrap to the exec failure: %v", err)
	}
}

// A GitAttributes path that is not one, or that leaves the tree, is refused
// rather than written outside the scratch repository.
func TestExportIgnored_RefusesAnAttributesPathOutsideTheTree(t *testing.T) {
	for _, name := range []string{"../" + GitAttributes, "/etc/" + GitAttributes, "docs/README.md"} {
		var attrErr *AttrError
		if _, err := exportIgnored(t.TempDir(), map[string][]byte{name: nil}, []string{"x"}); !errors.As(err, &attrErr) {
			t.Errorf("%q: err = %v, want *AttrError", name, err)
		}
	}
}

func TestExportIgnored_NoPathsAsksNothing(t *testing.T) {
	got, err := exportIgnored(filepath.Join(t.TempDir(), "absent"), nil, nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("exportIgnored(nil) = %v, %v; want empty, nil", got, err)
	}
}

// Output that is not one triple per path asked about is an error, never a
// guess that could pass an internal file.
func TestParseExportIgnored_RefusesWhatItDoesNotUnderstand(t *testing.T) {
	for name, out := range map[string]string{
		"empty":           "",
		"short triple":    "CLAUDE.md\x00export-ignore\x00",
		"unterminated":    "CLAUDE.md\x00export-ignore\x00set",
		"one path short":  "CLAUDE.md\x00export-ignore\x00set\x00",
		"one path extra":  "a\x00export-ignore\x00set\x00b\x00export-ignore\x00set\x00c\x00export-ignore\x00set\x00",
		"newline records": "CLAUDE.md: export-ignore: set\ngo.mod: export-ignore: unspecified\n",
	} {
		t.Run(name, func(t *testing.T) {
			var attrErr *AttrError
			if _, err := parseExportIgnored("/r", []byte(out), 2); !errors.As(err, &attrErr) {
				t.Fatalf("err = %v, want *AttrError", err)
			}
		})
	}
	got, err := parseExportIgnored("/r", []byte("CLAUDE.md\x00export-ignore\x00set\x00go.mod\x00export-ignore\x00unspecified\x00"), 2)
	if err != nil || !got["CLAUDE.md"] || got["go.mod"] {
		t.Fatalf("parse = %v, %v; want CLAUDE.md only", got, err)
	}
}

func TestNotExportIgnored_NamesOnlyAStrippedFileTheArchiveWouldShip(t *testing.T) {
	entries := []Entry{
		{Path: "AGENTS.md", ExportIgnored: true},
		{Path: "CLAUDE.md"},
		{Path: "go.mod"},
		{Path: "docs/notes.md", ExportIgnored: true},
	}
	got := NotExportIgnored(entries, DefaultStripAtPublish)
	if len(got) != 1 || got[0].Path != "CLAUDE.md" || !strings.Contains(got[0].Reason, GitAttributes) {
		t.Fatalf("NotExportIgnored = %v; want CLAUDE.md alone, naming %s", got, GitAttributes)
	}
}
