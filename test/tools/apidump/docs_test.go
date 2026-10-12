// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docsTree lays out a pkg root with one package and a docs root with one
// feature directory, and returns both roots.
func docsTree(t *testing.T, source string, docs map[string]string) (pkgRoot, docsRoot string) {
	t.Helper()
	root := t.TempDir()
	pkgRoot = filepath.Join(root, "pkg")
	docsRoot = filepath.Join(root, "docs")
	for _, dir := range []string{filepath.Join(pkgRoot, "widget"), filepath.Join(docsRoot, "widgets")} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(pkgRoot, "widget"), "widget.go", source)
	for name, content := range docs {
		writeFile(t, filepath.Join(docsRoot, "widgets"), name, content)
	}
	return pkgRoot, docsRoot
}

const widgetSource = `package widget

type Volume struct{}

func (Volume) Open() error { return nil }

func (Volume) Close() error { return nil }

func OpenVolume() Volume { return Volume{} }

const MaxSlots = 32
`

func TestCheckDocumentedNamesEveryUndocumentedExport(t *testing.T) {
	pkgRoot, docsRoot := docsTree(t, widgetSource, map[string]string{
		// OpenVolume is a whole identifier inside a code span; Volume is
		// named, so the backticked `Close` covers Volume.Close in this doc.
		"api.md": "Call `widget.OpenVolume()` for a `Volume`, then `Close` it.\n",
		// MaxSlots only in prose, never in code: not covered. Open only as
		// a substring of OpenVolume: not covered.
		"user.md": "At most MaxSlots slots. OpenVolume opens it.\n",
	})
	apis, err := DumpTree(pkgRoot)
	if err != nil {
		t.Fatal(err)
	}
	docs, err := ReadFeatureDocs(docsRoot)
	if err != nil {
		t.Fatal(err)
	}
	err = CheckDocumented(apis, docs, nil)
	if !errors.Is(err, ErrUndocumented) {
		t.Fatalf("CheckDocumented = %v, want ErrUndocumented", err)
	}
	for _, want := range []string{"widget.MaxSlots", "widget.Volume.Open"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q does not report %q", err, want)
		}
	}
	for _, covered := range []string{"widget.Volume\n", "widget.Volume.Close", "widget.OpenVolume"} {
		if strings.Contains(err.Error()+"\n", covered) {
			t.Errorf("%q wrongly flags the documented %q", err, covered)
		}
	}
}

func TestCheckDocumentedMethodRule(t *testing.T) {
	for _, tc := range []struct {
		name    string
		docs    map[string]string
		covered bool
	}{
		{"qualified in code", map[string]string{"api.md": "`v.Open` is wrong; `Volume.Open()` is right.\n"}, true},
		{"bare method in a span wrapped across lines", map[string]string{"api.md": "See `widget.Volume.\nOpen(ctx)`.\n"}, true},
		{"substring of another identifier", map[string]string{"api.md": "A `Volume` from `OpenVolume`.\n"}, false},
		{"qualified in a fenced block", map[string]string{"api.md": "```go\nvar v widget.Volume\n_ = Volume.Open\n```\n"}, true},
		{"bare method with its type in the same doc", map[string]string{"api.md": "A `Volume` has `Open`.\n"}, true},
		{"bare method, type only in another doc", map[string]string{"api.md": "`Open` it.\n", "user.md": "A `Volume`.\n"}, false},
		{"bare method, type only in prose", map[string]string{"api.md": "A Volume has `Open`.\n"}, false},
		{"qualified only in prose", map[string]string{"api.md": "Volume.Open opens it.\n"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkgRoot, docsRoot := docsTree(t, widgetSource, tc.docs)
			apis, err := DumpTree(pkgRoot)
			if err != nil {
				t.Fatal(err)
			}
			docs, err := ReadFeatureDocs(docsRoot)
			if err != nil {
				t.Fatal(err)
			}
			err = CheckDocumented(apis, docs, nil)
			if got := err == nil || !strings.Contains(err.Error()+"\n", "widget.Volume.Open\n"); got != tc.covered {
				t.Errorf("Volume.Open covered = %v, want %v (%v)", got, tc.covered, err)
			}
		})
	}
}

func TestCheckDocumentedHonoursExceptionsAndRefusesStaleOnes(t *testing.T) {
	pkgRoot, docsRoot := docsTree(t, widgetSource, map[string]string{
		"api.md": "`OpenVolume` returns a `Volume`: `Open`, `Close`.\n",
	})
	apis, err := DumpTree(pkgRoot)
	if err != nil {
		t.Fatal(err)
	}
	docs, err := ReadFeatureDocs(docsRoot)
	if err != nil {
		t.Fatal(err)
	}
	exceptions := []Exception{{Package: "widget", Name: "MaxSlots", Reason: "a protocol constant"}}
	if err := CheckDocumented(apis, docs, exceptions); err != nil {
		t.Fatalf("an excepted export refused: %v", err)
	}

	stale := append(exceptions,
		Exception{Package: "widget", Name: "Volume.Open", Reason: "documented after all"},
		Exception{Package: "widget", Name: "Gone", Reason: "no longer exported"},
	)
	err = CheckDocumented(apis, docs, stale)
	if !errors.Is(err, ErrUndocumented) {
		t.Fatalf("CheckDocumented = %v, want ErrUndocumented", err)
	}
	for _, want := range []string{"excepted but documented: widget.Volume.Open", "excepted but not exported: widget.Gone"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q does not report %q", err, want)
		}
	}
}

func TestReadExceptionsRefusesMalformedRows(t *testing.T) {
	dir := t.TempDir()
	good := writeFile(t, dir, "good.tsv", "# comment\n\nluks2\tVolume.String\tfmt.Stringer\n")
	got, err := ReadExceptions(good)
	if err != nil || len(got) != 1 || got[0] != (Exception{"luks2", "Volume.String", "fmt.Stringer"}) {
		t.Fatalf("ReadExceptions = %v, %v", got, err)
	}
	for _, bad := range []string{"luks2\tVolume.String\n", "luks2\tVolume.String\t\n", "\tX\treason\n", "luks2\tX\tr\nluks2\tX\tagain\n"} {
		if _, err := ReadExceptions(writeFile(t, dir, "bad.tsv", bad)); !errors.Is(err, ErrMalformed) {
			t.Errorf("ReadExceptions(%q) = %v, want ErrMalformed", bad, err)
		}
	}
}

func TestReadFeatureDocsRefusesATreeWithoutFeatures(t *testing.T) {
	dir := t.TempDir()
	// A directory without an api.md is not a feature (docs/design).
	if err := os.MkdirAll(filepath.Join(dir, "design"), 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "design"), "DESIGN.md", "`Volume`\n")
	if _, err := ReadFeatureDocs(dir); !errors.Is(err, ErrNoDocs) {
		t.Fatalf("ReadFeatureDocs = %v, want ErrNoDocs", err)
	}
}

// TestEveryPkgExportIsNamedInAFeatureDoc is the gate (#335): every exported identifier of every package under pkg/ is named
// in a feature doc under docs/, or listed with a reason in doc-exceptions.tsv.
func TestEveryPkgExportIsNamedInAFeatureDoc(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"documented", "doc-exceptions.tsv", "../../../docs", "../../../pkg"}, &out, &out); code != 0 {
		t.Fatalf("documented failed:\n%s", out.String())
	}
}
