// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package labstrings

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// fixturePatterns is a pattern set of documentation values, one pattern per
// class, shaped like the fleet set: an address block, a numbered host family,
// a home path and the account inside it. The scanner's mechanics are proved
// against it, so the published tests never spell a fleet value; the fleet set
// itself is proved in fleet_test.go, which is stripped at publish.
var fixturePatterns = []Pattern{
	{Class: ClassLabAddress, Expr: regexp.MustCompile(`\b203\.0\.113\.\d{1,3}\b`), Needle: "203.0.113.", Guidance: "use 198.51.100.0/24"},
	{Class: ClassLabHost, Expr: regexp.MustCompile(`(?i)\bnode-\d{2}\.example\b`), Needle: "node-", Guidance: "name the role"},
	{Class: ClassOwnerPath, Expr: regexp.MustCompile(`/home/example-owner\b`), Needle: "/home/example-owner", Guidance: "use a repository-relative path"},
	{Class: ClassOwnerAccount, Expr: regexp.MustCompile(`(?i)\bexample-owner\b`), Needle: "example-owner", Guidance: "name the role", YieldsTo: ClassOwnerPath},
}

// entriesOf turns a path-to-content map into regular-file index entries,
// sorted by path, in the form Scan takes.
func entriesOf(files map[string]string) []Entry {
	entries := make([]Entry, 0, len(files))
	for name, content := range files {
		entries = append(entries, Entry{Path: name, Kind: KindFile, Content: []byte(content)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries
}

// writeFiles writes files under root.
func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

func TestScan_ReportsEveryClassWithItsLineAndMatch(t *testing.T) {
	cases := []struct {
		name      string
		content   string
		wantClass Class
		wantMatch string
		wantLine  int
	}{
		{"address in help text", "package main\n\nconst help = \"dial 203.0.113.51:8443\"\n", ClassLabAddress, "203.0.113.51", 3},
		{"host in a doc, mixed case", "# Runbook\n\nRun it on NODE-04.example first.\n", ClassLabHost, "NODE-04.example", 3},
		{"owner home path in a doc", "See /home/example-owner/sources for the checkout.\n", ClassOwnerPath, "/home/example-owner", 1},
		{"owner account in an ssh command", "ssh example-owner@ci-runner-01 uptime\n", ClassOwnerAccount, "example-owner", 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := entriesOf(map[string]string{"shipping/file.txt": tc.content})
			findings, err := Scan(files, fixturePatterns, nil)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("want one finding, got %v", findings)
			}
			got := findings[0]
			if got.Class != tc.wantClass || got.Match != tc.wantMatch || got.Line != tc.wantLine {
				t.Errorf("finding = %+v, want class %s match %q line %d", got, tc.wantClass, tc.wantMatch, tc.wantLine)
			}
			if got.Path != "shipping/file.txt" {
				t.Errorf("path = %q, want shipping/file.txt", got.Path)
			}
			if got.Guidance == "" {
				t.Error("finding carries no guidance; the report would not say what to do")
			}
			if !strings.Contains(got.String(), "shipping/file.txt:"+strconv.Itoa(tc.wantLine)) {
				t.Errorf("String() is not file:line clickable: %s", got.String())
			}
		})
	}
}

func TestScan_AcceptsWhatItShould(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"values outside the set", "dial 198.51.100.7:8443, run on node-4.example or node-04.test\n"},
		{"a waiver on the offending line", "Measured on node-04.example. <!-- lab-string-ok: measurement provenance -->\n"},
		{"a waiver on the line above", "# lab-string-ok: measurement provenance\nMeasured on node-04.example.\n"},
		{"a waiver whose reason ends at a comment closer", "x := 1 /* lab-string-ok: provenance */ // node-04.example\n"},
		{"a word that merely contains the owner account", "xexample-owner and example-owners are not the account\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := Scan(entriesOf(map[string]string{"clean.txt": tc.content}), fixturePatterns, nil)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("expected no findings, got %v", findings)
			}
		})
	}
}

// A scan with no pattern set would report every tree clean, so it is an
// error, not an empty result.
func TestScan_WithNoPatternsIsAnError(t *testing.T) {
	files := entriesOf(map[string]string{"a.txt": "x\n", "b.txt": "y\n"})
	findings, err := Scan(files, nil, nil)
	var noPatterns *NoPatternsError
	if !errors.As(err, &noPatterns) {
		t.Fatalf("err = %v, want *NoPatternsError", err)
	}
	if noPatterns.Tracked != 2 || findings != nil {
		t.Errorf("tracked = %d, findings = %v; want 2 and none", noPatterns.Tracked, findings)
	}
}

// The allow-list may accept only files that never ship: an allow rule over a
// published file would let a fleet value into the release.
func TestDefaultAllowList_AcceptsOnlyStrippedFiles(t *testing.T) {
	stripped := map[string]bool{}
	for _, s := range DefaultStripAtPublish {
		stripped[s.Path] = true
	}
	for _, r := range DefaultAllowList {
		if !stripped[r.Path] {
			t.Errorf("allow rule %q names a file that is not stripped at publish", r.Path)
		}
	}
}

func TestScan_AWaiverWithNoReasonIsNotAWaiver(t *testing.T) {
	files := entriesOf(map[string]string{
		"bare.md":       "Measured on node-04.example. <!-- lab-string-ok: -->\n",
		"whitespace.md": "Measured on node-04.example. # lab-string-ok:    \n",
	})
	findings, err := Scan(files, fixturePatterns, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings (one per file), got %d: %v", len(findings), findings)
	}
}

func TestScan_AnAllowRuleAcceptsOnlyTheClassesItNames(t *testing.T) {
	content := "host node-04.example under /home/example-owner/sources\n"
	files := entriesOf(map[string]string{"pkg/thing_test.go": content})

	rules := []AllowRule{{
		Path:    "**/*_test.go",
		Classes: []Class{ClassLabHost},
		Reason:  "test fixtures may name a fleet host",
	}}
	findings, err := Scan(files, fixturePatterns, rules)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want exactly the owner-path finding, got %v", findings)
	}
	if findings[0].Class != ClassOwnerPath {
		t.Errorf("class = %s, want %s", findings[0].Class, ClassOwnerPath)
	}
}

// TestScan_AnOwnerPathIsOneFindingNotTwo: the account inside an owner path is
// the same leak, reported once as the more specific owner-path, and an allow
// rule that accepts the path accepts the account in it.
func TestScan_AnOwnerPathIsOneFindingNotTwo(t *testing.T) {
	content := "cd /home/example-owner/sources && ssh example-owner@ci-runner-01\n"
	files := entriesOf(map[string]string{"notes.md": content})

	findings, err := Scan(files, fixturePatterns, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 2 || findings[0].Class != ClassOwnerPath || findings[1].Class != ClassOwnerAccount {
		t.Fatalf("want one owner-path and one owner-account finding, got %v", findings)
	}

	rules := []AllowRule{{Path: "notes.md", Classes: []Class{ClassOwnerPath}, Reason: "a path under the owner's home is the point"}}
	findings, err = Scan(files, fixturePatterns, rules)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 || findings[0].Class != ClassOwnerAccount || !strings.Contains(findings[0].Excerpt, "ssh") {
		t.Fatalf("want only the bare account reported, got %v", findings)
	}
}

func TestScan_RejectsAnUnusableAllowList(t *testing.T) {
	files := entriesOf(map[string]string{"clean.txt": "nothing here\n"})
	rules := []AllowRule{{Path: "**/*.go", Classes: []Class{ClassLabHost}}}

	_, err := Scan(files, fixturePatterns, rules)
	var ruleErr *AllowRuleError
	if !errors.As(err, &ruleErr) {
		t.Fatalf("err = %v, want *AllowRuleError", err)
	}
	if !strings.Contains(ruleErr.Error(), "no reason given") {
		t.Errorf("error does not name the defect: %v", ruleErr)
	}
}

// A NUL byte does not stop a file being published, so it does not stop the scan:
// a tracked log or dump with binary noise in it still ships whatever it names.
func TestScan_ABinaryFileIsScanned(t *testing.T) {
	files := entriesOf(map[string]string{
		"capture.bin": "\x00\x01header\x00node-04.example\x00more bytes\n",
	})

	findings, err := Scan(files, fixturePatterns, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("a lab hostname inside a binary file was accepted")
	}
	for _, f := range findings {
		if f.Path != "capture.bin" {
			t.Errorf("finding path = %q, want capture.bin", f.Path)
		}
	}
}

func TestScan_ScansASymlinkTarget(t *testing.T) {
	entries := []Entry{{
		Path:    "go-luks2",
		Kind:    KindSymlink,
		Content: []byte("/home/example-owner/go-luks2/"),
	}}

	findings, err := Scan(entries, fixturePatterns, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var sawOwnerPath bool
	for _, f := range findings {
		if f.Class == ClassOwnerPath {
			sawOwnerPath = true
		}
		if f.Path != "go-luks2" {
			t.Errorf("finding path = %q, want the link itself", f.Path)
		}
	}
	if !sawOwnerPath {
		t.Fatalf("the link target was not scanned: %v", findings)
	}
}

func TestErrors_NameTheirSubjectAndUnwrap(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		contains []string
		wrapped  error
	}{
		{
			name:     "list failure names the root and what git said",
			err:      &ListError{Root: "/srv/tree", Stderr: "not a git repository", Err: os.ErrNotExist},
			contains: []string{"/srv/tree", "not a git repository"},
			wrapped:  os.ErrNotExist,
		},
		{
			name:     "read failure names the file",
			err:      &ReadError{Path: "pkg/x/y.go", Err: os.ErrPermission},
			contains: []string{"pkg/x/y.go"},
			wrapped:  os.ErrPermission,
		},
		{
			name:     "index-entry failure names the path and the problem",
			err:      &IndexEntryError{Path: "logs/run.log", Problem: "blob abc is missing from the object store"},
			contains: []string{"logs/run.log", "missing from the object store"},
		},
		{
			name:     "an oversized blob names the path, its size and the limit",
			err:      &FileTooLargeError{Path: "huge.log", Size: 40, Limit: 32},
			contains: []string{"huge.log", "40 bytes", "32-byte"},
		},
		{
			name:     "allow-rule failure names the entry and the defect",
			err:      &AllowRuleError{Index: 3, Path: "pkg/**", Problem: "no reason given"},
			contains: []string{"entry 3", "pkg/**", "no reason given"},
		},
		{
			name:     "a scan with no patterns says it cannot look",
			err:      &NoPatternsError{Tracked: 12},
			contains: []string{"no lab-value pattern set", "12 tracked files"},
		},
		{
			name:     "report failure names the cause",
			err:      &ReportError{Err: os.ErrClosed},
			contains: []string{"cannot write report"},
			wrapped:  os.ErrClosed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, want := range tc.contains {
				if !strings.Contains(tc.err.Error(), want) {
					t.Errorf("%q omits %q", tc.err.Error(), want)
				}
			}
			if tc.wrapped != nil && !errors.Is(tc.err, tc.wrapped) {
				t.Errorf("%v does not unwrap to %v", tc.err, tc.wrapped)
			}
		})
	}
}

func TestReport_SaysWhatToDoAndOnlyWhenDirty(t *testing.T) {
	var clean strings.Builder
	dirty, err := Report(&clean, nil)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if dirty {
		t.Error("dirty = true for no findings")
	}
	if clean.String() != "" {
		t.Errorf("clean report wrote %q", clean.String())
	}

	var out strings.Builder
	dirty, err = Report(&out, []Finding{{
		Path:     "cmd/luks2/thing.go",
		Line:     7,
		Class:    ClassLabHost,
		Match:    "node-04.example",
		Excerpt:  "// observed on node-04.example",
		Guidance: "name the role",
	}})
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if !dirty {
		t.Error("dirty = false with a finding")
	}
	for _, want := range []string{"cmd/luks2/thing.go:7", "node-04.example", "name the role", waiverPrefix} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("report omits %q:\n%s", want, out.String())
		}
	}
}

// failingWriter fails every write, so a report that cannot reach the engineer is
// an error rather than a silently passing gate.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestReport_AWriteFailureIsATypedError(t *testing.T) {
	dirty, err := Report(failingWriter{}, []Finding{{Path: "x", Line: 1, Class: ClassLabHost}})
	if !dirty {
		t.Error("dirty = false although findings were passed")
	}
	var reportErr *ReportError
	if !errors.As(err, &reportErr) {
		t.Fatalf("err = %v, want *ReportError", err)
	}
	if !errors.Is(err, os.ErrClosed) {
		t.Errorf("err does not unwrap to the write failure: %v", err)
	}
}

func TestScan_AMinifiedLineIsQuotedBounded(t *testing.T) {
	long := "const x=\"" + strings.Repeat("padding;", 200) + "node-04.example\";"
	files := entriesOf(map[string]string{"dist/bundle.js": long + "\n"})

	findings, err := Scan(files, fixturePatterns, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want one finding, got %v", len(findings))
	}
	excerpt := findings[0].Excerpt
	if len(excerpt) > excerptLimit+len(" ...") {
		t.Errorf("excerpt is %d bytes; a report of these would be unreadable", len(excerpt))
	}
	if !strings.HasSuffix(excerpt, " ...") {
		t.Errorf("a truncated excerpt does not say so: %q", excerpt)
	}
}

func TestScan_AnEntryWhoseEveryClassIsAllowedIsAccepted(t *testing.T) {
	every := classes
	rules := []AllowRule{{
		Path:    "vendored/**",
		Classes: every,
		Reason:  "a tree this repository does not author and does not publish edits to",
	}}

	findings, err := Scan(entriesOf(map[string]string{
		"vendored/thing.js": "fetch('http://node-04.example/')\n",
	}), fixturePatterns, rules)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %v", findings)
	}
}

// A tracked file's path ships as surely as its content, so a lab value that
// appears only in a filename is a finding. Line 0 marks the path itself.
func TestScan_ReportsALabValueThatAppearsOnlyInThePath(t *testing.T) {
	cases := []struct {
		path      string
		wantClass Class
		wantMatch string
	}{
		{"logs/node-04.example.log", ClassLabHost, "node-04.example"},
		{"testdata/203.0.113.7/capture.txt", ClassLabAddress, "203.0.113.7"},
		{"docs/runs/NODE-02.example-bench.md", ClassLabHost, "NODE-02.example"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			findings, err := Scan(entriesOf(map[string]string{tc.path: "ordinary text\n"}), fixturePatterns, nil)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("findings = %v, want exactly one for the path", findings)
			}
			got := findings[0]
			if got.Path != tc.path || got.Line != 0 || got.Class != tc.wantClass || got.Match != tc.wantMatch {
				t.Errorf("finding = %+v, want path %s line 0 class %s match %q", got, tc.path, tc.wantClass, tc.wantMatch)
			}
			if !strings.Contains(got.String(), "file path") {
				t.Errorf("a path finding does not say it is in the path: %s", got)
			}
		})
	}
}

// A path finding honors the allow-list exactly as a content finding does:
// the rule accepts classes for the files it names, whatever part of the file
// carries the value.
func TestScan_APathFindingHonorsTheAllowList(t *testing.T) {
	rules := []AllowRule{{Path: "logs/**", Classes: []Class{ClassLabHost}, Reason: "captured logs"}}
	files := entriesOf(map[string]string{
		"logs/node-04.example.log": "ordinary text\n",
		"logs/203.0.113.9-run.log": "ordinary text\n",
	})
	findings, err := Scan(files, fixturePatterns, rules)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 || findings[0].Class != ClassLabAddress {
		t.Fatalf("findings = %v, want only the lab address the rule does not accept", findings)
	}
}
