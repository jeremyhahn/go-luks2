// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package labstrings

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ownerPathFixture is the owner home prefix this gate bans, assembled at runtime
// so the fixture does not itself have to be waived on every line that uses it.
var ownerPathFixture = "/home/" + "jhahn" // lab-string-ok: fixture for the owner-path rule

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
		{
			name:      "fleet address in help text",
			content:   "package main\n\nconst help = \"dial 198.51.100.51:8443\"\n",
			wantClass: ClassLabAddress,
			wantMatch: "198.51.100.51",
			wantLine:  3,
		},
		{
			name:      "fleet hostname in a doc",
			content:   "# Runbook\n\nRun it on GODLIKE first.\n",
			wantClass: ClassLabHost,
			wantMatch: "GODLIKE",
			wantLine:  3,
		},
		{
			name:      "runner hostname in a captured log",
			content:   "2026-09-12T00:00:00Z ci-node-2(version:v3.1.0)\n",
			wantClass: ClassLabHost,
			wantMatch: "ci-node-2",
			wantLine:  1,
		},
		{
			name:      "fleet hostname quoted in a workflow comment",
			content:   "jobs:\n# the fleet is idle: Omega is at 21%\n",
			wantClass: ClassLabHost,
			wantMatch: "Omega",
			wantLine:  2,
		},
		{
			name:      "fleet hostname as an internal endpoint",
			content:   "cfg.BaseURL = \"http://omega.internal:8077\"\n",
			wantClass: ClassLabHost,
			wantMatch: "omega.internal",
			wantLine:  1,
		},
		{
			name:      "agent hostname in a comment",
			content:   "// observed on vm-host-4\n",
			wantClass: ClassLabHost,
			wantMatch: "vm-host-4",
			wantLine:  1,
		},
		{
			name:      "owner home path in a doc",
			content:   "See " + ownerPathFixture + "/sources for the checkout.\n",
			wantClass: ClassOwnerPath,
			wantMatch: ownerPathFixture,
			wantLine:  1,
		},
		{
			name:      "lab NFS mount in a script default",
			content:   "QRDB=${QRDB:-/mnt/" + "vstation" + "-01/go-qrdb}\n", // lab-string-ok: fixture for the owner-path rule
			wantClass: ClassOwnerPath,
			wantMatch: "/mnt/" + "vstation",
			wantLine:  1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := entriesOf(map[string]string{"shipping/file.txt": tc.content})
			findings, err := Scan(files, nil)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			var got *Finding
			for i := range findings {
				if findings[i].Class == tc.wantClass {
					got = &findings[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("no %s finding; got %v", tc.wantClass, findings)
			}
			if got.Match != tc.wantMatch {
				t.Errorf("match = %q, want %q", got.Match, tc.wantMatch)
			}
			if got.Line != tc.wantLine {
				t.Errorf("line = %d, want %d", got.Line, tc.wantLine)
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
		{
			name:    "documentation addresses",
			content: "dial 198.51.100.7:8443 or 192.0.2.10 or 203.0.113.4\n",
		},
		{
			name:    "RFC 1918 literals that are not the fleet subnet",
			content: "peers: 192.168.1.10, 192.168.100.4, 10.0.0.1\n",
		},
		{
			name:    "the repository's own example names",
			content: "--keyserver https://luks.example.com:8443 --runner ci-runner-01\n",
		},
		{
			name:    "a waiver on the offending line",
			content: "Measured on gpu-host. <!-- lab-string-ok: measurement provenance -->\n",
		},
		{
			name:    "a waiver on the line above",
			content: "# lab-string-ok: measurement provenance\nMeasured on gpu-host.\n",
		},
		{
			name:    "a waiver whose reason ends at a comment closer",
			content: "x := 1 /* lab-string-ok: provenance */ // gpu-host\n",
		},
		{
			name:    "a hostname that merely contains a fleet name as a substring",
			content: "ungodlikeness is not a host, and vstation-0 has no second digit\n",
		},
		{
			name:    "a word that merely contains the fleet name omega",
			content: "megaomegalith and omegas are words, not hosts\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := entriesOf(map[string]string{"clean.txt": tc.content})
			findings, err := Scan(files, nil)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("expected no findings, got %v", findings)
			}
		})
	}
}

func TestScan_AWaiverWithNoReasonIsNotAWaiver(t *testing.T) {
	files := entriesOf(map[string]string{
		"bare.md":       "Measured on gpu-host. <!-- lab-string-ok: -->\n",
		"whitespace.md": "Measured on gpu-host. # lab-string-ok:    \n",
	})
	findings, err := Scan(files, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings (one per file), got %d: %v", len(findings), findings)
	}
}

func TestScan_AnAllowRuleAcceptsOnlyTheClassesItNames(t *testing.T) {
	content := "host vm-host-4 under " + ownerPathFixture + "/sources\n"
	files := entriesOf(map[string]string{"pkg/thing_test.go": content})

	rules := []AllowRule{{
		Path:    "**/*_test.go",
		Classes: []Class{ClassLabHost},
		Reason:  "test fixtures may name a fleet host",
	}}
	findings, err := Scan(files, rules)
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

func TestScan_RejectsAnUnusableAllowList(t *testing.T) {
	files := entriesOf(map[string]string{"clean.txt": "nothing here\n"})
	rules := []AllowRule{{Path: "**/*.go", Classes: []Class{ClassLabHost}}}

	_, err := Scan(files, rules)
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
		"capture.bin": "\x00\x01header\x00godlike\x00more bytes\n", // lab-string-ok: fixture for the binary-content rule
	})

	findings, err := Scan(files, nil)
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
		Content: []byte("/mnt/" + "vstation" + "-01/go-luks2/"), // lab-string-ok: fixture for the owner-path rule
	}}

	findings, err := Scan(entries, nil)
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
		Match:    "vm-host-4",
		Excerpt:  "// observed on vm-host-4",
		Guidance: "name the role",
	}})
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if !dirty {
		t.Error("dirty = false with a finding")
	}
	for _, want := range []string{"cmd/luks2/thing.go:7", "vm-host-4", "name the role", waiverPrefix} {
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

// TestPatterns_EveryNeedleIsImpliedByItsExpr pins the sieve's invariant: a
// pattern whose Needle its own matches do not contain would be skipped for every
// file in the tree, and the gate would pass while seeing nothing.
func TestPatterns_EveryNeedleIsImpliedByItsExpr(t *testing.T) {
	// One string per pattern that the pattern is known to match. They are the
	// values the audit actually found, so this doubles as the record of what
	// each rule was written for.
	samples := map[string][]string{
		`\b192\.168\.101\.\d{1,3}\b`:   {"198.51.100.91:3001", "at 198.51.100.51:8443"},
		`(?i)\bvstation-\d{2}\b`:       {"agent-vm-host-4", "VSTATION-01 rebooted"},
		`(?i)\bdellemc-\d{2}\b`:        {"runner ci-node-2", "DELLEMC-01"},
		`(?i)\bgodlike(\.internal)?\b`: {"on gpu-host", "http://GODLIKE.internal:8077"},
		`(?i)\bomega(\.internal)?\b`:   {"omega is 21%", "http://OMEGA.internal:8077"},
		`/home/jhahn\b`:                {ownerPathFixture + "/sources"},        // lab-string-ok: sample for the owner-path rule
		`/mnt/vstation`:                {"/mnt/" + "vstation" + "-01/go-qrdb"}, // lab-string-ok: sample for the owner-path rule
	}

	for _, p := range patterns {
		t.Run(p.Expr.String(), func(t *testing.T) {
			if p.Needle == "" {
				t.Fatal("pattern has no sieve needle")
			}
			if p.Needle != strings.ToLower(p.Needle) {
				t.Errorf("needle %q is not lowercase; the sieve folds case before searching", p.Needle)
			}
			got, ok := samples[p.Expr.String()]
			if !ok {
				t.Fatalf("no sample for this pattern: add one so its needle stays honest")
			}
			for _, sample := range got {
				if !p.Expr.MatchString(sample) {
					t.Errorf("%q does not match its own sample %q", p.Expr, sample)
				}
				if !strings.Contains(strings.ToLower(sample), p.Needle) {
					t.Errorf("sample %q matches but does not contain needle %q: the sieve would skip it", sample, p.Needle)
				}
			}
		})
	}
}

func TestScan_AMinifiedLineIsQuotedBounded(t *testing.T) {
	long := "const x=\"" + strings.Repeat("padding;", 200) + "gpu-host\";"
	files := entriesOf(map[string]string{"dist/bundle.js": long + "\n"})

	findings, err := Scan(files, nil)
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
	every := make([]Class, 0, len(patterns))
	seen := map[Class]bool{}
	for _, p := range patterns {
		if !seen[p.Class] {
			seen[p.Class] = true
			every = append(every, p.Class)
		}
	}
	rules := []AllowRule{{
		Path:    "vendored/**",
		Classes: every,
		Reason:  "a tree this repository does not author and does not publish edits to",
	}}

	findings, err := Scan(entriesOf(map[string]string{
		"vendored/thing.js": "fetch('http://gpu-host.internal/')\n", // lab-string-ok: fixture for the allow-everything shortcut
	}), rules)
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
		{"logs/vm-host-4.log", ClassLabHost, "vm-host-4"},
		{"testdata/198.51.100.7/capture.txt", ClassLabAddress, "198.51.100.7"},
		{"docs/runs/DELLEMC-02-bench.md", ClassLabHost, "DELLEMC-02"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			findings, err := Scan(entriesOf(map[string]string{tc.path: "ordinary text\n"}), nil)
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
		"logs/vm-host-4.log":       "ordinary text\n",
		"logs/198.51.100.9-run.log": "ordinary text\n",
	})
	findings, err := Scan(files, rules)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 || findings[0].Class != ClassLabAddress {
		t.Fatalf("findings = %v, want only the lab address the rule does not accept", findings)
	}
}
