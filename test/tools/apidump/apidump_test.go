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

const fixtureDump = `const	Const	fixture.go
fields	Struct{A,B}	fixture.go
func	Func	fixture.go
iface	Iface	fixture.go
ifacemethods	Iface{M,N}	fixture.go
method	Generic.Get	fixture.go
method	Named.Value	fixture.go
method	Struct.Method	fixture.go
type	Empty	fixture.go
type	Generic	fixture.go
type	Named	fixture.go
type	Struct	fixture.go
var	Var	fixture.go
`

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func render(entries []Entry) string {
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.String() + "\n")
	}
	return b.String()
}

func TestDumpRecordsEveryExportedDeclarationKind(t *testing.T) {
	entries, err := Dump("testdata/fixture")
	if err != nil {
		t.Fatal(err)
	}
	if got := render(entries); got != fixtureDump {
		t.Fatalf("dump:\n%s\nwant:\n%s", got, fixtureDump)
	}
}

func TestDumpRefusesUnusableDirectories(t *testing.T) {
	broken := t.TempDir()
	writeFile(t, broken, "broken.go", "package broken\n\nfunc (\n")
	empty := t.TempDir()
	writeFile(t, empty, "empty.go", "package empty\n\nconst x = 1\n")

	for _, tc := range []struct {
		name string
		dir  string
		want error
	}{
		{"a file that does not parse", broken, ErrParse},
		{"no exported identifier", empty, ErrNoAPI},
		{"no Go files at all", t.TempDir(), ErrNoAPI},
		{"a malformed glob", "[", filepath.ErrBadPattern},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Dump(tc.dir); !errors.Is(err, tc.want) {
				t.Fatalf("Dump(%q) = %v, want %v", tc.dir, err, tc.want)
			}
		})
	}
}

func TestReadDumpRoundTripsAndRefusesMalformedLines(t *testing.T) {
	dir := t.TempDir()
	good := writeFile(t, dir, "good.tsv", fixtureDump)
	entries, err := ReadDump(good)
	if err != nil {
		t.Fatal(err)
	}
	if got := render(entries); got != fixtureDump {
		t.Fatalf("round trip:\n%s", got)
	}

	for _, line := range []string{"func\tF", "func\t\tf.go", "\tF\tf.go", "func\tF\t"} {
		path := writeFile(t, dir, "bad.tsv", line+"\n")
		if _, err := ReadDump(path); !errors.Is(err, ErrMalformed) {
			t.Errorf("ReadDump(%q) = %v, want ErrMalformed", line, err)
		}
	}
	if _, err := ReadDump(filepath.Join(dir, "absent.tsv")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ReadDump(absent) = %v, want ErrNotExist", err)
	}
}

func TestDiffIgnoresTheFileColumn(t *testing.T) {
	base := []Entry{{"func", "Kept", "a.go"}, {"func", "Moved", "a.go"}, {"func", "Gone", "a.go"}}
	current := []Entry{{"func", "Kept", "a.go"}, {"func", "Moved", "b.go"}, {"func", "New", "b.go"}}
	removed, added := Diff(base, current)
	if render(removed) != "func\tGone\ta.go\n" || render(added) != "func\tNew\tb.go\n" {
		t.Fatalf("removed %v, added %v", removed, added)
	}
}

func TestReadDispositionsRefusesMalformedRows(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, line string
	}{
		{"too few columns", "F\tKEEP"},
		{"no name", "\tKEEP\t"},
		{"unknown action", "F\tKILL\tx"},
		{"no target for a change", "F\tRENAME\t"},
	} {
		path := writeFile(t, dir, "d.tsv", tc.line+"\n")
		if _, err := ReadDispositions(path); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: ReadDispositions = %v, want ErrMalformed", tc.name, err)
		}
	}
	if _, err := ReadDispositions(filepath.Join(dir, "absent.tsv")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ReadDispositions(absent) = %v, want ErrNotExist", err)
	}
	path := writeFile(t, dir, "ok.tsv", "F\tKEEP\t\nG\tDELETE\tuse H\n")
	got, err := ReadDispositions(path)
	if err != nil || len(got) != 2 || got[1] != (Disposition{"G", Delete, "use H"}) {
		t.Fatalf("ReadDispositions = %v, %v", got, err)
	}
}

func TestCheckCoverageNamesEveryProblem(t *testing.T) {
	base := []Entry{{"func", "A", "a.go"}, {"func", "B", "a.go"}, {"fields", "T{X}", "a.go"}}
	err := CheckCoverage(base, []Disposition{{"A", Keep, ""}, {"A", Keep, ""}, {"Z", Delete, "x"}})
	if !errors.Is(err, ErrCoverage) {
		t.Fatalf("CheckCoverage = %v, want ErrCoverage", err)
	}
	for _, want := range []string{"disposed twice: A", "not in the baseline: Z", "no disposition: B"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q does not report %q", err, want)
		}
	}
	if err := CheckCoverage(base, []Disposition{{"A", Keep, ""}, {"B", Unexport, "x"}}); err != nil {
		t.Fatalf("exact coverage refused: %v", err)
	}
}

// TestBaselineDispositionsCoverTheReleasedAPI is the check the checked-in
// files are held to: every identifier pkg/luks2 exported in 0.5.0-alpha has
// exactly one disposition.
func TestBaselineDispositionsCoverTheReleasedAPI(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"check", "baseline/luks2.tsv", "baseline/disposition-luks2.tsv"}, &out, &out); code != 0 {
		t.Fatalf("check failed:\n%s", out.String())
	}
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	base := writeFile(t, dir, "base.tsv", "func\tFunc\tfixture.go\nfunc\tGone\tfixture.go\n")
	disp := writeFile(t, dir, "disp.tsv", "Func\tKEEP\t\nGone\tDELETE\tnothing\n")
	short := writeFile(t, dir, "short.tsv", "Func\tKEEP\t\n")
	bad := writeFile(t, dir, "bad.tsv", "junk\n")

	for _, tc := range []struct {
		name     string
		args     []string
		code     int
		contains string
	}{
		{"dump", []string{"dump", "testdata/fixture"}, 0, "func\tFunc\tfixture.go"},
		{"dump of a bad directory", []string{"dump", t.TempDir()}, 1, "no exported API"},
		{"diff", []string{"diff", base, "testdata/fixture"}, 0, "- func\tGone"},
		{"diff of a bad baseline", []string{"diff", bad, "testdata/fixture"}, 1, "malformed"},
		{"diff of a bad directory", []string{"diff", base, t.TempDir()}, 1, "no exported API"},
		{"check", []string{"check", base, disp}, 0, "2 dispositions cover"},
		{"check of a short disposition", []string{"check", base, short}, 1, "no disposition: Gone"},
		{"check of a bad baseline", []string{"check", bad, disp}, 1, "malformed"},
		{"check of bad dispositions", []string{"check", base, bad}, 1, "malformed"},
		{"no command", nil, 1, "usage:"},
		{"unknown command", []string{"frob"}, 1, `unknown command "frob"`},
		{"wrong operand count", []string{"dump"}, 1, "dump takes 1 operand"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if code := run(tc.args, &out, &out); code != tc.code {
				t.Fatalf("exit %d, want %d:\n%s", code, tc.code, out.String())
			}
			if !strings.Contains(out.String(), tc.contains) {
				t.Fatalf("output does not contain %q:\n%s", tc.contains, out.String())
			}
		})
	}
}
