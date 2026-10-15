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

// fakeHost serves one go.mod and a fixed answer per module.
func fakeHost(gomod string, answers map[string]listing, fails map[string]error) host {
	return host{
		readFile: func(name string) ([]byte, error) {
			if name != "go.mod" {
				return nil, os.ErrNotExist
			}
			return []byte(gomod), nil
		},
		list: func(module string) (listing, error) {
			if err, ok := fails[module]; ok {
				return listing{}, err
			}
			l, ok := answers[module]
			if !ok {
				return listing{}, &QueryError{Module: module, Err: errors.New("no answer")}
			}
			return l, nil
		},
	}
}

func runCLI(t *testing.T, h host, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := cli(args, &out, &errOut, h)
	return code, out.String(), errOut.String()
}

const sampleMod = `module example.com/m

go 1.27.2

require (
	example.com/current v1.2.0
	github.com/jeremyhahn/first v0.8.0-rc.2
	golang.org/x/old v0.47.0 // held: v0.48 drops the API the CLI uses
	// waiting on the upstream fix for the pinned regression
	example.com/above v1.0.0
)

require (
	example.com/pseudo v1.1.2-0.20180830191138-d8f796af33cc // indirect
	example.com/indirectold v1.0.0 // indirect; pinned by the test helper
)
`

func TestAllCurrentPasses(t *testing.T) {
	h := fakeHost("module m\n\nrequire example.com/a v1.2.0\n", map[string]listing{
		"example.com/a": {Version: "v1.2.0", Versions: []string{"v1.0.0", "v1.2.0"}},
	}, nil)
	code, out, errOut := runCLI(t, h)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if !strings.Contains(out, "example.com/a") || !strings.Contains(out, "ok") {
		t.Fatalf("output %q does not report the module ok", out)
	}
}

func TestDocumentedLagPassesAndPrintsTheReason(t *testing.T) {
	h := fakeHost(sampleMod, map[string]listing{
		"example.com/current":         {Version: "v1.2.0"},
		"github.com/jeremyhahn/first": {Version: "v0.8.0-rc.2", Versions: []string{"v0.8.0-rc.1", "v0.8.0-rc.2"}},
		"golang.org/x/old":            {Version: "v0.49.0"},
		"example.com/above":           {Version: "v1.1.0"},
		"example.com/pseudo":          {Version: "v1.1.1", Versions: []string{"v1.1.1"}},
		"example.com/indirectold":     {Version: "v1.0.1"},
	}, nil)
	code, out, errOut := runCLI(t, h)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q\n%s", code, errOut, out)
	}
	for _, want := range []string{
		"behind, documented: held: v0.48 drops the API the CLI uses",
		"behind, documented: waiting on the upstream fix for the pinned regression",
		"behind, documented: pinned by the test helper",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "example.com/pseudo") && !strings.HasSuffix(line, "ok") {
			t.Errorf("a pseudo-version after the last tag was not reported current: %q", line)
		}
	}
}

func TestUndocumentedLagFails(t *testing.T) {
	h := fakeHost("module m\n\nrequire (\n\texample.com/a v1.2.0 // indirect\n)\n", map[string]listing{
		"example.com/a": {Version: "v1.3.0"},
	}, nil)
	code, out, errOut := runCLI(t, h)
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(out, "BEHIND, UNDOCUMENTED (go.mod:4)") {
		t.Errorf("output %q does not name the undocumented line", out)
	}
	if !strings.Contains(errOut, "example.com/a v1.2.0 < v1.3.0") {
		t.Errorf("stderr %q does not name the lag", errOut)
	}
}

// A first-party module is behind when a higher tag exists, even a
// prerelease the go command's @latest would not choose.
func TestFirstPartyComparesAgainstEveryTag(t *testing.T) {
	gomod := "module m\n\nrequire github.com/jeremyhahn/x v0.8.0-rc.2\n"
	answer := map[string]listing{
		"github.com/jeremyhahn/x": {Version: "v0.7.0", Versions: []string{"v0.7.0", "v0.8.0-rc.2", "v0.8.0-alpha.1", "v0.9.0-alpha.1"}},
	}
	code, out, _ := runCLI(t, fakeHost(gomod, answer, nil))
	if code != 1 || !strings.Contains(out, "v0.9.0-alpha.1") {
		t.Fatalf("exit %d, output %q: want the newer alpha tag to count", code, out)
	}
	// The same listing for a third-party module follows @latest only.
	code, out, _ = runCLI(t, fakeHost(gomod, answer, nil), "-first-party", "example.org/")
	if code != 0 {
		t.Fatalf("exit %d, output %q: a third-party prerelease tag must not count", code, out)
	}
}

func TestQueryFailureFailsClosed(t *testing.T) {
	h := fakeHost("module m\n\nrequire example.com/a v1.2.0 // pinned\n", nil, map[string]error{
		"example.com/a": &QueryError{Module: "example.com/a", Output: "go: example.com/a@latest: module lookup disabled by GOPROXY=off", Err: errors.New("exit status 1")},
	})
	code, out, errOut := runCLI(t, h)
	if code != 1 {
		t.Fatalf("exit %d, want 1: an unanswered query is not currency", code)
	}
	if !strings.Contains(out, "ERROR") || !strings.Contains(errOut, "DEPS_CHECK_GOPROXY") {
		t.Errorf("stdout %q stderr %q: want ERROR row and the GOPROXY hint", out, errOut)
	}
	var qe *QueryError
	if err := run(nil, &bytes.Buffer{}, h); !errors.As(err, &qe) {
		t.Errorf("error %v is not a *QueryError", err)
	}
}

func TestBadVersionsFail(t *testing.T) {
	cases := map[string]struct {
		gomod  string
		answer listing
	}{
		"used":   {"module m\nrequire example.com/a latest\n", listing{Version: "v1.0.0"}},
		"latest": {"module m\nrequire example.com/a v1.0.0\n", listing{Version: "master"}},
		"tag":    {"module m\nrequire github.com/jeremyhahn/a v1.0.0\n", listing{Version: "v1.0.0", Versions: []string{"bogus"}}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := "example.com/a"
			if strings.Contains(tc.gomod, "jeremyhahn") {
				path = "github.com/jeremyhahn/a"
			}
			h := fakeHost(tc.gomod, map[string]listing{path: tc.answer}, nil)
			var ve *VersionError
			if err := run(nil, &bytes.Buffer{}, h); !errors.As(err, &ve) {
				t.Fatalf("error %v is not a *VersionError", err)
			}
		})
	}
}

func TestUsageAndModfileErrors(t *testing.T) {
	h := fakeHost("module m\n", nil, nil)
	var ue *UsageError
	if err := run([]string{"-nope"}, &bytes.Buffer{}, h); !errors.As(err, &ue) {
		t.Errorf("unknown flag: %v", err)
	}
	if err := run([]string{"extra"}, &bytes.Buffer{}, h); !errors.As(err, &ue) {
		t.Errorf("extra argument: %v", err)
	}
	var me *ModfileError
	if err := run([]string{"-modfile", "missing.mod"}, &bytes.Buffer{}, h); !errors.As(err, &me) {
		t.Errorf("missing go.mod: %v", err)
	}
	if err := run(nil, &bytes.Buffer{}, fakeHost("module m\nrequire (\n\texample.com/a v1\n", nil, nil)); !errors.As(err, &me) {
		t.Errorf("unterminated block: %v", err)
	}
	var out bytes.Buffer
	if err := run(nil, &out, h); err != nil || !strings.Contains(out.String(), "no requirements") {
		t.Errorf("no requirements: %v %q", err, out.String())
	}
	for _, e := range []error{ue, me, &ModfileError{Path: "go.mod", Msg: "x"}, &BehindError{Modules: []string{"a"}}} {
		if e.Error() == "" {
			t.Errorf("%T has an empty message", e)
		}
	}
}

func TestParseGoMod(t *testing.T) {
	gomod := `module m

// a comment before a block is not a reason for its first line
require (
	example.com/a v1.0.0

	// reason for b,
	// second line
	"example.com/b" v1.0.0
	example.com/c v1.0.0 // indirect
)

require example.com/d v1.0.0 // single-line reason

replace example.com/c => example.com/c v1.0.0 // replace reason

replace (
	example.com/a v1.0.0 => ../a
)

exclude example.com/z v0.1.0
retract [v0.1.0, v0.2.0]
`
	reqs, err := parseGoMod("go.mod", []byte(gomod))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]requirement{
		"example.com/a": {Version: "v1.0.0", Line: 5},
		"example.com/b": {Version: "v1.0.0", Line: 9, Reason: "reason for b, second line"},
		"example.com/c": {Version: "v1.0.0", Line: 10, Indirect: true, Reason: "replace reason"},
		"example.com/d": {Version: "v1.0.0", Line: 13, Reason: "single-line reason"},
	}
	if len(reqs) != len(want) {
		t.Fatalf("got %d requirements, want %d: %+v", len(reqs), len(want), reqs)
	}
	for _, r := range reqs {
		w := want[r.Path]
		w.Path = r.Path
		if r != w {
			t.Errorf("got %+v, want %+v", r, w)
		}
	}

	bad := []string{
		"require example.com/a\n",
		"require (\n\texample.com/a v1 extra\n)\n",
		"require \"unterminated v1.0.0\n",
		"replace example.com/a\n",
		"replace \"bad => x v1\n",
	}
	for _, b := range bad {
		var me *ModfileError
		if _, err := parseGoMod("go.mod", []byte(b)); !errors.As(err, &me) {
			t.Errorf("%q: error %v is not a *ModfileError", b, err)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	// Each version is older than the next (semver.org §11 example, plus the
	// go command's pseudo-versions).
	ordered := []string{
		"v0.0.0-20180101000000-aaaaaaaaaaaa",
		"v0.0.0-20260315162726-c47dfb6cf674",
		"v1.0.0-alpha",
		"v1.0.0-alpha.1",
		"v1.0.0-alpha.beta",
		"v1.0.0-beta",
		"v1.0.0-beta.2",
		"v1.0.0-beta.11",
		"v1.0.0-rc.1",
		"v1.0.0",
		"v1.1.1",
		"v1.1.2-0.20180830191138-d8f796af33cc",
		"v1.1.2",
		"v1.10.0",
		"v2.0.0+incompatible",
		"v2.0.1-99999999999999999999999",
	}
	for i := range ordered {
		for j := range ordered {
			a, ok := parseVersion(ordered[i])
			b, ok2 := parseVersion(ordered[j])
			if !ok || !ok2 {
				t.Fatalf("parse %q / %q", ordered[i], ordered[j])
			}
			got := a.compare(b)
			want := 0
			switch {
			case i < j:
				want = -1
			case i > j:
				want = 1
			}
			if got != want {
				t.Errorf("compare(%s, %s) = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
	for _, bad := range []string{"1.0.0", "v1.0", "v1.0.0-", "v1.0.0-a..b", "v01.0.0", "vx.0.0", "v1.-1.0"} {
		if _, ok := parseVersion(bad); ok {
			t.Errorf("parseVersion(%q) accepted a non-semver string", bad)
		}
	}
}

func TestGoListRunsOutsideTheModuleWithAPrivateCache(t *testing.T) {
	var gotDir string
	var gotEnv, gotArgs []string
	fake := func(dir string, env []string, args ...string) ([]byte, error) {
		gotDir, gotEnv, gotArgs = dir, env, args
		return []byte(`{"Path":"example.com/a","Version":"v1.2.0","Versions":["v1.0.0","v1.2.0"]}`), nil
	}
	l, err := goList("example.com/a", fake)
	if err != nil {
		t.Fatal(err)
	}
	if l.Version != "v1.2.0" || len(l.Versions) != 2 {
		t.Errorf("listing %+v", l)
	}
	if want := "list -m -versions -json example.com/a@latest"; strings.Join(gotArgs, " ") != want {
		t.Errorf("args %q, want %q", gotArgs, want)
	}
	if !strings.Contains(strings.Join(gotEnv, " "), "GOMODCACHE="+filepath.Join(gotDir, "modcache")) {
		t.Errorf("env %q does not use a private module cache under %s", gotEnv, gotDir)
	}
	if _, err := os.Stat(gotDir); !os.IsNotExist(err) {
		t.Errorf("temp dir %s was not removed: %v", gotDir, err)
	}

	failing := func(string, []string, ...string) ([]byte, error) {
		return []byte("go: lookup failed"), errors.New("exit status 1")
	}
	var qe *QueryError
	if _, err := goList("example.com/a", failing); !errors.As(err, &qe) || !strings.Contains(err.Error(), "lookup failed") {
		t.Errorf("failed lookup: %v", err)
	}
	garbled := func(string, []string, ...string) ([]byte, error) { return []byte("not json"), nil }
	if _, err := goList("example.com/a", garbled); !errors.As(err, &qe) {
		t.Errorf("garbled output: %v", err)
	}
	if qe.Unwrap() == nil {
		t.Error("QueryError does not unwrap")
	}
}

// runCommand is the real go command; asking it for its version needs no
// network and proves the environment and directory are wired through.
func TestRunCommandRunsGo(t *testing.T) {
	dir := t.TempDir()
	out, err := runCommand(dir, []string{"GOFLAGS="}, "env", "GOFLAGS")
	if err != nil {
		t.Fatalf("go env: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "" {
		t.Errorf("GOFLAGS override not applied: %q", out)
	}
	if h := systemHost(); h.readFile == nil || h.list == nil {
		t.Error("systemHost is incomplete")
	}
}
