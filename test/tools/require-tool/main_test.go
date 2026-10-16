// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The self-reports below are what each tool actually prints, copied from the
// tools themselves. A parser tested against invented output proves nothing
// about the output it will meet in CI.
const (
	golangciReport    = "golangci-lint has version 2.14.0 built with go1.27.1 from 1a2b3c4 on 2026-08-01T00:00:00Z\n"
	gosecReport       = "Version: v2.29.0\nGit tag: v2.29.0\nBuild date: 2026-08-01\n"
	govulncheckReport = "Go: go1.27.1\nScanner: govulncheck@v1.8.0\nDB: https://vuln.go.dev\n"
)

func TestExtractVersion_ReadsEachToolsDocumentedLine(t *testing.T) {
	cases := []struct {
		bin    string
		report string
		want   string
	}{
		{"golangci-lint", golangciReport, "2.14.0"},
		{"gosec", gosecReport, "v2.29.0"},
		// The FIRST version-shaped token in govulncheck's output is the Go
		// toolchain's. A generic extractor pins go1.27.1; this must not.
		{"govulncheck", govulncheckReport, "v1.8.0"},
		{"gosec", "Version:   v2.29.0   \n", "v2.29.0"},
	}
	for _, tc := range cases {
		t.Run(tc.bin, func(t *testing.T) {
			got, err := extractVersion(tc.bin, tc.report)
			if err != nil {
				t.Fatalf("extractVersion: %v", err)
			}
			if got != tc.want {
				t.Errorf("extractVersion(%s) = %q, want %q", tc.bin, got, tc.want)
			}
		})
	}
}

func TestExtractVersion_RefusesAnUnknownTool(t *testing.T) {
	_, err := extractVersion("staticcheck", "staticcheck 2026.1 (v0.7.0)\n")
	var unknown *UnknownToolError
	if !errors.As(err, &unknown) {
		t.Fatalf("err = %v, want *UnknownToolError", err)
	}
	if unknown.Bin != "staticcheck" {
		t.Errorf("Bin = %q", unknown.Bin)
	}
}

func TestExtractVersion_RefusesAReportItCannotParse(t *testing.T) {
	cases := []struct {
		bin    string
		report string
	}{
		// gosec built without -X main.Version (#21).
		{"gosec", "Version: dev\nGit tag: \n"},
		{"gosec", "gosec v2.29.0\n"},
		{"govulncheck", "Go: go1.27.1\n"},
		{"golangci-lint", "version 2.14.0\n"},
		// Not anchored at the start of the line: a prefix that merely
		// contains the documented text is not the documented line.
		{"govulncheck", "note: Scanner: govulncheck@v1.8.0\n"},
	}
	for _, tc := range cases {
		t.Run(tc.bin+"/"+tc.report, func(t *testing.T) {
			got, err := extractVersion(tc.bin, tc.report)
			if tc.report == "Version: dev\nGit tag: \n" {
				// "dev" parses; it is the comparison that refuses it.
				if err != nil || got != "dev" {
					t.Fatalf("got %q, %v; want dev, nil", got, err)
				}
				return
			}
			var parse *VersionParseError
			if !errors.As(err, &parse) {
				t.Fatalf("got %q, err = %v, want *VersionParseError", got, err)
			}
			if parse.Report != tc.report {
				t.Errorf("the error does not carry what the tool said: %q", parse.Report)
			}
		})
	}
}

func TestSameVersion_IsExactWithTheVPrefixOptional(t *testing.T) {
	cases := []struct {
		got, pin string
		want     bool
	}{
		{"2.14.0", "v2.14.0", true},
		{"v2.29.0", "v2.29.0", true},
		{"v1.8.0", "1.8.0", true},
		// The substring test these replace accepted both of these.
		{"v11.8.0", "v1.8.0", false},
		{"v12.29.0", "v2.29.0", false},
		{"dev", "v2.29.0", false},
		{"v2.29.0-rc1", "v2.29.0", false},
	}
	for _, tc := range cases {
		if got := sameVersion(tc.got, tc.pin); got != tc.want {
			t.Errorf("sameVersion(%q, %q) = %v, want %v", tc.got, tc.pin, got, tc.want)
		}
	}
}

// fakeHost is the environment require runs against: what is on PATH, what
// each command prints, and what was run.
type fakeHost struct {
	onPath   map[string]bool
	outputs  map[string]string // "bin arg" -> output
	failures map[string]bool   // "bin arg" -> exits non-zero
	env      map[string]string
	manifest string
	pins     string // the pin file's content; "" is a pin file that cannot be read
	ran      []string
	removed  []string
	// installs puts the binary on PATH, the way actions/setup-go's
	// GOPATH/bin does, unless it is false.
	installPutsOnPath bool
}

// fakeModuleDir is the throwaway module directory fakeHost hands out.
const fakeModuleDir = "/tmp/gosec-build-x"

const pinsWithXTools = "# x/tools for gosec\nGOSEC_VERSION=v2.29.0\nXTOOLS_VERSION=v0.52.0\n"

func (h *fakeHost) host() host {
	return host{
		lookPath: func(bin string) (string, error) {
			if h.onPath[bin] {
				return "/usr/local/bin/" + bin, nil
			}
			return "", errors.New("executable file not found in $PATH")
		},
		run: func(name string, args ...string) (string, error) {
			key := strings.Join(append([]string{name}, args...), " ")
			h.ran = append(h.ran, key)
			if name == "go" && slices.Contains(args, "install") && h.installPutsOnPath {
				h.onPath[strings.Split(args[len(args)-1][strings.LastIndex(args[len(args)-1], "/")+1:], "@")[0]] = true
			}
			if h.failures[key] {
				return h.outputs[key], errors.New("exit status 2")
			}
			return h.outputs[key], nil
		},
		getenv: func(k string) string { return h.env[k] },
		readFile: func(path string) ([]byte, error) {
			content := h.manifest
			if path == pinFile {
				content = h.pins
			}
			if content == "" {
				return nil, os.ErrNotExist
			}
			return []byte(content), nil
		},
		mkdirTemp: func() (string, error) { return fakeModuleDir, nil },
		removeAll: func(path string) error {
			h.removed = append(h.removed, path)
			return nil
		},
	}
}

func TestRequire_AcceptsThePinnedVersion(t *testing.T) {
	h := &fakeHost{
		onPath:   map[string]bool{"govulncheck": true},
		outputs:  map[string]string{"govulncheck --version": govulncheckReport},
		manifest: "govulncheck v1.8.0\n",
	}
	var out bytes.Buffer
	err := require(&out, h.host(), request{bin: "govulncheck", pin: "v1.8.0", module: "golang.org/x/vuln/cmd/govulncheck"})
	if err != nil {
		t.Fatalf("require: %v", err)
	}
	for _, want := range []string{"ok  govulncheck v1.8.0", "runner image tool manifest", "  govulncheck v1.8.0"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output omits %q:\n%s", want, out.String())
		}
	}
}

func TestRequire_FallsBackToTheSingleDashFlag(t *testing.T) {
	h := &fakeHost{
		onPath:   map[string]bool{"gosec": true},
		outputs:  map[string]string{"gosec -version": gosecReport},
		failures: map[string]bool{"gosec --version": true},
	}
	var out bytes.Buffer
	if err := require(&out, h.host(), request{bin: "gosec", pin: "v2.29.0", module: "m"}); err != nil {
		t.Fatalf("require: %v", err)
	}
}

func TestRequire_AnUnreadableVersionFails(t *testing.T) {
	cases := map[string]*fakeHost{
		"both flags fail": {
			onPath:   map[string]bool{"gosec": true},
			failures: map[string]bool{"gosec --version": true, "gosec -version": true},
		},
		"both flags print nothing": {
			onPath: map[string]bool{"gosec": true},
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			err := require(&bytes.Buffer{}, h.host(), request{bin: "gosec", pin: "v2.29.0", module: "m"})
			var unreadable *VersionUnreadableError
			if !errors.As(err, &unreadable) {
				t.Fatalf("err = %v, want *VersionUnreadableError", err)
			}
		})
	}
}

func TestRequire_AMismatchFailsAndSaysWhatTheToolSaid(t *testing.T) {
	h := &fakeHost{
		onPath:  map[string]bool{"gosec": true},
		outputs: map[string]string{"gosec --version": "Version: v12.29.0\n"},
	}
	err := require(&bytes.Buffer{}, h.host(), request{bin: "gosec", pin: "v2.29.0", module: "m"})
	var mismatch *VersionMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("err = %v, want *VersionMismatchError", err)
	}
	if mismatch.Got != "v12.29.0" || mismatch.Pin != "v2.29.0" {
		t.Errorf("mismatch = %+v", mismatch)
	}
	if !strings.Contains(err.Error(), "Version: v12.29.0") {
		t.Errorf("the error does not quote the report: %v", err)
	}
}

func TestRequire_AMissingToolOnTheSelfHostedRunnerIsAnImageDefect(t *testing.T) {
	h := &fakeHost{
		onPath: map[string]bool{},
		env:    map[string]string{"GITHUB_SERVER_URL": "https://forge.example.com"},
	}
	err := require(&bytes.Buffer{}, h.host(), request{bin: "gosec", pin: "v2.29.0", module: "m"})
	var missing *MissingToolError
	if !errors.As(err, &missing) {
		t.Fatalf("err = %v, want *MissingToolError", err)
	}
	for _, cmd := range h.ran {
		if strings.HasPrefix(cmd, "go install") {
			t.Fatalf("installed over the network on a self-hosted runner (#44): %v", h.ran)
		}
	}
}

func TestRequire_OnGitHubAMissingToolIsInstalledThenVerified(t *testing.T) {
	h := &fakeHost{
		onPath: map[string]bool{},
		env:    map[string]string{"GITHUB_SERVER_URL": "https://github.com"},
		outputs: map[string]string{
			"gosec --version": gosecReport,
		},
		installPutsOnPath: true,
		pins:              pinsWithXTools,
	}
	var out bytes.Buffer
	err := require(&out, h.host(), request{
		bin:         "gosec",
		pin:         "v2.29.0",
		module:      "github.com/securego/gosec/v2/cmd/gosec",
		installArgs: []string{"-ldflags", "-X main.Version=v2.29.0"},
	})
	if err != nil {
		t.Fatalf("require: %v", err)
	}
	// The devcontainer image's recipe: a throwaway module with x/tools at the
	// pin file's XTOOLS_VERSION, never a bare `go install gosec@pin`.
	want := []string{
		"go -C " + fakeModuleDir + " mod init gosec-build",
		"go -C " + fakeModuleDir + " get github.com/securego/gosec/v2/cmd/gosec@v2.29.0 golang.org/x/tools@v0.52.0",
		"go -C " + fakeModuleDir + " install -ldflags -X main.Version=v2.29.0 github.com/securego/gosec/v2/cmd/gosec",
	}
	if len(h.ran) < len(want) || !slices.Equal(h.ran[:len(want)], want) {
		t.Fatalf("ran %q, want first %q", h.ran, want)
	}
	if !slices.Equal(h.removed, []string{fakeModuleDir}) {
		t.Errorf("removed %q, want the throwaway module %q", h.removed, fakeModuleDir)
	}
}

// Every tool but gosec builds with the x/tools its own go.mod names.
func TestRequire_OnGitHubOtherToolsInstallAtThePin(t *testing.T) {
	h := &fakeHost{
		onPath:            map[string]bool{},
		env:               map[string]string{"GITHUB_SERVER_URL": "https://github.com"},
		outputs:           map[string]string{"govulncheck --version": govulncheckReport},
		installPutsOnPath: true,
	}
	err := require(&bytes.Buffer{}, h.host(), request{bin: "govulncheck", pin: "v1.8.0", module: "golang.org/x/vuln/cmd/govulncheck"})
	if err != nil {
		t.Fatalf("require: %v", err)
	}
	if want := "go install golang.org/x/vuln/cmd/govulncheck@v1.8.0"; len(h.ran) == 0 || h.ran[0] != want {
		t.Fatalf("ran %q, want first %q", h.ran, want)
	}
}

// gosec without its x/tools pin is not installed at all.
func TestRequire_OnGitHubGosecWithoutTheXToolsPinFails(t *testing.T) {
	for name, pins := range map[string]string{
		"unreadable pin file":  "",
		"no XTOOLS_VERSION":    "GOSEC_VERSION=v2.29.0\n",
		"empty XTOOLS_VERSION": "XTOOLS_VERSION=\n",
	} {
		t.Run(name, func(t *testing.T) {
			h := &fakeHost{
				onPath: map[string]bool{},
				env:    map[string]string{"GITHUB_SERVER_URL": "https://github.com"},
				pins:   pins,
			}
			err := require(&bytes.Buffer{}, h.host(), request{bin: "gosec", pin: "v2.29.0", module: "github.com/securego/gosec/v2/cmd/gosec"})
			var pin *PinError
			if !errors.As(err, &pin) || pin.Key != "XTOOLS_VERSION" {
				t.Fatalf("err = %v, want *PinError for XTOOLS_VERSION", err)
			}
			if len(h.ran) != 0 {
				t.Errorf("ran %q before the pin was known", h.ran)
			}
		})
	}
}

// A failing step of the gosec build stops it, says what go said, and still
// removes the throwaway module.
func TestRequire_OnGitHubAFailedGosecBuildIsReported(t *testing.T) {
	get := "go -C " + fakeModuleDir + " get github.com/securego/gosec/v2/cmd/gosec@v2.29.0 golang.org/x/tools@v0.52.0"
	h := &fakeHost{
		onPath:   map[string]bool{},
		env:      map[string]string{"GITHUB_SERVER_URL": "https://github.com"},
		pins:     pinsWithXTools,
		failures: map[string]bool{get: true},
		outputs:  map[string]string{get: "no route to host"},
	}
	err := require(&bytes.Buffer{}, h.host(), request{bin: "gosec", pin: "v2.29.0", module: "github.com/securego/gosec/v2/cmd/gosec"})
	var install *InstallError
	if !errors.As(err, &install) || !strings.Contains(err.Error(), "no route to host") {
		t.Fatalf("err = %v, want *InstallError carrying go's output", err)
	}
	if h.ran[len(h.ran)-1] != get {
		t.Errorf("ran %q after the failed step", h.ran)
	}
	if !slices.Equal(h.removed, []string{fakeModuleDir}) {
		t.Errorf("removed %q, want the throwaway module %q", h.removed, fakeModuleDir)
	}
}

func TestRequire_OnGitHubAnInstallThatIsNotOnPathFails(t *testing.T) {
	h := &fakeHost{
		onPath: map[string]bool{},
		env:    map[string]string{"GITHUB_SERVER_URL": "https://github.com"},
		pins:   pinsWithXTools,
	}
	err := require(&bytes.Buffer{}, h.host(), request{bin: "gosec", pin: "v2.29.0", module: "github.com/securego/gosec/v2/cmd/gosec"})
	var notOnPath *NotOnPathError
	if !errors.As(err, &notOnPath) {
		t.Fatalf("err = %v, want *NotOnPathError", err)
	}
}

func TestRequire_OnGitHubAFailedInstallIsReported(t *testing.T) {
	h := &fakeHost{
		onPath:   map[string]bool{},
		env:      map[string]string{"GITHUB_SERVER_URL": "https://github.com"},
		failures: map[string]bool{"go install m@v1": true},
		outputs:  map[string]string{"go install m@v1": "no route to host"},
	}
	err := require(&bytes.Buffer{}, h.host(), request{bin: "govulncheck", pin: "v1", module: "m"})
	var install *InstallError
	if !errors.As(err, &install) {
		t.Fatalf("err = %v, want *InstallError", err)
	}
	if !strings.Contains(err.Error(), "no route to host") {
		t.Errorf("the error drops what go install said: %v", err)
	}
}

func TestRequire_AnUnknownToolFailsBeforeAnythingRuns(t *testing.T) {
	h := &fakeHost{
		onPath:  map[string]bool{"staticcheck": true},
		outputs: map[string]string{"staticcheck --version": "staticcheck 2026.1\n"},
	}
	err := require(&bytes.Buffer{}, h.host(), request{bin: "staticcheck", pin: "2026.1", module: "m"})
	var unknown *UnknownToolError
	if !errors.As(err, &unknown) {
		t.Fatalf("err = %v, want *UnknownToolError", err)
	}
}

func TestParseArgs(t *testing.T) {
	req, err := parseArgs([]string{"gosec", "v2.29.0", "github.com/securego/gosec/v2/cmd/gosec", "-ldflags", "-X main.Version=v2.29.0"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if req.bin != "gosec" || req.pin != "v2.29.0" || req.module != "github.com/securego/gosec/v2/cmd/gosec" {
		t.Errorf("req = %+v", req)
	}
	if strings.Join(req.installArgs, "|") != "-ldflags|-X main.Version=v2.29.0" {
		t.Errorf("installArgs = %q", req.installArgs)
	}

	for _, bad := range [][]string{nil, {"gosec"}, {"gosec", "v1"}, {"", "v1", "m"}, {"gosec", "", "m"}, {"gosec", "v1", ""}} {
		_, err := parseArgs(bad)
		var usage *UsageError
		if !errors.As(err, &usage) {
			t.Errorf("parseArgs(%q) err = %v, want *UsageError", bad, err)
		}
	}
}

func TestErrors_NameTheirSubject(t *testing.T) {
	cause := errors.New("cause")
	cases := []struct {
		err      error
		contains []string
		wrapped  error
	}{
		{&UsageError{Problem: "missing pin"}, []string{"usage", "missing pin"}, nil},
		{&MissingToolError{Bin: "gosec", Pin: "v2.29.0"}, []string{"gosec", "v2.29.0", "#44"}, nil},
		{&InstallError{Module: "m", Pin: "v1", Output: "out", Err: cause}, []string{"m@v1", "out"}, cause},
		{&PinError{Path: "pins.env", Key: "XTOOLS_VERSION"}, []string{"pins.env", "XTOOLS_VERSION"}, nil},
		{&PinError{Path: "pins.env", Key: "XTOOLS_VERSION", Err: cause}, []string{"pins.env", "XTOOLS_VERSION", "cause"}, cause},
		{&NotOnPathError{Bin: "gosec", Module: "m", Pin: "v1"}, []string{"gosec", "PATH"}, nil},
		{&VersionUnreadableError{Bin: "gosec"}, []string{"gosec", "not a matching version"}, nil},
		{&UnknownToolError{Bin: "x"}, []string{"'x'", "knownTools"}, nil},
		{&VersionParseError{Bin: "gosec", Report: "said this"}, []string{"gosec", "said this"}, nil},
		{&VersionMismatchError{Bin: "gosec", Got: "v1", Pin: "v2", Report: "Version: v1"}, []string{"gosec", "v1", "v2", "#21"}, nil},
	}
	for _, tc := range cases {
		msg := tc.err.Error()
		for _, want := range tc.contains {
			if !strings.Contains(msg, want) {
				t.Errorf("%T: %q omits %q", tc.err, msg, want)
			}
		}
		if tc.wrapped != nil && !errors.Is(tc.err, tc.wrapped) {
			t.Errorf("%T does not unwrap to its cause", tc.err)
		}
	}
}

// TestCLI_ExitStatusFollowsTheOutcome: 0 for a tool at its pin, 1 with a FAIL
// line for a bad invocation or a mismatch.
func TestCLI_ExitStatusFollowsTheOutcome(t *testing.T) {
	good := func() host {
		return (&fakeHost{
			onPath:  map[string]bool{"govulncheck": true},
			outputs: map[string]string{"govulncheck --version": govulncheckReport},
		}).host()
	}
	args := []string{"govulncheck", "v1.8.0", "golang.org/x/vuln/cmd/govulncheck"}

	var stdout, stderr bytes.Buffer
	if code := cli(args, &stdout, &stderr, good()); code != 0 {
		t.Fatalf("exit = %d, want 0; stderr %q", code, stderr.String())
	}

	for name, tc := range map[string][]string{
		"no arguments":    nil,
		"a different pin": {"govulncheck", "v1.9.0", "golang.org/x/vuln/cmd/govulncheck"},
		"an unknown tool": {"staticcheck", "v1", "honnef.co/go/tools/cmd/staticcheck"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := cli(tc, &stdout, &stderr, good()); code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			if !strings.HasPrefix(stderr.String(), "FAIL: ") {
				t.Fatalf("stderr = %q, want a FAIL line", stderr.String())
			}
		})
	}
}

// TestSystemHost_TouchesTheRealSystem: the production host finds and runs a
// real binary (the go tool running this test), reads a real file and the real
// environment, and reports a missing binary as an error.
func TestSystemHost_TouchesTheRealSystem(t *testing.T) {
	h := systemHost()

	goBin, err := h.lookPath("go")
	if err != nil {
		t.Fatalf("lookPath(go): %v", err)
	}
	out, err := h.run(goBin, "env", "GOVERSION")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(out), "go") {
		t.Fatalf("run(go env GOVERSION) = %q, %v", out, err)
	}
	if _, err := h.run(goBin, "no-such-subcommand"); err == nil {
		t.Fatal("run reported success for a failing command")
	}
	if _, err := h.lookPath("no-such-binary-for-require-tool"); err == nil {
		t.Fatal("lookPath found a binary that does not exist")
	}

	t.Setenv("REQUIRE_TOOL_PROBE", "set")
	if got := h.getenv("REQUIRE_TOOL_PROBE"); got != "set" {
		t.Fatalf("getenv = %q, want %q", got, "set")
	}
	path := filepath.Join(t.TempDir(), "manifest")
	if err := os.WriteFile(path, []byte("gosec v2\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if b, err := h.readFile(path); err != nil || string(b) != "gosec v2\n" {
		t.Fatalf("readFile = %q, %v", b, err)
	}

	dir, err := h.mkdirTemp()
	if err != nil {
		t.Fatalf("mkdirTemp: %v", err)
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Fatalf("mkdirTemp made no directory: %v", err)
	}
	if err := h.removeAll(dir); err != nil {
		t.Fatalf("removeAll: %v", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removeAll left %s: %v", dir, err)
	}
}

// The pin the gosec build reads is the one the devcontainer image builds with.
func TestPinned_ReadsTheRepositoryPinFile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", pinFile))
	if err != nil {
		t.Fatalf("reading the pin file: %v", err)
	}
	h := (&fakeHost{pins: string(data)}).host()
	got, err := pinned(h, "XTOOLS_VERSION")
	if err != nil {
		t.Fatalf("pinned: %v", err)
	}
	if !strings.HasPrefix(got, "v0.") {
		t.Errorf("XTOOLS_VERSION = %q, want a v0.x x/tools version", got)
	}
}
