// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Command require-tool makes a Go analysis tool available at an EXACT pinned
// version, or fails the CI job. .github/workflows/ci.yml runs it before every
// step that lints or scans:
//
//	go run ./test/tools/require-tool <binary> <pin> <module-path> [go-install args...]
//
// It replaces .github/require-tool.sh, because the public release ships no
// shell scripts (owner ruling on #211). Its behavior is the script's, unchanged.
//
// # WHY THIS EXISTS
//
// (#44) CI used to `go install tool@version` at job time. Runner job containers
// use host networking, and on hosts that resolve an AAAA record for
// sum.golang.org with no default IPv6 route, Go's v6-to-v4 fallback sometimes
// does not complete — more often on a loaded runner. Every Lint and Security
// Scan leg was exposed. The tools are now baked into the self-hosted runner
// image at pinned versions, so on that host this command performs no network
// access at all.
//
// (#21) Pinning alone was never enough for gosec: it takes its version string
// from ldflags rather than from the module path, so `go install ...@v2.29.0`
// still self-reports `dev` — which is how `make security` came to print
// `Gosec : dev`, meaning results could not be attributed to a scanner version
// and two runs of one commit could disagree. The ASSERTION is therefore the
// deliverable, not the pin: whatever the binary is and wherever it came from,
// this refuses to continue unless it SAYS it is the pinned version.
//
// FAIL-CLOSED, in every direction:
//
//   - A tool missing on a self-hosted runner is an IMAGE defect. It is not
//     quietly papered over with a network install, because doing so would
//     restore precisely the flake this removes while reporting success.
//   - A tool whose self-report does not match the pin fails, rather than
//     scanning with an unknown version and calling the result a gate.
//   - A version that cannot be READ AT ALL fails. An unreadable self-report is
//     not evidence of a matching version.
//
// The github.com fallback is deliberate and narrow: the public host runs the
// same workflow file on GitHub-hosted runners, where no image of ours exists and
// there is nothing to bake into. It is the only path here that touches the
// network, and it still has to satisfy the same assertion afterwards. gosec is
// built there the way the devcontainer image builds it, against the pin file's
// golang.org/x/tools (see install).
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// manifestPath is where the runner image records what it baked. A version skew
// between the workflow's pin and the image's is a real inconsistency, and
// printing the manifest means it is caught before a scan runs rather than
// inferred afterwards from a result nobody can reproduce.
const manifestPath = "/etc/ci-runner-tools.txt"

// githubServer is the one server on which a missing tool is installed rather
// than refused.
const githubServer = "https://github.com"

// pinFile is the pin file the Makefile and the devcontainer image read,
// relative to the repository root, where CI runs this command.
const pinFile = "build/docker/devcontainer/tool-pins.env"

// knownTools maps each tool to the line its self-report documents its version
// on, anchored at the start of that line.
//
// A GENERIC "find something version-shaped" regex is not safe, and govulncheck
// shows why: its output's FIRST version-shaped token is the Go toolchain's.
//
//	Go: go1.27.1
//	Scanner: govulncheck@v1.8.0
//
// A loose extractor pins the wrong number. So each tool is parsed by its own
// documented line:
//
//	golangci-lint   golangci-lint has version 2.14.0 built with go1.27.1 ...
//	gosec           Version: v2.29.0
//	govulncheck     Scanner: govulncheck@v1.8.0
//
// An UNRECOGNIZED tool is a hard failure rather than a fallback to something
// looser. A version format nobody has read is a version that cannot be verified.
var knownTools = map[string]*regexp.Regexp{
	"golangci-lint": regexp.MustCompile(`(?m)^golangci-lint has version (\S+)`),
	"gosec":         regexp.MustCompile(`(?m)^Version:[ \t]+(\S+)[ \t]*$`),
	"govulncheck":   regexp.MustCompile(`(?m)^Scanner:[ \t]+govulncheck@(\S+)`),
}

// request is one parsed command line.
type request struct {
	bin         string
	pin         string
	module      string
	installArgs []string
}

// host is everything require touches outside itself, so each fail-closed branch
// can be driven by a test without a runner, a network or a real tool.
type host struct {
	lookPath func(bin string) (string, error)
	// run returns the command's combined output.
	run      func(name string, args ...string) (string, error)
	getenv   func(key string) string
	readFile func(path string) ([]byte, error)
	// mkdirTemp and removeAll hold the throwaway module gosec builds in.
	mkdirTemp func() (string, error)
	removeAll func(path string) error
}

func main() {
	os.Exit(cli(os.Args[1:], os.Stdout, os.Stderr, systemHost()))
}

// cli runs one invocation against h and returns the exit status: 0 the tool is
// present at the pin, 1 anything else, with the reason on stderr.
func cli(args []string, stdout, stderr io.Writer, h host) int {
	req, err := parseArgs(args)
	if err == nil {
		err = require(stdout, h, req)
	}
	if err != nil {
		fmt.Fprintln(stderr, "FAIL:", err)
		return 1
	}
	return 0
}

func systemHost() host {
	return host{
		lookPath: exec.LookPath,
		run: func(name string, args ...string) (string, error) {
			// The binary and its arguments are the CI workflow's own pinned
			// tool names and versions, not untrusted input.
			out, err := exec.Command(name, args...).CombinedOutput() // #nosec G204 -- the workflow's pinned tool name and version
			return string(out), err
		},
		getenv:    os.Getenv,
		readFile:  os.ReadFile,
		mkdirTemp: func() (string, error) { return os.MkdirTemp("", "gosec-build-") },
		removeAll: os.RemoveAll,
	}
}

// parseArgs reads `<binary> <pin> <module-path> [go-install args...]`.
func parseArgs(args []string) (request, error) {
	names := []string{"binary", "pinned version", "module path"}
	for i, name := range names {
		if len(args) <= i || args[i] == "" {
			return request{}, &UsageError{Problem: "missing " + name}
		}
	}
	return request{bin: args[0], pin: args[1], module: args[2], installArgs: args[3:]}, nil
}

// require makes req.bin available and asserts it reports req.pin.
func require(out io.Writer, h host, req request) error {
	// Refuse an unknown tool before anything runs: there is no way to verify
	// it afterwards, so installing or invoking it would be wasted work.
	if _, ok := knownTools[req.bin]; !ok {
		return &UnknownToolError{Bin: req.bin}
	}

	if manifest, err := h.readFile(manifestPath); err == nil {
		fmt.Fprintln(out, "runner image tool manifest:")
		fmt.Fprint(out, indent(string(manifest)))
	}

	path, err := h.lookPath(req.bin)
	if err != nil {
		if h.getenv("GITHUB_SERVER_URL") != githubServer {
			return &MissingToolError{Bin: req.bin, Pin: req.pin}
		}
		fmt.Fprintf(out, "note: %s is absent; installing %s@%s (GitHub-hosted runner, no baked image)\n",
			req.bin, req.module, req.pin)
		if err := install(h, req); err != nil {
			return err
		}
		// actions/setup-go puts GOPATH/bin on PATH. Assert it rather than
		// assume it.
		if path, err = h.lookPath(req.bin); err != nil {
			return &NotOnPathError{Bin: req.bin, Module: req.module, Pin: req.pin}
		}
	}

	report, err := selfReport(h, req.bin)
	if err != nil {
		return err
	}
	got, err := extractVersion(req.bin, report)
	if err != nil {
		return err
	}
	if !sameVersion(got, req.pin) {
		return &VersionMismatchError{Bin: req.bin, Got: got, Pin: req.pin, Report: report}
	}

	fmt.Fprintf(out, "ok  %s %s  (%s)\n", req.bin, req.pin, path)
	return nil
}

// install runs `go install` for req at its pin. gosec is built the way the
// devcontainer image builds it: in a throwaway module, with golang.org/x/tools
// raised to the pin file's XTOOLS_VERSION, because the x/tools gosec's own
// go.mod names cannot read the export data a current Go writes and every
// import then fails to type-check.
func install(h host, req request) error {
	if req.bin != "gosec" {
		args := append(append([]string{"install"}, req.installArgs...), req.module+"@"+req.pin)
		if output, err := h.run("go", args...); err != nil {
			return &InstallError{Module: req.module, Pin: req.pin, Output: output, Err: err}
		}
		return nil
	}
	xtools, err := pinned(h, "XTOOLS_VERSION")
	if err != nil {
		return err
	}
	dir, err := h.mkdirTemp()
	if err != nil {
		return &InstallError{Module: req.module, Pin: req.pin, Err: err}
	}
	defer func() { _ = h.removeAll(dir) }()
	for _, args := range [][]string{
		{"-C", dir, "mod", "init", "gosec-build"},
		{"-C", dir, "get", req.module + "@" + req.pin, "golang.org/x/tools@" + xtools},
		append(append([]string{"-C", dir, "install"}, req.installArgs...), req.module),
	} {
		if output, err := h.run("go", args...); err != nil {
			return &InstallError{Module: req.module, Pin: req.pin, Output: output, Err: err}
		}
	}
	return nil
}

// pinned reads key's value from the pin file. A pin that is absent or empty
// fails: building against whatever x/tools happens to resolve is the defect
// the pin exists to prevent.
func pinned(h host, key string) (string, error) {
	data, err := h.readFile(pinFile)
	if err != nil {
		return "", &PinError{Path: pinFile, Key: key, Err: err}
	}
	for _, line := range strings.Split(string(data), "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && name == key && value != "" {
			return value, nil
		}
	}
	return "", &PinError{Path: pinFile, Key: key}
}

// selfReport asks the tool for its version. Tools disagree on the flag, so both
// spellings are tried; a tool that answers neither has not said its version.
func selfReport(h host, bin string) (string, error) {
	for _, flag := range []string{"--version", "-version"} {
		report, err := h.run(bin, flag)
		if err == nil && strings.TrimSpace(report) != "" {
			return report, nil
		}
	}
	return "", &VersionUnreadableError{Bin: bin}
}

// extractVersion reads the version token from bin's documented self-report line.
func extractVersion(bin, report string) (string, error) {
	expr, ok := knownTools[bin]
	if !ok {
		return "", &UnknownToolError{Bin: bin}
	}
	m := expr.FindStringSubmatch(report)
	if m == nil {
		return "", &VersionParseError{Bin: bin, Report: report}
	}
	return m[1], nil
}

// sameVersion compares EXACTLY, with the `v` prefix optional on either side:
// golangci-lint reports bare (2.14.0) while gosec and govulncheck report
// prefixed (v2.29.0), and the pins are written prefixed. Nothing else is
// normalised away. The substring test this replaced FAILED OPEN: a v1.8.0 pin
// accepted a report of v11.8.0.
func sameVersion(got, pin string) bool {
	return strings.TrimPrefix(got, "v") == strings.TrimPrefix(pin, "v")
}

// indent prefixes every line of s with two spaces, for quoting a tool's output
// inside an error.
func indent(s string) string {
	var b bytes.Buffer
	for _, line := range strings.SplitAfter(s, "\n") {
		if line == "" {
			continue
		}
		b.WriteString("  ")
		b.WriteString(line)
	}
	if b.Len() > 0 && !bytes.HasSuffix(b.Bytes(), []byte("\n")) {
		b.WriteByte('\n')
	}
	return b.String()
}
