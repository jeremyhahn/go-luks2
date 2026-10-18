// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package workflows

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var needsResult = regexp.MustCompile(`\$\{\{ needs\.([A-Za-z0-9_-]+)\.result \}\}`)

// gateScript returns the CI Gate's run script as written in ci.yml, with each
// `${{ needs.<job>.result }}` replaced by results[job]. It fails the test when
// the script is missing, names a job results lacks, leaves a job of results
// unread, or keeps any other `${{ … }}` expression: a gate the test cannot run
// in full is a gate the test cannot fail.
func gateScript(t *testing.T, results map[string]string) string {
	t.Helper()
	lines := strings.Split(job(t, readFile(t, ".github/workflows/ci.yml"), "ci-gate"), "\n")
	start, indent := -1, 0
	for i, l := range lines {
		if strings.TrimSpace(l) == "run: |" {
			if start >= 0 {
				t.Fatal("CI Gate has more than one run block")
			}
			start, indent = i+1, len(l)-len(strings.TrimLeft(l, " "))
		}
	}
	if start < 0 {
		t.Fatal("CI Gate has no `run: |` block")
	}
	var body []string
	strip := -1
	for _, l := range lines[start:] {
		if strings.TrimSpace(l) == "" {
			body = append(body, "")
			continue
		}
		in := len(l) - len(strings.TrimLeft(l, " "))
		if in <= indent {
			break
		}
		if strip < 0 {
			strip = in
		}
		if in < strip {
			t.Fatalf("CI Gate run line %q is indented less than the first", l)
		}
		body = append(body, l[strip:])
	}
	script := strings.TrimSpace(strings.Join(body, "\n"))
	if script == "" {
		t.Fatal("CI Gate's run block is empty")
	}

	read := map[string]bool{}
	script = needsResult.ReplaceAllStringFunc(script, func(m string) string {
		id := needsResult.FindStringSubmatch(m)[1]
		v, ok := results[id]
		if !ok {
			t.Fatalf("CI Gate reads needs.%s.result, which the test has no result for", id)
		}
		read[id] = true
		return v
	})
	for id := range results {
		if !read[id] {
			t.Fatalf("CI Gate never reads needs.%s.result", id)
		}
	}
	if strings.Contains(script, "${{") {
		t.Fatalf("CI Gate's script keeps an unsubstituted expression:\n%s", script)
	}
	return script + "\n"
}

// runGate executes the gate script the way the runner does (bash -e with
// pipefail) and returns its exit status and output.
func runGate(t *testing.T, script, fullTier string) (int, string) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash is required to run the CI Gate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "gate.sh")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bash, "--noprofile", "--norc", "-eo", "pipefail", path) // #nosec G204 -- bash from PATH on a script this test wrote
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "FULL_TIER=" + fullTier}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, out.String()
	case errors.As(err, &exit):
		return exit.ExitCode(), out.String()
	default:
		t.Fatalf("running the CI Gate: %v", err)
		return -1, ""
	}
}

// TestCIGateScriptDecides runs the CI Gate's script, as written, over every
// tier selection and job result. Checking that the script contains the right
// lines cannot fail when the logic around them is wrong; running it can.
func TestCIGateScriptDecides(t *testing.T) {
	type gateCase struct {
		name     string
		fullTier string
		results  map[string]string // overrides; every other job is success
		wantExit int
		wantLine string
	}
	var cases []gateCase
	for _, ft := range []string{"true", "false"} {
		cases = append(cases, gateCase{name: "all success/FULL_TIER=" + ft, fullTier: ft, wantLine: "CI gate passed."})
	}
	allFullSkipped := map[string]string{}
	for _, j := range fullTier {
		allFullSkipped[j] = "skipped"
	}
	cases = append(cases,
		gateCase{name: "full tier skipped/FULL_TIER=false", fullTier: "false", results: allFullSkipped, wantLine: "CI gate passed."},
		gateCase{name: "full tier skipped/FULL_TIER=true", fullTier: "true", results: allFullSkipped, wantExit: 1, wantLine: "FAIL " + fullTier[0] + " (skipped)"},
	)
	for _, j := range fullTier {
		cases = append(cases,
			gateCase{name: j + "=skipped/FULL_TIER=false", fullTier: "false", results: map[string]string{j: "skipped"}, wantLine: "SKIP " + j + " (full tier not selected)"},
			gateCase{name: j + "=skipped/FULL_TIER=true", fullTier: "true", results: map[string]string{j: "skipped"}, wantExit: 1, wantLine: "FAIL " + j + " (skipped)"},
		)
	}
	for _, ft := range []string{"true", "false"} {
		for _, j := range prTier {
			cases = append(cases, gateCase{name: j + "=skipped/FULL_TIER=" + ft, fullTier: ft, results: map[string]string{j: "skipped"}, wantExit: 1, wantLine: "FAIL " + j + " (skipped)"})
		}
		for _, j := range append(append([]string{}, prTier...), fullTier...) {
			for _, r := range []string{"failure", "cancelled", ""} { //nolint:misspell // the runner's spelling, not prose
				shown := r
				if r == "" {
					shown = "<unreadable>"
				}
				cases = append(cases, gateCase{name: j + "=" + shown + "/FULL_TIER=" + ft, fullTier: ft, results: map[string]string{j: r}, wantExit: 1, wantLine: "FAIL " + j + " (" + shown + ")"})
			}
		}
	}
	for _, ft := range []string{"", "TRUE", "1", "yes"} {
		cases = append(cases, gateCase{name: "FULL_TIER=" + ft, fullTier: ft, wantExit: 1, wantLine: "FAIL FULL_TIER is '" + ft + "', neither true nor false"})
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			results := map[string]string{}
			for _, j := range append(append([]string{}, prTier...), fullTier...) {
				results[j] = "success"
			}
			for j, r := range c.results {
				results[j] = r
			}
			code, out := runGate(t, gateScript(t, results), c.fullTier)
			if code != c.wantExit {
				t.Errorf("exit %d, want %d; output:\n%s", code, c.wantExit, out)
			}
			if !containsLine(out, c.wantLine) {
				t.Errorf("output lacks the line %q:\n%s", c.wantLine, out)
			}
		})
	}
}

func containsLine(out, want string) bool {
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) == want {
			return true
		}
	}
	return false
}
