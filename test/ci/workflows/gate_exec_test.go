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

// runGateDraft is runGate with the DRAFT the gate reads (ci-template v1.26).
func runGateDraft(t *testing.T, script, fullTier, nightly, draft string) (int, string) {
	t.Helper()
	return runGateEnv(t, script, fullTier, nightly, draft, nil)
}

// gateEnvDefaults are the preflight values an ordinary run hands CI Gate
// (ci-template v1.29.3, v1.30): not a schedule run, the guard's `run`, no
// proof, not a docs-only PR, and lint-gates selected.
var gateEnvDefaults = map[string]string{
	"SCHEDULE":       "false",
	"SCHEDULE_GUARD": "run",
	"PROOF":          "",
	"DOCS_ONLY":      "false",
	"LINT_GATES_SEL": "true",
}

// runGateEnv executes the gate script the way the runner does (bash -e with
// pipefail), with the preflight values in env over gateEnvDefaults, and
// returns its exit status and output.
func runGateEnv(t *testing.T, script, fullTier, nightly, draft string, env map[string]string) (int, string) {
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
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "FULL_TIER=" + fullTier, "NIGHTLY=" + nightly, "DRAFT=" + draft}
	for k, v := range gateEnvDefaults {
		if o, ok := env[k]; ok {
			v = o
		}
		cmd.Env = append(cmd.Env, k+"="+v)
	}
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
		nightly  string            // "" means false: every case but the NIGHTLY validation sets it
		results  map[string]string // overrides; every other job is success
		env      map[string]string // preflight values over gateEnvDefaults
		wantExit int
		wantLine string
	}
	var cases []gateCase
	for _, ft := range []string{"true", "false"} {
		cases = append(cases, gateCase{name: "all success/FULL_TIER=" + ft, fullTier: ft, wantLine: "CI gate passed."})
	}
	cases = append(cases, gateCase{name: "all success/NIGHTLY=true", fullTier: "true", nightly: "true", wantLine: "CI gate passed."})
	allFullSkipped := map[string]string{}
	for _, j := range append(append([]string{}, fullTier...), nightlyTier...) {
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
	for _, j := range nightlyTier {
		for _, ft := range []string{"true", "false"} {
			cases = append(cases, gateCase{name: j + "=skipped/NIGHTLY=false/FULL_TIER=" + ft, fullTier: ft, results: map[string]string{j: "skipped"}, wantLine: "SKIP " + j + " (nightly and dispatch only)"})
		}
		cases = append(cases, gateCase{name: j + "=skipped/NIGHTLY=true", fullTier: "true", nightly: "true", results: map[string]string{j: "skipped"}, wantExit: 1, wantLine: "FAIL " + j + " (skipped)"})
	}
	for _, ft := range []string{"true", "false"} {
		for _, j := range append(append(append([]string{}, prTier...), codeTier...), scopedTier...) {
			cases = append(cases, gateCase{name: j + "=skipped/FULL_TIER=" + ft, fullTier: ft, results: map[string]string{j: "skipped"}, wantExit: 1, wantLine: "FAIL " + j + " (skipped)"})
		}
		for _, j := range allJobs() {
			for _, r := range []string{"failure", "cancelled", ""} { //nolint:misspell // the runner's spelling, not prose
				shown := r
				if r == "" {
					shown = "<unreadable>"
				}
				cases = append(cases, gateCase{name: j + "=" + shown + "/FULL_TIER=" + ft, fullTier: ft, results: map[string]string{j: r}, wantExit: 1, wantLine: "FAIL " + j + " (" + shown + ")"})
			}
		}
	}
	// ci-template v1.30: a `code` job may skip on a docs-only PR, a `scoped`
	// job when no changed file matched, and every job but a nightly one on a
	// tree the guard proved; nothing else widens. A refused run fails, and
	// so does a schedule run whose guard did not read `run`.
	for _, j := range codeTier {
		cases = append(cases,
			gateCase{name: j + "=skipped/docs-only", fullTier: "false", results: map[string]string{j: "skipped"}, env: map[string]string{"DOCS_ONLY": "true"}, wantLine: "SKIP " + j + " (docs-only pull request)"},
			gateCase{name: j + "=skipped/lint-gates unselected", fullTier: "false", results: map[string]string{j: "skipped"}, env: map[string]string{"LINT_GATES_SEL": "false"}, wantExit: 1, wantLine: "FAIL " + j + " (skipped)"},
		)
	}
	for _, j := range scopedTier {
		cases = append(cases,
			gateCase{name: j + "=skipped/lint-gates unselected", fullTier: "false", results: map[string]string{j: "skipped"}, env: map[string]string{"LINT_GATES_SEL": "false"}, wantLine: "SKIP " + j + " (no changed file matches LINT_GATES_PATTERN)"},
			gateCase{name: j + "=skipped/docs-only", fullTier: "false", results: map[string]string{j: "skipped"}, env: map[string]string{"DOCS_ONLY": "true"}, wantExit: 1, wantLine: "FAIL " + j + " (skipped)"},
		)
	}
	for _, j := range prTier {
		cases = append(cases, gateCase{name: j + "=skipped/docs-only", fullTier: "false", results: map[string]string{j: "skipped"}, env: map[string]string{"DOCS_ONLY": "true", "LINT_GATES_SEL": "false"}, wantExit: 1, wantLine: "FAIL " + j + " (skipped)"})
	}
	proven := map[string]string{"SCHEDULE_GUARD": "proven", "PROOF": "4242"}
	for _, j := range allJobs() {
		if j == "preflight" || contains(nightlyTier, j) {
			continue
		}
		cases = append(cases, gateCase{name: j + "=skipped/proven", fullTier: "true", results: map[string]string{j: "skipped"}, env: proven, wantLine: "SKIP " + j + " (tree proven by run 4242)"})
	}
	for _, j := range nightlyTier {
		cases = append(cases, gateCase{name: j + "=skipped/proven/NIGHTLY=true", fullTier: "true", nightly: "true", results: map[string]string{j: "skipped"}, env: proven, wantExit: 1, wantLine: "FAIL " + j + " (skipped)"})
	}
	cases = append(cases,
		gateCase{name: "proven without a proof", fullTier: "true", results: map[string]string{"integration": "skipped"}, env: map[string]string{"SCHEDULE_GUARD": "proven"}, wantExit: 1, wantLine: "FAIL integration (skipped)"},
		gateCase{name: "refused", fullTier: "false", env: map[string]string{"SCHEDULE_GUARD": "refused"}, wantExit: 1, wantLine: "FAIL preflight (refused: a workflow_dispatch off main or a PR from lane-ckpt/*; see its log)"},
		gateCase{name: "schedule unreadable", fullTier: "true", nightly: "true", env: map[string]string{"SCHEDULE": "true", "SCHEDULE_GUARD": "unreadable"}, wantExit: 1, wantLine: "FAIL preflight (verdict 'unreadable': the guarded jobs skipped because the guard could not read the API; see its log)"},
		gateCase{name: "schedule run", fullTier: "true", nightly: "true", env: map[string]string{"SCHEDULE": "true"}, wantLine: "CI gate passed."},
	)
	for _, ft := range []string{"", "TRUE", "1", "yes"} {
		cases = append(cases, gateCase{name: "FULL_TIER=" + ft, fullTier: ft, wantExit: 1, wantLine: "FAIL FULL_TIER is '" + ft + "', neither true nor false"})
	}
	for _, n := range []string{"TRUE", "1", "yes"} {
		cases = append(cases, gateCase{name: "NIGHTLY=" + n, fullTier: "true", nightly: n, wantExit: 1, wantLine: "FAIL NIGHTLY is '" + n + "', neither true nor false"})
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			results := map[string]string{}
			for _, j := range allJobs() {
				results[j] = "success"
			}
			for j, r := range c.results {
				results[j] = r
			}
			nightly := c.nightly
			if nightly == "" {
				nightly = "false"
			}
			code, out := runGateEnv(t, gateScript(t, results), c.fullTier, nightly, "false", c.env)
			if code != c.wantExit {
				t.Errorf("exit %d, want %d; output:\n%s", code, c.wantExit, out)
			}
			if !containsLine(out, c.wantLine) {
				t.Errorf("output lacks the line %q:\n%s", c.wantLine, out)
			}
		})
	}
}

// allJobs is every job CI Gate needs, over every tier.
func allJobs() []string {
	var all []string
	for _, tier := range [][]string{prTier, codeTier, scopedTier, fullTier, nightlyTier} {
		all = append(all, tier...)
	}
	return all
}

func containsLine(out, want string) bool {
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) == want {
			return true
		}
	}
	return false
}
