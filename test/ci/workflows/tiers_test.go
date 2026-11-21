// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package workflows

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/test/internal/labstrings"
)

// The tiers of ci.yml (#341). A job moved between them, or a condition
// edited on one job and not its siblings, changes what gates a merge without
// failing anything else; these tests are what fails. ci-template v1.30 adds
// two PR-tier tags: `code`, a job a docs-only PR skips (the image job), and
// `scoped`, lint-gates, which a PR skips when no changed file matches
// LINT_GATES_PATTERN.
var (
	prTier     = []string{"preflight", "lint", "merge-check", "test-race"}
	codeTier   = []string{"image", "fips", "integration"}
	scopedTier = []string{"lint-gates"}
	fullTier   = []string{}
	// codeFullTier is the part of codeTier that carries CI_FULL_TIER's
	// condition in its `if:` (codeFullJobIf): ci-template v1.41 (ruling
	// 742 (2)) moved integration and FIPS from the full tier to every PR.
	codeFullTier = []string{"fips", "integration"}
	nightlyTier  = []string{"soak"}
)

var (
	jobIf = regexp.MustCompile(`(?m)^    if: (.*)$`)
	// trailingComment is a YAML comment after a job's `if:` value.
	trailingComment = regexp.MustCompile(`\s+#.*$`)
	jobName         = regexp.MustCompile(`(?m)^    name: (.*)$`)
	prTypes         = regexp.MustCompile(`(?m)^  pull_request:\n    branches: \[main\]\n(?:    #.*\n)*    types: \[(.*)\]$`)
	fullTierEn      = regexp.MustCompile(`(?m)^          FULL_TIER: \$\{\{ (.*) \}\}$`)
	scheduleOn      = regexp.MustCompile(`(?m)^\s*schedule:`)
	// jobRunsOn matches a job's own runs-on line.
	jobRunsOn = regexp.MustCompile(`(?m)^    runs-on: (.+)$`)
)

func jobIfOf(t *testing.T, jobText string) string {
	t.Helper()
	m := jobIf.FindStringSubmatch(jobText)
	if m == nil {
		return ""
	}
	return trailingComment.ReplaceAllString(m[1], "")
}

func sameSet(a, b []string) bool {
	a, b = append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, ",") == strings.Join(b, ",")
}

// TestNoScheduleTrigger: this repository's nightly run is suspended, so no
// workflow is scheduled: main's full tier and Soak run on dispatch (the full
// tier also on push to main and a `ci:full` PR), and nightly.yml stays
// dispatch-only (sdlc §5a).
func TestNoScheduleTrigger(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join(repoRoot(t), ".github", "workflows"))
	if err != nil {
		t.Fatal(err)
	}
	var scheduled []string
	for _, e := range entries {
		f := ".github/workflows/" + e.Name()
		if n := len(scheduleOn.FindAllString(readFile(t, f), -1)); n > 0 {
			scheduled = append(scheduled, fmt.Sprintf("%s:%d", e.Name(), n))
		}
	}
	if len(scheduled) > 0 {
		t.Errorf("schedule: triggers %v, want none", scheduled)
	}
}

// TestMainRunsNeverCancel: on main one group per event and commit, so no
// main run cancels another (a newer push no longer cancels an older commit's
// run, and a schedule or dispatch run never cancels a push run); every other
// ref is one group. cancel-in-progress is a literal true, never an expression.
func TestMainRunsNeverCancel(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	m := regexp.MustCompile(`(?m)^concurrency:\n((?:  .*\n)+)`).FindStringSubmatch(ci)
	if m == nil {
		t.Fatal("ci.yml has no workflow-level concurrency block")
	}
	want := "  group: ${{ github.workflow }}-${{ github.event_name == 'schedule' && format('schedule-{0}', github.repository) || github.ref == 'refs/heads/main' && format('main-{0}-{1}', github.event_name, github.sha) || github.ref }}\n" +
		"  cancel-in-progress: true\n"
	if m[1] != want {
		t.Errorf("ci.yml's concurrency block is\n%s\nwant main runs that never cancel\n%s", m[1], want)
	}
}

// TestJobNamesAreLiteral: Gitea does not evaluate expressions in a job's
// `name:`; it posts the expression verbatim as the status context, so a gate
// named by one is never reported under the name branch protection requires.
func TestJobNamesAreLiteral(t *testing.T) {
	for _, f := range workflowFiles(t) {
		for _, m := range jobName.FindAllStringSubmatch(readFile(t, rel(t, f)), -1) {
			if strings.Contains(m[1], "${{") {
				t.Errorf("%s: job name %q is an expression", rel(t, f), m[1])
			}
		}
	}
	ci := readFile(t, ".github/workflows/ci.yml")
	if m := jobName.FindStringSubmatch(job(t, ci, "ci-gate")); m == nil || m[1] != "CI Gate" {
		t.Error(`job gate is not literally named "CI Gate"`)
	}
}

// hostedRunner is the runs-on of every ci.yml job (Company Agent m2077):
// GitHub-hosted ubuntu-latest, so main's CI Gate can go green on GitHub.
// Ruling 999: there is no exception. Self-hosted runners are only for a
// hardware-specific job or one that exceeds a measured hosted limit (disk,
// memory, or 6 h), and no ci.yml job does.
const hostedRunner = "ubuntu-latest"

// retiredLabels are the self-hosted runner labels the workflows ran on
// before m2077 (bigdisk, ci-gate, batch) and before ruling 999
// (bigdisk-docker, the pool ruling 442 routed main pushes and same-repository
// pull requests to). No workflow names them, and .github/actionlint.yaml does
// not list them, so a typo of one is still caught as an unknown runner.
var retiredLabels = []string{"bigdisk", "ci-gate", "batch", "bigdisk-docker"}

// TestCIGateRunsOnTheHostedRunner: CI Gate runs on ubuntu-latest. It still
// takes no checkout and no action: the gate is one run step that reads needs.
func TestCIGateRunsOnTheHostedRunner(t *testing.T) {
	gate := job(t, readFile(t, ".github/workflows/ci.yml"), "ci-gate")
	if got := jobRunsOn.FindAllStringSubmatch(gate, -1); len(got) != 1 || got[0][1] != hostedRunner {
		t.Errorf("CI Gate runs on %v, want %s", got, hostedRunner)
	}
	if strings.Contains(gate, "actions/checkout") {
		t.Error("CI Gate checks out the repository; the gate is one run step")
	}
	if regexp.MustCompile(`(?m)^\s*(-\s+)?uses:`).MatchString(gate) {
		t.Error("CI Gate has a uses: step; the gate is one run step")
	}
}

// freeDiskStep is the step every image-building job runs before its build on
// a hosted runner, whose stock free disk (about 14 GB) does not hold the
// devcontainer images.
const freeDiskStep = "Free runner disk"

// TestEveryCIJobRunsOnTheHostedRunner: every ci.yml job runs on
// a literal ubuntu-latest (ruling 999): no routing expression, no self-hosted
// label. Every job that builds a devcontainer image frees the runner's disk
// first, on github.com only, before any image build.
func TestEveryCIJobRunsOnTheHostedRunner(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	for _, id := range jobIDs(t, ci) {
		got := jobRunsOn.FindAllStringSubmatch(job(t, ci, id), -1)
		if id == "preflight" && len(got) == 1 && isPreflightTemplateRunsOn(t, ".github/workflows/ci.yml", ci, got[0][1]) {
			continue // ci-template v1.49: hosted off github.com and by CI_PREFLIGHT_RUNS_ON
		}
		if len(got) != 1 || got[0][1] != hostedRunner {
			t.Errorf("job %s runs on %v, want %s (ruling 999)", id, got, hostedRunner)
		}
	}
	for _, id := range toolchainJobs {
		j := job(t, ci, id)
		free := strings.Index(j, "- name: "+freeDiskStep+"\n")
		if free < 0 {
			t.Errorf("job %s builds a devcontainer image and has no %q step", id, freeDiskStep)
			continue
		}
		if build := strings.Index(j, "make docker-build"); build >= 0 && build < free {
			t.Errorf("job %s builds an image before %q", id, freeDiskStep)
		}
		block, _, _ := strings.Cut(j[free:], "\n\n")
		if !strings.Contains(block, "github.server_url == 'https://github.com'") {
			t.Errorf("job %s's %q step is not limited to github.com:\n%s", id, freeDiskStep, block)
		}
	}
}

// TestNoRetiredRunnerLabel: no workflow runs a job on a retired self-hosted
// label, and .github/actionlint.yaml no longer accepts one.
func TestNoRetiredRunnerLabel(t *testing.T) {
	for _, f := range workflowFiles(t) {
		text := readFile(t, rel(t, f))
		for _, m := range jobRunsOn.FindAllStringSubmatch(text, -1) {
			if isPreflightTemplateRunsOn(t, rel(t, f), text, m[1]) {
				continue
			}
			if l, ok := retiredRunsOnLabel(m[1]); ok {
				t.Errorf("%s runs a job on the retired label %s: %s", rel(t, f), l, m[1])
			}
		}
	}
	al := readFile(t, ".github/actionlint.yaml")
	for _, l := range retiredLabels {
		if regexp.MustCompile(`(?m)^    - ` + regexp.QuoteMeta(l) + `$`).MatchString(al) {
			t.Errorf(".github/actionlint.yaml still lists the retired label %s", l)
		}
	}
}

// isPreflightTemplateRunsOn reports whether a runs-on value is ci-template
// v1.49's preflight form on ci.yml's preflight job, held once in the file:
// the one place bigdisk may still be named (the github.com default, which
// CI_PREFLIGHT_RUNS_ON overrides).
func isPreflightTemplateRunsOn(t *testing.T, path, workflow, value string) bool {
	t.Helper()
	if path != ".github/workflows/ci.yml" || value != preflightRunsOn+"   # v1.49" {
		return false
	}
	line := "    runs-on: " + value + "\n"
	return strings.Count(workflow, line) == 1 && strings.Contains(job(t, workflow, "preflight"), line)
}

// serverURLArms matches a runs-on value that picks its label by forge:
// the first arm runs on github.com, the second only on Gitea (retired).
var serverURLArms = regexp.MustCompile(`^\$\{\{ github\.server_url == 'https://github\.com' && '([^']*)' \|\| '([^']*)' \}\}$`)

// retiredRunsOnLabel reports the retired label a runs-on value would run
// on. For a server_url conditional only the github.com arm is checked;
// every other value is checked whole: a label counts as the bare value, in single
// quotes, or in double quotes (an element of a fromJSON array).
func retiredRunsOnLabel(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if m := serverURLArms.FindStringSubmatch(v); m != nil {
		v = m[1]
	}
	fields := strings.Fields(v)
	for _, l := range retiredLabels {
		if strings.Contains(v, "'"+l+"'") || strings.Contains(v, `"`+l+`"`) || (len(fields) > 0 && fields[0] == l) {
			return l, true
		}
	}
	return "", false
}

func TestRetiredRunsOnLabel(t *testing.T) {
	for _, c := range []struct {
		v       string
		retired bool
	}{
		{`${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || 'bigdisk' }}`, false},
		{`${{ github.server_url == 'https://github.com' && 'bigdisk' || 'ubuntu-latest' }}`, true},
		{`bigdisk`, true},
		{`bigdisk-docker`, true},
		{`${{ github.event_name == 'push' && fromJSON('["self-hosted","linux","x64","bigdisk-docker"]') || 'ubuntu-latest' }}`, true},
		{`ubuntu-latest`, false},
	} {
		if _, got := retiredRunsOnLabel(c.v); got != c.retired {
			t.Errorf("retiredRunsOnLabel(%q) = %v, want %v", c.v, got, c.retired)
		}
	}
}

// TestNoLabelTrigger: ci.yml does not fire on `labeled`. Gitea sends every
// label add and remove as `labeled`, so each review or task label started a
// run that canceled the PR's run in progress. A `ci:full` added later is read
// when the next run starts. Nothing in ci.yml may branch on the label event
// either: a job skipped by such a condition still posts a status under its
// name, and a skipped CI Gate would overwrite the head's real one.
func TestNoLabelTrigger(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	m := prTypes.FindStringSubmatch(ci)
	if m == nil {
		t.Fatal("ci.yml's pull_request trigger lists no types")
	}
	if m[1] != "opened, synchronize, reopened, ready_for_review" {
		t.Errorf("ci.yml's pull_request types are [%s], want [opened, synchronize, reopened, ready_for_review]", m[1])
	}
	for _, bad := range []string{"github.event.action", "github.event.label.name"} {
		if strings.Contains(ci, bad) {
			t.Errorf("ci.yml tests %s; the gate must never be skipped by an event condition", bad)
		}
	}
}

// TestReadyForReviewTriggers: marking a draft ready starts both CI and the
// code review. CI Gate fails on a draft, so without `ready_for_review` a PR
// marked ready keeps the draft's failed gate and gets no review until its
// next push.
func TestReadyForReviewTriggers(t *testing.T) {
	cr, ok := readUnlessStripped(t, ".github/workflows/code-review.yml")
	if !ok {
		return
	}
	m := regexp.MustCompile(`(?m)^  pull_request_target:\n    types: \[(.*)\]$`).FindStringSubmatch(cr)
	if m == nil {
		t.Fatal("code-review.yml's pull_request_target trigger lists no types")
	}
	if !strings.Contains(", "+m[1]+",", " ready_for_review,") {
		t.Errorf("code-review.yml's pull_request_target types are [%s], want ready_for_review among them", m[1])
	}
}

// readUnlessStripped reads a repository file the published tree may not
// carry. It reports false only when the file is absent and a rule of
// labstrings.DefaultStripAtPublish names it: the exported tree drops it, so
// there is nothing to check. A file absent that no strip rule names, or any
// other read error, fails the test.
func readUnlessStripped(t *testing.T, rel string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), rel)) // #nosec G304 -- a fixed path in this repository
	if err == nil {
		return string(b), true
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("reading %s: %v", rel, err)
	}
	stripped, matchErr := strippedAtPublish(rel)
	if matchErr != nil {
		t.Fatalf("matching %s against the strip-at-publish rules: %v", rel, matchErr)
	}
	if !stripped {
		t.Fatalf("reading %s: %v (no strip-at-publish rule names it, so every tree must carry it)", rel, err)
	}
	return "", false
}

// scansWorkflow reads scans.yml, the internal scans workflow that the
// published tree does not carry (stripped at publish): there, with nothing
// to check, it skips the rest of the test.
func scansWorkflow(t *testing.T) string {
	t.Helper()
	s, ok := readUnlessStripped(t, ".github/workflows/scans.yml")
	if !ok {
		t.Skip("scans.yml is stripped at publish")
	}
	return s
}

// strippedAtPublish reports whether a rule of labstrings.DefaultStripAtPublish
// names the slash-separated repository path rel.
func strippedAtPublish(rel string) (bool, error) {
	for _, rule := range labstrings.DefaultStripAtPublish {
		ok, err := labstrings.MatchPath(rule.Path, rel)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// TestStrippedAtPublish pins the rule readUnlessStripped relies on: the
// internal review workflow is stripped at publish, the public workflows are
// not, so an absent public workflow still fails.
func TestStrippedAtPublish(t *testing.T) {
	if ok, err := strippedAtPublish(".github/workflows/code-review.yml"); err != nil || !ok {
		t.Errorf("strippedAtPublish(code-review.yml) = %v, %v; want true, nil", ok, err)
	}
	for _, name := range labstrings.PublishedWorkflows {
		if ok, err := strippedAtPublish(".github/workflows/" + name); err != nil || ok {
			t.Errorf("strippedAtPublish(%s) = %v, %v; want false, nil", name, ok, err)
		}
	}
}

// fullTierIf is ci.yml's CI_FULL_TIER, which CI Gate's FULL_TIER reads
// (ci-template v1.30: a workflow_dispatch off main is not the full tier; the
// guard refuses it; v1.41: every other event, every PR too, and ci/deps-bump's
// dispatch). nightlyIf is CI Gate's NIGHTLY: the schedule and
// dispatch only.
const (
	fullTierIf = "${{ " + fullTierCond + " }}"
	nightlyIf  = "${{ github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' }}"
)

var (
	jobKey    = regexp.MustCompile(`^  ([A-Za-z0-9_-]+):$`)
	gateCheck = regexp.MustCompile(`(?m)^\s*check ([A-Za-z0-9_-]+)\s+"\$\{\{ needs\.([A-Za-z0-9_-]+)\.result \}\}" (\S+)$`)
)

// jobIDs lists the keys under ci.yml's `jobs:`.
func jobIDs(t *testing.T, workflow string) []string {
	t.Helper()
	var ids []string
	in := false
	for _, l := range strings.Split(workflow, "\n") {
		if l == "jobs:" {
			in = true
			continue
		}
		if !in {
			continue
		}
		if l != "" && l[0] != ' ' && l[0] != '#' {
			break
		}
		if m := jobKey.FindStringSubmatch(l); m != nil {
			ids = append(ids, m[1])
		}
	}
	if len(ids) == 0 {
		t.Fatal("ci.yml has no jobs")
	}
	return ids
}

// TestCIGateTiersMatchTheJobs: CI Gate is the one required check and the only
// gate. It needs every job, reads each by name with one `check` line, and the
// tag on that line is what lets a job skip: `full` exactly for the jobs whose
// `if:` is the full-tier condition, and only while FULL_TIER is not true.
// A mis-tagged line either fails every ordinary PR or lets a skipped PR-tier
// job through, so the tags are derived from the jobs, never listed by hand.
func TestCIGateTiersMatchTheJobs(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	gate := job(t, ci, "ci-gate")
	if got := jobIfOf(t, gate); got != gateIf {
		t.Errorf("CI Gate has if %q, want %q", got, gateIf)
	}
	if m := fullTierEn.FindStringSubmatch(gate); m == nil || m[1] != "env.CI_FULL_TIER" {
		t.Error("CI Gate's FULL_TIER is not ${{ env.CI_FULL_TIER }}")
	}
	if m := regexp.MustCompile(`(?m)^  CI_FULL_TIER: (.*)$`).FindStringSubmatch(ci); m == nil || m[1] != fullTierIf {
		t.Errorf("ci.yml's CI_FULL_TIER is not the full-tier condition %q", fullTierIf)
	}
	if m := regexp.MustCompile(`(?m)^          NIGHTLY: (.*)$`).FindStringSubmatch(gate); m == nil || m[1] != nightlyIf {
		t.Errorf("CI Gate's NIGHTLY is not the nightly condition %q", nightlyIf)
	}

	checks := map[string][]string{}
	for _, m := range gateCheck.FindAllStringSubmatch(gate, -1) {
		if m[1] != m[2] {
			t.Errorf("check line for %s reads needs.%s", m[1], m[2])
		}
		checks[m[1]] = append(checks[m[1]], m[3])
	}
	gateNeeds := needs(t, gate)

	var pr, code, scoped, full, nightly []string
	for _, id := range jobIDs(t, ci) {
		text := job(t, ci, id)
		if id == "ci-gate" {
			continue
		}
		if m := jobName.FindStringSubmatch(text); m != nil && (m[1] == "CI Gate" || m[1] == "Full Gate") {
			t.Errorf("job %s is named %q; CI Gate is the only gate", id, m[1])
		}
		want := "pr"
		switch cond := jobIfOf(t, text); cond {
		case fullJobIf:
			want = "full"
			full = append(full, id)
		case nightlyJobIf:
			want = "nightly"
			nightly = append(nightly, id)
		case codeJobIf, codeFullJobIf:
			want = "code"
			code = append(code, id)
		case scopedJobIf:
			want = "scoped"
			scoped = append(scoped, id)
		case draftIf, prJobIf:
			pr = append(pr, id)
		default:
			t.Errorf("job %s has if %q; a job carries the PR-tier, code, scoped, full-tier or nightly condition", id, cond)
		}
		if !contains(gateNeeds, id) {
			t.Errorf("CI Gate does not need %s", id)
		}
		switch tags := checks[id]; {
		case len(tags) != 1:
			t.Errorf("CI Gate has %d check lines for %s, want 1", len(tags), id)
		case tags[0] != want:
			t.Errorf("CI Gate tags %s %q, want %q", id, tags[0], want)
		}
		delete(checks, id)
	}
	for id := range checks {
		t.Errorf("CI Gate checks %s, which is not a job", id)
	}
	if len(gateNeeds) != len(jobIDs(t, ci))-1 {
		t.Errorf("CI Gate needs %v, want every other job exactly once", gateNeeds)
	}
	if !sameSet(pr, prTier) {
		t.Errorf("the PR tier is %v, want %v", pr, prTier)
	}
	if !sameSet(code, codeTier) {
		t.Errorf("the code tier is %v, want %v", code, codeTier)
	}
	if !sameSet(scoped, scopedTier) {
		t.Errorf("the scoped tier is %v, want %v", scoped, scopedTier)
	}
	if !sameSet(full, fullTier) {
		t.Errorf("the full tier is %v, want %v", full, fullTier)
	}
	if !sameSet(nightly, nightlyTier) {
		t.Errorf("the nightly tier is %v, want %v", nightly, nightlyTier)
	}
	// A full-tier job may need a PR-tier job; never the other way round.
	for _, j := range append(append(append([]string{}, prTier...), codeTier...), scopedTier...) {
		for _, n := range needs(t, job(t, ci, j)) {
			if contains(fullTier, n) || contains(nightlyTier, n) {
				t.Errorf("PR-tier job %s needs full-tier job %s", j, n)
			}
		}
	}
	// The skip rule itself is exercised by running the script:
	// TestCIGateScriptDecides.
}

// TestUnitTiers: the image job's unit run is uninstrumented and keeps every
// gate that rode on it; the -race run with its budget is Race's, which v1.23
// puts on the PR tier.
func TestUnitTiers(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	// The PR tier's unit legs, their coverage gate and the checks beside them
	// run in the toolchain image, each through ci-toolchain-run. The
	// releasability gate is lint-class (ci-template v1.30: the lint job).
	image := job(t, ci, "image")
	for _, want := range []string{
		`make ci-toolchain-run CMD="make test-unit-norace UNIT_TEST_FLAGS=-v && make coverage-gate" CI_OUT=coverage.out`,
		`make ci-toolchain-run CMD="make test-calibration"`,
		`make ci-toolchain-run CMD="make api-diff"`,
	} {
		if !strings.Contains(image, want) {
			t.Errorf("the image job lacks %q", want)
		}
	}
	if want := `make ci-toolchain-run CMD="make releasability"`; !strings.Contains(job(t, ci, "lint"), want) {
		t.Errorf("the lint job lacks %q", want)
	}
	race := job(t, ci, "test-race")
	if !strings.Contains(race, `run: make ci-toolchain-run CMD="make test-unit UNIT_TEST_FLAGS=-v"`+"\n") {
		t.Error("Race does not run make test-unit in the toolchain image")
	}
	mk := readFile(t, "Makefile")
	for _, want := range []string{
		"UNIT_TEST_RACE ?= -race",
		"test-unit UNIT_TEST_RACE=\n",
		"UNIT_TEST_TARGET ?= 240",
	} {
		if !strings.Contains(mk, want) {
			t.Errorf("Makefile lacks %q", want)
		}
	}
}

// TestFIPSGateIsStrictAndInCI: FIPS moved from nightly.yml into the full tier
// without losing its strict mode or either of its test steps.
func TestFIPSGateIsStrictAndInCI(t *testing.T) {
	fips := job(t, readFile(t, ".github/workflows/ci.yml"), "fips")
	for _, want := range []string{
		"name: FIPS\n",
		`run: make ci-toolchain-run CMD="make ` + fipsModeTarget + `"` + "\n",
	} {
		if !strings.Contains(fips, want) {
			t.Errorf("the FIPS job lacks %q", want)
		}
	}
	// The gate's mode, packages and timeouts live in the target the job runs
	// in the toolchain image, in this order: a failure stops the ones after.
	mk := readFile(t, "Makefile")
	at := strings.Index(mk, "\n"+fipsModeTarget+":")
	if at < 0 {
		t.Fatalf("the Makefile has no %s target", fipsModeTarget)
	}
	recipe := mk[at:]
	if end := strings.Index(recipe[1:], "\n\n"); end >= 0 {
		recipe = recipe[:end+1]
	}
	last := -1
	for _, want := range []string{
		fipsModeTarget + ": export GOFIPS140 := latest",
		fipsModeTarget + ": export GODEBUG := fips140=only",
		"go build ./...",
		"go test -count=1 -timeout=900s -v -run '^TestFIPSImportOf(ACryptsetupArgon2idVolume|ACryptsetupVolumeWithShortSalts|ACryptsetupVolumeWithAnUnboundKey|SHA1AFVolumes)$$' ./pkg/luks2",
		"go test -count=1 -timeout=900s ./...",
	} {
		i := strings.Index(recipe, want)
		if i < 0 {
			t.Errorf("%s lacks %q", fipsModeTarget, want)
			continue
		}
		if i < last {
			t.Errorf("%s runs %q out of order", fipsModeTarget, want)
		}
		last = i
	}
	if !regexp.MustCompile(`(?m)^\.PHONY:.* ` + regexp.QuoteMeta(fipsModeTarget) + `( |$)`).MatchString(mk) {
		t.Errorf("%s is not .PHONY", fipsModeTarget)
	}
	if strings.Contains(readFile(t, ".github/workflows/nightly.yml"), "fips140") {
		t.Error("nightly.yml still carries a FIPS job; it runs in ci.yml's full tier")
	}
}

// fipsModeTarget is the Makefile target the FIPS job runs.
const fipsModeTarget = "test-fips-mode"

// The FIPS-mode target must not be a name a per-package pattern rule answers
// to: an explicit `test-fips` shadowed `test-%` for ./internal/fips, so
// `make test-fips` ran the whole module in FIPS mode instead of that package.
func TestFIPSModeTargetShadowsNoPerPackageTarget(t *testing.T) {
	mk := readFile(t, "Makefile")
	m := regexp.MustCompile(`(?m)^([^\s:#]+): export GODEBUG := fips140=only$`).FindStringSubmatch(mk)
	if m == nil {
		t.Fatal("the Makefile has no target that exports GODEBUG=fips140=only")
	}
	target := m[1]
	if target != fipsModeTarget {
		t.Errorf("the Makefile's FIPS-mode target is %s, want %s", target, fipsModeTarget)
	}
	var pkgs []string
	for _, m := range regexp.MustCompile(`(?m)^PKG_([A-Za-z0-9_]+)\s*:=`).FindAllStringSubmatch(mk, -1) {
		pkgs = append(pkgs, m[1])
	}
	if !contains(pkgs, "fips") {
		t.Fatal("the Makefile has no PKG_fips; this check has gone dark")
	}
	patterns := regexp.MustCompile(`(?m)^([A-Za-z0-9_.-]*)%:`).FindAllStringSubmatch(mk, -1)
	if len(patterns) == 0 {
		t.Fatal("the Makefile has no pattern rule; this check has gone dark")
	}
	for _, p := range patterns {
		for _, pkg := range pkgs {
			if target == p[1]+pkg {
				t.Errorf("%s is the per-package target %s%% for PKG_%s, which it shadows", target, p[1], pkg)
			}
		}
	}
}
