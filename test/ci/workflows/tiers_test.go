// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package workflows

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The two tiers of ci.yml (#341). A job moved between them, or a condition
// edited on one job and not its siblings, changes what gates a merge without
// failing anything else; these tests are what fails.
var (
	prTier      = []string{"changes", "image", "lint-gates", "merge-check", "arch-gates", "test-race"}
	fullTier    = []string{"fips", "integration"}
	nightlyTier = []string{"soak"}
)

var (
	jobIf = regexp.MustCompile(`(?m)^    if: (.*)$`)
	// trailingComment is a YAML comment after a job's `if:` value.
	trailingComment = regexp.MustCompile(`\s+#.*$`)
	jobName         = regexp.MustCompile(`(?m)^    name: (.*)$`)
	prTypes         = regexp.MustCompile(`(?m)^  pull_request:\n    branches: \[main\]\n(?:    #.*\n)*    types: \[(.*)\]$`)
	fullTierEn      = regexp.MustCompile(`(?m)^          FULL_TIER: \$\{\{ (.*) \}\}$`)
	scheduleOn      = regexp.MustCompile(`(?m)^\s*schedule:`)
	// jobRunsOn is declared here, not shared with batch_test.go, which is
	// export-ignore: the published tree has no batch_test.go to borrow from.
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

// TestExactlyOneScheduleTriggerInCI: ci-template v1.23 runs main's full tier
// and Soak nightly through ci.yml's own `schedule:` trigger, and that is the
// only scheduled workflow: nightly.yml and batch.yml stay dispatch-only, so
// nothing is run twice on a timer, unowned (sdlc §5a). automerge.yml is not
// CI: its timer merges green PRs and runs no stage.
func TestExactlyOneScheduleTriggerInCI(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join(repoRoot(t), ".github", "workflows"))
	if err != nil {
		t.Fatal(err)
	}
	var scheduled []string
	for _, e := range entries {
		if e.Name() == "automerge.yml" {
			continue
		}
		f := ".github/workflows/" + e.Name()
		if n := len(scheduleOn.FindAllString(readFile(t, f), -1)); n > 0 {
			scheduled = append(scheduled, fmt.Sprintf("%s:%d", e.Name(), n))
		}
	}
	if want := []string{"ci.yml:1"}; !sameSet(scheduled, want) {
		t.Errorf("schedule: triggers %v, want %v", scheduled, want)
	}
	ci := readFile(t, ".github/workflows/ci.yml")
	if !regexp.MustCompile(`(?m)^on:\n(?:  .*\n|\n)*?  schedule:\n    - cron: '[^']+'\n`).MatchString(ci) {
		t.Error("ci.yml's schedule: is not one cron under on:")
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
	want := "  group: ${{ github.workflow }}-${{ github.ref == 'refs/heads/main' && format('main-{0}-{1}', github.event_name, github.sha) || github.ref }}\n" +
		"  cancel-in-progress: true\n"
	if m[1] != want {
		t.Errorf("ci.yml's concurrency block is\n%s\nwant main runs that never cancel\n%s", m[1], want)
	}
}

// TestJobNamesAreLiteral: Gitea does not evaluate expressions in a job's
// `name:`; it posts the expression verbatim as the status context, so a gate
// named by one is never reported under the name branch protection requires.
// batch.yml is exempt: it is the handbook's batch template verbatim, its jobs
// are in no gate (TestBatchIsNeverInAMergeGate), and a context nobody
// requires cannot go missing.
func TestJobNamesAreLiteral(t *testing.T) {
	for _, f := range workflowFiles(t) {
		if rel(t, f) == batchWorkflow {
			continue
		}
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
const hostedRunner = "ubuntu-latest"

// retiredLabels are the self-hosted runner labels ci.yml and batch.yml ran on
// before m2077. No workflow names them, and .github/actionlint.yaml does not
// list them, so a typo of one is still caught as an unknown runner.
var retiredLabels = []string{"bigdisk", "ci-gate", "batch"}

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
// ubuntu-latest, and every job that builds a devcontainer image frees the
// runner's disk first, on github.com only, before any image build.
func TestEveryCIJobRunsOnTheHostedRunner(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	for _, id := range jobIDs(t, ci) {
		if got := jobRunsOn.FindAllStringSubmatch(job(t, ci, id), -1); len(got) != 1 || got[0][1] != hostedRunner {
			t.Errorf("job %s runs on %v, want %s", id, got, hostedRunner)
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
		for _, m := range jobRunsOn.FindAllStringSubmatch(readFile(t, rel(t, f)), -1) {
			for _, l := range retiredLabels {
				if strings.Contains(m[1], "'"+l+"'") || strings.Fields(m[1])[0] == l {
					t.Errorf("%s runs a job on the retired label %s: %s", rel(t, f), l, m[1])
				}
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
	if m[1] != "opened, synchronize, reopened" {
		t.Errorf("ci.yml's pull_request types are [%s], want [opened, synchronize, reopened]", m[1])
	}
	for _, bad := range []string{"github.event.action", "github.event.label.name"} {
		if strings.Contains(ci, bad) {
			t.Errorf("ci.yml tests %s; the gate must never be skipped by an event condition", bad)
		}
	}
}

// fullTierIf is the one condition every full-tier job carries, written out on
// each, and ci.yml's CI_FULL_TIER, which CI Gate's FULL_TIER reads.
// nightlyIf is the nightly tier's: the schedule and dispatch only.
const (
	fullTierIf = "${{ github.event_name != 'pull_request' || contains(github.event.pull_request.labels.*.name, 'ci:full') }}"
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
	if got := jobIfOf(t, gate); got != "always()" {
		t.Errorf("CI Gate has if %q, want always()", got)
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

	var pr, full, nightly []string
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
		case nightlyIf:
			want = "nightly"
			nightly = append(nightly, id)
		case draftIf:
			pr = append(pr, id)
		case "":
			// Skipped with the job it needs: the image job needs `changes`.
			if !contains(needs(t, text), "changes") {
				t.Errorf("job %s has no if and does not need changes, so it runs on a draft", id)
			}
			pr = append(pr, id)
		default:
			t.Errorf("job %s has if %q; a job carries the draft condition (pr), the full-tier condition with it, or the nightly condition", id, cond)
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
	if !sameSet(full, fullTier) {
		t.Errorf("the full tier is %v, want %v", full, fullTier)
	}
	if !sameSet(nightly, nightlyTier) {
		t.Errorf("the nightly tier is %v, want %v", nightly, nightlyTier)
	}
	// A full-tier job may need a PR-tier job; never the other way round.
	for _, j := range prTier {
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
	// run in the toolchain image, each through ci-toolchain-run.
	image := job(t, ci, "image")
	for _, want := range []string{
		`make ci-toolchain-run CMD="make test-unit-norace UNIT_TEST_FLAGS=-v && make coverage-gate" CI_OUT=coverage.out`,
		`make ci-toolchain-run CMD="make test-calibration"`,
		`make ci-toolchain-run CMD="make releasability"`,
		`make ci-toolchain-run CMD="make api-diff"`,
	} {
		if !strings.Contains(image, want) {
			t.Errorf("the image job lacks %q", want)
		}
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
