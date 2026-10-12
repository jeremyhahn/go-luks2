// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package workflows

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The two tiers of ci.yml (#341). A job moved between them, or a condition
// edited on one job and not its siblings, changes what gates a merge without
// failing anything else; these tests are what fails.
var (
	prTier   = []string{"lint", "security", "build", "test-unit", "merge-check"}
	fullTier = []string{"fips", "test-integration", "test-race"}
)

var (
	jobIf      = regexp.MustCompile(`(?m)^    if: (.*)$`)
	jobName    = regexp.MustCompile(`(?m)^    name: (.*)$`)
	prTypes    = regexp.MustCompile(`(?m)^  pull_request:\n    branches: \[main\]\n(?:    #.*\n)*    types: \[(.*)\]$`)
	fullTierEn = regexp.MustCompile(`(?m)^          FULL_TIER: \$\{\{ (.*) \}\}$`)
	scheduleOn = regexp.MustCompile(`(?m)^\s*schedule:`)
)

func jobIfOf(t *testing.T, jobText string) string {
	t.Helper()
	m := jobIf.FindStringSubmatch(jobText)
	if m == nil {
		return ""
	}
	return m[1]
}

func sameSet(a, b []string) bool {
	a, b = append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, ",") == strings.Join(b, ",")
}

// TestNoCIWorkflowIsScheduled: the full tier is dispatched by the
// coordinator's loop; a schedule would run it a second time, unowned (sdlc
// §5a). The CI workflows only: automerge.yml's poll is held for the owner and
// is not part of this change.
func TestNoCIWorkflowIsScheduled(t *testing.T) {
	for _, f := range []string{".github/workflows/ci.yml", ".github/workflows/nightly.yml"} {
		if scheduleOn.MatchString(readFile(t, f)) {
			t.Errorf("%s has a schedule: trigger", f)
		}
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
	if m := jobName.FindStringSubmatch(job(t, ci, "gate")); m == nil || m[1] != "CI Gate" {
		t.Error(`job gate is not literally named "CI Gate"`)
	}
}

// TestLabelEventsRunCI: adding ci:full starts the full tier, so ci.yml fires
// on `labeled`. Any other label re-runs the PR tier on the same commit, a real
// evaluation, so nothing in ci.yml may branch on the label event itself: a job
// skipped by such a condition still posts a status under its name, and a
// skipped CI Gate would overwrite the head's real one.
func TestLabelEventsRunCI(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	m := prTypes.FindStringSubmatch(ci)
	if m == nil {
		t.Fatal("ci.yml's pull_request trigger lists no types")
	}
	if m[1] != "opened, synchronize, reopened, labeled" {
		t.Errorf("ci.yml's pull_request types are [%s], want [opened, synchronize, reopened, labeled]", m[1])
	}
	for _, bad := range []string{"github.event.action", "github.event.label.name"} {
		if strings.Contains(ci, bad) {
			t.Errorf("ci.yml tests %s; the gate must never be skipped by an event condition", bad)
		}
	}
}

// fullTierIf is the one condition every full-tier job carries, written out on
// each, and the expression CI Gate's FULL_TIER evaluates.
const fullTierIf = "github.event_name == 'push' || github.event_name == 'workflow_dispatch' || contains(github.event.pull_request.labels.*.name, 'ci:full')"

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
	gate := job(t, ci, "gate")
	if got := jobIfOf(t, gate); got != "always()" {
		t.Errorf("CI Gate has if %q, want always()", got)
	}
	if m := fullTierEn.FindStringSubmatch(gate); m == nil || m[1] != fullTierIf {
		t.Errorf("CI Gate's FULL_TIER is not the full-tier condition %q", fullTierIf)
	}

	checks := map[string][]string{}
	for _, m := range gateCheck.FindAllStringSubmatch(gate, -1) {
		if m[1] != m[2] {
			t.Errorf("check line for %s reads needs.%s", m[1], m[2])
		}
		checks[m[1]] = append(checks[m[1]], m[3])
	}
	gateNeeds := needs(t, gate)

	var pr, full []string
	for _, id := range jobIDs(t, ci) {
		text := job(t, ci, id)
		if id == "gate" {
			continue
		}
		if m := jobName.FindStringSubmatch(text); m != nil && (m[1] == "CI Gate" || m[1] == "Full Gate") {
			t.Errorf("job %s is named %q; CI Gate is the only gate", id, m[1])
		}
		want := "pr"
		switch cond := jobIfOf(t, text); cond {
		case fullTierIf:
			want = "full"
			full = append(full, id)
		case "":
			pr = append(pr, id)
		default:
			t.Errorf("job %s has if %q; a job is either unconditional (pr) or carries the full-tier condition", id, cond)
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
	// A full-tier job may need a PR-tier job; never the other way round.
	for _, j := range prTier {
		for _, n := range needs(t, job(t, ci, j)) {
			if contains(fullTier, n) {
				t.Errorf("PR-tier job %s needs full-tier job %s", j, n)
			}
		}
	}
	// The skip rule itself is exercised by running the script:
	// TestCIGateScriptDecides.
}

// TestUnitTiers: the PR tier's unit run is uninstrumented and keeps every gate
// that rode on it; the -race run with its budget is the full tier's.
func TestUnitTiers(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	unit := job(t, ci, "test-unit")
	for _, want := range []string{
		"make test-unit-norace", "make test-calibration", "make releasability",
		"make api-diff", "make coverage-gate", "name: Unit Tests\n",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("Unit Tests lacks %q", want)
		}
	}
	race := job(t, ci, "test-race")
	if !strings.Contains(race, "run: make test-unit UNIT_TEST_FLAGS=-v\n") {
		t.Error("Race does not run make test-unit")
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
		"GOFIPS140: latest",
		"GODEBUG: fips140=only",
		"go build ./...",
		"TestFIPSImportOf(ACryptsetupArgon2idVolume|ACryptsetupVolumeWithShortSalts|ACryptsetupVolumeWithAnUnboundKey|SHA1AFVolumes)",
		"run: go test -count=1 -timeout=900s ./...",
	} {
		if !strings.Contains(fips, want) {
			t.Errorf("the FIPS job lacks %q", want)
		}
	}
	if strings.Contains(readFile(t, ".github/workflows/nightly.yml"), "fips140") {
		t.Error("nightly.yml still carries a FIPS job; it runs in ci.yml's full tier")
	}
}
