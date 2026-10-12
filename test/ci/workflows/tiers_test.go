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
func TestJobNamesAreLiteral(t *testing.T) {
	for _, f := range workflowFiles(t) {
		for _, m := range jobName.FindAllStringSubmatch(readFile(t, rel(t, f)), -1) {
			if strings.Contains(m[1], "${{") {
				t.Errorf("%s: job name %q is an expression", rel(t, f), m[1])
			}
		}
	}
	ci := readFile(t, ".github/workflows/ci.yml")
	for id, want := range map[string]string{"gate": "CI Gate", "full-gate": "Full Gate"} {
		if m := jobName.FindStringSubmatch(job(t, ci, id)); m == nil || m[1] != want {
			t.Errorf("job %s is not literally named %q", id, want)
		}
	}
}

// TestLabelEventsDoNotRunCI: a job skipped by `if:` still posts a status
// under its name, and a skipped required check counts as passing. A label
// event that ran ci.yml would therefore overwrite a PR head's real CI Gate,
// so ci.yml does not fire on one at all, and nothing in it tests for one.
func TestLabelEventsDoNotRunCI(t *testing.T) {
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
			t.Errorf("ci.yml still tests %s, which only a label event needed", bad)
		}
	}
}

// TestCIGateAggregatesThePRTierOnly: CI Gate is the one required check, so it
// needs exactly the PR tier, and every PR-tier job runs on every event.
func TestCIGateAggregatesThePRTierOnly(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	gate := job(t, ci, "gate")
	if got := needs(t, gate); !sameSet(got, prTier) {
		t.Errorf("CI Gate needs %v, want the PR tier %v", got, prTier)
	}
	for _, j := range prTier {
		if !strings.Contains(gate, "needs."+j+".result") {
			t.Errorf("CI Gate does not read %s's result by name", j)
		}
		if got := jobIfOf(t, job(t, ci, j)); got != "" {
			t.Errorf("PR-tier job %s has if %q; the PR tier runs on every event", j, got)
		}
	}
	if got := jobIfOf(t, gate); got != "always()" {
		t.Errorf("CI Gate has if %q, want always()", got)
	}
}

// TestFullTierSharesOneCondition: every full-tier job and Full Gate's
// FULL_TIER carry the same expression, and it covers push, dispatch and the
// ci:full label.
func TestFullTierSharesOneCondition(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	full := job(t, ci, "full-gate")
	m := fullTierEn.FindStringSubmatch(full)
	if m == nil {
		t.Fatal("Full Gate has no FULL_TIER expression")
	}
	cond := m[1]
	for _, want := range []string{
		"github.event_name == 'push'",
		"github.event_name == 'workflow_dispatch'",
		"contains(github.event.pull_request.labels.*.name, 'ci:full')",
	} {
		if !strings.Contains(cond, want) {
			t.Errorf("the full-tier condition lacks %q", want)
		}
	}
	for _, j := range fullTier {
		if got := jobIfOf(t, job(t, ci, j)); got != cond {
			t.Errorf("full-tier job %s has if %q, want Full Gate's FULL_TIER %q", j, got, cond)
		}
		if !strings.Contains(full, "needs."+j+".result") {
			t.Errorf("Full Gate does not read %s's result by name", j)
		}
	}
	if got := needs(t, full); !sameSet(got, fullTier) {
		t.Errorf("Full Gate needs %v, want the full tier %v", got, fullTier)
	}
	if got := jobIfOf(t, full); got != "always()" {
		t.Errorf("Full Gate has if %q, want always()", got)
	}
	for _, want := range []string{"true)  want=success", "false) want=skipped", "exit 1"} {
		if !strings.Contains(full, want) {
			t.Errorf("Full Gate lacks %q", want)
		}
	}
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
