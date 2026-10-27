package workflows

import (
	"strings"
	"testing"
)

// draftIf is the condition every PR-tier job carries (ci-template v1.26): a
// draft pull request runs no CI. A full-tier job carries it beside the
// full-tier condition (fullJobIf); the nightly Soak job runs on no pull
// request at all.
const draftIf = "${{ !github.event.pull_request.draft }}"

// fullJobIf is the full-tier condition with the draft rule.
var fullJobIf = "${{ (" + strings.TrimSuffix(strings.TrimPrefix(fullTierIf, "${{ "), " }}") + ") && !github.event.pull_request.draft }}"

// TestDraftPullRequestSkipsEveryJobButTheGate: every job but CI Gate skips on
// a draft, so a draft head posts no green status of its own. The image job
// needs `changes`, which skips, and skips with it.
func TestDraftPullRequestSkipsEveryJobButTheGate(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	for _, id := range jobIDs(t, ci) {
		if id == "ci-gate" {
			continue
		}
		cond := jobIfOf(t, job(t, ci, id))
		switch {
		case contains(nightlyTier, id):
			// Soak runs on the schedule and dispatch only: no pull request,
			// so no draft, and the template's Soak carries no draft clause.
			if cond != nightlyIf {
				t.Errorf("job %s has if %q, want the nightly condition %q", id, cond, nightlyIf)
			}
		case contains(fullTier, id):
			if cond != fullJobIf {
				t.Errorf("job %s has if %q, want the full-tier condition with the draft rule %q", id, cond, fullJobIf)
			}
		case cond == "":
			// No `if:` of its own: a job whose needed job skipped is skipped.
			if !contains(needs(t, job(t, ci, id)), "changes") {
				t.Errorf("job %s has no if and does not need changes, so it runs on a draft", id)
			}
		case cond != draftIf:
			t.Errorf("job %s has if %q, want %q: a draft PR runs no CI", id, cond, draftIf)
		}
	}
	if got := jobIfOf(t, job(t, ci, "changes")); got != draftIf {
		t.Errorf("job changes has if %q, want %q, which also skips the image job that needs it", got, draftIf)
	}
}

// TestCIGateFailsOnADraft: CI Gate is the one job that runs on a draft, and it
// fails without reading a single result, so no draft head carries a green or
// skipped gate into its merge.
func TestCIGateFailsOnADraft(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	gate := job(t, ci, "ci-gate")
	if got := jobIfOf(t, gate); got != "always()" {
		t.Errorf("CI Gate has if %q, want always()", got)
	}
	if !strings.Contains(gate, "DRAFT: ${{ github.event.pull_request.draft == true }}") {
		t.Error("CI Gate's DRAFT is not ${{ github.event.pull_request.draft == true }}")
	}
	for _, results := range []string{"skipped", "success"} {
		all := map[string]string{}
		for _, j := range allJobs() {
			all[j] = results
		}
		script := gateScript(t, all)
		code, out := runGateDraft(t, script, "false", "false", "true")
		if code != 1 || !strings.Contains(out, "FAIL draft pull request") {
			t.Errorf("a draft with every job %s: exit %d, output %q; want exit 1 and the draft failure", results, code, out)
		}
		if strings.Contains(out, "CI gate passed") || strings.Contains(out, "OK ") {
			t.Errorf("a draft with every job %s read the results anyway: %q", results, out)
		}
	}
	all := map[string]string{}
	for _, j := range allJobs() {
		all[j] = "success"
	}
	if code, out := runGateDraft(t, gateScript(t, all), "true", "true", "false"); code != 0 {
		t.Errorf("a ready PR with every job green: exit %d, output %q", code, out)
	}
}

// TestLintGatesJob (ci-template v1.27): a repository's `make -k lint-gates`
// runs in its own job in parallel with the image job's lint, on the PR tier,
// and only when the Makefile or a tracked *.mk defines the target.
func TestLintGatesJob(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	lg := job(t, ci, "lint-gates")

	if !contains(prTier, "lint-gates") || contains(fullTier, "lint-gates") || contains(nightlyTier, "lint-gates") {
		t.Error("lint-gates is not in the PR tier")
	}
	if got := jobIfOf(t, lg); got != draftIf {
		t.Errorf("lint-gates has if %q, want %q", got, draftIf)
	}
	if !contains(needs(t, job(t, ci, "ci-gate")), "lint-gates") {
		t.Error("CI Gate does not need lint-gates")
	}
	if !strings.Contains(ci, "check lint-gates  \"${{ needs.lint-gates.result }}\" pr\n") {
		t.Error("CI Gate does not check lint-gates as pr")
	}
	if contains(needs(t, lg), "image") {
		t.Error("lint-gates needs the image job; it runs beside it, not after it")
	}

	steps := stepRun(t, lg)
	probe := steps["Does the Makefile define lint-gates?"]
	if probe == "" || strings.Contains(probe, "make ") {
		t.Errorf("the probe step is missing or runs a recipe: %q", probe)
	}
	if !strings.Contains(probe, "git ls-files -- Makefile '*.mk'") || !strings.Contains(probe, "has_target=") {
		t.Errorf("the probe does not look for the target in the Makefile and tracked *.mk: %q", probe)
	}
	run := steps["make lint-gates"]
	if !strings.Contains(run, `make ci-toolchain-run CMD="make -k lint-gates `) {
		t.Errorf("lint-gates does not run make -k lint-gates in the toolchain image: %q", run)
	}
	const defined = "steps.probe.outputs.has_target == 'true'"
	for _, block := range strings.Split(lg, "\n      - ")[1:] {
		name, _, _ := strings.Cut(strings.TrimPrefix(block, "name: "), "\n")
		switch {
		case strings.HasPrefix(block, "uses: "), name == "Mask the forge credentials",
			name == "Does the Makefile define lint-gates?", name == "Tear down":
		case !strings.Contains(block, defined):
			t.Errorf("lint-gates step %q runs whether or not the Makefile defines the target", name)
		}
	}
}

// TestCIHeaderNamesTheTemplateVersion: line 1 names the template revision the
// workflow is an instance of.
func TestCIHeaderNamesTheTemplateVersion(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	if first, _, _ := strings.Cut(ci, "\n"); first != "# ci-template: v1.28.0 (customized)" {
		t.Errorf("ci.yml's first line is %q, want the v1.28.0 header", first)
	}
}
