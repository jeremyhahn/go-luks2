package workflows

import (
	"strings"
	"testing"
)

// draftIf is the preflight job's condition (ci-template v1.26, v1.34): a
// draft pull request runs no CI.
const draftIf = "${{ !github.event.pull_request.draft }}"

// guardRun is the schedule guard's `run` verdict (ci-template v1.29.3,
// v1.30): every job but preflight and CI Gate runs only on it, so a refused
// run (a workflow_dispatch off main, a PR from a checkpoint branch) starts
// nothing.
const guardRun = "needs.preflight.outputs.verdict == 'run'"

// The conditions each tier's jobs carry. A PR-tier job carries the draft rule
// and the guard (prJobIf); the image job, which a docs-only PR skips, the
// guard and the docs-only rule (codeJobIf), and skips on a draft with the
// preflight job it needs; lint-gates the draft rule, the guard and its path
// scope (scopedJobIf); a full-tier job the full-tier condition, the draft
// rule and the guard (fullJobIf); the nightly Soak job the nightly condition
// and the guard (nightlyJobIf), and runs on no pull request at all.
const (
	prJobIf      = "${{ !github.event.pull_request.draft && " + guardRun + " }}"
	codeJobIf    = "${{ " + guardRun + " && needs.preflight.outputs.docs_only != 'true' }}"
	scopedJobIf  = "${{ !github.event.pull_request.draft && " + guardRun + " && needs.preflight.outputs.lint_gates != 'false' }}"
	fullJobIf    = "${{ (github.event_name != 'pull_request' || contains(github.event.pull_request.labels.*.name, 'ci:full')) && !github.event.pull_request.draft && " + guardRun + " }}"
	nightlyJobIf = "${{ (github.event_name == 'schedule' || github.event_name == 'workflow_dispatch') && " + guardRun + " }}"
	// gateIf is CI Gate's: it always runs, but a schedule run whose guard
	// reads main as busy skips it (no workflow here is scheduled).
	gateIf = "${{ always() && (github.event_name != 'schedule' || needs.preflight.outputs.verdict != 'busy') }}"
)

// TestDraftPullRequestSkipsEveryJobButTheGate: every job but CI Gate skips on
// a draft, so a draft head posts no green status of its own. Every job but
// preflight needs preflight and runs only on its guard's `run`; the image job
// carries no draft rule of its own and skips with preflight on a draft.
func TestDraftPullRequestSkipsEveryJobButTheGate(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	for _, id := range jobIDs(t, ci) {
		if id == "ci-gate" {
			continue
		}
		text := job(t, ci, id)
		cond := jobIfOf(t, text)
		want := prJobIf
		switch {
		case id == "preflight", id == "signatures":
			// ci-template v1.35: Signatures, like preflight, runs on every
			// non-draft event and needs nothing.
			want = draftIf
		case contains(nightlyTier, id):
			// Soak runs on dispatch only: no pull request, so no draft.
			want = nightlyJobIf
		case contains(fullTier, id):
			want = fullJobIf
		case contains(codeTier, id):
			want = codeJobIf
		case contains(scopedTier, id):
			want = scopedJobIf
		}
		if cond != want {
			t.Errorf("job %s has if %q, want %q: a draft PR runs no CI, and nothing runs without the guard's run", id, cond, want)
		}
		if id != "preflight" && id != "signatures" && !contains(needs(t, text), "preflight") {
			t.Errorf("job %s does not need preflight, so neither a draft nor a refused run skips it", id)
		}
	}
}

// TestCIGateFailsOnADraft: CI Gate is the one job that runs on a draft, and it
// fails without reading a single result, so no draft head carries a green or
// skipped gate into its merge.
func TestCIGateFailsOnADraft(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	gate := job(t, ci, "ci-gate")
	if got := jobIfOf(t, gate); got != gateIf {
		t.Errorf("CI Gate has if %q, want %q", got, gateIf)
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

// TestLintGatesJob (ci-template v1.27): a repository's `make lint-gates`
// runs in its own job in parallel with the lint job, and only when the
// Makefile or a tracked *.mk defines the target. v1.29.1 drops -k, so the
// first failing gate ends the step. v1.30 scopes it on a PR to the changed
// files LINT_GATES_PATTERN matches (`scoped` in CI Gate).
func TestLintGatesJob(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	lg := job(t, ci, "lint-gates")

	if !contains(scopedTier, "lint-gates") || contains(prTier, "lint-gates") || contains(fullTier, "lint-gates") || contains(nightlyTier, "lint-gates") {
		t.Error("lint-gates is not the scoped tier")
	}
	if got := jobIfOf(t, lg); got != scopedJobIf {
		t.Errorf("lint-gates has if %q, want %q", got, scopedJobIf)
	}
	if !contains(needs(t, job(t, ci, "ci-gate")), "lint-gates") {
		t.Error("CI Gate does not need lint-gates")
	}
	if !strings.Contains(ci, "check lint-gates  \"${{ needs.lint-gates.result }}\" scoped\n") {
		t.Error("CI Gate does not check lint-gates as scoped")
	}
	if contains(needs(t, lg), "image") || contains(needs(t, lg), "lint") {
		t.Error("lint-gates needs the image or lint job; it runs beside them, not after them")
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
	// v1.29.1: no -k; the first failing gate ends the step.
	if !strings.Contains(run, `make ci-toolchain-run CMD="make lint-gates `) {
		t.Errorf("lint-gates does not run make lint-gates, without -k, in the toolchain image: %q", run)
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
	if first, _, _ := strings.Cut(ci, "\n"); first != "# ci-template: v1.35 (customized)" {
		t.Errorf("ci.yml's first line is %q, want the v1.35 header", first)
	}
}
