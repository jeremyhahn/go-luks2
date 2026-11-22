package workflows

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// reviewJobIf is the `if:` of code-review.yml's review job, its folded
// scalar joined into one line.
func reviewJobIf(t *testing.T, workflow string) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)\n    if: >-\n(.*?)\n    [a-z#]`).FindStringSubmatch(job(t, workflow, "review"))
	if m == nil {
		t.Fatal("the review job has no folded if")
	}
	return strings.Join(strings.Fields(m[1]), " ")
}

// reviewSkipProblem: code-review.yml v5.12.1's review job skips a change
// InfoSec's guard (the scope job) clears, which is a workflow-only change;
// this repository's gate never exempts a workflow (NO_REVIEW_PATHS), so such
// a change would get no review and could never pass the gate. The guard
// clears no workflow whose stem is in PROTECTED (Y-3), so the skip is safe
// only when PROTECTED holds every workflow stem in stems.
func reviewSkipProblem(t *testing.T, workflow string, stems []string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^\s+NO_REVIEW_PATHS: '([^']*)'\s*$`).FindStringSubmatch(workflow)
	if m == nil {
		t.Fatal("gate: no NO_REVIEW_PATHS")
	}
	exempt := regexp.MustCompile(m[1]).MatchString(".github/workflows/ci.yml")
	if exempt || !strings.Contains(reviewJobIf(t, workflow), "needs.scope.outputs.skip") {
		return ""
	}
	protected := map[string]bool{}
	for _, s := range protectedStems(workflow) {
		protected[strings.ToLower(s)] = true
	}
	var open []string
	for _, s := range stems {
		if !protected[strings.ToLower(s)] {
			open = append(open, s)
		}
	}
	if len(open) > 0 {
		return "the review job skips a change the scope job clears, but the gate never exempts a workflow" +
			" and PROTECTED misses " + strings.Join(open, ", ")
	}
	return ""
}

// protectedStems is the PROTECTED list of the scope guard's CUSTOMIZE
// block, or nil when the workflow has none.
func protectedStems(workflow string) []string {
	m := regexp.MustCompile(`(?m)^\s+PROTECTED = \[([^\]]*)\]\s*$`).FindStringSubmatch(workflow)
	if m == nil {
		return nil
	}
	var stems []string
	for _, s := range strings.Split(m[1], ",") {
		if s = strings.Trim(strings.TrimSpace(s), `"`); s != "" {
			stems = append(stems, s)
		}
	}
	return stems
}

// workflowStems is the stem of every workflow file in .github/workflows,
// lower-cased as the guard compares them.
func workflowStems(t *testing.T) []string {
	t.Helper()
	var stems []string
	for _, f := range workflowFiles(t) {
		base := filepath.Base(f)
		stems = append(stems, strings.ToLower(strings.TrimSuffix(base, filepath.Ext(base))))
	}
	return stems
}

// TestReviewRunsWhereTheGateNeedsIt: a workflow change always takes a round
// here (Codex P1 on go-quicraft #1170, the same template change).
func TestReviewRunsWhereTheGateNeedsIt(t *testing.T) {
	if p := reviewSkipProblem(t, codeReview(t), workflowStems(t)); p != "" {
		t.Error(p)
	}
}

func TestReviewRunsWhereTheGateNeedsIt_CanFail(t *testing.T) {
	const fixture = "jobs:\n  review:\n    name: Codex review\n    if: >-\n      github.event.pull_request.state == 'open'\n      && needs.scope.outputs.skip != 'true'\n    runs-on: codex\n  gate:\n    env:\n      NO_REVIEW_PATHS: '^(docs/.+|\\.github/actionlint\\.yaml)$'\n"
	stems := []string{"ci", "code-review"}
	if reviewSkipProblem(t, fixture, stems) == "" {
		t.Fatal("a review skipped on the scope verdict while the gate never exempts a workflow: no problem reported")
	}
	scope := func(list string) string {
		return fixture + "  scope:\n    steps:\n      - run: |\n          PROTECTED = [" + list + "]\n"
	}
	if p := reviewSkipProblem(t, scope(`"code-review"`), stems); p == "" || !strings.Contains(p, "misses ci") {
		t.Fatalf("PROTECTED without the ci stem: problem %q, want one naming ci", p)
	}
	if p := reviewSkipProblem(t, scope(`"code-review", "CI"`), stems); p != "" {
		t.Fatalf("PROTECTED holding every workflow stem: %s", p)
	}
	ok := strings.Replace(fixture, "\n      && needs.scope.outputs.skip != 'true'", "", 1)
	if p := reviewSkipProblem(t, ok, stems); p != "" {
		t.Fatalf("the review job without the scope skip: %s", p)
	}
}
