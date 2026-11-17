package workflows

import (
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
// a change would get no review and could never pass the gate.
func reviewSkipProblem(t *testing.T, workflow string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^\s+NO_REVIEW_PATHS: '([^']*)'\s*$`).FindStringSubmatch(workflow)
	if m == nil {
		t.Fatal("gate: no NO_REVIEW_PATHS")
	}
	exempt := regexp.MustCompile(m[1]).MatchString(".github/workflows/ci.yml")
	if !exempt && strings.Contains(reviewJobIf(t, workflow), "needs.scope.outputs.skip") {
		return "the review job skips a change the scope job clears, but the gate never exempts a workflow"
	}
	return ""
}

// TestReviewRunsWhereTheGateNeedsIt: a workflow change always takes a round
// here (Codex P1 on go-quicraft #1170, the same template change).
func TestReviewRunsWhereTheGateNeedsIt(t *testing.T) {
	if p := reviewSkipProblem(t, codeReview(t)); p != "" {
		t.Error(p)
	}
}

func TestReviewRunsWhereTheGateNeedsIt_CanFail(t *testing.T) {
	const fixture = "jobs:\n  review:\n    name: Codex review\n    if: >-\n      github.event.pull_request.state == 'open'\n      && needs.scope.outputs.skip != 'true'\n    runs-on: codex\n  gate:\n    env:\n      NO_REVIEW_PATHS: '^(docs/.+|\\.github/actionlint\\.yaml)$'\n"
	if reviewSkipProblem(t, fixture) == "" {
		t.Fatal("a review skipped on the scope verdict while the gate never exempts a workflow: no problem reported")
	}
	ok := strings.Replace(fixture, "\n      && needs.scope.outputs.skip != 'true'", "", 1)
	if p := reviewSkipProblem(t, ok); p != "" {
		t.Fatalf("the review job without the scope skip: %s", p)
	}
}
