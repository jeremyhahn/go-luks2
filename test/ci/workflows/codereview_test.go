package workflows

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const codeReviewWorkflow = ".github/workflows/code-review.yml"

// codeReview is code-review.yml, or a skip in a tree that strips it at
// publish (readUnlessStripped: a tree that must carry it still fails).
func codeReview(t *testing.T) string {
	t.Helper()
	cr, ok := readUnlessStripped(t, codeReviewWorkflow)
	if !ok {
		t.Skipf("%s is stripped at publish", codeReviewWorkflow)
	}
	return cr
}

// noReviewPaths is the gate's NO_REVIEW_PATHS, compiled as the extended
// regex `grep -E` reads it.
func noReviewPaths(t *testing.T) *regexp.Regexp {
	t.Helper()
	m := regexp.MustCompile(`(?m)^\s+NO_REVIEW_PATHS: '([^']*)'\s*$`).
		FindAllStringSubmatch(codeReview(t), -1)
	if len(m) != 1 {
		t.Fatalf("%s: want one NO_REVIEW_PATHS, found %d", codeReviewWorkflow, len(m))
	}
	re, err := regexp.CompilePOSIX(m[0][1])
	if err != nil {
		t.Fatalf("NO_REVIEW_PATHS %q: %v", m[0][1], err)
	}
	return re
}

// Codex P1: a workflow controls credentials and merge enforcement, so no
// change under .github/workflows/ is ever review-exempt.
func TestNoReviewPathsNeverExemptAWorkflow(t *testing.T) {
	re := noReviewPaths(t)
	paths := []string{
		".github/workflows/code-review.yml",
		".github/workflows/release.yml",
		".github/workflows/automerge.yml",
		".github/workflows/ci.yml",
		".github/workflows/signatures.yml",
		".github/workflows/new.yaml",
		".github/workflows/sub/dir.yml",
		// Codex P1: the Signatures job's key registry (ci.yml) is trust.
		".github/allowed_signers",
	}
	for _, f := range workflowFiles(t) {
		paths = append(paths, rel(t, f))
	}
	for _, p := range paths {
		if re.MatchString(p) {
			t.Errorf("NO_REVIEW_PATHS exempts the workflow %s from review", p)
		}
	}
	// The rest of the template's list still stands.
	for _, p := range []string{"docs/a.md", "docs/x/y.txt", "README.md", ".github/actionlint.yaml", ".gitea/x.yml", "changelog.d/1.md"} {
		if !re.MatchString(p) {
			t.Errorf("NO_REVIEW_PATHS no longer exempts %s", p)
		}
	}
}

// gateGetAll is the gate step's get_all function, as the workflow has it.
func gateGetAll(t *testing.T) string {
	t.Helper()
	m := regexp.MustCompile(`(?ms)^( +)get_all\(\) \{.*?^( +)\}$`).
		FindString(codeReview(t))
	if m == "" {
		t.Fatalf("%s: no get_all function", codeReviewWorkflow)
	}
	return m
}

func runGetAll(t *testing.T, mode string) (int, string) {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not installed")
	}
	script := `set -euo pipefail
FORGE=github
fail() { echo "fail: $*" >&2; exit 3; }
get() {
  case "$1" in
    *page=1) echo '[1]' ;;
    *page=2)
      case "$MODE" in
        fail) fail "GET $1 answered HTTP 502" ;;
        empty) : ;;
        *) echo '[2]' ;;
      esac ;;
    *) echo '[]' ;;
  esac
}
` + gateGetAll(t) + `
all=$(get_all "/pulls/1/reviews?") || fail "cannot read the reviews"
echo "all=$all"
`
	path := filepath.Join(t.TempDir(), "get_all.sh")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", path)
	cmd.Env = append(os.Environ(), "MODE="+mode)
	out, _ := cmd.CombinedOutput()
	return cmd.ProcessState.ExitCode(), string(out)
}

// Codex P1: a failed page read stops get_all; it never returns the
// earlier pages as if they were all.
func TestGateGetAllPropagatesAFailedPage(t *testing.T) {
	if code, out := runGetAll(t, "ok"); code != 0 || !strings.Contains(out, "all=[1,2]") {
		t.Errorf("two pages: exit %d, output %q; want 0 and all=[1,2]", code, out)
	}
	for _, mode := range []string{"fail", "empty"} {
		code, out := runGetAll(t, mode)
		if code == 0 || strings.Contains(out, "all=") {
			t.Errorf("page 2 %s: exit %d, output %q; want a failure and no pages", mode, code, out)
		}
	}
}

// gateStep is the gate's one step, the last in code-review.yml.
func gateStep(t *testing.T) string {
	t.Helper()
	cr := codeReview(t)
	i := strings.Index(cr, "- name: Require a Codex approval of the head, or a no-review change")
	if i < 0 {
		t.Fatalf("%s: no gate step", codeReviewWorkflow)
	}
	return cr[i:]
}

// Codex P1: a PR retargeted since the event passes nothing. The gate reads
// the live base, as the review job's skip=retargeted guards do, before the
// no-review exit and again after the wait for in-flight reviews.
func TestGateRefusesARetargetedPullRequest(t *testing.T) {
	g := gateStep(t)
	def := regexp.MustCompile(`(?ms)^ +check_base\(\) \{\n.*?^ +\}$`).FindString(g)
	if def == "" || !strings.Contains(def, `"/pulls/$PR_NUM"`) || !strings.Contains(def, ".base.ref") ||
		!strings.Contains(def, `"$BASE_REF"`) || !strings.Contains(def, "fail ") {
		t.Fatalf("gate: no check_base reading the live base.ref against $BASE_REF:\n%s", def)
	}
	exempt := regexp.MustCompile(`(?ms)^ +if \[ "\$exempt" = 1 \]; then\n.*?^ +fi$`).FindString(g)
	if !regexp.MustCompile(`(?m)^ +check_base$[\s\S]*exit 0`).MatchString(exempt) {
		t.Errorf("gate: the no-review exit does not check the live base first:\n%s", exempt)
	}
	wait := strings.Index(g, "waited=$((waited + 30))")
	verdict := strings.Index(g, "verdict=$(")
	if wait < 0 || verdict < wait || !regexp.MustCompile(`(?m)^ +check_base$`).MatchString(g[wait:verdict]) {
		t.Errorf("gate: no live base check between the review wait and the verdict")
	}
}

// gateVerdict runs the gate's verdict jq program on reviews.
func gateVerdict(t *testing.T, reviews string) string {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not installed")
	}
	m := regexp.MustCompile(`(?s)verdict=\$\(get_all "/pulls/\$PR_NUM/reviews\?" \| jq -r --arg u "\$REVIEWER" --arg s "\$EVENT_SHA" '(.*?)'\)`).
		FindStringSubmatch(gateStep(t))
	if m == nil {
		t.Fatalf("gate: no verdict jq program")
	}
	cmd := exec.Command("jq", "-r", "--arg", "u", "codex", "--arg", "s", "abc", m[1])
	cmd.Stdin = strings.NewReader(reviews)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("jq: %v: %s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// Codex P1: a standing CHANGES_REQUESTED on the head blocks the gate even
// when a later APPROVED exists; only a dismissal lifts it.
func TestGateKeepsAStandingChangeRequest(t *testing.T) {
	rv := func(id int, state, at string, dismissed bool) string {
		d := ""
		if dismissed {
			d = `,"dismissed":true`
		}
		return fmt.Sprintf(`{"id":%d,"user":{"login":"codex"},"commit_id":"abc","state":%q,"submitted_at":%q%s}`, id, state, at, d)
	}
	for _, c := range []struct {
		name, reviews, want string
	}{
		{"approval after a change request", "[" + rv(1, "CHANGES_REQUESTED", "2026-11-16T01:00:00Z", false) + "," + rv(2, "APPROVED", "2026-11-16T02:00:00Z", false) + "]", "REQUEST_CHANGES"},
		{"approval after a dismissed change request", "[" + rv(1, "CHANGES_REQUESTED", "2026-11-16T01:00:00Z", true) + "," + rv(2, "APPROVED", "2026-11-16T02:00:00Z", false) + "]", "APPROVED"},
		{"approval alone", "[" + rv(2, "APPROVED", "2026-11-16T02:00:00Z", false) + "]", "APPROVED"},
		{"no review", "[]", "NONE"},
	} {
		if got := gateVerdict(t, c.reviews); got != c.want {
			t.Errorf("%s: verdict %q, want %q", c.name, got, c.want)
		}
	}
}

// Codex P1: a failed or canceled review job (a requested re-review that
// did not finish) fails the gate before it accepts an older approval; a
// skipped review job (no labels) leaves the gate as it was.
func TestGateRefusesAFailedReviewJob(t *testing.T) {
	cr := codeReview(t)
	gate := cr[strings.Index(cr, "\n  gate:\n"):]
	if !regexp.MustCompile(`(?m)^      REVIEW_RESULT: \$\{\{ needs\.review\.result \}\}$`).MatchString(gate) {
		t.Fatalf("gate: no REVIEW_RESULT from needs.review.result in its env")
	}
	g := gateStep(t)
	def := regexp.MustCompile(`(?ms)^ +check_review_result\(\) \{\n.*?^ +\}$`).FindString(g)
	if def == "" {
		t.Fatalf("gate: no check_review_result")
	}
	exempt := strings.Index(g, `if [ "$exempt" = 1 ]; then`)
	verdict := strings.Index(g, "verdict=$(")
	call := regexp.MustCompile(`(?m)^ +check_review_result$`).FindStringIndex(g)
	if call == nil || call[0] < exempt || call[0] > verdict {
		t.Errorf("gate: check_review_result is not called after the no-review exit and before the verdict")
	}
	for _, c := range []struct {
		result string
		ok     bool
	}{{"failure", false}, {"cancelled", false}, {"skipped", true}, {"success", true}} { //nolint:misspell // the runner's spelling, not prose
		script := "set -euo pipefail\nfail() { echo \"fail: $*\" >&2; exit 3; }\n" + def + "\ncheck_review_result\necho passed\n"
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append(os.Environ(), "REVIEW_RESULT="+c.result)
		out, _ := cmd.CombinedOutput()
		if passed := cmd.ProcessState.ExitCode() == 0 && strings.Contains(string(out), "passed"); passed != c.ok {
			t.Errorf("review job %s: passed=%v, want %v (%s)", c.result, passed, c.ok, out)
		}
	}
}

// fakeCurl answers the gate's curl from $FIX: the API path, query cut and
// each / made _, then _<sha> for a head_sha query, names the fixture; a
// missing one answers 404. A page past the first of a paged list, and a
// list of the queued or in-progress runs, is empty.
const fakeCurl = `#!/usr/bin/env bash
out= url=
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    -w|-H|--proto|--max-time|--retry) shift 2 ;;
    http*) url=$1; shift ;;
    *) shift ;;
  esac
done
p=${url#"$REPO_API"}
case "$p" in *[?\&]page=[2-9]*|*[?\&]page=[1-9][0-9]*) echo '[]' > "$out"; printf 200; exit 0 ;; esac
case "$p" in *[?\&]status=*) echo '{"total_count":0,"workflow_runs":[]}' > "$out"; printf 200; exit 0 ;; esac
f="$FIX/$(printf '%s' "${p%%\?*}" | tr / _)"
case "$p" in *head_sha=*) h=${p#*head_sha=}; f=${f}_${h%%&*} ;; esac
if [ -f "$f" ]; then cp "$f" "$out"; printf 200; else echo '{}' > "$out"; printf 404; fi
`

// runGate runs the gate step's script against fixtures (API path, with /
// made _, to body) for a code change on PR 1 at head into main.
func runGate(t *testing.T, head string, fix map[string]string) (int, string) {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not installed")
	}
	g := gateStep(t)
	i := strings.Index(g, "run: |\n")
	if i < 0 {
		t.Fatalf("gate: no run script")
	}
	var script strings.Builder
	for _, l := range strings.Split(g[i+len("run: |\n"):], "\n") {
		script.WriteString(strings.TrimPrefix(l, "          ") + "\n")
	}
	m := regexp.MustCompile(`(?m)^\s+NO_REVIEW_PATHS: '([^']*)'\s*$`).FindStringSubmatch(codeReview(t))
	if m == nil {
		t.Fatalf("gate: no NO_REVIEW_PATHS")
	}
	dir := t.TempDir()
	bin, fixDir, work := filepath.Join(dir, "bin"), filepath.Join(dir, "fix"), filepath.Join(dir, "work")
	for _, d := range []string{bin, fixDir, work} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(fakeCurl), 0o700); err != nil { //nolint:gosec // a test stub on PATH
		t.Fatal(err)
	}
	base := strings.Repeat("b", 40)
	all := map[string]string{
		"_actions_runs_42":                `{"workflow_id":7}`,
		"_compare_" + base + "..." + head: `{"files":[{"filename":"main.go"}]}`,
		"_pulls_1":                        `{"base":{"ref":"main"},"head":{"sha":"` + head + `"}}`,
	}
	for k, v := range fix {
		all[k] = v
	}
	for k, v := range all {
		if err := os.WriteFile(filepath.Join(fixDir, k), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "gate.sh")
	if err := os.WriteFile(path, []byte(script.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", path)
	cmd.Dir = work
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FIX="+fixDir, "GITHUB_RUN_ID=42", "GH_API_TOKEN=x", "FORGE=github", "REVIEWER=codex",
		"REPO_API=https://api.example/repos/o/r", "PR_NUM=1", "EVENT_SHA="+head,
		"BASE_SHA="+base, "BASE_REF=main", "REVIEW_RESULT=skipped", "NO_REVIEW_PATHS="+m[1])
	out, _ := cmd.CombinedOutput()
	return cmd.ProcessState.ExitCode(), string(out)
}

// reviewRuns are fixtures for review runs on PR 1 into main at head: each
// run id to its Codex review job, "skipped" for a job that did not run, or
// a job conclusion (success, failure, ...) with the codex step "success" or
// "skipped". A missing head lists no fixture (HTTP 404).
func reviewRuns(fix map[string]string, head string, runs [][3]string) {
	var list []string
	for _, r := range runs {
		list = append(list, fmt.Sprintf(`{"id":%s,"display_title":"Code Review: PR #1 into main at %s"}`, r[0], head))
		job := fmt.Sprintf(`{"name":"Codex review","status":"completed","conclusion":%q,"steps":[{"name":"Review the head with codex as uid 1000","conclusion":%q}]}`, r[1], r[2])
		fix["_actions_runs_"+r[0]+"_jobs"] = `{"jobs":[` + job + `]}`
	}
	fix["_actions_workflows_7_runs_"+head] = fmt.Sprintf(`{"total_count":%d,"workflow_runs":[%s]}`, len(list), strings.Join(list, ","))
}

// Codex P1: the latest codex review attempt on the head, or on the head
// its approval was carried from, decides: a failed or canceled one (a
// requested re-review that did not finish) keeps the gate red, whatever
// label or same-patch push follows, until a later attempt succeeds. A run
// whose review job was skipped, or that ran no codex step, is no attempt.
func TestGateRefusesAfterAFailedReviewAttempt(t *testing.T) {
	a, b := strings.Repeat("a", 40), strings.Repeat("c", 40)
	approval := func(head, body string) string {
		return fmt.Sprintf(`[{"id":1,"user":{"login":"codex"},"commit_id":%q,"state":"APPROVED","submitted_at":"2026-11-16T01:00:00Z","body":%q}]`, head, body)
	}
	ok, failed, ranNot, skip := [3]string{"", "success", "success"}, [3]string{"", "failure", "success"}, [3]string{"", "success", "skipped"}, [3]string{"", "skipped", "skipped"}
	id := func(n string, r [3]string) [3]string { r[0] = n; return r }
	for _, c := range []struct {
		name     string
		head     string
		runs     map[string][][3]string
		pass     bool
		mentions string
	}{
		{"failed re-review, then an unrelated label", a, map[string][][3]string{
			a: {id("10", ok), id("11", failed), id("12", skip)},
		}, false, "a requested re-review has not approved head " + a},
		{"failed re-review, then an empty commit carries the approval", b, map[string][][3]string{
			b: {id("20", ranNot)},
			a: {id("10", ok), id("11", failed)},
		}, false, "a requested re-review has not approved head " + b},
		{"failed codex request, then agent:opencode and an unrelated label", a, map[string][][3]string{
			a: {id("10", ok), id("11", [3]string{"", "cancelled", "skipped"}), id("12", ranNot), id("13", skip)}, //nolint:misspell // the runner's spelling, not prose
		}, false, "a requested re-review has not approved head " + a},
		{"a later attempt succeeds", a, map[string][][3]string{
			a: {id("10", ok), id("11", failed), id("14", ok)},
		}, true, "codex approved " + a},
		{"no re-review", a, map[string][][3]string{
			a: {id("10", ok), id("12", skip), id("13", ranNot)},
		}, true, "codex approved " + a},
		{"the runs cannot be read", a, map[string][][3]string{}, false, "HTTP 404"},
	} {
		fix := map[string]string{}
		for h, r := range c.runs {
			reviewRuns(fix, h, r)
		}
		body := ""
		if c.head == b {
			body = "<!-- codex-review:verdict head=" + b + " patch=" + strings.Repeat("d", 40) + " carried=" + a + " -->\nCarried"
		}
		fix["_pulls_1_reviews"] = approval(c.head, body)
		code, out := runGate(t, c.head, fix)
		if (code == 0) != c.pass || !strings.Contains(out, c.mentions) {
			t.Errorf("%s: exit %d, want pass=%v and %q in:\n%s", c.name, code, c.pass, c.mentions, out)
		}
	}
}

// Codex P1: the same-patch carry reads the source head's latest codex
// review attempt before it posts, and carries nothing from a failed one.
func TestCarryRefusesAHeadWhoseLatestAttemptFailed(t *testing.T) {
	cr := codeReview(t)
	i := strings.Index(cr, "\n          # SAME PATCH:")
	j := strings.Index(cr, `posted=$(api POST "/pulls/$PR_NUM/reviews" "$WORK/review.json")`)
	if i < 0 || j < i {
		t.Fatalf("%s: no same-patch carry", codeReviewWorkflow)
	}
	if !regexp.MustCompile(`latest_attempt "\$psha"`).MatchString(cr[i:j]) {
		t.Errorf("the carry posts without reading the latest attempt on its source head")
	}
	def := regexp.MustCompile(`(?ms)^ +latest_attempt\(\) \{[^\n]*\n.*?^ +\}$`).FindString(cr[:i])
	if def == "" {
		t.Fatalf("guard: no latest_attempt")
	}
	vars := regexp.MustCompile(`(?ms)^ +jq_(runs|attempt)='.*?'$`).FindAllString(cr[:i], -1)
	if len(vars) != 2 {
		t.Fatalf("guard: want jq_runs and jq_attempt, found %d", len(vars))
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not installed")
	}
	a := strings.Repeat("a", 40)
	for _, c := range []struct {
		name string
		runs [][3]string
		want string
	}{
		{"failed last", [][3]string{{"10", "success", "success"}, {"11", "failure", "skipped"}, {"12", "skipped", "skipped"}}, "failed"},
		{"succeeded last", [][3]string{{"11", "cancelled", "success"}, {"14", "success", "success"}}, "success"}, //nolint:misspell // the runner's spelling, not prose
		{"no attempt", [][3]string{{"12", "success", "skipped"}}, "none"},
	} {
		fix := map[string]string{}
		reviewRuns(fix, a, c.runs)
		dir := t.TempDir()
		for k, v := range fix {
			if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		script := "set -euo pipefail\nshopt -s inherit_errexit\ndie() { echo \"die: $*\" >&2; exit 1; }\n" +
			"api() { local p=$2 f; f=$(printf '%s' \"${p%%\\?*}\" | tr / _); case \"$p\" in *head_sha=*) p=${p#*head_sha=}; f=${f}_${p%%&*} ;; esac; cat \"$FIX/$f\"; }\n" +
			strings.Join(vars, "\n") + "\n" + def + "\nwf=7 PR_NUM=1 BASE_REF=main\nlatest_attempt " + a + "\n"
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append(os.Environ(), "FIX="+dir)
		out, err := cmd.CombinedOutput()
		if got := strings.TrimSpace(string(out)); err != nil || got != c.want {
			t.Errorf("%s: latest_attempt %q (%v), want %q", c.name, got, err, c.want)
		}
	}
}
