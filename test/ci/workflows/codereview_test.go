package workflows

import (
	"errors"
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

// runScope runs the scope job's step with InfoSec's guard stubbed to pass
// (python3 on PATH writes true to GUARD_RESULT) and returns its skip output.
func runScope(t *testing.T) string {
	t.Helper()
	cr := codeReview(t)
	i := strings.Index(cr, "        id: scope\n")
	if i < 0 {
		t.Fatalf("%s: no scope step", codeReviewWorkflow)
	}
	step := cr[i:]
	j := strings.Index(step, "run: |\n")
	k := strings.Index(step, "\n  review:\n")
	if j < 0 || k < j {
		t.Fatalf("%s: no scope run script", codeReviewWorkflow)
	}
	var script strings.Builder
	for _, l := range strings.Split(step[j+len("run: |\n"):k], "\n") {
		script.WriteString(strings.TrimPrefix(l, "          ") + "\n")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	stub := "#!/usr/bin/env bash\ncat >/dev/null\nprintf true > \"$GUARD_RESULT\"\n"
	if err := os.WriteFile(filepath.Join(bin, "python3"), []byte(stub), 0o700); err != nil { //nolint:gosec // a test stub on PATH
		t.Fatal(err)
	}
	path, output := filepath.Join(dir, "scope.sh"), filepath.Join(dir, "output")
	if err := os.WriteFile(path, []byte(script.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", path)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GITHUB_OUTPUT="+output, "GITHUB_STEP_SUMMARY=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("scope step: %v\n%s", err, out)
	}
	b, err := os.ReadFile(output) // #nosec G304 -- the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^skip=(.*)$`).FindSubmatch(b)
	if m == nil {
		t.Fatalf("scope step wrote no skip output: %q", b)
	}
	return string(m[1])
}

// TestScopeSkipNeverSuppressesAWorkflowReview: InfoSec's guard clears only a
// change of workflow files (Y-2), and this repository's NO_REVIEW_PATHS keeps
// .github/workflows/ under review, so the gate needs a Codex approval of such
// a change. A scope skip there would suppress the review job the gate waits
// for (Codex P1, #490): a workflow change never skips the review, and the
// gate still asks for the approval the review gives.
func TestScopeSkipNeverSuppressesAWorkflowReview(t *testing.T) {
	if _, err := exec.LookPath("timeout"); err != nil {
		t.Skip("timeout not installed")
	}
	skip := runScope(t)
	if skip == "true" {
		t.Errorf("the scope job skips the review of a workflow change the guard cleared; the gate still needs a Codex approval of it")
	}
	head, base := strings.Repeat("a", 40), strings.Repeat("b", 40)
	fix := map[string]string{
		"_compare_" + base + "..." + head: `{"files":[{"filename":".github/workflows/ci.yml"}]}`,
		"_pulls_1_reviews":                `[]`,
	}
	code, out := runGateWith(t, head, fix, "SCOPE_SKIP="+skip)
	if code == 0 {
		t.Errorf("the gate passes a workflow change with no review (scope skip=%s):\n%s", skip, out)
	}
	if !strings.Contains(out, "at least one is code") && !strings.Contains(out, "needs a Codex approval") {
		t.Errorf("the gate does not ask for a Codex approval of a workflow change:\n%s", out)
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
	twin := strings.Index(g, "twin=${twin:-$id}")
	verdict := strings.Index(g, "verdict=$(")
	if twin < 0 || verdict < twin || !regexp.MustCompile(`(?m)^ +check_base$`).MatchString(g[twin:verdict]) {
		t.Errorf("gate: no live base check between the twin read and the verdict")
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
[ -z "${CALLS:-}" ] || printf '%s\n' "$p" >> "$CALLS"
case "$p" in *[?\&]page=[2-9]*|*[?\&]page=[1-9][0-9]*) echo '[]' > "$out"; printf 200; exit 0 ;; esac
case "$p" in *[?\&]status=*)
  st=${p#*status=}; st=${st%%&*}
  if [ -f "$FIX/twins_$st" ]; then cp "$FIX/twins_$st" "$out"; printf 200
  elif [ -f "$FIX/twins_unreadable" ]; then echo '{}' > "$out"; printf 500
  else echo '{"total_count":0,"workflow_runs":[]}' > "$out"; printf 200; fi
  exit 0 ;;
esac
f="$FIX/$(printf '%s' "${p%%\?*}" | tr / _)"
case "$p" in *head_sha=*) h=${p#*head_sha=}; f=${f}_${h%%&*} ;; esac
case "$p" in *filter=all*) ;; *) [ ! -f "${f}_latest" ] || f=${f}_latest ;; esac
if [ -f "$f" ]; then cp "$f" "$out"; printf 200; else echo '{}' > "$out"; printf 404; fi
`

// runGate runs the gate step's script against fixtures (API path, with /
// made _, to body) for a code change on PR 1 at head into main.
func runGate(t *testing.T, head string, fix map[string]string) (int, string) {
	t.Helper()
	return runGateWith(t, head, fix)
}

// runGateWith is runGate with extra NAME=value environment entries, which
// override the defaults (the last entry of a name wins).
func runGateWith(t *testing.T, head string, fix map[string]string, extra ...string) (int, string) {
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
	docs := regexp.MustCompile(`(?m)^\s+DOCS_PATHS: '([^']*)'\s*$`).FindStringSubmatch(codeReview(t))
	if docs == nil {
		t.Fatal("gate: no DOCS_PATHS")
	}
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
	// The gate never sleeps (v5.12.6): a sleep it calls fails the run loudly.
	if err := os.WriteFile(filepath.Join(bin, "sleep"), []byte("#!/bin/sh\necho \"gate called sleep $*\" >&2\nexit 97\n"), 0o700); err != nil { //nolint:gosec // a test stub on PATH
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
		"BASE_SHA="+base, "BASE_REF=main", "REVIEW_RESULT=skipped", "NO_REVIEW_PATHS="+m[1],
		// v5.12.1/v5.12.2: the gate also reads the docs list and the scope job.
		"DOCS_PATHS="+docs[1], "SCOPE_SKIP=", "SCOPE_RESULT=success")
	cmd.Env = append(cmd.Env, extra...)
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
		// r[0] is "id" (started at second id, first attempt) or
		// "id@time" (a re-run: second attempt, started at time), or
		// "id+guard" (then a later guard-only re-run that ran no codex).
		// A "~review" or "~re-review" suffix names the run's request kind
		// in its run-name (an ordinary trigger, or an explicit re-review
		// label); without one the run-name is the old one, kind unknown.
		r0, title := r[0], "Code Review: PR #1 into main at "+head
		if k := strings.Index(r0, "~"); k >= 0 {
			kind := r0[k+1:]
			r0 = r0[:k]
			title += map[string]string{"review": " (review: synchronize)", "re-review": " (re-review: labeled effort:high)"}[kind]
		}
		r[0] = r0
		id, started, attempt := r[0], "2026-11-16T00:00:"+r[0]+"Z", 1
		guard := strings.HasSuffix(id, "+guard")
		if guard {
			id = strings.TrimSuffix(id, "+guard")
			started = "2026-11-16T00:00:" + id + "Z"
		}
		if k := strings.Index(r[0], "@"); k >= 0 {
			id, started, attempt = r[0][:k], r[0][k+1:], 2
		}
		list = append(list, fmt.Sprintf(`{"id":%s,"run_started_at":%q,"display_title":%q}`, id, started, title))
		// r[2] "absent": the job lists no review step (stopped before it).
		steps := fmt.Sprintf(`[{"name":"Review the head with codex as uid 1000","conclusion":%q}]`, r[2])
		if r[2] == "absent" {
			steps = `[]`
		}
		// r[1] "scope:<conclusion>": the run's scope job ended so (failure or
		// canceled) and its review job was skipped (needs: scope); else the
		// scope job succeeded.
		scope := "success"
		if c, found := strings.CutPrefix(r[1], "scope:"); found {
			scope, r[1], steps = c, "skipped", `[]`
		}
		job := fmt.Sprintf(`{"id":%s9,"name":"Review scope (InfoSec guard)","run_attempt":%d,"started_at":%q,"status":"completed","conclusion":%q,"steps":[]},`, id, attempt, started, scope)
		job += fmt.Sprintf(`{"id":%s0,"name":"Codex review","run_attempt":%d,"started_at":%q,"status":"completed","conclusion":%q,"steps":%s}`, id, attempt, started, r[1], steps)
		if guard { // the jobs endpoint without filter=all lists only the re-run
			rerun := fmt.Sprintf(`{"id":%s1,"name":"Codex review","run_attempt":2,"started_at":"2026-11-16T09:00:00Z","status":"completed","conclusion":"success","steps":[{"name":"Review the head with codex as uid 1000","conclusion":"skipped"}]}`, id)
			fix["_actions_runs_"+id+"_jobs_latest"] = `{"jobs":[` + rerun + `]}`
			job += "," + rerun
		}
		fix["_actions_runs_"+id+"_jobs"] = `{"jobs":[` + job + `]}`
		if r[1] == "page2" { // a successful page one; a blocking attempt on page two
			fix["_actions_runs_"+id+"_jobs"] = `{"total_count":101,"jobs":[` + strings.Replace(job, `"conclusion":"page2"`, `"conclusion":"success"`, 1) + `]}`
		}
	}
	fix["_actions_workflows_7_runs_"+head] = fmt.Sprintf(`{"total_count":%d,"workflow_runs":[%s]}`, len(list), strings.Join(list, ","))
}

// Codex P1: the latest codex review attempt on the head, or on the head
// its approval was carried from, decides: a failed or canceled one (a
// requested re-review that did not finish) keeps the gate red, whatever
// label or same-patch push follows, until a later attempt succeeds. A run
// whose review job was skipped, or that ran no codex step, is no attempt.
// carryChain: codex approved root, carried it to mid, and mid's to head.
func carryChain(root, mid, head string) string {
	review := func(n int, h, from string) string {
		body := ""
		if from != "" {
			body = "<!-- codex-review:verdict head=" + h + " patch=" + strings.Repeat("d", 40) + " carried=" + from + " -->\nCarried"
		}
		return fmt.Sprintf(`{"id":%d,"user":{"login":"codex"},"commit_id":%q,"state":"APPROVED","submitted_at":"2026-11-16T0%d:00:00Z","body":%q}`, n, h, n, body)
	}
	return "[" + review(1, root, "") + "," + review(2, mid, root) + "," + review(3, head, mid) + "]"
}

func TestGateRefusesAfterAFailedReviewAttempt(t *testing.T) {
	a, b, e := strings.Repeat("a", 40), strings.Repeat("c", 40), strings.Repeat("e", 40)
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
			a: {id("10", ok), id("11", [3]string{"", "failure", "skipped"}), id("12", ranNot), id("13", skip)},
		}, false, "a requested re-review has not approved head " + a},
		// Codex P1 (#490): the shared concurrency group cancels an older
		// pending duplicate before its review step starts; that is no attempt.
		// Round 4: only a later job whose codex step ran and succeeded (a
		// real replacement review) clears it; a guard-only skip=reviewed
		// job ran no review and replaces nothing.
		{"approved, then a dedup-canceled duplicate and a real replacement review", a, map[string][][3]string{
			a: {id("10", ok), id("11", [3]string{"", "cancelled", "skipped"}), id("12", ok)}, //nolint:misspell // the runner's spelling, not prose
		}, true, "codex approved " + a},
		{"approved, then a duplicate canceled before it listed a review step and a real review", a, map[string][][3]string{
			a: {id("10", ok), id("11", [3]string{"", "cancelled", "absent"}), id("12", ok)}, //nolint:misspell // the runner's spelling, not prose
		}, true, "codex approved " + a},
		{"approved, then an effort re-review canceled before codex and a guard-only skip=reviewed run", a, map[string][][3]string{
			a: {id("10", ok), id("11", [3]string{"", "cancelled", "skipped"}), id("12", ranNot)}, //nolint:misspell // the runner's spelling, not prose
		}, false, "a requested re-review has not approved head " + a},
		{"approved, then a re-review canceled before any step and a guard-only run", a, map[string][][3]string{
			a: {id("10", ok), id("11", [3]string{"", "cancelled", "absent"}), id("12", ranNot)}, //nolint:misspell // the runner's spelling, not prose
		}, false, "a requested re-review has not approved head " + a},
		{"approved, then a re-review canceled while codex ran", a, map[string][][3]string{
			a: {id("10", ok), id("11", [3]string{"", "cancelled", "cancelled"}), id("12", ranNot)}, //nolint:misspell // the runner's spelling, not prose
		}, false, "a requested re-review has not approved head " + a},
		// Codex P1 (#490, round 3): an explicit re-review canceled while it
		// waited still blocks; only a later same-head review run that ended
		// success (a replacing duplicate) makes the canceled one no attempt.
		{"approved, then an effort re-review canceled while queued and an unrelated label", a, map[string][][3]string{
			a: {id("10", ok), id("11", [3]string{"", "cancelled", "skipped"}), id("12", skip)}, //nolint:misspell // the runner's spelling, not prose
		}, false, "a requested re-review has not approved head " + a},
		{"approved, then a re-review canceled before any step and an unrelated label", a, map[string][][3]string{
			a: {id("10", ok), id("11", [3]string{"", "cancelled", "absent"}), id("12", skip)}, //nolint:misspell // the runner's spelling, not prose
		}, false, "a requested re-review has not approved head " + a},
		{"approved, then a canceled re-review alone", a, map[string][][3]string{
			a: {id("10", ok), id("11", [3]string{"", "cancelled", "skipped"})}, //nolint:misspell // the runner's spelling, not prose
		}, false, "a requested re-review has not approved head " + a},
		// Codex P1 (#490, round 5): the run-name carries the request kind. A
		// canceled job of an ordinary run (a duplicate the shared group
		// replaced) is no attempt whatever follows; one of an explicit
		// re-review, or of a run whose kind cannot be read, blocks until a
		// later real review succeeds.
		{"round 5: approved, an ordinary duplicate canceled, an ordinary guard-only run", a, map[string][][3]string{
			a: {id("10~review", ok), id("11~review", [3]string{"", "cancelled", "skipped"}), id("12~review", ranNot)}, //nolint:misspell // the runner's spelling, not prose
		}, true, "codex approved " + a},
		{"round 5: approved, an ordinary duplicate canceled before any step, a guard-only run", a, map[string][][3]string{
			a: {id("10~review", ok), id("11~review", [3]string{"", "cancelled", "absent"}), id("12~review", ranNot)}, //nolint:misspell // the runner's spelling, not prose
		}, true, "codex approved " + a},
		{"round 4: approved, an effort:high re-review canceled before codex, a guard-only run", a, map[string][][3]string{
			a: {id("10~review", ok), id("11~re-review", [3]string{"", "cancelled", "skipped"}), id("12~review", ranNot)}, //nolint:misspell // the runner's spelling, not prose
		}, false, "a requested re-review has not approved head " + a},
		{"an explicit re-review canceled, then a real review succeeds", a, map[string][][3]string{
			a: {id("10~review", ok), id("11~re-review", [3]string{"", "cancelled", "skipped"}), id("12~review", ok)}, //nolint:misspell // the runner's spelling, not prose
		}, true, "codex approved " + a},
		{"a canceled run of unknown kind, then a guard-only run", a, map[string][][3]string{
			a: {id("10~review", ok), id("11", [3]string{"", "cancelled", "skipped"}), id("12~review", ranNot)}, //nolint:misspell // the runner's spelling, not prose
		}, false, "a requested re-review has not approved head " + a},
		{"an ordinary run canceled while codex ran", a, map[string][][3]string{
			a: {id("10~review", ok), id("11~review", [3]string{"", "cancelled", "cancelled"}), id("12~review", ranNot)}, //nolint:misspell // the runner's spelling, not prose
		}, false, "a requested re-review has not approved head " + a},
		// Codex P1 (#490, round 6): the scope job of an explicit re-review
		// failed or was canceled, so its review was skipped (needs: scope);
		// a later ordinary run's skipped or guard-only review passes no
		// approval until a real review succeeds.
		{"round 6: approved, an explicit re-review's scope failed, an ordinary guard-only run", a, map[string][][3]string{
			a: {id("10~review", ok), id("11~re-review", [3]string{"", "scope:failure", ""}), id("12~review", ranNot)},
		}, false, "a requested re-review has not approved head " + a},
		{"round 6: an explicit re-review's scope failed, then a real review succeeds", a, map[string][][3]string{
			a: {id("10~review", ok), id("11~re-review", [3]string{"", "scope:failure", ""}), id("12~review", ranNot), id("13~review", ok)},
		}, true, "codex approved " + a},
		{"round 6: approved, an explicit re-review's scope canceled, an ordinary guard-only run", a, map[string][][3]string{
			a: {id("10~review", ok), id("11~re-review", [3]string{"", "scope:cancelled", ""}), id("12~review", ranNot)}, //nolint:misspell // the runner's spelling, not prose
		}, false, "a requested re-review has not approved head " + a},
		{"round 6: approved, an ordinary duplicate's scope canceled, an ordinary guard-only run", a, map[string][][3]string{
			a: {id("10~review", ok), id("11~review", [3]string{"", "scope:cancelled", ""}), id("12~review", ranNot)}, //nolint:misspell // the runner's spelling, not prose
		}, true, "codex approved " + a},
		{"a later attempt succeeds", a, map[string][][3]string{
			a: {id("10", ok), id("11", failed), id("14", ok)},
		}, true, "codex approved " + a},
		{"no re-review", a, map[string][][3]string{
			a: {id("10", ok), id("12", skip), id("13", ranNot)},
		}, true, "codex approved " + a},
		{"a lower-ID run re-run after a later approval fails", a, map[string][][3]string{
			a: {id("10@2026-11-16T09:00:00Z", failed), id("11", ok)},
		}, false, "a requested re-review has not approved head " + a},
		{"a lower-ID run re-run after a failure approves", a, map[string][][3]string{
			a: {id("10@2026-11-16T09:00:00Z", ok), id("11", failed)},
		}, true, "codex approved " + a},
		{"a failed attempt, then a guard-only re-run of the same run", a, map[string][][3]string{
			a: {id("10", ok), id("11+guard", failed)},
		}, false, "a requested re-review has not approved head " + a},
		{"more jobs than one page", a, map[string][][3]string{
			a: {id("10", ok), id("11", [3]string{"", "page2", "success"})},
		}, false, "cannot read the jobs of run 11"},
		{"a failed re-review on the root of a two-hop carry", e, map[string][][3]string{
			e: {id("30", ranNot)}, b: {id("20", ranNot)}, a: {id("10", ok), id("11", failed)},
		}, false, "a requested re-review has not approved head " + e},
		{"a clean two-hop carry", e, map[string][][3]string{
			e: {id("30", ranNot)}, b: {id("20", ranNot)}, a: {id("10", ok)},
		}, true, "codex approved " + e},
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
		if c.head == e { // e carried from b, b carried from a
			fix["_pulls_1_reviews"] = carryChain(a, b, e)
		}
		code, out := runGate(t, c.head, fix)
		if (code == 0) != c.pass || !strings.Contains(out, c.mentions) {
			t.Errorf("%s: exit %d, want pass=%v and %q in:\n%s", c.name, code, c.pass, c.mentions, out)
		}
	}
}

// The gate never waits for a twin review (template v5.12.6). It reads the
// queued and in-progress runs of the same PR, base and head once, with or
// without the run-name's request kind; an APPROVED head passes as before,
// and otherwise a twin whose "Codex review" job is queued or in progress
// fails the gate at once, naming that run, whose own gate posts the head's
// check. It never sleeps, and an API error still fails closed. Its timeout
// is 10 minutes, since no wait is left to budget for.
func TestGateNeverWaitsForATwinReview(t *testing.T) {
	cr := codeReview(t)
	if !strings.Contains(cr, "# code-review-template: v5.12.6 ") {
		t.Errorf("%s: not template v5.12.6", codeReviewWorkflow)
	}
	gate := regexp.MustCompile(`(?ms)^  gate:\n.*?(?:^  [a-z]|\z)`).FindString(cr)
	if gate == "" {
		t.Fatalf("%s: no gate job", codeReviewWorkflow)
	}
	if !regexp.MustCompile(`(?m)^    timeout-minutes: 10$`).MatchString(gate) {
		t.Errorf("gate: timeout-minutes is not 10")
	}
	g := gateStep(t)
	if strings.Contains(g, "sleep") {
		t.Errorf("gate: the gate sleeps")
	}
	start, end := regexp.MustCompile(`(?m)^ +twin=$`).FindStringIndex(g), strings.Index(g, "verdict=$(")
	if start == nil || end < start[1] {
		t.Fatalf("gate: no twin read before the verdict")
	}
	for _, gone := range []string{"waited", "4500", "busy="} {
		if strings.Contains(g[start[0]:end], gone) {
			t.Errorf("gate: the twin wait is back (%q)", gone)
		}
	}
	if loop := regexp.MustCompile(`(?m)^ +(?:while|until) `).FindString(g[start[0]:end]); loop != "" {
		t.Errorf("gate: the twin read loops (%q)", loop)
	}
	// The go-luks2 twin selector: the run-name alone or with either kind.
	sel := `select(.id != $me and ($d == $t or ($d | startswith($t + " (review: ")) or ($d | startswith($t + " (re-review: ")))) | .id`
	if strings.Count(g, sel) != 1 || strings.Contains(g, ".display_title == $t") {
		t.Errorf("gate: the twin read does not match the PR, base and head with any request kind")
	}
	failNow := regexp.MustCompile(`(?m)^ +\[ "\$verdict" = APPROVED \] \|\| \[ -z "\$twin" \] \|\|\n +fail "the Codex review of \$EVENT_SHA runs in run \$twin; that run's gate posts this head's check`)
	if !failNow.MatchString(g) {
		t.Errorf("gate: no fail-at-once branch for an unapproved head with a twin review")
	}
	if fn, v := failNow.FindStringIndex(g), strings.Index(g, "verdict=$("); fn != nil && fn[0] < v {
		t.Errorf("gate: the twin branch runs before the verdict is read")
	}

	a := strings.Repeat("a", 40)
	title := "Code Review: PR #1 into main at " + a
	approved := `[{"id":1,"user":{"login":"codex"},"commit_id":"` + a + `","state":"APPROVED","submitted_at":"2026-11-16T01:00:00Z","body":""}]`
	changes := `[{"id":1,"user":{"login":"codex"},"commit_id":"` + a + `","state":"REQUEST_CHANGES","submitted_at":"2026-11-16T01:00:00Z","body":""}]`
	runs := func(rs ...string) string {
		return `{"total_count":` + fmt.Sprint(len(rs)) + `,"workflow_runs":[` + strings.Join(rs, ",") + `]}`
	}
	run := func(id, name string) string { return fmt.Sprintf(`{"id":%s,"display_title":%q}`, id, name) }
	jobs := func(status string) string {
		return `{"jobs":[{"id":1,"name":"Review scope (InfoSec guard)","status":"completed","conclusion":"success"},` +
			`{"id":2,"name":"Codex review","status":"` + status + `","conclusion":null}]}`
	}
	for _, c := range []struct {
		name     string
		reviews  string
		twins    map[string]string // fixture name -> body
		pass     bool
		mentions string
		absent   string
	}{
		{"no twin, approved", approved, nil, true, "codex approved " + a, "runs in run"},
		{"no twin, not approved", "[]", nil, false, "no codex approval of " + a, "runs in run"},
		{"no twin, changes requested", changes, nil, false, "codex requested changes on " + a, "runs in run"},
		{"a queued twin of an ordinary push, not approved", "[]", map[string]string{
			"twins_queued": runs(run("50", title+" (review: synchronize)")), "_actions_runs_50_jobs": jobs("queued"),
		}, false, "the Codex review of " + a + " runs in run 50; that run's gate posts this head's check (verdict here: NONE", "no codex approval"},
		{"an in-progress twin of an explicit re-review, changes requested", changes, map[string]string{
			"twins_in_progress": runs(run("51", title+" (re-review: labeled effort:high)")), "_actions_runs_51_jobs": jobs("in_progress"),
		}, false, "runs in run 51; that run's gate posts this head's check (verdict here: REQUEST_CHANGES", "requested changes on"},
		{"a twin with the run-name of no kind", "[]", map[string]string{
			"twins_queued": runs(run("52", title)), "_actions_runs_52_jobs": jobs("queued"),
		}, false, "runs in run 52;", "no codex approval"},
		{"a twin reviews, the head is already approved", approved, map[string]string{
			"twins_in_progress": runs(run("53", title+" (review: labeled code-review)")), "_actions_runs_53_jobs": jobs("in_progress"),
		}, true, "codex approved " + a, "runs in run"},
		{"the first twin is named", "[]", map[string]string{
			"twins_queued":          runs(run("54", title+" (review: synchronize)")),
			"twins_in_progress":     runs(run("55", title+" (review: labeled code-review)")),
			"_actions_runs_54_jobs": jobs("queued"), "_actions_runs_55_jobs": jobs("in_progress"),
		}, false, "runs in run 54;", "run 55"},
		{"a twin whose review has ended is no twin", "[]", map[string]string{
			"twins_in_progress": runs(run("56", title+" (review: synchronize)")), "_actions_runs_56_jobs": jobs("completed"),
		}, false, "no codex approval of " + a, "runs in run"},
		{"this run itself is no twin", "[]", map[string]string{
			"twins_in_progress": runs(run("42", title+" (review: synchronize)")), "_actions_runs_42_jobs": jobs("in_progress"),
		}, false, "no codex approval of " + a, "runs in run"},
		{"a run into another base is no twin", "[]", map[string]string{
			"twins_queued": runs(run("57", "Code Review: PR #1 into dev at "+a+" (review: synchronize)")), "_actions_runs_57_jobs": jobs("queued"),
		}, false, "no codex approval of " + a, "runs in run"},
		{"a run of another PR is no twin", "[]", map[string]string{
			"twins_queued": runs(run("58", "Code Review: PR #10 into main at "+a+" (review: synchronize)")), "_actions_runs_58_jobs": jobs("queued"),
		}, false, "no codex approval of " + a, "runs in run"},
		{"a run-name with another suffix is no twin", "[]", map[string]string{
			"twins_queued": runs(run("59", title+" (other: x)")), "_actions_runs_59_jobs": jobs("queued"),
		}, false, "no codex approval of " + a, "runs in run"},
		{"the twin listing cannot be read", approved, map[string]string{"twins_unreadable": ""},
			false, "cannot list the queued runs on " + a, "codex approved"},
		{"a twin's jobs cannot be read", approved, map[string]string{
			"twins_queued": runs(run("60", title+" (review: synchronize)")),
		}, false, "cannot read the jobs of run 60", "codex approved"},
	} {
		fix := map[string]string{"_pulls_1_reviews": c.reviews}
		reviewRuns(fix, a, [][3]string{{"10~review", "success", "success"}})
		for k, v := range c.twins {
			fix[k] = v
		}
		calls := filepath.Join(t.TempDir(), "calls")
		code, out := runGateWith(t, a, fix, "CALLS="+calls)
		if (code == 0) != c.pass || !strings.Contains(out, c.mentions) || strings.Contains(out, c.absent) {
			t.Errorf("%s: exit %d, want pass=%v, %q and not %q in:\n%s", c.name, code, c.pass, c.mentions, c.absent, out)
		}
		if !c.pass && code != 3 {
			t.Errorf("%s: exit %d, want the gate's fail (3)", c.name, code)
		}
		if strings.Contains(out, "gate called sleep") {
			t.Errorf("%s: the gate slept:\n%s", c.name, out)
		}
		log, err := os.ReadFile(calls) //nolint:gosec // the test's own temp file
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		for _, st := range []string{"queued", "in_progress"} {
			if n := strings.Count(string(log), "&status="+st+"&"); n > 1 {
				t.Errorf("%s: the gate listed the %s runs %d times, want one read", c.name, st, n)
			}
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
	if !regexp.MustCompile(`check_lineage "\$psha"`).MatchString(cr[i:j]) {
		t.Errorf("the carry posts without reading the latest attempt on its source head")
	}
	def := regexp.MustCompile(`(?ms)^ +latest_attempt\(\) \{[^\n]*\n.*?^ +\}$`).FindString(cr[:i])
	if def == "" {
		t.Fatalf("guard: no latest_attempt")
	}
	lineage := regexp.MustCompile(`(?ms)^ +check_lineage\(\) \{[^\n]*\n.*?^ +\}$`).FindString(cr[:i])
	if lineage == "" {
		t.Fatalf("guard: no check_lineage")
	}
	vars := regexp.MustCompile(`(?ms)^ +jq_(runs|attempt|chain)='.*?'$`).FindAllString(cr[:i], -1)
	if len(vars) != 3 {
		t.Fatalf("guard: want jq_runs, jq_attempt and jq_chain, found %d", len(vars))
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
		{"lower-ID re-run failed last", [][3]string{{"10@2026-11-16T09:00:00Z", "failure", "success"}, {"11", "success", "success"}}, "failed"},
		{"lower-ID re-run succeeded last", [][3]string{{"10@2026-11-16T09:00:00Z", "success", "success"}, {"11", "failure", "success"}}, "success"},
		{"failed, then a guard-only re-run", [][3]string{{"10", "success", "success"}, {"11+guard", "failure", "success"}}, "failed"},
		{"more jobs than one page", [][3]string{{"10", "success", "success"}, {"11", "page2", "success"}}, "die: cannot read the jobs of run 11"},
		{"no attempt", [][3]string{{"12", "success", "skipped"}}, "none"},
		// Codex P1 (#490): a duplicate the concurrency group canceled before
		// its review step started, and a later same-head review run replaced
		// with success, is no attempt; one canceled mid-review is. Round 3: a
		// re-review canceled before its step with no later successful review
		// run (only an unrelated label run, or none) still failed.
		// Round 4: only a later real review (codex step success) replaces
		// it; a guard-only skip=reviewed job does not.
		{"dedup-cancelled after an approval, then a real review", [][3]string{{"10", "success", "success"}, {"11", "cancelled", "skipped"}, {"12", "success", "success"}}, "success"},                       //nolint:misspell // the runner's spelling, not prose
		{"cancelled before any step after an approval, then a real review", [][3]string{{"10", "success", "success"}, {"11", "cancelled", "absent"}, {"12", "success", "success"}}, "success"},              //nolint:misspell // the runner's spelling, not prose
		{"effort re-review cancelled before codex, then a guard-only skip=reviewed job", [][3]string{{"10", "success", "success"}, {"11", "cancelled", "skipped"}, {"12", "success", "skipped"}}, "failed"}, //nolint:misspell // the runner's spelling, not prose
		{"cancelled before any step after an approval, then a guard-only job", [][3]string{{"10", "success", "success"}, {"11", "cancelled", "absent"}, {"12", "success", "skipped"}}, "failed"},            //nolint:misspell // the runner's spelling, not prose
		{"re-review cancelled while queued, then an unrelated label", [][3]string{{"10", "success", "success"}, {"11", "cancelled", "skipped"}, {"12", "skipped", "skipped"}}, "failed"},                    //nolint:misspell // the runner's spelling, not prose
		{"re-review cancelled before any step, nothing later", [][3]string{{"10", "success", "success"}, {"11", "cancelled", "absent"}}, "failed"},                                                          //nolint:misspell // the runner's spelling, not prose
		{"cancelled while codex ran", [][3]string{{"10", "success", "success"}, {"11", "cancelled", "cancelled"}}, "failed"},                                                                                //nolint:misspell // the runner's spelling, not prose
		{"failed before the review step", [][3]string{{"10", "success", "success"}, {"11", "failure", "absent"}}, "failed"},
		// Round 5: the run-name's request kind decides a canceled job.
		{"round 5: ordinary duplicate cancelled, ordinary guard-only job", [][3]string{{"10~review", "success", "success"}, {"11~review", "cancelled", "skipped"}, {"12~review", "success", "skipped"}}, "success"}, //nolint:misspell // the runner's spelling, not prose
		{"round 4: effort:high re-review cancelled, guard-only job", [][3]string{{"10~review", "success", "success"}, {"11~re-review", "cancelled", "skipped"}, {"12~review", "success", "skipped"}}, "failed"},     //nolint:misspell // the runner's spelling, not prose
		{"explicit re-review cancelled, then a real review", [][3]string{{"10~review", "success", "success"}, {"11~re-review", "cancelled", "absent"}, {"12~review", "success", "success"}}, "success"},             //nolint:misspell // the runner's spelling, not prose
		{"unknown-kind run cancelled, guard-only job", [][3]string{{"10~review", "success", "success"}, {"11", "cancelled", "skipped"}, {"12~review", "success", "skipped"}}, "failed"},                             //nolint:misspell // the runner's spelling, not prose
		{"ordinary duplicate cancelled, nothing later", [][3]string{{"10~review", "success", "success"}, {"11~review", "cancelled", "absent"}}, "success"},                                                          //nolint:misspell // the runner's spelling, not prose
		// Round 6: a failed or canceled scope job of an explicit re-review skipped its review.
		{"round 6: explicit re-review's scope failed, ordinary guard-only job", [][3]string{{"10~review", "success", "success"}, {"11~re-review", "scope:failure", ""}, {"12~review", "success", "skipped"}}, "failed"},
		{"round 6: explicit re-review's scope failed, then a real review", [][3]string{{"10~review", "success", "success"}, {"11~re-review", "scope:failure", ""}, {"12~review", "success", "skipped"}, {"13~review", "success", "success"}}, "success"},
		{"round 6: explicit re-review's scope cancelled, ordinary guard-only job", [][3]string{{"10~review", "success", "success"}, {"11~re-review", "scope:cancelled", ""}, {"12~review", "success", "skipped"}}, "failed"}, //nolint:misspell // the runner's spelling, not prose
		{"round 6: ordinary duplicate's scope cancelled, ordinary guard-only job", [][3]string{{"10~review", "success", "success"}, {"11~review", "scope:cancelled", ""}, {"12~review", "success", "skipped"}}, "success"},   //nolint:misspell // the runner's spelling, not prose
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
			"api() { local p=$2 f; f=$(printf '%s' \"${p%%\\?*}\" | tr / _); case \"$p\" in *head_sha=*) p=${p#*head_sha=}; f=${f}_${p%%&*} ;; esac; case \"$2\" in *filter=all*) ;; *) [ ! -f \"$FIX/${f}_latest\" ] || f=${f}_latest ;; esac; cat \"$FIX/$f\"; }\n" +
			strings.Join(vars, "\n") + "\n" + def + "\nwf=7 PR_NUM=1 BASE_REF=main\nlatest_attempt " + a + "\n"
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append(os.Environ(), "FIX="+dir)
		out, err := cmd.CombinedOutput()
		if got := strings.TrimSpace(string(out)); strings.HasPrefix(c.want, "die: ") {
			if err == nil || !strings.Contains(got, c.want) {
				t.Errorf("%s: latest_attempt %q (%v), want it to fail with %q", c.name, got, err, c.want)
			}
		} else if err != nil || got != c.want {
			t.Errorf("%s: latest_attempt %q (%v), want %q", c.name, got, err, c.want)
		}
	}
	// The A->B->C carry: B only carried A's approval; C is about to carry B's.
	b := strings.Repeat("c", 40)
	for _, c := range []struct {
		name  string
		aRuns [][3]string
		want  string
	}{
		{"a failed re-review on the root A", [][3]string{{"10", "success", "success"}, {"11", "failure", "success"}}, "failed"},
		{"a clean chain", [][3]string{{"10", "success", "success"}}, "success"},
	} {
		fix := map[string]string{"_pulls_1_reviews": carryChain(a, b, strings.Repeat("e", 40))}
		reviewRuns(fix, a, c.aRuns)
		reviewRuns(fix, b, [][3]string{{"20", "success", "skipped"}})
		dir := t.TempDir()
		for k, v := range fix {
			if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		script := "set -euo pipefail\nshopt -s inherit_errexit\ndie() { echo \"die: $*\" >&2; exit 1; }\n" +
			"api() { local p=$2 f; f=$(printf '%s' \"${p%%\\?*}\" | tr / _); case \"$p\" in *head_sha=*) p=${p#*head_sha=}; f=${f}_${p%%&*} ;; esac; cat \"$FIX/$f\"; }\n" +
			"api_all() { api GET \"$1\"; }\n" +
			strings.Join(vars, "\n") + "\n" + def + "\n" + lineage + "\nwf=7 PR_NUM=1 BASE_REF=main REVIEWER=codex\ncheck_lineage " + b + "\n"
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append(os.Environ(), "FIX="+dir)
		out, err := cmd.CombinedOutput()
		if got := strings.TrimSpace(string(out)); err != nil || got != c.want {
			t.Errorf("%s: check_lineage %q (%v), want %q", c.name, got, err, c.want)
		}
	}
}

// Codex P1 (#490, round 5): each run's run-name (display_title) names its
// request kind, an explicit re-review (an agent:, model: or effort: label)
// or an ordinary trigger, so the reducers can tell a replaced duplicate
// from a canceled re-review; every reader of the run-name accepts it.
func TestRunNameCarriesTheRequestKind(t *testing.T) {
	cr := codeReview(t)
	m := regexp.MustCompile(`(?m)^run-name: (.*)$`).FindStringSubmatch(cr)
	if m == nil {
		t.Fatalf("%s: no run-name", codeReviewWorkflow)
	}
	base := `"Code Review: PR #${{ github.event.pull_request.number }} into ${{ github.event.pull_request.base.ref }} at ${{ github.event.pull_request.head.sha }} (`
	if !strings.HasPrefix(m[1], base) {
		t.Errorf("the run-name does not start with the PR, base and head, then the kind: %s", m[1])
	}
	for _, want := range []string{
		"github.event.action", "github.event.label.name", "'re-review'", "'review'",
		"startsWith(github.event.label.name, 'agent:')", "startsWith(github.event.label.name, 'model:')", "startsWith(github.event.label.name, 'effort:')",
	} {
		if !strings.Contains(m[1], want) {
			t.Errorf("the run-name lacks %s: %s", want, m[1])
		}
	}
	if n := strings.Count(cr, `+ " (review: ")`); n < 4 {
		t.Errorf("want the guard's twins and runs and the gate's runs and twin read to accept a run-name with its kind, found %d", n)
	}
	if n := strings.Count(cr, `+ " (re-review: ")`); n < 4 {
		t.Errorf("want every run-name reader to accept an explicit re-review's run-name, found %d", n)
	}
	if strings.Contains(cr, `.display_title == $t)`) || strings.Contains(cr, `.display_title == $mine)`) {
		t.Errorf("a run-name reader still matches only the run-name without its kind")
	}
	if !strings.Contains(cr, `"$my_base (review: "*")"`) || !strings.Contains(cr, `"$my_base (re-review: "*")"`) {
		t.Errorf("the guard refuses its own run-name with the kind")
	}
}

// Codex P1 (#490, round 3): enablePullRequestAutoMerge can answer with no
// error and no auto-merge request; the step reads the request it selected
// and reports such an answer not armed. expectedHeadOid stays: GitHub's live
// schema (introspection 2026-11-17) lists it on EnablePullRequestAutoMergeInput.
func TestRearmChecksTheAutoMergeRequest(t *testing.T) {
	cr := codeReview(t)
	i := strings.Index(cr, "- name: Re-arm auto-merge on the approved head")
	if i < 0 {
		t.Fatalf("%s: no re-arm step", codeReviewWorkflow)
	}
	j := strings.Index(cr[i:], `gh_call PUT "$REPO_API/pulls/$PR_NUM/merge"`)
	if j < 0 {
		t.Fatalf("%s: the re-arm step has no clean-status merge", codeReviewWorkflow)
	}
	step := cr[i : i+j]
	m := regexp.MustCompile(`mutation\([^']*enablePullRequestAutoMerge\(input:\{([^}]*)\}\)\{([^']*)\}'`).FindStringSubmatch(step)
	if m == nil {
		t.Fatalf("the re-arm step has no enablePullRequestAutoMerge mutation")
	}
	if !strings.Contains(m[1], "expectedHeadOid:$h") {
		t.Errorf("the mutation is not pinned to the approved head (expectedHeadOid): %s", m[1])
	}
	if !regexp.MustCompile(`pullRequest\{[^']*autoMergeRequest\{enabledAt\}`).MatchString(m[2]) {
		t.Errorf("the mutation does not select pullRequest.autoMergeRequest.enabledAt: %s", m[2])
	}
	check := regexp.MustCompile(`\.data\.enablePullRequestAutoMerge\.pullRequest\.autoMergeRequest\.enabledAt`).FindStringIndex(step)
	armed := strings.Index(step, "armed to auto-merge (squash)")
	if check == nil || armed < 0 || check[0] > armed {
		t.Errorf("the step reports armed without reading the auto-merge request it got back")
	}
	if !strings.Contains(step, "# CUSTOMIZE: local fix pending upstream (template v5.12.3, Codex P1 on #490)") {
		t.Errorf("the auto-merge request check carries no CUSTOMIZE marker")
	}
}

// rearmCurl stands in for curl in the re-arm step: it records each call as
// "METHOD URL" in $STUB_DIR/calls and answers from the fixture files.
const rearmCurl = `#!/usr/bin/env bash
out= method=GET url=
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    -X) method=$2; shift 2 ;;
    -w|-H|--proto|--max-time|--data-binary) shift 2 ;;
    -*) shift ;;
    *) url=$1; shift ;;
  esac
done
echo "$method $url" >> "$STUB_DIR/calls"
case "$method $url" in
  "GET "*/pulls/*) f=pr.json ;;
  "POST "*/graphql) f=arm.json ;;
  "PUT "*/merge) f=merge.json ;;
  *) f=none ;;
esac
if [ -f "$STUB_DIR/$f" ]; then cp "$STUB_DIR/$f" "$out"; printf 200; else echo '{}' > "$out"; printf 404; fi
`

// runRearm runs the re-arm step's script against a PR whose live base is
// liveBase, for a run reviewed against main, and returns its exit status,
// output and the API calls it made.
func runRearm(t *testing.T, liveBase string) (int, string, []string) {
	t.Helper()
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found: %v", tool, err)
		}
	}
	script := runScript(t, stepBlock(t, codeReview(t), "Re-arm auto-merge on the approved head"))
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	bin := filepath.Join(dir, "bin")
	for _, d := range []string{work, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	const head = "1111111111111111111111111111111111111111"
	files := map[string]string{
		filepath.Join(bin, "curl"):       rearmCurl,
		filepath.Join(work, "lib.sh"):    "load_token() { :; }\nHDR=\"$WORK/hdr\"\n",
		filepath.Join(work, "hdr"):       "Authorization: token x\n",
		filepath.Join(dir, "pr.json"):    fmt.Sprintf(`{"state":"open","draft":false,"auto_merge":null,"node_id":"PR_1","head":{"sha":%q},"base":{"ref":%q}}`, head, liveBase),
		filepath.Join(dir, "arm.json"):   `{"errors":[{"message":"Pull request is in clean status"}]}`,
		filepath.Join(dir, "merge.json"): `{"sha":"2222222222222222222222222222222222222222","merged":true}`,
		filepath.Join(dir, "step.sh"):    script,
	}
	for p, body := range files {
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", filepath.Join(dir, "step.sh"))
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"STUB_DIR="+dir, "WORK="+work, "PR_NUM=7", "EVENT_SHA="+head, "BASE_REF=main",
		"REPO_API=https://api.example/repos/o/r", "FORGE_API=https://api.example")
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("re-arm step did not run: %v", err)
		}
		code = ee.ExitCode()
	}
	calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
	return code, string(out), strings.Fields(strings.ReplaceAll(string(calls), " ", "_"))
}

// TestRearmRefusesARetargetedPullRequest: a PR retargeted after the confirm
// step is neither armed nor merged; on the reviewed base the step goes on
// (here GitHub reads it clean, so it squash-merges at the approved head).
func TestRearmRefusesARetargetedPullRequest(t *testing.T) {
	code, out, calls := runRearm(t, "release")
	for _, c := range calls {
		if !strings.HasPrefix(c, "GET_") {
			t.Errorf("retargeted PR: the step made a write call %s\n%s", c, out)
		}
	}
	if code == 0 || !strings.Contains(out, "retargeted") {
		t.Errorf("retargeted PR: want a red step naming the retarget, got exit %d:\n%s", code, out)
	}

	code, out, calls = runRearm(t, "main")
	want := []string{
		"GET_https://api.example/repos/o/r/pulls/7",
		"POST_https://api.example/graphql",
		"PUT_https://api.example/repos/o/r/pulls/7/merge",
	}
	if code != 0 || strings.Join(calls, " ") != strings.Join(want, " ") || !strings.Contains(out, "squash-merged") {
		t.Errorf("same base: want exit 0, calls %v and a squash merge; got exit %d, calls %v:\n%s", want, code, calls, out)
	}
}

// TestFreshOwnerResumeResetsAnExhaustedCount: an exhausted review keeps
// needs-coordinator, so a fresh owner-resume must restart the count with
// that label still on (and take it off), or the new head hits round-limit.
func TestFreshOwnerResumeResetsAnExhaustedCount(t *testing.T) {
	cr := codeReview(t)
	i := strings.Index(cr, "          # v5.10.7: THE OWNER RESUMES.")
	j := strings.Index(cr, `          if [ "$done_rounds" -ge "$limit" ] && [ "$latest" != APPROVED ]; then`)
	if i < 0 || j < i {
		t.Fatalf("%s: no owner-resume block before the round limit", codeReviewWorkflow)
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not installed")
	}
	for _, c := range []struct {
		name, labels, resumeID, want string
	}{
		{"fresh owner-resume with needs-coordinator on", `["code-review","needs-coordinator","owner-resume"]`, "77", "rounds=0 limit=2 relabel= needs-coordinator"},
		{"no owner-resume with needs-coordinator on", `["code-review","needs-coordinator"]`, "", "rounds=5 limit=5 relabel="},
	} {
		script := "set -euo pipefail\nshopt -s inherit_errexit\ndie() { echo \"die: $*\" >&2; exit 1; }\n" +
			"rel=''; relabel() { rel=\"$rel$1 $2\"; }\napi_all() { die \"unexpected api_all $*\"; }\n" +
			"FORGE=github PR_NUM=1 hist='[]' latest=CHANGES_REQUESTED done_rounds=5 last_round=5 limit=5 GITHUB_OUTPUT=/dev/null\n" +
			"labels='" + c.labels + "' resume_id='" + c.resumeID + "'\n" +
			cr[i:j] + "echo \"rounds=$done_rounds limit=$limit relabel=$rel\"\n"
		out, err := exec.Command("bash", "-c", script).CombinedOutput()
		if lines := strings.Split(strings.TrimSpace(string(out)), "\n"); err != nil || lines[len(lines)-1] != c.want {
			t.Errorf("%s: got %q (%v), want last line %q", c.name, out, err, c.want)
		}
	}
}
