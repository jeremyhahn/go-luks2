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
