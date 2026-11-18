package workflows

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// scanGh stands in for `gh api` in the scan issue step. It records each call
// as "METHOD PATH" in $STUB_DIR/calls and its request body (the --input on
// stdin, or the -f fields joined by &) in $STUB_DIR/body.<n>, answers a GET
// with $STUB_DIR/issues.json, applies --jq with the real jq as gh does, and
// fails a call whose "METHOD PATH" matches the glob in $GH_FAIL.
const scanGh = `#!/usr/bin/env bash
[ "$1" = api ] || { echo "stub gh: only 'gh api' is stubbed, got: $*" >&2; exit 2; }
shift
method= path= jqx= input= fields=()
while [ $# -gt 0 ]; do
  case "$1" in
    --paginate) shift ;;
    -X) method=$2; shift 2 ;;
    --input) input=$2; shift 2 ;;
    -f) fields+=("$2"); shift 2 ;;
    --jq) jqx=$2; shift 2 ;;
    -*) echo "stub gh: unknown flag $1" >&2; exit 2 ;;
    *) path=$1; shift ;;
  esac
done
if [ -z "$method" ]; then
  if [ -n "$input" ] || [ ${#fields[@]} -gt 0 ]; then method=POST; else method=GET; fi
fi
body=
[ "$input" = - ] && body=$(cat)
[ ${#fields[@]} -gt 0 ] && body=$(IFS='&'; printf '%s' "${fields[*]}")
n=0
[ -f "$STUB_DIR/calls" ] && n=$(wc -l < "$STUB_DIR/calls")
printf '%s %s\n' "$method" "$path" >> "$STUB_DIR/calls"
printf '%s' "$body" > "$STUB_DIR/body.$n"
if [ -n "${GH_FAIL:-}" ] && [[ "$method $path" == $GH_FAIL ]]; then
  echo "gh: HTTP 502: Bad Gateway ($path)" >&2
  exit 1
fi
case "$method $path" in
  GET*) resp=$(cat "$STUB_DIR/issues.json") ;;
  "POST "*/comments) resp='{"id": 1}' ;;
  POST*) resp='{"number": 42}' ;;
  *) resp='{}' ;;
esac
if [ -n "$jqx" ]; then jq -r "$jqx" <<<"$resp"; else printf '%s\n' "$resp"; fi
`

// scanStep returns the run script of a scans.yml step.
func scanStep(t *testing.T, name string) string {
	t.Helper()
	return runScript(t, stepBlock(t, scansWorkflow(t), name))
}

// scanIssueTitle is the workflow's SCAN_ISSUE_TITLE.
func scanIssueTitle(t *testing.T) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^\s+SCAN_ISSUE_TITLE: '([^']+)'$`).FindStringSubmatch(scansWorkflow(t))
	if m == nil {
		t.Fatal("scans.yml sets no SCAN_ISSUE_TITLE")
	}
	return m[1]
}

func needBashJq(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found, the scan issue scripts cannot run: %v", tool, err)
		}
	}
}

func runBash(t *testing.T, dir, script string, env ...string) (int, string) {
	t.Helper()
	path := filepath.Join(dir, "step.sh")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", path)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("bash did not run: %v", err)
		}
		return ee.ExitCode(), string(out)
	}
	return 0, string(out)
}

// collectFindings runs "Collect the findings" with the three scan outcomes
// and returns the fired output it writes.
func collectFindings(t *testing.T, deps, security, trivy string) string {
	t.Helper()
	dir := t.TempDir()
	outFile := filepath.Join(dir, "github_output")
	code, out := runBash(t, dir, scanStep(t, "Collect the findings"),
		"DEPS="+deps, "SECURITY="+security, "TRIVY="+trivy, "GITHUB_OUTPUT="+outFile)
	if code != 0 {
		t.Fatalf("Collect the findings exited %d:\n%s", code, out)
	}
	b, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^fired=(.*)$`).FindStringSubmatch(string(b))
	if m == nil {
		t.Fatalf("Collect the findings wrote no fired output: %q", b)
	}
	return m[1]
}

type ghCall struct{ req, body string }

// runScanIssue runs "Open, update or close the scan issue" with FIRED set to
// fired, the open issues (and pull requests) GitHub lists, and gh failing
// the calls matching ghFail. It returns the exit status, output and calls.
func runScanIssue(t *testing.T, fired string, open []map[string]any, ghFail string) (int, string, []ghCall) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(scanGh), 0o755); err != nil {
		t.Fatal(err)
	}
	if open == nil {
		open = []map[string]any{}
	}
	issues, err := json.Marshal(open)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "issues.json"), issues, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := runBash(t, dir, scanStep(t, "Open, update or close the scan issue"),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"STUB_DIR="+dir, "GH_FAIL="+ghFail, "FIRED="+fired,
		"REPO=o/r", "SCAN_ISSUE_TITLE="+scanIssueTitle(t),
		"RUN_URL=https://github.example/o/r/actions/runs/9")
	var calls []ghCall
	if b, err := os.ReadFile(filepath.Join(dir, "calls")); err == nil {
		for i, req := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			body, _ := os.ReadFile(filepath.Join(dir, "body."+strconv.Itoa(i)))
			calls = append(calls, ghCall{req: req, body: string(body)})
		}
	}
	return code, out, calls
}

func scanIssue(t *testing.T, number int, pr bool) map[string]any {
	t.Helper()
	i := map[string]any{"number": number, "title": scanIssueTitle(t)}
	if pr {
		i["pull_request"] = map[string]any{"url": "https://api.example/pulls/1"}
	}
	return i
}

func requests(calls []ghCall) []string {
	var r []string
	for _, c := range calls {
		r = append(r, c.req)
	}
	return r
}

const listOpen = "GET repos/o/r/issues?state=open&per_page=100"

func wantCalls(t *testing.T, what string, code int, out string, calls []ghCall, want ...string) {
	t.Helper()
	if code != 0 {
		t.Errorf("%s: the step exited %d:\n%s", what, code, out)
	}
	if got := requests(calls); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("%s: gh calls\n got %q\nwant %q\n%s", what, got, want, out)
	}
}

// TestScanFindingsCountFailedAndSkipped: a scan step that did not succeed,
// failed or skipped (the images did not build), is a finding.
func TestScanFindingsCountFailedAndSkipped(t *testing.T) {
	needBashJq(t)
	for _, c := range []struct{ deps, security, trivy, want string }{
		{"success", "success", "success", ""},
		{"failure", "success", "success", "deps-check"},
		{"success", "skipped", "success", "security"},
		{"skipped", "success", "failure", "deps-check trivy-image"},
		{"skipped", "skipped", "skipped", "deps-check security trivy-image"},
	} {
		if got := collectFindings(t, c.deps, c.security, c.trivy); got != c.want {
			t.Errorf("deps=%s security=%s trivy=%s: fired %q, want %q", c.deps, c.security, c.trivy, got, c.want)
		}
	}
}

// TestScanIssueLifecycle drives the scan issue step through each state.
func TestScanIssueLifecycle(t *testing.T) {
	needBashJq(t)
	other := map[string]any{"number": 3, "title": "something else"}

	t.Run("no finding closes the open issue with a comment", func(t *testing.T) {
		code, out, calls := runScanIssue(t, "", []map[string]any{other, scanIssue(t, 5, false)}, "")
		wantCalls(t, "close", code, out, calls, listOpen, "POST repos/o/r/issues/5/comments", "PATCH repos/o/r/issues/5")
		if len(calls) == 3 {
			if !strings.Contains(calls[1].body, "body=The scans found nothing. Run: https://github.example/o/r/actions/runs/9") {
				t.Errorf("close comment body %q", calls[1].body)
			}
			if !strings.Contains(calls[2].body, "state=closed") || !strings.Contains(calls[2].body, "state_reason=completed") {
				t.Errorf("close PATCH body %q", calls[2].body)
			}
		}
	})

	t.Run("no finding and no issue writes nothing", func(t *testing.T) {
		code, out, calls := runScanIssue(t, "", []map[string]any{other}, "")
		wantCalls(t, "clean", code, out, calls, listOpen)
	})

	t.Run("a finding with no issue opens one", func(t *testing.T) {
		code, out, calls := runScanIssue(t, "deps-check trivy-image", []map[string]any{other}, "")
		wantCalls(t, "create", code, out, calls, listOpen, "POST repos/o/r/issues")
		if len(calls) == 2 {
			var b struct{ Title, Body string }
			if err := json.Unmarshal([]byte(calls[1].body), &b); err != nil {
				t.Fatalf("create body is not JSON: %v: %q", err, calls[1].body)
			}
			if b.Title != scanIssueTitle(t) || !strings.Contains(b.Body, "Firing: deps-check trivy-image.") ||
				!strings.Contains(b.Body, "Run: https://github.example/o/r/actions/runs/9") {
				t.Errorf("create body %+v", b)
			}
		}
		if !strings.Contains(out, "opened #42") {
			t.Errorf("create: output does not name the new issue:\n%s", out)
		}
	})

	t.Run("a finding with an open issue replaces its body", func(t *testing.T) {
		code, out, calls := runScanIssue(t, "security", []map[string]any{scanIssue(t, 5, false), other}, "")
		wantCalls(t, "update", code, out, calls, listOpen, "PATCH repos/o/r/issues/5")
		if len(calls) == 2 {
			var b map[string]string
			if err := json.Unmarshal([]byte(calls[1].body), &b); err != nil {
				t.Fatalf("update body is not JSON: %v: %q", err, calls[1].body)
			}
			if len(b) != 1 || !strings.Contains(b["body"], "Firing: security.") {
				t.Errorf("update body %v", b)
			}
		}
	})

	t.Run("a pull request with the title is not the issue", func(t *testing.T) {
		pr := scanIssue(t, 8, true)
		code, out, calls := runScanIssue(t, "security", []map[string]any{pr}, "")
		wantCalls(t, "finding beside a PR", code, out, calls, listOpen, "POST repos/o/r/issues")
		code, out, calls = runScanIssue(t, "", []map[string]any{pr}, "")
		wantCalls(t, "clean beside a PR", code, out, calls, listOpen)
	})

	t.Run("a failed gh call fails the step", func(t *testing.T) {
		for _, c := range []struct {
			fired, fail string
			open        []map[string]any
		}{
			{"security", "GET *", nil},
			{"", "GET *", []map[string]any{scanIssue(t, 5, false)}},
			{"security", "POST repos/o/r/issues", nil},
			{"security", "PATCH *", []map[string]any{scanIssue(t, 5, false)}},
			{"", "POST */comments", []map[string]any{scanIssue(t, 5, false)}},
			{"", "PATCH *", []map[string]any{scanIssue(t, 5, false)}},
		} {
			if code, out, _ := runScanIssue(t, c.fired, c.open, c.fail); code == 0 {
				t.Errorf("fired=%q, gh failing %q: the step exited 0:\n%s", c.fired, c.fail, out)
			}
		}
	})
}
