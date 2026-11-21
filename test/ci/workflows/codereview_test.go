package workflows

import (
	"crypto/sha256"
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
func TestNoReviewPathsIsTheTemplateList(t *testing.T) {
	// v5.12.11 exactly: the list is docs and CI config, .github/ included;
	// a workflow change is held by the guard before the exemption applies.
	re := noReviewPaths(t)
	for _, p := range []string{"docs/a.md", "docs/x/y.txt", "README.md", ".github/actionlint.yaml",
		".github/workflows/ci.yml", ".gitea/x.yml", "changelog.d/1.md"} {
		if !re.MatchString(p) {
			t.Errorf("NO_REVIEW_PATHS no longer exempts %s", p)
		}
	}
	for _, p := range []string{"go.mod", "Makefile", "pkg/luks2/header.go", "cmd/x/main.go", "test/ci/workflows/a_test.go"} {
		if re.MatchString(p) {
			t.Errorf("NO_REVIEW_PATHS exempts the code path %s from review", p)
		}
	}
}

// codeReviewTemplateSHA256 is the sha256 of the handbook's code-review.yml
// template v5.12.11, the file this repository carries byte for byte: its
// runner labels and PROTECTED list are the template's own, so no site is
// re-applied (codeReviewCustomizeLines counts the template's markers).
const (
	codeReviewTemplateSHA256 = "0b10d5b4b90f4b110ed4b9c167e088cac81f2d1356968847102e8965cb17827c"
	codeReviewCustomizeLines = 1
)

// TestCodeReviewIsTheTemplate fails when code-review.yml drifts from the
// v5.12.11 template. CI cannot read the handbook, so the template is pinned
// by its hash, its header and its count of `# CUSTOMIZE:` lines.
func TestCodeReviewIsTheTemplate(t *testing.T) {
	cr := codeReview(t)
	if first, _, _ := strings.Cut(cr, "\n"); !strings.HasPrefix(first, "# code-review-template: v5.12.11 ") {
		t.Errorf("%s: header %q is not template v5.12.11", codeReviewWorkflow, first)
	}
	if n := len(regexp.MustCompile(`(?m)# CUSTOMIZE:`).FindAllStringIndex(cr, -1)); n != codeReviewCustomizeLines {
		t.Errorf("%s: %d `# CUSTOMIZE:` lines, want %d (one per re-applied site)", codeReviewWorkflow, n, codeReviewCustomizeLines)
	}
	if sum := fmt.Sprintf("%x", sha256.Sum256([]byte(cr))); sum != codeReviewTemplateSHA256 {
		t.Errorf("%s: sha256 %s, want the v5.12.11 template's %s: only the runner labels and the PROTECTED list may differ, and they do not", codeReviewWorkflow, sum, codeReviewTemplateSHA256)
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
