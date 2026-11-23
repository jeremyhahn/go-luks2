package workflows

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// specRoadmapCheck is ci-template v1.56's SPEC/ROADMAP agreement check, which
// the lint job runs. The repository ships no file that opens with #!, so it
// carries the template's script without its first line; the step runs it as
// `python3 -I scripts/spec-roadmap-check.py`.
const specRoadmapCheck = "scripts/spec-roadmap-check.py"

// TestLintRunsTheSpecRoadmapCheck: the lint job runs v1.56's check, as the
// template has it.
func TestLintRunsTheSpecRoadmapCheck(t *testing.T) {
	lint := job(t, readFile(t, ".github/workflows/ci.yml"), "lint")
	step := "      - name: SPEC and ROADMAP agree (roadmap.md §2a)\n        run: python3 -I " + specRoadmapCheck + "\n"
	if !strings.Contains(lint, step) {
		t.Errorf("the lint job does not run %s as the step %q", specRoadmapCheck, step)
	}
	if strings.HasPrefix(readFile(t, specRoadmapCheck), "#!") {
		t.Errorf("%s opens with #!; the public release ships no file that does", specRoadmapCheck)
	}
}

// TestTemplatePythonCasesPass runs ci-template v1.55's row-job-tests.py and
// v1.56's spec-roadmap-check-tests.py against ci.yml and the check script, in
// the template's layout (ci.yml and the script beside testdata/).
func TestTemplatePythonCasesPass(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed; row-job-tests.py builds repositories")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "testdata"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"ci.yml":                               ".github/workflows/ci.yml",
		"spec-roadmap-check.py":                specRoadmapCheck,
		"testdata/row-job-tests.py":            "test/ci/workflows/testdata/row-job-tests.py",
		"testdata/spec-roadmap-check-tests.py": "test/ci/workflows/testdata/spec-roadmap-check-tests.py",
	}
	for dst, src := range files {
		if err := os.WriteFile(filepath.Join(dir, dst), []byte(readFile(t, src)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"row-job-tests.py", "spec-roadmap-check-tests.py"} {
		out, err := exec.Command(python, "-I", filepath.Join(dir, "testdata", name)).CombinedOutput() // #nosec G204 -- python3 from PATH on a file this test wrote
		if err != nil || !strings.Contains(string(out), "ALL PASS") {
			t.Errorf("%s against ci.yml: %v\n%s", name, err, out)
		}
	}
}
