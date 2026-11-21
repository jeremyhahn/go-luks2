package workflows

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runnerLabelsStep is the preflight step whose Python checks every job's
// runs-on (rulings 633, 833, 999, 1007; ci-template v1.49).
const runnerLabelsStep = "Runner labels (ruling 633)"

// runnerLabelsScript returns the Python program of ci.yml's runner-label step:
// the heredoc between `python3 -I - <<'PY'` and `PY`, dedented.
func runnerLabelsScript(t *testing.T) string {
	t.Helper()
	lines := strings.Split(job(t, readFile(t, ".github/workflows/ci.yml"), "preflight"), "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == "- name: "+runnerLabelsStep {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("preflight has no %q step", runnerLabelsStep)
	}
	open, indent := -1, 0
	for i := start; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "python3 -I - <<'PY'" {
			open, indent = i, len(lines[i])-len(strings.TrimLeft(lines[i], " "))
			break
		}
	}
	if open < 0 {
		t.Fatalf("%q runs no `python3 -I - <<'PY'` heredoc", runnerLabelsStep)
	}
	var body []string
	for _, l := range lines[open+1:] {
		if strings.TrimSpace(l) == "PY" {
			return strings.Join(body, "\n") + "\n"
		}
		if strings.TrimSpace(l) == "" {
			body = append(body, "")
			continue
		}
		if len(l)-len(strings.TrimLeft(l, " ")) < indent {
			t.Fatalf("%q's heredoc line %q is indented less than its opening line", runnerLabelsStep, l)
		}
		body = append(body, l[indent:])
	}
	t.Fatalf("%q's heredoc has no closing PY line", runnerLabelsStep)
	return ""
}

// runRunnerLabels runs the step's program in dir, where it reads
// .github/workflows, and returns its exit code and output.
func runRunnerLabels(t *testing.T, script, dir string) (int, string) {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("python3 is required to run ci.yml's %q step: %v", runnerLabelsStep, err)
	}
	path := filepath.Join(t.TempDir(), "runner-labels.py")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(py, "-I", path) // #nosec G204 -- python3 from PATH on a script this test wrote
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, out.String()
	case errors.As(err, &exit):
		return exit.ExitCode(), out.String()
	default:
		t.Fatalf("running the %q step: %v", runnerLabelsStep, err)
		return -1, ""
	}
}

// labelsWorkflow is a fixture workflow on push and pull_request with one job
// on runs-on ro.
func labelsWorkflow(jobID, ro string) string {
	return "name: t\non: [push, pull_request]\njobs:\n  " + jobID + ":\n    runs-on: " + ro + "\n    steps:\n      - run: true\n"
}

// preflightRunsOn is ci-template v1.49's preflight runs-on (ruling 1047 (3)):
// the bigdisk pool on github.com, the repository variable
// CI_PREFLIGHT_RUNS_ON its fallback switch, ubuntu-latest off github.com.
const preflightRunsOn = `${{ github.server_url == 'https://github.com' && fromJSON(vars.CI_PREFLIGHT_RUNS_ON || '["self-hosted","linux","x64","bigdisk"]') || 'ubuntu-latest' }}`

// TestRunnerLabelsStep runs ci.yml's runner-label step on fixture workflows.
// A runs-on expression's unknown operand of `||` stays a possible value:
// GitHub returns the left operand whenever it is truthy, so an unknown left
// operand may select any runner, and the job fails as an unknown label. A job
// whose runs-on can evaluate to `release` is a release job, whether or not its
// text names the label.
func TestRunnerLabelsStep(t *testing.T) {
	script := runnerLabelsScript(t)
	for _, c := range []struct {
		name  string
		files map[string]string
		rc    int
		want  []string
		not   []string
	}{
		{"known literal", map[string]string{"x.yml": labelsWorkflow("lint", "ubuntu-latest")}, 0, []string{"OK:"}, nil},
		{"known literal in an expression", map[string]string{"x.yml": labelsWorkflow("lint", "${{ 'ubuntu-latest' }}")}, 0, []string{"OK:"}, nil},
		{"server_url routing", map[string]string{"x.yml": labelsWorkflow("lint", templateRoutingExpression)}, 0, []string{"OK:"}, nil},
		{"known operands of ||", map[string]string{"x.yml": labelsWorkflow("lint", "${{ github.event_name == 'nothing' && 'bigdisk' || 'ubuntu-latest' }}")}, 0, []string{"OK:"}, nil},
		{"vars fallback", map[string]string{"x.yml": labelsWorkflow("lint", "${{ vars.RUNNER || 'ubuntu-latest' }}")}, 1,
			[]string{"x.yml:lint: (c)", "an unknown label"}, nil},
		{"needs output fallback", map[string]string{"x.yml": labelsWorkflow("lint", "${{ needs.setup.outputs.runner || 'ubuntu-latest' }}")}, 1,
			[]string{"x.yml:lint: (c)", "an unknown label"}, nil},
		{"inputs fallback", map[string]string{"x.yml": labelsWorkflow("lint", "${{ inputs.runner || 'ubuntu-latest' }}")}, 1,
			[]string{"x.yml:lint: (c)", "an unknown label"}, nil},
		{"vars fallback behind a known arm", map[string]string{"x.yml": labelsWorkflow("lint", "${{ github.server_url == 'https://github.com' && (vars.RUNNER || 'ubuntu-latest') || 'bigdisk' }}")}, 1,
			[]string{"x.yml:lint: (c)", "an unknown label"}, nil},
		{"release by value, waived", map[string]string{"x.yml": labelsWorkflow("lint", "${{ format('{0}{1}', 'rel', 'ease') }}  # self-hosted: hardware: the host")}, 1,
			[]string{"x.yml:lint: (b) names `release`"}, nil},
		{"release by name, waived", map[string]string{"x.yml": labelsWorkflow("lint", "release  # self-hosted: hardware: the host")}, 1,
			[]string{"x.yml:lint: (b) names `release`"}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			wf := filepath.Join(dir, ".github", "workflows")
			if err := os.MkdirAll(wf, 0o750); err != nil {
				t.Fatal(err)
			}
			for name, body := range c.files {
				if err := os.WriteFile(filepath.Join(wf, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			rc, out := runRunnerLabels(t, script, dir)
			if rc != c.rc {
				t.Errorf("exit %d, want %d:\n%s", rc, c.rc, out)
			}
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
			for _, n := range c.not {
				if strings.Contains(out, n) {
					t.Errorf("output has %q:\n%s", n, out)
				}
			}
		})
	}
}

// TestRunnerLabelsStepPassesThisRepository: the step passes on this
// repository's own workflows, preflight's v1.49 runs-on included.
func TestRunnerLabelsStepPassesThisRepository(t *testing.T) {
	rc, out := runRunnerLabels(t, runnerLabelsScript(t), repoRoot(t))
	if rc != 0 || !strings.Contains(out, "OK:") {
		t.Errorf("exit %d on this repository's workflows:\n%s", rc, out)
	}
}
