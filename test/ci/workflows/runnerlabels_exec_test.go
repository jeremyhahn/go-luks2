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

// runnerLabelsScript is the Python of ci.yml's "Runner labels (ruling 633)"
// step: the heredoc body between `python3 -I - <<'PY'` and `PY`, dedented.
func runnerLabelsScript(t *testing.T) string {
	t.Helper()
	lines := strings.Split(readFile(t, ".github/workflows/ci.yml"), "\n")
	step := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == "- name: Runner labels (ruling 633)" {
			step = i
			break
		}
	}
	if step < 0 {
		t.Fatal("ci.yml has no `Runner labels (ruling 633)` step")
	}
	start, indent := -1, 0
	for i := step + 1; i < len(lines) && i < step+4; i++ {
		if strings.TrimSpace(lines[i]) == "python3 -I - <<'PY'" {
			start, indent = i+1, len(lines[i])-len(strings.TrimLeft(lines[i], " "))
			break
		}
	}
	if start < 0 {
		t.Fatal("the Runner labels step does not run `python3 -I - <<'PY'`")
	}
	var body []string
	for _, l := range lines[start:] {
		if strings.TrimSpace(l) == "PY" {
			return strings.Join(body, "\n") + "\n"
		}
		if strings.TrimSpace(l) == "" {
			body = append(body, "")
			continue
		}
		if len(l)-len(strings.TrimLeft(l, " ")) < indent {
			t.Fatalf("Runner labels line %q is indented less than the heredoc", l)
		}
		body = append(body, l[indent:])
	}
	t.Fatal("the Runner labels heredoc has no closing PY line")
	return ""
}

// runRunnerLabels runs the step's Python in a directory whose only workflow
// is .github/workflows/<name> with the given text, and returns its exit code
// and output.
func runRunnerLabels(t *testing.T, script, name, workflow string) (int, string) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("python3 is required to run the Runner labels step: %v", err)
	}
	dir := t.TempDir()
	wf := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wf, name), []byte(workflow), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "-I", "-") // #nosec G204 -- python3 from PATH on ci.yml's own step script
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	cmd.Stdin = strings.NewReader(script)
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
		t.Fatalf("running the Runner labels step: %v", err)
		return -1, ""
	}
}

// GitHub's `||` yields its left operand whenever that is truthy, so a
// runs-on of `<unknown> || 'ubuntu-latest'` can be any runner the unknown
// names: the step must read it as an unknown label, not as its fallback. A
// known left operand, and the template's server_url routing, still pass; a
// label an expression computes counts as named when it is `release`.
func TestRunnerLabelsStepReadsEveryPossibleRunsOnValue(t *testing.T) {
	script := runnerLabelsScript(t)
	for _, tc := range []struct {
		name, runsOn string
		pass         bool
		want         string
	}{
		{"literal", "ubuntu-latest", true, ""},
		{"known literal expression", "${{ 'ubuntu-latest' }}", true, ""},
		{"known false left operand", "${{ false || 'ubuntu-latest' }}", true, ""},
		{"known truthy left operand", "${{ 'ubuntu-24.04' || vars.RUNNER }}", true, ""},
		{"server_url routing", templateRoutingExpression, true, ""},
		{"vars fallback", "${{ vars.RUNNER || 'ubuntu-latest' }}", false, "an unknown label"},
		{"needs output fallback", "${{ needs.pick.outputs.runner || 'ubuntu-latest' }}", false, "an unknown label"},
		{"inputs fallback", "${{ inputs.runner || 'ubuntu-latest' }}", false, "an unknown label"},
		{"chained unknown fallbacks", "${{ vars.A || vars.B || 'ubuntu-latest' }}", false, "an unknown label"},
		{"unknown guard, both arms standard", "${{ vars.BIG && 'ubuntu-24.04' || 'ubuntu-latest' }}", true, ""},
		{"unknown guard, one arm self-hosted", "${{ vars.BIG && 'bigdisk' || 'ubuntu-latest' }}", false, "bigdisk"},
		{"computed release label", "${{ format('{0}ease', 'rel') }}", false, "names `release`"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wf := "on: push\njobs:\n  j:\n    runs-on: " + tc.runsOn + "\n    steps:\n      - run: true\n"
			code, out := runRunnerLabels(t, script, "w.yml", wf)
			if tc.pass && code != 0 {
				t.Fatalf("runs-on %s: the step failed (exit %d):\n%s", tc.runsOn, code, out)
			}
			if !tc.pass {
				if code == 0 {
					t.Fatalf("runs-on %s: the step passed:\n%s", tc.runsOn, out)
				}
				if !strings.Contains(out, tc.want) {
					t.Fatalf("runs-on %s: the finding does not say %q:\n%s", tc.runsOn, tc.want, out)
				}
			}
		})
	}
}
