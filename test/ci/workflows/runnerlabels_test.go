package workflows

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// runnerLabelsStep is the preflight step that checks every workflow's
// runs-on; runnerLabelsSelfTest runs its Python on the fixtures first.
const (
	runnerLabelsStep     = "Runner labels (ruling 633)"
	runnerLabelsSelfTest = "Runner labels self-test"
	runnerLabelsDir      = "test/ci/workflows/testdata/runnerlabels"
)

// preflightRunsOn is ci-template v1.49's preflight runs-on: the bigdisk pool
// on github.com, the repository variable CI_PREFLIGHT_RUNS_ON (runs-on JSON)
// its override, and ubuntu-latest off github.com.
const preflightRunsOn = `${{ github.server_url == 'https://github.com' && fromJSON(vars.CI_PREFLIGHT_RUNS_ON || '["self-hosted","linux","x64","bigdisk"]') || 'ubuntu-latest' }}`

// labelsCase is one manifest.txt line: the expected result, the workflow
// file name the fixture is copied to, the fixture and the output texts.
type labelsCase struct {
	result, file, fixture string
	texts                 []string
}

func labelsManifest(t *testing.T) []labelsCase {
	t.Helper()
	var cases []labelsCase
	for i, l := range strings.Split(readFile(t, runnerLabelsDir+"/manifest.txt"), "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Split(l, "|")
		if len(f) < 4 {
			t.Fatalf("manifest.txt line %d has %d fields, want result|file|fixture|text...: %q", i+1, len(f), l)
		}
		cases = append(cases, labelsCase{f[0], f[1], f[2], f[3:]})
	}
	return cases
}

// stepBody returns the text of a preflight step, from its `- name:` line to
// the next step.
func stepBody(t *testing.T, name string) string {
	t.Helper()
	pre := job(t, readFile(t, ".github/workflows/ci.yml"), "preflight")
	_, rest, ok := strings.Cut(pre, "      - name: "+name+"\n")
	if !ok {
		t.Fatalf("preflight has no %q step", name)
	}
	if i := strings.Index(rest, "\n      - "); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// TestRunnerLabelsManifest: every case names a fixture that exists, whose
// name states its result; every fixture is listed; every runner-label form
// the step must reject or accept has its case.
func TestRunnerLabelsManifest(t *testing.T) {
	cases := labelsManifest(t)
	byFixture := map[string]labelsCase{}
	for _, c := range cases {
		if c.result != "accept" && c.result != "reject" {
			t.Errorf("%s: result %q, want accept or reject", c.fixture, c.result)
		}
		if !strings.HasPrefix(c.fixture, c.result+"-") {
			t.Errorf("%s: its name does not start with its result %q", c.fixture, c.result+"-")
		}
		if c.file != filepath.Base(c.file) || (!strings.HasSuffix(c.file, ".yml") && !strings.HasSuffix(c.file, ".yaml")) {
			t.Errorf("%s: workflow file %q is not a bare .yml or .yaml name", c.fixture, c.file)
		}
		if _, dup := byFixture[c.fixture]; dup {
			t.Errorf("%s is listed twice", c.fixture)
		}
		byFixture[c.fixture] = c
		want := "OK:"
		if c.result == "reject" {
			want = c.file + ":"
		}
		if !strings.HasPrefix(c.texts[0], want) {
			t.Errorf("%s: first text %q, want one starting %q", c.fixture, c.texts[0], want)
		}
	}
	entries, err := os.ReadDir(filepath.Join(repoRoot(t), runnerLabelsDir))
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range entries {
		if e.Name() != "manifest.txt" {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	for _, f := range files {
		if _, ok := byFixture[f]; !ok {
			t.Errorf("%s/%s is in no manifest case", runnerLabelsDir, f)
		}
	}
	for f := range byFixture {
		if _, err := os.Stat(filepath.Join(repoRoot(t), runnerLabelsDir, f)); err != nil {
			t.Errorf("manifest case %s: %v", f, err)
		}
	}

	// fixture -> (workflow file, runs-on the fixture's one job carries).
	for _, w := range []struct{ fixture, file, job, runsOn string }{
		{"reject-vars-fallback.yml", "", "lint", "${{ vars.RUNNER || 'ubuntu-latest' }}"},
		{"reject-needs-fallback.yml", "", "lint", "${{ needs.setup.outputs.runner || 'ubuntu-latest' }}"},
		{"reject-inputs-fallback.yml", "", "lint", "${{ inputs.runner || 'ubuntu-latest' }}"},
		{"reject-release-by-value.yml", "", "lint", "${{ format('{0}{1}', 'rel', 'ease') }}  # self-hosted: hardware: the host"},
		{"reject-release-by-name.yml", "", "lint", "release  # self-hosted: hardware: the host"},
		{"accept-literal.yml", "", "lint", "ubuntu-latest"},
		{"accept-server-url-routing.yml", "", "lint", templateRoutingExpression},
		// ci-template v1.49 part F.
		{"accept-preflight.yml", "ci.yml", "preflight", preflightRunsOn},
		{"reject-preflight-form-other-job.yml", "ci.yml", "lint", preflightRunsOn},
		{"reject-preflight-outside-ci.yml", "batch.yml", "preflight", preflightRunsOn},
		{"reject-preflight-other-default.yml", "ci.yml", "preflight", strings.Replace(preflightRunsOn, `"bigdisk"]`, `"bigdisk-docker"]`, 1)},
		{"reject-preflight-self-hosted-on-push.yml", "ci.yml", "preflight",
			`${{ github.event_name == 'push' && fromJSON('["self-hosted","linux","x64","bigdisk"]') || fromJSON(vars.CI_PREFLIGHT_RUNS_ON || '"ubuntu-latest"') }}`},
		{"reject-preflight-without-fromjson.yml", "ci.yml", "preflight", "${{ vars.CI_PREFLIGHT_RUNS_ON || 'ubuntu-latest' }}"},
		{"reject-preflight-other-variable.yml", "ci.yml", "preflight", strings.Replace(preflightRunsOn, "CI_PREFLIGHT_RUNS_ON", "CI_PREFLIGHT_RUNS_ON_X", 1)},
		{"accept-preflight-off-github-label.yml", "ci.yml", "preflight", strings.Replace(preflightRunsOn, "|| 'ubuntu-latest' }}", "|| 'bigdisk' }}", 1)},
	} {
		c, ok := byFixture[w.fixture]
		if !ok {
			t.Errorf("the manifest has no %s case", w.fixture)
			continue
		}
		if w.file != "" && c.file != w.file {
			t.Errorf("%s runs as %s, want %s", w.fixture, c.file, w.file)
		}
		body := readFile(t, runnerLabelsDir+"/"+w.fixture)
		if want := "jobs:\n  " + w.job + ":\n    runs-on: " + w.runsOn + "\n"; !strings.Contains(body, want) {
			t.Errorf("%s does not hold job %s with runs-on %s", w.fixture, w.job, w.runsOn)
		}
	}
}

// TestRunnerLabelsSelfTestStep: preflight runs the runner-labels Python on
// the manifest's fixtures before the check itself, cut from that step's
// heredoc, so the Python has one copy.
func TestRunnerLabelsSelfTestStep(t *testing.T) {
	pre := job(t, readFile(t, ".github/workflows/ci.yml"), "preflight")
	self := strings.Index(pre, "      - name: "+runnerLabelsSelfTest+"\n")
	check := strings.Index(pre, "      - name: "+runnerLabelsStep+"\n")
	if self < 0 || check < 0 || self > check {
		t.Fatalf("preflight's %q step (at %d) does not come before %q (at %d)", runnerLabelsSelfTest, self, runnerLabelsStep, check)
	}
	if n := strings.Count(stepBody(t, runnerLabelsStep), "\n          python3 -I - <<'PY'\n"); n != 1 {
		t.Errorf("%q runs %d `python3 -I - <<'PY'` heredocs, want 1", runnerLabelsStep, n)
	}
	body := stepBody(t, runnerLabelsSelfTest)
	for _, want := range []string{
		"dir=" + runnerLabelsDir + "\n",
		`done < "$dir/manifest.txt"`,
		`lines.index("      - name: ` + runnerLabelsStep + `")`,
		`lines[i].strip() == "python3 -I - <<'PY'"`,
		`python3 -I "$py"`,
		`cp "$dir/${f[2]}" "$t/.github/workflows/${f[1]}"`,
		"accept) want=0 ;; reject) want=1 ;;",
		`[ "$rc" -eq "$want" ]`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("%q lacks %q", runnerLabelsSelfTest, want)
		}
	}
	if strings.Contains(body, "glob.glob(") {
		t.Errorf("%q holds a copy of the runner-labels Python; it must cut it from %q", runnerLabelsSelfTest, runnerLabelsStep)
	}
}

// TestPreflightRunsOnTemplateForm: ci-template v1.49's preflight runs-on,
// exactly once and on preflight only, and the schedule guard's AGENT_TOKEN
// passed off github.com only.
func TestPreflightRunsOnTemplateForm(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	line := "    runs-on: " + preflightRunsOn + "   # v1.49\n"
	if n := strings.Count(ci, line); n != 1 {
		t.Errorf("ci.yml holds v1.49's preflight runs-on %d times, want 1", n)
	}
	if !strings.Contains(job(t, ci, "preflight"), line) {
		t.Error("ci.yml's preflight job does not run on v1.49's preflight runs-on")
	}
	bot := "          BOT: ${{ github.server_url != 'https://github.com' && (github.event_name == 'schedule' || (github.event_name == 'push' && github.ref == 'refs/heads/main')) && secrets.AGENT_TOKEN || '' }}\n"
	if !strings.Contains(job(t, ci, "preflight"), bot) {
		t.Error("the schedule guard's BOT is not v1.49's off-github.com-only form")
	}
}
