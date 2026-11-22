package workflows

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
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
	runnerLabelsScript   = ".github/scripts/runner_labels.py"
)

// preflightRunsOn is ci-template v1.52's preflight runs-on: the bigdisk pool
// on github.com, the repository variable CI_PREFLIGHT_RUNS_ON (runs-on JSON)
// its override, and ubuntu-latest off github.com.
const preflightRunsOn = `${{ github.server_url == 'https://github.com' && (!startsWith(github.event_name, 'pull_request') || github.event.pull_request.head.repo.full_name == github.repository) && fromJSON(vars.CI_PREFLIGHT_RUNS_ON || '["self-hosted","linux","x64","bigdisk"]') || 'ubuntu-latest' }}`

// releaseRunsOn is the runs-on line of the release-runner `if:` fixtures.
const releaseRunsOn = "release  # self-hosted: hardware: the host"

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
		// Any case of .yml or .yaml, dotfiles too; another name only for a
		// reject-workflow- case (the check refuses any other file there).
		ext := strings.ToLower(filepath.Ext(c.file))
		if c.file != filepath.Base(c.file) || (ext != ".yml" && ext != ".yaml" && !strings.HasPrefix(c.fixture, "reject-workflow-")) {
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
		// A release job's `if:` passes only in the allow-listed form: its
		// top-level && terms name a push and a tag ref; nothing is sampled.
		{"reject-release-pr-head-format.yml", "", "lint", releaseRunsOn},
		{"reject-release-push-ref-format.yml", "", "lint", releaseRunsOn},
		{"reject-release-push-ref-name-format.yml", "", "lint", releaseRunsOn},
		{"reject-release-top-level-or.yml", "", "lint", releaseRunsOn},
		{"reject-release-top-level-not.yml", "", "lint", releaseRunsOn},
		{"accept-release-tag-narrowed.yml", "", "lint", releaseRunsOn},
		{"reject-release-pr-head-ref.yml", "", "lint", releaseRunsOn},
		{"reject-release-pr-head-prefix.yml", "", "lint", releaseRunsOn},
		{"reject-release-prt-base-ref.yml", "", "lint", releaseRunsOn},
		{"reject-release-push-branch.yml", "", "lint", releaseRunsOn},
		{"reject-release-push-ref-name.yml", "", "lint", releaseRunsOn},
		{"reject-release-dispatch-branch.yml", "", "lint", releaseRunsOn},
		{"reject-release-other-tag.yml", "", "lint", releaseRunsOn},
		// GitHub compares strings case-insensitively and git refs are not:
		// == 'refs/heads/main' also holds on a branch MAIN. A default branch
		// (schedule) can have any name.
		{"reject-release-push-main-case.yml", "", "lint", releaseRunsOn},
		{"reject-release-dispatch-main-case.yml", "", "lint", releaseRunsOn},
		{"reject-release-pr-head-ref-case.yml", "", "lint", releaseRunsOn},
		{"reject-release-schedule-other-default.yml", "", "lint", releaseRunsOn},
		{"accept-release-push-tag.yml", "", "lint", releaseRunsOn},
		// Resume 15: a runs-on expression the repository does not use (RO_ALLOW)
		// counts as reaching `release`; nothing is sampled from its literals.
		{"reject-hosted-ref-self-hosted.yml", "", "lint", "${{ github.ref == 'refs/heads/topic' && 'self-hosted' || 'ubuntu-latest' }}"},
		{"reject-hosted-head-ref-case.yml", "", "lint", "${{ github.head_ref == 'Topic' && 'self-hosted' || 'ubuntu-latest' }}"},
		{"reject-release-pr-head-ref-index.yml", "", "lint", "${{ startsWith(github['head_ref'], 'rel') && github['head_ref'] || 'ubuntu-latest' }}"},
		{"reject-release-pr-head-ref-equals-format.yml", "", "lint", "${{ github.head_ref == format('{0}{1}', 'rele', 'ase') && github.head_ref || 'ubuntu-latest' }}"},
		{"reject-release-pr-head-ref-index-format.yml", "", "lint", "${{ github['head_ref'] == format('{0}{1}', 'rele', 'ase') && format('{0}{1}', 'rele', 'ase') || 'ubuntu-latest' }}"},
		{"reject-release-pr-head-ref-spaced.yml", "", "lint", "${{ startsWith(github . head_ref, 'rel') && github . head_ref || 'ubuntu-latest' }}"},
		{"reject-release-hidden-file.yml", ".hidden.yml", "lint", releaseRunsOn},
		{"reject-release-upper-extension.yml", "x.YML", "lint", releaseRunsOn},
		{"reject-workflow-other-file.yml", "notes.txt", "lint", releaseRunsOn},
		{"reject-release-hosted-ref-routing.yml", "", "lint", "${{ (github.ref == 'refs/heads/topic' || github.head_ref == 'topic') && 'ubuntu-22.04' || 'ubuntu-latest' }}"},
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
		{"reject-preflight-off-github-label.yml", "ci.yml", "preflight", strings.Replace(preflightRunsOn, "|| 'ubuntu-latest' }}", "|| 'bigdisk' }}", 1)},
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
	// Resume 23 (Codex P1 on PR #495): the checker is a repository file,
	// run as is, with no heredoc copy left in the step.
	step := stepBody(t, runnerLabelsStep)
	if n := strings.Count(step, "\n          python3 -I "+runnerLabelsScript+"\n"); n != 1 {
		t.Errorf("%q runs `python3 -I %s` %d times, want 1", runnerLabelsStep, runnerLabelsScript, n)
	}
	if strings.Contains(step, "<<'PY'") {
		t.Errorf("%q still holds a heredoc; the checker is %s", runnerLabelsStep, runnerLabelsScript)
	}
	if src := readFile(t, runnerLabelsScript); !strings.Contains(src, "\nimport json, os, re, sys\n") || !strings.Contains(src, `WF = ".github/workflows"`) {
		t.Errorf("%s is not the runner-labels checker", runnerLabelsScript)
	}
	body := stepBody(t, runnerLabelsSelfTest)
	for _, want := range []string{
		"dir=" + runnerLabelsDir + "\n",
		`done < "$dir/manifest.txt"`,
		`py="$PWD/` + runnerLabelsScript + `"`,
		`python3 -I "$py"`,
		`cp "$dir/${f[2]}" "$t/.github/workflows/${f[1]}"`,
		"accept) want=0 ;; reject) want=1 ;;",
		`[ "$rc" -eq "$want" ]`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("%q lacks %q", runnerLabelsSelfTest, want)
		}
	}
	if strings.Contains(body, "glob.glob(") || strings.Contains(body, "<<'") {
		t.Errorf("%q holds a script of its own; it must run %s", runnerLabelsSelfTest, runnerLabelsScript)
	}
}

// TestPreflightRunsOnTemplateForm: ci-template v1.52's preflight runs-on,
// exactly once and on preflight only, and the schedule guard's AGENT_TOKEN
// passed off github.com only.
func TestPreflightRunsOnTemplateForm(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	line := "    runs-on: " + preflightRunsOn + "   # v1.52\n"
	if n := strings.Count(ci, line); n != 1 {
		t.Errorf("ci.yml holds v1.52's preflight runs-on %d times, want 1", n)
	}
	if !strings.Contains(job(t, ci, "preflight"), line) {
		t.Error("ci.yml's preflight job does not run on v1.52's preflight runs-on")
	}
	bot := "          BOT: ${{ github.server_url != 'https://github.com' && (github.event_name == 'schedule' || (github.event_name == 'push' && github.ref == 'refs/heads/main')) && secrets.AGENT_TOKEN || '' }}\n"
	if !strings.Contains(job(t, ci, "preflight"), bot) {
		t.Error("the schedule guard's BOT is not v1.49's off-github.com-only form")
	}
}

// balancedPoolStep is ci-template v1.54's runner selection step in preflight;
// its outputs `runner` and `runner_docker` are every other job's runs-on.
const balancedPoolStep = "Balanced runner pool (ruling 1137)"

// balancedPoolSHA256 is the SHA-256 of the v1.54 template's step body (the
// text after its `- name:` line up to the next step), byte for byte. A change
// to the step is a template bump, made with this pin.
const balancedPoolSHA256 = "82eeb1dfddc72f27b053e94529ff41f33b7701acbbb213ee5b2355bd5d79e49c"

// runnerSelectTests is the template's testdata/runner-select-tests.py,
// carried verbatim but for its #! line, runnerSelectShebang
// (runnerSelectTestsSHA256 pins the whole file). It reads the step out of the
// ci.yml in its parent directory and runs it against a fake Actions API.
const (
	runnerSelectTests       = "test/ci/workflows/testdata/runner-select-tests.py"
	runnerSelectShebang     = "#!/usr/bin/env python3\n"
	runnerSelectTestsSHA256 = "b53de0fa0282b1825d60f259680b293a259ef62398c31312daf2c15e311b346f"
)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestBalancedRunnerPoolStepIsTheTemplates: preflight holds v1.54's
// `Balanced runner pool` step once, its body the template's byte for byte,
// and outputs what it picks as `runner` and `runner_docker`; v1.48's
// overflow step and its env limits are gone.
func TestBalancedRunnerPoolStepIsTheTemplates(t *testing.T) {
	ci := readFile(t, ".github/workflows/ci.yml")
	if n := strings.Count(ci, "      - name: "+balancedPoolStep+"\n"); n != 1 {
		t.Fatalf("ci.yml holds the %q step %d times, want 1", balancedPoolStep, n)
	}
	body := stepBody(t, balancedPoolStep)
	if got := sha256Hex(body); got != balancedPoolSHA256 {
		t.Errorf("the %q step body drifted from ci-template v1.54: sha256 %s, want %s", balancedPoolStep, got, balancedPoolSHA256)
	}
	if !strings.HasPrefix(body, "        id: runner\n") {
		t.Errorf("the %q step's id is not `runner`", balancedPoolStep)
	}
	pre := job(t, ci, "preflight")
	for _, out := range []string{
		"      runner: ${{ steps.runner.outputs.runner }}\n",
		"      runner_docker: ${{ steps.runner.outputs.runner_docker }}\n",
	} {
		if !strings.Contains(pre, out) {
			t.Errorf("preflight does not output %q", strings.TrimSpace(out))
		}
	}
	for _, gone := range []string{"HOSTED_JOBS_PER_REPO:", "HOSTED_QUEUE_GRACE_SECONDS:", "      - name: Hosted or overflow runner"} {
		if strings.Contains(ci, gone) {
			t.Errorf("ci.yml still holds %q, which ci-template v1.54 removes", gone)
		}
	}
}

// TestRunnerSelectTestsPassOnTheStep: the carried template test data is the
// template's, and every case passes against the step as ci.yml holds it. It
// needs python3 and bash; without them it skips, and
// TestBalancedRunnerPoolStepIsTheTemplates still pins the step.
func TestRunnerSelectTestsPassOnTheStep(t *testing.T) {
	// The repository ships no file that opens with #!, so the template's
	// first line is carried here and the rest in testdata; together they
	// are the template file byte for byte.
	data := runnerSelectShebang + readFile(t, runnerSelectTests)
	if got := sha256Hex(data); got != runnerSelectTestsSHA256 {
		t.Fatalf("%s is not ci-template v1.54's runner-select-tests.py: sha256 %s, want %s", runnerSelectTests, got, runnerSelectTestsSHA256)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed; the step body is pinned by TestBalancedRunnerPoolStepIsTheTemplates")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed; the step body is pinned by TestBalancedRunnerPoolStepIsTheTemplates")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "testdata"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ci.yml"), []byte(readFile(t, ".github/workflows/ci.yml")), 0o644); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "testdata", "runner-select-tests.py")
	if err := os.WriteFile(script, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(python, "-I", script).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ALL PASS") {
		t.Fatalf("runner-select-tests.py against ci.yml: %v\n%s", err, out)
	}
}
