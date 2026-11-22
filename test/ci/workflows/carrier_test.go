package workflows

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The ci-template v1.53 tests of the LAN mask and of the job-output handoff
// are carried verbatim under testdata/carrier. They expect a carrier layout:
// .github/workflows/ci.yml and scripts/ci-mask-lan.sh next to testdata/.
// go-luks2 ships no shell scripts, so the mask is the Makefile target
// ci-mask-lan; the carrier is built in a temporary directory, with the
// template's step text in its ci.yml and a wrapper that runs the real recipe.

// carrierTests are the carried template tests, in testdata/carrier.
var carrierTests = []string{"ci-mask-lan-tests.py", "job-output-handoff-tests.py"}

const (
	maskStepRun     = "run: make ci-mask-lan"
	templateStepRun = "run: scripts/ci-mask-lan.sh"
	maskSteps       = 8
)

// buildCarrier lays out the carrier the template tests expect and returns
// its root.
func buildCarrier(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	ci := readFile(t, ".github/workflows/ci.yml")
	if n := strings.Count(ci, maskStepRun+"\n"); n != maskSteps {
		t.Fatalf("ci.yml has %d %q steps, want %d", n, maskStepRun, maskSteps)
	}
	dir := t.TempDir()
	write := func(rel, body string, mode os.FileMode) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(".github/workflows/ci.yml", strings.ReplaceAll(ci, maskStepRun+"\n", templateStepRun+"\n"), 0o600)
	wrapper := "#!/usr/bin/env bash\n" +
		"# The carrier's ci-mask-lan.sh: the repository's make ci-mask-lan.\n" +
		"unset MAKEFLAGS MFLAGS MAKELEVEL\n" +
		"exec make -s --no-print-directory -C '" + root + "' ci-mask-lan\n"
	write("scripts/ci-mask-lan.sh", wrapper, 0o700)
	for _, name := range carrierTests {
		write("testdata/"+name, readFile(t, "test/ci/workflows/testdata/carrier/"+name), 0o600)
	}
	return dir
}

// TestCarrierRunsTheTemplateMaskTests runs the carried ci-mask-lan-tests.py
// (M1 to M5 and the script cases) and job-output-handoff-tests.py (H1 to H5)
// on this repository's ci.yml and make ci-mask-lan.
func TestCarrierRunsTheTemplateMaskTests(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not on PATH")
	}
	if _, err := exec.LookPath("make"); err != nil {
		t.Fatalf("make is required to run make ci-mask-lan: %v", err)
	}
	dir := buildCarrier(t)
	for _, name := range carrierTests {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(python, "-I", filepath.Join("testdata", name)) // #nosec G204 -- python3 from PATH on a carried test file
			cmd.Dir = dir
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Run(); err != nil {
				t.Fatalf("python3 -I testdata/%s: %v\n%s", name, err, out.String())
			}
			lines := strings.Split(strings.TrimSpace(out.String()), "\n")
			t.Logf("%s: %s", name, lines[len(lines)-1])
		})
	}
}

// cancelWord is the runner's spelling of a stopped run's status.
const cancelWord = "cancel" + "led"

// gateIfHolds evaluates CI Gate's if: expression for one run, as the
// template's ci-gate-cancel-tests.py does: the status functions, the event
// tests and the preflight verdict become true or false, and the rest is
// && / || / ! over parentheses.
func gateIfHolds(t *testing.T, expr, event string, stopped bool, verdict string) bool {
	t.Helper()
	b := func(v bool) string {
		if v {
			return "true"
		}
		return "false"
	}
	e := strings.TrimSuffix(strings.TrimPrefix(expr, "${{ "), " }}")
	e = strings.ReplaceAll(e, "startsWith(github.event_name, 'pull_request')", b(strings.HasPrefix(event, "pull_request")))
	e = strings.ReplaceAll(e, "always()", "true")
	e = strings.ReplaceAll(e, cancelWord+"()", b(stopped))
	e = strings.ReplaceAll(e, "success()", b(!stopped))
	e = strings.ReplaceAll(e, "failure()", "false")
	for _, ev := range []string{"schedule", "push", "pull_request", "pull_request_target", "workflow_dispatch"} {
		e = strings.ReplaceAll(e, "github.event_name != '"+ev+"'", b(event != ev))
		e = strings.ReplaceAll(e, "github.event_name == '"+ev+"'", b(event == ev))
	}
	for _, v := range []string{"busy", "run", "proven", "refused"} {
		e = strings.ReplaceAll(e, "needs.preflight.outputs.verdict != '"+v+"'", b(verdict != v))
		e = strings.ReplaceAll(e, "needs.preflight.outputs.verdict == '"+v+"'", b(verdict == v))
	}
	p := &boolExpr{src: strings.ReplaceAll(e, " ", "")}
	v := p.or()
	if p.err || p.pos != len(p.src) {
		t.Fatalf("CI Gate's if: has a term the evaluator does not know: %s", e)
	}
	return v
}

// boolExpr is a recursive-descent reader of true/false, !, &&, || and
// parentheses, with the Actions precedence (! over && over ||).
type boolExpr struct {
	src string
	pos int
	err bool
}

func (p *boolExpr) or() bool {
	v := p.and()
	for strings.HasPrefix(p.src[p.pos:], "||") {
		p.pos += 2
		r := p.and()
		v = v || r
	}
	return v
}

func (p *boolExpr) and() bool {
	v := p.unary()
	for strings.HasPrefix(p.src[p.pos:], "&&") {
		p.pos += 2
		r := p.unary()
		v = v && r
	}
	return v
}

func (p *boolExpr) unary() bool {
	rest := p.src[p.pos:]
	switch {
	case strings.HasPrefix(rest, "!"):
		p.pos++
		return !p.unary()
	case strings.HasPrefix(rest, "("):
		p.pos++
		v := p.or()
		if !strings.HasPrefix(p.src[p.pos:], ")") {
			p.err = true
			return false
		}
		p.pos++
		return v
	case strings.HasPrefix(rest, "true"):
		p.pos += 4
		return true
	case strings.HasPrefix(rest, "false"):
		p.pos += 5
		return false
	}
	p.err = true
	p.pos = len(p.src)
	return false
}

// TestCIGateIfIsCancelSafe holds G1 to G6 of the template's
// ci-gate-cancel-tests.py on this repository's CI Gate: off pull_request a
// stopped run posts no gate (it would read the stopped needs and fail), a
// run that is not stopped always gates, a pull request always gates (a
// skipped required check counts as passed), and the schedule guard's busy
// verdict still skips it.
func TestCIGateIfIsCancelSafe(t *testing.T) {
	expr := jobIfOf(t, job(t, readFile(t, ".github/workflows/ci.yml"), "ci-gate"))
	if expr == "" {
		t.Fatal("CI Gate has no if:")
	}
	for _, ev := range []string{"push", "schedule", "workflow_dispatch"} {
		if gateIfHolds(t, expr, ev, true, "run") {
			t.Errorf("G1 a %s %s run still runs CI Gate, which reads the stopped needs and fails", cancelWord, ev)
		}
		if !gateIfHolds(t, expr, ev, false, "run") {
			t.Errorf("G2 a %s run that is not %s skips CI Gate: a failed need would pass unseen", ev, cancelWord)
		}
	}
	for _, ev := range []string{"pull_request", "pull_request_target"} {
		if !gateIfHolds(t, expr, ev, true, "run") {
			t.Errorf("G3 a %s %s run skips CI Gate; a skipped required check counts as passed", cancelWord, ev)
		}
		if !gateIfHolds(t, expr, ev, false, "run") {
			t.Errorf("G4 a %s run skips CI Gate", ev)
		}
	}
	if gateIfHolds(t, expr, "schedule", false, "busy") {
		t.Error("G5 a busy schedule run runs CI Gate")
	}
	if !gateIfHolds(t, expr, "schedule", false, "proven") {
		t.Error("G6 a proven schedule run skips CI Gate")
	}
}

// TestCIGateFailsOnACancelledNeed holds G7 to G9 of the template's
// ci-gate-cancel-tests.py: on a pull request, which always runs the gate, a
// stopped need never leaves a passing gate, under the guard's run and proven
// verdicts alike.
func TestCIGateFailsOnACancelledNeed(t *testing.T) {
	all := allJobs()
	results := func(set map[string]string) map[string]string {
		r := map[string]string{}
		for _, j := range all {
			r[j] = "success"
		}
		for k, v := range set {
			r[k] = v
		}
		return r
	}
	if rc, out := runGateEnv(t, gateScript(t, results(nil)), "true", "false", "false", nil); rc != 0 {
		t.Fatalf("G7 control: a PR run with every job green fails the gate:\n%s", out)
	}
	for _, j := range all {
		for _, env := range []map[string]string{{"SCHEDULE_GUARD": "run"}, {"SCHEDULE_GUARD": "proven", "PROOF": "12345"}} {
			rc, out := runGateEnv(t, gateScript(t, results(map[string]string{j: cancelWord})), "true", "false", "false", env)
			if rc == 0 || !strings.Contains(out, "FAIL "+j+" ("+cancelWord+")") {
				t.Errorf("G8 a PR run with %s %s (verdict %s) leaves a passing CI Gate (exit %d):\n%s", j, cancelWord, env["SCHEDULE_GUARD"], rc, out)
			}
		}
	}
	every := map[string]string{}
	for _, j := range all {
		every[j] = cancelWord
	}
	if rc, out := runGateEnv(t, gateScript(t, results(every)), "true", "false", "false", nil); rc == 0 {
		t.Errorf("G9 a PR run with every job %s leaves a passing CI Gate:\n%s", cancelWord, out)
	}
}
