package workflows

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The review lock waits in the job's budget (code-review.yml v5.12.5, owner
// ruling 1012): lock_wait NEED prints what is left of JOB_BUDGET since
// $WORK/job-start, less NEED, and dies when nothing is left. These tests
// extract lock_wait, JOB_BUDGET and the two flock callers from the workflow
// text and run them under bash with a stub clock, die and flock.

const lockBudgetStart = 1_000_000

// indentOf returns the number of leading spaces of l.
func indentOf(l string) int { return len(l) - len(strings.TrimLeft(l, " ")) }

// lockWaitLib returns the workflow's JOB_BUDGET line and lock_wait function,
// dedented, and the budget in seconds.
func lockWaitLib(t *testing.T) (string, int) {
	t.Helper()
	lines := strings.Split(codeReview(t), "\n")
	budget, fn := "", -1
	for i, l := range lines {
		switch s := strings.TrimSpace(l); {
		case strings.HasPrefix(s, "JOB_BUDGET="):
			if budget != "" {
				t.Fatal("code-review.yml sets JOB_BUDGET more than once")
			}
			budget = s
		case s == "lock_wait() {":
			if fn >= 0 {
				t.Fatal("code-review.yml defines lock_wait more than once")
			}
			fn = i
		}
	}
	if budget == "" || fn < 0 {
		t.Fatalf("code-review.yml has no JOB_BUDGET (%q) or no lock_wait (line %d)", budget, fn)
	}
	in := indentOf(lines[fn])
	body := []string{budget}
	for _, l := range lines[fn:] {
		if strings.TrimSpace(l) != "" && indentOf(l) < in {
			t.Fatal("lock_wait ends without a closing brace")
		}
		body = append(body, strings.TrimPrefix(l, strings.Repeat(" ", in)))
		if indentOf(l) == in && strings.TrimSpace(l) == "}" {
			break
		}
	}
	if body[len(body)-1] != "}" {
		t.Fatal("lock_wait has no closing brace at its own indent")
	}
	code, out := runLockScript(t, strings.Join(body, "\n")+"\necho \"$JOB_BUDGET\"\n", nil, nil)
	if code != 0 {
		t.Fatalf("JOB_BUDGET does not evaluate (exit %d): %s", code, out)
	}
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("JOB_BUDGET is %q, not a number", out)
	}
	return strings.Join(body, "\n") + "\n", n
}

// runLockScript runs the script under bash -eo pipefail with a stub die and
// a date that prints $NOW. start, when not nil, is written to
// $WORK/job-start. It returns the exit code and the combined output.
func runLockScript(t *testing.T, script string, start *string, env map[string]string) (int, string) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash is required to run lock_wait: %v", err)
	}
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	if start != nil {
		if err := os.WriteFile(filepath.Join(work, "job-start"), []byte(*start), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stubs := "die() { echo \"DIE: $*\" >&2; exit 1; }\n" +
		"date() { [ \"$1\" = +%s ] || { echo \"date called with $*\" >&2; exit 97; }; echo \"$NOW\"; }\n"
	path := filepath.Join(dir, "lock.sh")
	if err := os.WriteFile(path, []byte(stubs+script), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bash, "--noprofile", "--norc", "-eo", "pipefail", path) // #nosec G204 -- bash from PATH on a script this test wrote
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "WORK=" + work, "CODEX_MASTER=" + filepath.Join(dir, "master"), "NOW=" + strconv.Itoa(lockBudgetStart)}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
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
		t.Fatalf("running lock_wait: %v", err)
		return -1, ""
	}
}

// lockWait runs lock_wait need with the job started at lockBudgetStart and
// the clock elapsed seconds later.
func lockWait(t *testing.T, lib string, elapsed, need int) (int, string) {
	t.Helper()
	start := strconv.Itoa(lockBudgetStart)
	return runLockScript(t, lib+"lock_wait "+strconv.Itoa(need)+"\n", &start,
		map[string]string{"NOW": strconv.Itoa(lockBudgetStart + elapsed)})
}

func lockWaitSeconds(t *testing.T, lib string, elapsed, need int) int {
	t.Helper()
	code, out := lockWait(t, lib, elapsed, need)
	if code != 0 {
		t.Fatalf("lock_wait %d after %d s exited %d: %s", need, elapsed, code, out)
	}
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("lock_wait %d after %d s printed %q, not a number", need, elapsed, out)
	}
	return n
}

func TestLockWaitSpendsTheJobBudget(t *testing.T) {
	lib, budget := lockWaitLib(t)
	if budget != 75*60 {
		t.Fatalf("JOB_BUDGET is %d s, want the review job's 75 minutes", budget)
	}

	// 1. The wait is no longer a fixed 600 s: with budget left it is more.
	if got := lockWaitSeconds(t, lib, 60, 100); got <= 600 {
		t.Fatalf("lock_wait 100 after 60 s = %d s, want more than the old fixed 600 s", got)
	}

	// 2. and 3. left = budget - elapsed - NEED, exactly.
	for _, c := range []struct{ elapsed, need int }{
		{0, 0}, {0, 100}, {500, 100}, {1800, 1000}, {3000, 1499}, {120, 3660},
	} {
		want := budget - c.elapsed - c.need
		if got := lockWaitSeconds(t, lib, c.elapsed, c.need); got != want {
			t.Errorf("lock_wait %d after %d s = %d, want budget %d - elapsed - NEED = %d",
				c.need, c.elapsed, got, budget, want)
		}
	}
	if a, b := lockWaitSeconds(t, lib, 100, 200), lockWaitSeconds(t, lib, 700, 200); a-b != 600 {
		t.Errorf("600 more seconds of job time shrank the wait by %d s, want 600", a-b)
	}
	if a, b := lockWaitSeconds(t, lib, 100, 200), lockWaitSeconds(t, lib, 100, 1200); a-b != 1000 {
		t.Errorf("1000 more seconds of NEED shrank the wait by %d s, want 1000", a-b)
	}

	// The last second still waits; none left dies.
	if got := lockWaitSeconds(t, lib, budget-101, 100); got != 1 {
		t.Errorf("lock_wait with 1 s left = %d, want 1", got)
	}
}

// 4. An exhausted budget dies at once and names it.
func TestLockWaitDiesWhenTheBudgetIsSpent(t *testing.T) {
	lib, budget := lockWaitLib(t)
	for _, c := range []struct{ elapsed, need int }{
		{budget - 100, 100}, {budget, 0}, {budget - 50, 100}, {budget + 600, 10}, {0, budget},
	} {
		code, out := lockWait(t, lib, c.elapsed, c.need)
		if code == 0 {
			t.Errorf("lock_wait %d after %d s succeeded (%q), want it to die", c.need, c.elapsed, out)
			continue
		}
		if !strings.Contains(out, "DIE: ") || !strings.Contains(out, strconv.Itoa(budget)+" s") ||
			!strings.Contains(out, "needs "+strconv.Itoa(c.need)+" s") {
			t.Errorf("lock_wait %d after %d s: die message %q does not name the %d s budget and the NEED",
				c.need, c.elapsed, out, budget)
		}
	}
}

// 5. A missing or non-numeric job-start dies.
func TestLockWaitDiesWithoutAJobStart(t *testing.T) {
	lib, _ := lockWaitLib(t)
	code, out := runLockScript(t, lib+"lock_wait 100\n", nil, nil)
	if code == 0 || !strings.Contains(out, "DIE: cannot read the job's start time") {
		t.Errorf("lock_wait without $WORK/job-start: exit %d, %q; want it to die naming the start file", code, out)
	}
	for _, bad := range []string{"", "abc", "12a", "-5", "1.5", "1e9"} {
		code, out := runLockScript(t, lib+"lock_wait 100\n", &bad, nil)
		if code == 0 || !strings.Contains(out, "is not a number") {
			t.Errorf("lock_wait with job-start %q: exit %d, %q; want it to die (not a number)", bad, code, out)
		}
	}
}

// lockCaller returns the caller's script from its wait_s=$(lock_wait ...)
// line through the first line of its flock, dedented, with the flock's
// continuation cut off.
func lockCaller(t *testing.T, need string) string {
	t.Helper()
	lines := strings.Split(codeReview(t), "\n")
	var calls []int
	for i, l := range lines {
		if strings.Contains(l, "$(lock_wait ") {
			calls = append(calls, i)
		}
	}
	if len(calls) != 2 {
		t.Fatalf("code-review.yml calls lock_wait %d times, want 2 (the refresh and review paths)", len(calls))
	}
	want := "wait_s=$(lock_wait " + need + ")"
	at := -1
	for _, i := range calls {
		if strings.TrimSpace(lines[i]) == want {
			at = i
		}
	}
	if at < 0 {
		t.Fatalf("no lock_wait caller is exactly %q", want)
	}
	in := indentOf(lines[at])
	var body []string
	for _, l := range lines[at:] {
		if strings.TrimSpace(l) != "" && indentOf(l) < in {
			break
		}
		s := strings.TrimPrefix(l, strings.Repeat(" ", in))
		if strings.HasPrefix(s, "flock ") {
			if !strings.HasPrefix(s, `flock -w "$wait_s" `) || !strings.HasSuffix(s, `"$CODEX_MASTER/.review.lock" \`) {
				t.Fatalf("the flock after %q does not wait $wait_s on the review lock: %q", want, s)
			}
			return strings.Join(append(body, strings.TrimSuffix(s, `\`)+"true"), "\n") + "\n"
		}
		if strings.Contains(s, "wait_s=") && len(body) > 0 {
			t.Fatalf("wait_s is set again before the flock after %q: %q", want, s)
		}
		body = append(body, s)
	}
	t.Fatalf("no flock follows %q", want)
	return ""
}

// 6. Each caller passes its NEED and waits flock for what lock_wait prints.
func TestLockWaitCallersFeedFlock(t *testing.T) {
	lib, budget := lockWaitLib(t)
	const limit, elapsed = 2730, 300
	flockStub := "flock() { [ \"$1\" = -w ] || { echo \"flock without -w: $*\" >&2; exit 98; }; echo \"FLOCK-W=$2\"; }\n"
	for _, c := range []struct {
		name, need string
		needS      int
	}{
		{"refresh", "$(( 130 + 360 + 2730 + 440 ))", 130 + 360 + 2730 + 440},
		{"review", "$(( limit + 30 + 440 ))", limit + 30 + 440},
	} {
		t.Run(c.name, func(t *testing.T) {
			script := lib + flockStub + "limit=" + strconv.Itoa(limit) + "\n" + lockCaller(t, c.need)
			start := strconv.Itoa(lockBudgetStart)
			code, out := runLockScript(t, script, &start,
				map[string]string{"NOW": strconv.Itoa(lockBudgetStart + elapsed)})
			if code != 0 {
				t.Fatalf("the %s path exited %d: %s", c.name, code, out)
			}
			want := "FLOCK-W=" + strconv.Itoa(budget-elapsed-c.needS)
			if !containsLine(out, want) {
				t.Errorf("the %s path's flock: %q, want %q (budget %d - %d s elapsed - NEED %d)",
					c.name, out, want, budget, elapsed, c.needS)
			}

			// A spent budget stops the path before flock runs.
			code, out = runLockScript(t, script, &start,
				map[string]string{"NOW": strconv.Itoa(lockBudgetStart + budget - c.needS)})
			if code == 0 || strings.Contains(out, "FLOCK-W=") || !strings.Contains(out, "DIE: no time is left") {
				t.Errorf("the %s path with no budget left: exit %d, %q; want it to die before flock", c.name, code, out)
			}
		})
	}
}
