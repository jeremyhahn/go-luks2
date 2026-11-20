package workflows

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const revertWorkflow = ".github/workflows/revert-red-main.yml"

// revertScripts returns the body of every `run: |` block in
// revert-red-main.yml, continuation lines joined.
func revertScripts(t *testing.T) []string {
	t.Helper()
	var scripts []string
	lines := strings.Split(readFile(t, revertWorkflow), "\n")
	head := regexp.MustCompile(`^(\s*)run: \|$`)
	for i := 0; i < len(lines); i++ {
		m := head.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		var b strings.Builder
		for i++; i < len(lines); i++ {
			l := lines[i]
			if strings.TrimSpace(l) != "" && len(l)-len(strings.TrimLeft(l, " ")) <= len(m[1]) {
				i--
				break
			}
			b.WriteString(l + "\n")
		}
		scripts = append(scripts, strings.ReplaceAll(b.String(), "\\\n", " "))
	}
	if len(scripts) == 0 {
		t.Fatalf("%s has no run: | script", revertWorkflow)
	}
	return scripts
}

// TestRevertRedMainScriptsHaveNoAndOrChains: shellcheck SC2015 (A && B || C
// is not if-then-else) fails CI's actionlint, so every such chain in the
// workflow's scripts is an explicit if/then/fi.
func TestRevertRedMainScriptsHaveNoAndOrChains(t *testing.T) {
	chain := regexp.MustCompile(`&&.*\|\|`)
	for _, s := range revertScripts(t) {
		for _, line := range strings.Split(s, "\n") {
			code, _, _ := strings.Cut(line, " # ")
			for _, stmt := range strings.Split(code, ";") {
				if chain.MatchString(stmt) {
					t.Errorf("an A && B || C chain (SC2015), write it as if/then/fi: %s", strings.TrimSpace(line))
				}
			}
		}
	}
}

// relandScript is the merged-PR branch of the reland loop: from its
// comment to the else of the closed-by-a-train case.
func relandScript(t *testing.T) string {
	t.Helper()
	s := strings.Join(revertScripts(t), "\n")
	i := strings.Index(s, `if [ "$(jq -r '.merged' /tmp/c.json)" = true ]; then`)
	if i < 0 {
		t.Fatal("revert-red-main.yml has no merged-PR reland branch")
	}
	j := strings.Index(s[i:], "# Closed by the train")
	if j < 0 {
		t.Fatal("revert-red-main.yml has no closed-by-a-train reland branch")
	}
	return s[i : i+j]
}

// TestRevertRedMainRelandBuildsOnTheRevert: a merged PR's old head is an
// ancestor of main, so a reland branch at it carries no commit and its PR
// restores nothing. The workflow builds reland/N on the revert commit with a
// revert of that commit, which restores the change once the revert lands.
func TestRevertRedMainRelandBuildsOnTheRevert(t *testing.T) {
	s := relandScript(t)
	if strings.Contains(s, `"$h:refs/heads/reland/$n"`) {
		t.Error("reland/N is pushed at the merged PR's old head, which is already on main")
	}
	for _, want := range []string{`revert --no-edit "$rtip"`, `"HEAD:refs/heads/reland/$n"`} {
		if !strings.Contains(s, want) {
			t.Errorf("the merged-PR reland branch does not run %s", want)
		}
	}
	if !regexp.MustCompile(`(?m)^\s*rtip=\$\(git -C "\$repo" rev-parse HEAD\)`).MatchString(strings.Join(revertScripts(t), "\n")) {
		t.Error("the workflow does not record the revert commit as rtip")
	}
}

// TestRevertRedMainRelandFixture shows, in a local repository, that the old
// reland form (the merged PR's head) has no diff against main once the
// revert lands, and the new form (revert commit plus its revert) has the
// change's diff.
func TestRevertRedMainRelandFixture(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not on PATH")
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "gitconfig")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var env []string
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); !strings.HasPrefix(k, "GIT_") && k != "HOME" {
			env = append(env, kv)
		}
	}
	env = append(env, "HOME="+dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+cfg,
		"GIT_AUTHOR_NAME=a", "GIT_AUTHOR_EMAIL=a@example.com",
		"GIT_COMMITTER_NAME=a", "GIT_COMMITTER_EMAIL=a@example.com")
	repo := filepath.Join(dir, "repo")
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...) // #nosec G204 -- fixed git arguments in a temp repository
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(repo, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(repo, 0o750); err != nil {
		t.Fatal(err)
	}
	git("init", "-q", "-b", "main")
	write("a.txt", "base\n")
	git("add", ".")
	git("commit", "-qm", "base")
	git("checkout", "-qb", "feature")
	write("b.txt", "change\n")
	git("add", ".")
	git("commit", "-qm", "change")
	h := git("rev-parse", "HEAD")
	git("checkout", "-q", "main")
	git("merge", "-q", "--no-ff", "-m", "merge feature", "feature")
	sha := git("rev-parse", "HEAD")

	// The workflow's revert onto main's tip, and the revert landing.
	git("checkout", "-q", "--detach", "main")
	git("revert", "--no-edit", "-m", "1", sha)
	rtip := git("rev-parse", "HEAD")
	git("update-ref", "refs/heads/main", rtip)

	// Old form: reland/N at the merged PR's head.
	git("update-ref", "refs/heads/old", h)
	// New form: the revert commit plus its revert.
	git("checkout", "-q", "--detach", rtip)
	git("revert", "--no-edit", rtip)
	git("update-ref", "refs/heads/new", "HEAD")

	if d := git("diff", "--name-only", "main...old"); d != "" {
		t.Errorf("the old reland form has a diff against main: %q", d)
	}
	if n := git("rev-list", "--count", "main..old"); n != "0" {
		t.Errorf("the old reland form carries %s commit(s) not on main", n)
	}
	if d := git("diff", "--name-only", "main...new"); d != "b.txt" {
		t.Errorf("the new reland form's diff against main is %q, want the change's b.txt", d)
	}
}

// TestRevertStepsNameCISteps: every alternative in revert-red-main.yml's
// REVERT_STEPS names at least one step of ci.yml, so a step renamed in a
// template merge (ci-template v1.48, #494) cannot leave a deterministic stage
// that no longer reverts a red main.
func TestRevertStepsNameCISteps(t *testing.T) {
	m := regexp.MustCompile(`(?m)^\s*REVERT_STEPS: '\^\((.*)\)\$'$`).FindStringSubmatch(readFile(t, ".github/workflows/revert-red-main.yml"))
	if m == nil {
		t.Fatal("revert-red-main.yml defines no REVERT_STEPS of the form '^(a|b|...)$'")
	}
	var steps []string
	for _, s := range regexp.MustCompile(`(?m)^\s*- name: (.+)$`).FindAllStringSubmatch(readFile(t, ".github/workflows/ci.yml"), -1) {
		steps = append(steps, strings.TrimSpace(s[1]))
	}
	for _, alt := range strings.Split(m[1], "|") {
		re, err := regexp.Compile(`^(?:` + alt + `)$`)
		if err != nil {
			t.Errorf("REVERT_STEPS alternative %q: %v", alt, err)
			continue
		}
		hit := false
		for _, s := range steps {
			if re.MatchString(s) {
				hit = true
				break
			}
		}
		if !hit {
			t.Errorf("REVERT_STEPS alternative %q names no ci.yml step", alt)
		}
	}
}
