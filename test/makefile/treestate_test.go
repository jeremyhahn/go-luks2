// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package makefile

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// treeState returns a function reporting the state of the tree at root that
// TestMain compares before and after the suite, and a cleanup to run after the
// last call.
//
// In a checkout (root/.git exists) the state is gitStatus(root). A tree with
// no .git -- the published archive, the integration image -- gets the same
// guard without a repository of its own: the tree is committed, as it is at
// the start of the suite, into a scratch repository outside it whose work tree
// is root, and the state is `git status --porcelain` there. The tree's own
// .gitignore files decide what is watched, as in a checkout, so the two agree
// on what a test may not change; the snapshot is, if anything, stricter,
// because a file already modified in a checkout shows the same status line
// however often it is modified again. The scratch repository has no
// templates, no system, global or XDG configuration and no inherited GIT_
// variable, so nothing outside the tree changes what is watched.
func treeState(root string) (func() (string, error), func(), error) {
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		return func() (string, error) { return gitStatus(root) }, func() {}, nil
	}
	scratch, err := os.MkdirTemp("", "makefile-tree-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(scratch) }
	home := filepath.Join(scratch, "home")
	repo := filepath.Join(scratch, "repo")
	if err := os.Mkdir(home, 0o700); err != nil {
		cleanup()
		return nil, nil, err
	}
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GIT_") || strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "XDG_CONFIG_HOME=") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "HOME="+home, "XDG_CONFIG_HOME="+home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", args...) // #nosec G204 -- git is resolved from PATH; arguments are constants and test directories
		cmd.Dir = root
		cmd.Env = env
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("git %v: %w: %s", args, err, strings.TrimSpace(stderr.String()))
		}
		return string(out), nil
	}
	inTree := []string{"--git-dir=" + filepath.Join(repo, ".git"), "--work-tree=" + root}
	for _, args := range [][]string{
		{"init", "-q", "--template=", repo},
		append(inTree, "add", "-A"),
		append(inTree, "-c", "user.name=snapshot", "-c", "user.email=snapshot@example.invalid",
			"-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "the tree before the suite"),
	} {
		if _, err := git(args...); err != nil {
			cleanup()
			return nil, nil, err
		}
	}
	return func() (string, error) { return git(append(inTree, "status", "--porcelain")...) }, cleanup, nil
}

// TestTreeStateWithoutACheckoutSeesEveryChange: in a tree with no .git, the
// guard reports nothing for an untouched tree and reports a modified, a
// deleted and a new file, and it does not report a file .gitignore ignores --
// exactly what git status reports in a checkout. Nothing is written into the
// tree but by the test itself.
func TestTreeStateWithoutACheckoutSeesEveryChange(t *testing.T) {
	write := func(root, name, content string) {
		t.Helper()
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, change := range map[string]func(root string){
		"modified": func(root string) { write(root, "Makefile", "all:\n\ttrue\n") },
		"deleted": func(root string) {
			if err := os.Remove(filepath.Join(root, "sub", "kept.go")); err != nil {
				t.Fatal(err)
			}
		},
		"new":         func(root string) { write(root, "coverage-pkg.out", "mode: set\n") },
		"new, nested": func(root string) { write(root, "sub/new/x.txt", "x\n") },
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(root))
			write(root, ".gitignore", "*.log\n")
			write(root, "Makefile", "all:\n")
			write(root, "sub/kept.go", "package sub\n")
			state, cleanup, err := treeState(root)
			if err != nil {
				t.Fatalf("treeState: %v", err)
			}
			defer cleanup()
			before, err := state()
			if err != nil || before != "" {
				t.Fatalf("an untouched tree: state %q, %v; want empty", before, err)
			}
			write(root, "build.log", "ignored\n")
			if same, err := state(); err != nil || same != before {
				t.Fatalf("an ignored file changed the state to %q (%v)", same, err)
			}
			change(root)
			after, err := state()
			if err != nil {
				t.Fatalf("state after the change: %v", err)
			}
			if after == before {
				t.Fatalf("the guard did not see the change; state %q", after)
			}
			if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
				t.Fatal("the guard created a .git in the tree it watches")
			}
		})
	}
}
