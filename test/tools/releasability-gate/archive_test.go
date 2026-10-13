// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/test/internal/labstrings"
)

// publishedTree copies into a new directory, with no .git in or above it,
// what an archive export of src carries: every file git would track there
// (whatever .gitignore does not ignore), less every path the tree's
// .gitattributes export-ignores. git answers both questions from a scratch
// repository whose work tree is src, so this works the same in a checkout and
// in a tree that is itself an archive export. The scratch repository is
// created without templates and git runs in labstrings.HermeticGitEnv, with no
// system, global or XDG configuration or attributes file and no GIT_ variable,
// so only the tree's own .gitignore and .gitattributes files decide.
//
// It copies the work tree, not an archive of HEAD, so that it works where
// there is no commit to archive: the published tree runs this test too. Which
// files a commit publishes is the archive checks' question (ArchiveHEAD); this
// one asks whether the packages' tests need a checkout.
func publishedTree(t *testing.T, src string) string {
	t.Helper()
	scratch := t.TempDir()
	home := filepath.Join(scratch, "home")
	repo := filepath.Join(scratch, "repo")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	env := labstrings.HermeticGitEnv(home)
	git := func(stdin string, args ...string) []byte {
		t.Helper()
		cmd := exec.Command("git", args...) // #nosec G204 -- git from PATH, fixed arguments over test directories
		// From the top of the work tree, so paths are relative to src.
		cmd.Dir = src
		cmd.Env = env
		cmd.Stdin = strings.NewReader(stdin)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, stderr.String())
		}
		return out
	}
	git("", "init", "-q", "--template=", repo)
	inTree := []string{"--git-dir=" + filepath.Join(repo, ".git"), "--work-tree=" + src}

	var paths []string
	for _, p := range strings.Split(string(git("", append(inTree, "ls-files", "-z", "--others", "--exclude-standard")...)), "\x00") {
		if p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		t.Fatalf("git lists no files under %s", src)
	}
	attrs := strings.Split(string(git(strings.Join(paths, "\x00")+"\x00",
		append(inTree, "check-attr", "--stdin", "-z", "export-ignore")...)), "\x00")
	if len(attrs) != 3*len(paths)+1 {
		t.Fatalf("git check-attr answered %d fields for %d paths", len(attrs)-1, len(paths))
	}
	ignored := map[string]bool{}
	for i := 0; i+2 < len(attrs); i += 3 {
		ignored[attrs[i]] = attrs[i+2] == "set"
	}

	dst := t.TempDir()
	for _, p := range paths {
		if ignored[p] {
			continue
		}
		from := filepath.Join(src, filepath.FromSlash(p))
		info, err := os.Lstat(from)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() {
			t.Fatalf("%s is not a regular file; the copy does not reproduce it", p)
		}
		content, err := os.ReadFile(from) // #nosec G304 -- copying this module's own files into a test directory
		if err != nil {
			t.Fatal(err)
		}
		to := filepath.Join(dst, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(to, content, info.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// TestPublishedTreeTestsPass reproduces the published archive and the
// integration image: this module's files as an archive export carries them,
// with no .git anywhere above them, and `go test` over the packages that read
// the tree itself: the gate's, the workflow tests and the Makefile tests. They
// must pass there. The gate runs as `make releasability`, where a checkout is
// guaranteed; the packages' own tests must need none, and a test that reads a
// strip-at-publish file must be stripped with it.
//
// This test is excluded from the nested run by -skip, or it would recurse.
func TestPublishedTreeTestsPass(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go tool is not on PATH: %v", err)
	}
	dst := publishedTree(t, moduleRoot(t))

	// The copy is the archive: no strip-at-publish file, every published
	// workflow.
	var entries []labstrings.Entry
	err = filepath.WalkDir(dst, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dst, path)
		entries = append(entries, labstrings.Entry{Path: filepath.ToSlash(rel)})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if stripped := labstrings.StripAtPublish(entries, labstrings.DefaultStripAtPublish); len(stripped) != 0 {
		t.Fatalf("the published tree carries strip-at-publish files: %v", stripped)
	}
	for _, name := range labstrings.PublishedWorkflows {
		if _, err := os.Stat(filepath.Join(dst, ".github", "workflows", name)); err != nil {
			t.Fatalf("the published tree lacks the workflow %s: %v", name, err)
		}
	}

	env := gitEnv(dst)
	// No enclosing checkout, and no build stamping that would look for one.
	env = append(env, "GOFLAGS=-buildvcs=false", "GOWORK=off")
	cmd := exec.Command(goBin, "test", "-count=1", // #nosec G204 -- the go tool on PATH, fixed arguments
		"-skip", "^TestPublishedTreeTestsPass$",
		"./test/internal/labstrings/...", "./test/tools/releasability-gate/...",
		"./test/ci/...", "./test/makefile/...")
	cmd.Dir = dst
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("package tests fail in the published tree, which has no .git: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(dst, ".git")); statErr == nil {
		t.Fatal("the nested run created a .git in the published tree; the test proves nothing")
	}
}
