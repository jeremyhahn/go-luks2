// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package makefile

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeAgentGit stands in for the standards repository's agent-git.sh: it drops
// the repository-name argument and runs git, so the recipe's signed writes land
// in the fixture repository unsigned.
const fakeAgentGit = `#!/bin/sh
shift
exec git "$@"
`

// gitIn runs git in dir and fails the test on error.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command(lookPath(t, "git"), args...) // #nosec G204 -- git is resolved from PATH; arguments are test constants
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// releaseFixture is a throwaway repository on main holding the real Makefile,
// a VERSION file, a CHANGELOG with the section for each version in sections and
// a bare remote named dev. It returns the work tree, the bare remote and the
// agent-git stand-in.
// noBackgroundMaintenance turns off the automatic maintenance git starts after
// a commit, and after a push in the repository it pushed to. Since git 2.47
// that run detaches (maintenance.autoDetach) and nothing waits for it, so it
// can still be writing the fixture's objects/pack when t.TempDir removes the
// directory. The settings go in the repository's own config rather than in
// GIT_CONFIG_* because git drops those for the receive-pack a local push runs
// in the remote. maintenance.auto alone stops the run; the rest keep any gc
// that does start in the foreground, where its caller waits for it.
func noBackgroundMaintenance(t *testing.T, repo string) {
	t.Helper()
	for _, kv := range [][2]string{
		{"maintenance.auto", "false"},
		{"maintenance.autoDetach", "false"},
		{"gc.auto", "0"},
		{"gc.autoDetach", "false"},
	} {
		gitIn(t, repo, "config", kv[0], kv[1])
	}
}

func releaseFixture(t *testing.T, version string, sections ...string) (work, remote, agentGit string) {
	t.Helper()
	root := repoRoot(t)
	base := t.TempDir()
	work = filepath.Join(base, "work")
	remote = filepath.Join(base, "remote.git")
	for _, d := range []string{work, filepath.Join(work, "changelog.d")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	mk, err := os.ReadFile(filepath.Join(root, "Makefile")) // #nosec G304 -- the repository's own Makefile
	if err != nil {
		t.Fatal(err)
	}
	gomod, err := os.ReadFile(filepath.Join(root, "go.mod")) // #nosec G304 -- the repository's own go.mod; the Makefile binds its toolchain to it
	if err != nil {
		t.Fatal(err)
	}
	changelog := "# Changelog\n\n"
	for _, s := range sections {
		changelog += "## [" + s + "] - 2026-01-01\n\n- entry\n\n"
	}
	files := map[string]string{
		"Makefile":              string(mk),
		"go.mod":                string(gomod),
		"VERSION":               version + "\n",
		"CHANGELOG.md":          changelog,
		"changelog.d/README.md": "fragments\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(work, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	agentGit = filepath.Join(base, "agent-git.sh")
	if err := os.WriteFile(agentGit, []byte(fakeAgentGit), 0o700); err != nil { // #nosec G306 -- an executable test stub in a temp dir
		t.Fatal(err)
	}
	gitIn(t, base, "init", "-q", "--bare", remote)
	gitIn(t, work, "init", "-q", "-b", "main")
	noBackgroundMaintenance(t, remote)
	noBackgroundMaintenance(t, work)
	gitIn(t, work, "remote", "add", "dev", remote)
	gitIn(t, work, "add", ".")
	gitIn(t, work, "commit", "-q", "-m", "fixture")
	return work, remote, agentGit
}

// targetFor names the one release target that cuts version's kind.
func targetFor(version string) string {
	switch {
	case strings.HasSuffix(version, "-alpha"):
		return "release-alpha"
	case strings.Contains(version, "-rc."):
		return "release-candidate"
	default:
		return "release"
	}
}

// runTarget runs `make <target> VERSION=<version>` in the fixture and returns
// the combined output and whether it succeeded. An empty version passes no
// VERSION argument at all.
func runTarget(t *testing.T, target, work, agentGit, version string) (string, bool) {
	t.Helper()
	args := []string{target, "AGENT_GIT=" + agentGit}
	if version != "" {
		args = append(args, "VERSION="+version)
	}
	cmd := exec.Command(lookPath(t, "make"), args...) // #nosec G204 -- make is resolved from PATH; arguments are test values
	cmd.Dir = work
	cmd.Env = append(environ(nil, nil),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// runRelease cuts version with the target for its own kind.
func runRelease(t *testing.T, work, agentGit, version string) (string, bool) {
	t.Helper()
	return runTarget(t, targetFor(version), work, agentGit, version)
}

// TestReleaseAcceptsAlphaRCAndFinalVersions: the recipe was alpha-only, so the
// 1.0.0-rc.1 release could not be cut at all.
func TestReleaseAcceptsAlphaRCAndFinalVersions(t *testing.T) {
	for _, v := range []string{"v0.3.2-alpha", "v1.0.0-rc.1", "v1.0.0-rc.12", "v1.0.0", "v1.2.3"} {
		t.Run(v, func(t *testing.T) {
			work, remote, agentGit := releaseFixture(t, "0.0.0", strings.TrimPrefix(v, "v"))
			if out, ok := runRelease(t, work, agentGit, v); !ok {
				t.Fatalf("make release VERSION=%s failed:\n%s", v, out)
			}
			if got := gitIn(t, remote, "tag", "--list", v); got != v {
				t.Errorf("tag %s was not pushed to the remote (got %q)", v, got)
			}
			ver, err := os.ReadFile(filepath.Join(work, "VERSION")) // #nosec G304 -- fixture path
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.TrimSpace(string(ver)); got != strings.TrimPrefix(v, "v") {
				t.Errorf("VERSION = %q, want %q", got, strings.TrimPrefix(v, "v"))
			}
		})
	}
}

// TestReleaseIsIdempotentWhenVERSIONAlreadyMatches: VERSION is bumped ahead of
// the tag for rc.1, so the version commit would be empty and fail the recipe.
func TestReleaseIsIdempotentWhenVERSIONAlreadyMatches(t *testing.T) {
	work, remote, agentGit := releaseFixture(t, "1.0.0-rc.1", "1.0.0-rc.1")
	before := gitIn(t, work, "rev-parse", "HEAD")
	if out, ok := runRelease(t, work, agentGit, "v1.0.0-rc.1"); !ok {
		t.Fatalf("make release failed with VERSION already matching:\n%s", out)
	}
	if after := gitIn(t, work, "rev-parse", "HEAD"); after != before {
		t.Errorf("HEAD moved from %s to %s: a matching VERSION must not be re-committed", before, after)
	}
	if got := gitIn(t, remote, "tag", "--list", "v1.0.0-rc.1"); got != "v1.0.0-rc.1" {
		t.Errorf("tag not pushed (got %q)", got)
	}
}

// TestReleaseCommitsVERSIONWhenItDiffers keeps the original behavior.
func TestReleaseCommitsVERSIONWhenItDiffers(t *testing.T) {
	work, _, agentGit := releaseFixture(t, "0.9.0", "1.0.0")
	before := gitIn(t, work, "rev-parse", "HEAD")
	if out, ok := runRelease(t, work, agentGit, "v1.0.0"); !ok {
		t.Fatalf("make release failed:\n%s", out)
	}
	if after := gitIn(t, work, "rev-parse", "HEAD"); after == before {
		t.Error("VERSION changed but no release commit was made")
	}
	if msg := gitIn(t, work, "log", "-1", "--format=%s"); msg != "chore(release): v1.0.0" {
		t.Errorf("release commit subject = %q", msg)
	}
}

// TestReleaseRefusesMalformedVersions pins the grammar guard.
func TestReleaseRefusesMalformedVersions(t *testing.T) {
	for _, v := range []string{"1.0.0", "v1.0", "v01.0.0", "v1.0.0-rc", "v1.0.0-rc.0", "v1.0.0-rc.01", "v1.0.0-beta", "v1.0.0-alpha.1", "v1.0.0-rc.1-x"} {
		t.Run(v, func(t *testing.T) {
			work, remote, agentGit := releaseFixture(t, "0.0.0", strings.TrimPrefix(v, "v"))
			out, ok := runRelease(t, work, agentGit, v)
			if ok {
				t.Fatalf("make release VERSION=%s succeeded; want refusal:\n%s", v, out)
			}
			if !strings.Contains(out, "not of the form") {
				t.Errorf("refusal does not name the grammar:\n%s", out)
			}
			if got := gitIn(t, remote, "tag", "--list"); got != "" {
				t.Errorf("a tag was pushed despite the refusal: %q", got)
			}
		})
	}
}

// TestReleaseKeepsItsGuards: the generalised recipe still refuses a duplicate
// tag, a missing changelog section and unassembled fragments.
func TestReleaseKeepsItsGuards(t *testing.T) {
	t.Run("duplicate tag", func(t *testing.T) {
		work, _, agentGit := releaseFixture(t, "1.0.0-rc.1", "1.0.0-rc.1")
		gitIn(t, work, "tag", "v1.0.0-rc.1")
		out, ok := runRelease(t, work, agentGit, "v1.0.0-rc.1")
		if ok || !strings.Contains(out, "already exists") {
			t.Fatalf("duplicate tag not refused (ok=%v):\n%s", ok, out)
		}
	})
	t.Run("no changelog section", func(t *testing.T) {
		work, _, agentGit := releaseFixture(t, "1.0.0-rc.1")
		out, ok := runRelease(t, work, agentGit, "v1.0.0-rc.1")
		if ok || !strings.Contains(out, "no \"## [1.0.0-rc.1]\" section heading") {
			t.Fatalf("missing CHANGELOG section not refused (ok=%v):\n%s", ok, out)
		}
	})
	t.Run("unassembled fragment", func(t *testing.T) {
		work, _, agentGit := releaseFixture(t, "1.0.0-rc.1", "1.0.0-rc.1")
		if err := os.WriteFile(filepath.Join(work, "changelog.d", "1-x.md"), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		gitIn(t, work, "add", ".")
		gitIn(t, work, "commit", "-q", "-m", "frag")
		out, ok := runRelease(t, work, agentGit, "v1.0.0-rc.1")
		if ok || !strings.Contains(out, "unassembled fragments") {
			t.Fatalf("fragment not refused (ok=%v):\n%s", ok, out)
		}
	})
	t.Run("not on main", func(t *testing.T) {
		work, _, agentGit := releaseFixture(t, "1.0.0-rc.1", "1.0.0-rc.1")
		gitIn(t, work, "checkout", "-q", "-b", "side")
		out, ok := runRelease(t, work, agentGit, "v1.0.0-rc.1")
		if ok || !strings.Contains(out, "releases are cut from main") {
			t.Fatalf("non-main branch not refused (ok=%v):\n%s", ok, out)
		}
	})
}

// releaseTargets are the three kinds' targets, each with a version of its kind.
var releaseTargets = []struct{ target, version string }{
	{"release-alpha", "v0.3.2-alpha"},
	{"release-candidate", "v1.0.0-rc.4"},
	{"release", "v1.0.0"},
}

// TestEachReleaseTargetCutsOnlyItsOwnKind: one target per kind. Each target
// cuts its own kind and refuses the other two, and the refusal names the target
// that does cut the kind.
func TestEachReleaseTargetCutsOnlyItsOwnKind(t *testing.T) {
	for _, tgt := range releaseTargets {
		for _, v := range releaseTargets {
			t.Run(tgt.target+"/"+v.version, func(t *testing.T) {
				work, remote, agentGit := releaseFixture(t, "0.0.0", strings.TrimPrefix(v.version, "v"))
				head := gitIn(t, work, "rev-parse", "HEAD")
				out, ok := runTarget(t, tgt.target, work, agentGit, v.version)
				if tgt.target == v.target {
					if !ok {
						t.Fatalf("make %s VERSION=%s failed:\n%s", tgt.target, v.version, out)
					}
					if got := gitIn(t, remote, "tag", "--list", v.version); got != v.version {
						t.Errorf("tag %s was not pushed (got %q)", v.version, got)
					}
					return
				}
				if ok {
					t.Fatalf("make %s VERSION=%s succeeded; want refusal:\n%s", tgt.target, v.version, out)
				}
				if want := "Use: make " + v.target + " VERSION=" + v.version; !strings.Contains(out, want) {
					t.Errorf("refusal does not name %q:\n%s", want, out)
				}
				// Refused before anything is written: no commit, no tag, no push, and
				// the VERSION file as the fixture left it.
				if got := gitIn(t, work, "rev-parse", "HEAD"); got != head {
					t.Errorf("HEAD moved from %s to %s on a refusal", head, got)
				}
				if got := gitIn(t, work, "tag", "--list"); got != "" {
					t.Errorf("a local tag was cut on a refusal: %q", got)
				}
				if got := gitIn(t, remote, "tag", "--list"); got != "" {
					t.Errorf("a tag was pushed on a refusal: %q", got)
				}
				if got := gitIn(t, work, "status", "--porcelain"); got != "" {
					t.Errorf("the tree was written on a refusal: %q", got)
				}
			})
		}
	}
}

// TestReleaseKindCheckComesBeforeTheRepositoryGuards: a wrong kind is refused
// for being the wrong kind even where the repository guards would also fire, so
// the message names the right target rather than a symptom.
func TestReleaseKindCheckComesBeforeTheRepositoryGuards(t *testing.T) {
	work, _, agentGit := releaseFixture(t, "1.0.0-rc.4", "1.0.0-rc.4")
	gitIn(t, work, "checkout", "-q", "-b", "side")
	out, ok := runTarget(t, "release", work, agentGit, "v1.0.0-rc.4")
	if ok || !strings.Contains(out, "Use: make release-candidate VERSION=v1.0.0-rc.4") {
		t.Fatalf("wrong kind off main not refused as a wrong kind (ok=%v):\n%s", ok, out)
	}
}

// TestReleaseTargetsKeepTheirOwnKindWhenNamedTogether: the targets share one
// recipe body, not one run, so naming two of them cannot clear one's kind check
// with the other's.
func TestReleaseTargetsKeepTheirOwnKindWhenNamedTogether(t *testing.T) {
	work, remote, agentGit := releaseFixture(t, "0.0.0", "1.0.0")
	cmd := exec.Command(lookPath(t, "make"), "release-candidate", "release", "VERSION=v1.0.0", "AGENT_GIT="+agentGit) // #nosec G204 -- test values
	cmd.Dir = work
	cmd.Env = append(environ(nil, nil),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "Use: make release VERSION=v1.0.0") {
		t.Fatalf("release-candidate cut a final release (err=%v):\n%s", err, out)
	}
	if got := gitIn(t, remote, "tag", "--list"); got != "" {
		t.Errorf("a tag was pushed: %q", got)
	}
}

// TestReleaseTargetsRequireAnExplicitVersion: none of the three guesses a
// version, release-alpha included, and each names itself in the refusal.
func TestReleaseTargetsRequireAnExplicitVersion(t *testing.T) {
	for _, tgt := range releaseTargets {
		t.Run(tgt.target, func(t *testing.T) {
			work, remote, agentGit := releaseFixture(t, "0.0.0", "0.0.0")
			out, ok := runTarget(t, tgt.target, work, agentGit, "")
			if ok || !strings.Contains(out, "state the version explicitly: make "+tgt.target+" VERSION=") {
				t.Fatalf("missing VERSION not refused by %s (ok=%v):\n%s", tgt.target, ok, out)
			}
			if got := gitIn(t, remote, "tag", "--list"); got != "" {
				t.Errorf("a tag was pushed: %q", got)
			}
		})
	}
}

// TestReleaseFixtureLeavesNoGitRunning: no git the fixture or the recipe runs
// starts automatic maintenance, in the work tree or in the remote, so nothing
// is left writing either repository when the test returns. git's trace2 log
// names every child a git process starts, including one it detaches.
func TestReleaseFixtureLeavesNoGitRunning(t *testing.T) {
	trace := filepath.Join(t.TempDir(), "trace2.json")
	t.Setenv("GIT_TRACE2_EVENT", trace)
	work, _, agentGit := releaseFixture(t, "0.9.0", "1.0.0")
	if out, ok := runRelease(t, work, agentGit, "v1.0.0"); !ok {
		t.Fatalf("make release failed:\n%s", out)
	}

	log, err := os.ReadFile(trace) // #nosec G304 -- a path in the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	starts := 0
	for _, line := range strings.Split(strings.TrimSpace(string(log)), "\n") {
		var event struct {
			Event string   `json:"event"`
			Argv  []string `json:"argv"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("trace2 line %q: %v", line, err)
		}
		if event.Event != "start" {
			continue
		}
		starts++
		if slices.Contains(event.Argv, "maintenance") || slices.Contains(event.Argv, "gc") {
			t.Errorf("git started %q, which outlives the command that started it", strings.Join(event.Argv, " "))
		}
	}
	if starts == 0 {
		t.Fatal("the trace2 log records no git at all; it cannot show that none ran maintenance")
	}
}
