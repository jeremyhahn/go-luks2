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
	pins, err := os.ReadFile(filepath.Join(root, "build/docker/devcontainer/tool-pins.env")) // #nosec G304 -- the repository's own tool pin file; the Makefile includes it
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(work, "build/docker/devcontainer"), 0o750); err != nil {
		t.Fatal(err)
	}
	changelog := "# Changelog\n\n"
	for _, s := range sections {
		changelog += "## [" + s + "] - 2026-01-01\n\n- entry\n\n"
	}
	files := map[string]string{
		"Makefile": string(mk),
		"go.mod":   string(gomod),
		"build/docker/devcontainer/tool-pins.env": string(pins),
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

// TestReleaseTargetsRequireAnExplicitVersion: release-candidate and release
// never guess a version. release-alpha derives one from the alpha tags, so the
// fixture here has none and it refuses; each names itself in the refusal.
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

// tagFixture creates each tag on the fixture's HEAD and publishes it to the
// remote. A tag in remoteOnly is then deleted from the work tree, so only the
// remote knows it.
func tagFixture(t *testing.T, work string, tags, remoteOnly []string) {
	t.Helper()
	for _, tag := range tags {
		gitIn(t, work, "tag", tag)
		gitIn(t, work, "push", "-q", "dev", "refs/tags/"+tag)
	}
	for _, tag := range remoteOnly {
		gitIn(t, work, "tag", "-d", tag)
	}
}

// remoteTags lists the remote's tags, one per line.
func remoteTags(t *testing.T, remote string) []string {
	t.Helper()
	out := gitIn(t, remote, "tag", "--list")
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}

// TestReleaseAlphaDerivesTheNextPatchFromTheHighestAlphaTag: with no VERSION,
// release-alpha counts PATCH + 1 from the highest alpha tag by number (not by
// text, so .10 outranks .9), reading the tags of the checkout and of the remote,
// prints the version before writing, and cuts it through the usual guards.
func TestReleaseAlphaDerivesTheNextPatchFromTheHighestAlphaTag(t *testing.T) {
	cases := []struct {
		name       string
		tags       []string
		remoteOnly []string
		want       string
	}{
		{"highest by number", []string{"v0.3.9-alpha", "v0.3.10-alpha", "v0.2.99-alpha"}, nil, "v0.3.11-alpha"},
		{"highest on the remote only", []string{"v0.3.1-alpha", "v0.3.2-alpha"}, []string{"v0.3.2-alpha"}, "v0.3.3-alpha"},
		{"highest in the checkout only", []string{"v0.3.1-alpha"}, nil, "v0.3.6-alpha"},
		{"lower rc and final do not matter", []string{"v0.4.0-alpha", "v0.3.0-rc.2", "v0.3.0"}, nil, "v0.4.1-alpha"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			work, remote, agentGit := releaseFixture(t, "0.0.0", strings.TrimPrefix(c.want, "v"))
			tagFixture(t, work, c.tags, c.remoteOnly)
			if c.name == "highest in the checkout only" {
				gitIn(t, work, "tag", "v0.3.5-alpha") // never pushed: only this checkout knows it
			}
			before := remoteTags(t, remote)
			out, ok := runTarget(t, "release-alpha", work, agentGit, "")
			if !ok {
				t.Fatalf("make release-alpha failed:\n%s", out)
			}
			if want := "Next alpha: " + c.want + " "; !strings.Contains(out, want) {
				t.Errorf("output does not announce %q before writing:\n%s", want, out)
			}
			if got := gitIn(t, remote, "tag", "--list", c.want); got != c.want {
				t.Errorf("tag %s was not pushed (got %q)", c.want, got)
			}
			if got := len(remoteTags(t, remote)); got != len(before)+1 {
				t.Errorf("remote holds %d tags, want %d: exactly one is cut", got, len(before)+1)
			}
			ver, err := os.ReadFile(filepath.Join(work, "VERSION")) // #nosec G304 -- fixture path
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.TrimSpace(string(ver)); got != strings.TrimPrefix(c.want, "v") {
				t.Errorf("VERSION = %q, want %q", got, strings.TrimPrefix(c.want, "v"))
			}
		})
	}
}

// TestReleaseAlphaPrefersAnExplicitVersion: the derived version is only the
// default. An explicit VERSION cuts exactly what it says (the hand-tagged MINOR
// bump), derives nothing, and still refuses any other kind.
func TestReleaseAlphaPrefersAnExplicitVersion(t *testing.T) {
	t.Run("explicit alpha wins", func(t *testing.T) {
		work, remote, agentGit := releaseFixture(t, "0.0.0", "0.4.0-alpha", "0.3.2-alpha")
		tagFixture(t, work, []string{"v0.3.1-alpha"}, nil)
		out, ok := runTarget(t, "release-alpha", work, agentGit, "v0.4.0-alpha")
		if !ok {
			t.Fatalf("make release-alpha VERSION=v0.4.0-alpha failed:\n%s", out)
		}
		if strings.Contains(out, "Next alpha:") {
			t.Errorf("derived a version although VERSION was given:\n%s", out)
		}
		if got := gitIn(t, remote, "tag", "--list", "v0.4.0-alpha"); got != "v0.4.0-alpha" {
			t.Errorf("tag v0.4.0-alpha was not pushed (got %q)", got)
		}
		if got := gitIn(t, remote, "tag", "--list", "v0.3.2-alpha"); got != "" {
			t.Errorf("the derived version %q was cut as well", got)
		}
	})
	t.Run("empty VERSION derives", func(t *testing.T) {
		work, remote, agentGit := releaseFixture(t, "0.0.0", "0.3.2-alpha")
		tagFixture(t, work, []string{"v0.3.1-alpha"}, nil)
		cmd := exec.Command(lookPath(t, "make"), "release-alpha", "VERSION=", "AGENT_GIT="+agentGit) // #nosec G204 -- test values
		cmd.Dir = work
		cmd.Env = append(environ(nil, nil),
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("make release-alpha VERSION= failed:\n%s", out)
		}
		if got := gitIn(t, remote, "tag", "--list", "v0.3.2-alpha"); got != "v0.3.2-alpha" {
			t.Errorf("tag v0.3.2-alpha was not pushed (got %q)", got)
		}
	})
	t.Run("other kinds still refused", func(t *testing.T) {
		work, remote, agentGit := releaseFixture(t, "0.0.0", "1.0.0-rc.4")
		tagFixture(t, work, []string{"v0.3.1-alpha"}, nil)
		out, ok := runTarget(t, "release-alpha", work, agentGit, "v1.0.0-rc.4")
		if ok || !strings.Contains(out, "Use: make release-candidate VERSION=v1.0.0-rc.4") {
			t.Fatalf("an rc was not refused by release-alpha (ok=%v):\n%s", ok, out)
		}
		if got := remoteTags(t, remote); !slices.Equal(got, []string{"v0.3.1-alpha"}) {
			t.Errorf("remote tags changed on a refusal: %q", got)
		}
	})
}

// TestReleaseAlphaRefusesWhenThereIsNoAlphaTagToCountFrom: nothing to derive
// from, so it prints the explicit form instead of inventing a version. An rc or
// a final release is not an alpha tag to count from.
func TestReleaseAlphaRefusesWhenThereIsNoAlphaTagToCountFrom(t *testing.T) {
	for _, tags := range [][]string{nil, {"v1.0.0-rc.3", "v0.9.0"}} {
		t.Run(strings.Join(tags, ","), func(t *testing.T) {
			work, remote, agentGit := releaseFixture(t, "0.0.0", "0.0.1-alpha", "1.0.0-rc.4")
			tagFixture(t, work, tags, nil)
			out, ok := runTarget(t, "release-alpha", work, agentGit, "")
			if ok {
				t.Fatalf("make release-alpha succeeded with no alpha tag:\n%s", out)
			}
			for _, want := range []string{"no vX.Y.Z-alpha tag exists", "state the version explicitly: make release-alpha VERSION=vX.Y.Z-alpha"} {
				if !strings.Contains(out, want) {
					t.Errorf("refusal does not say %q:\n%s", want, out)
				}
			}
			if got := remoteTags(t, remote); !slices.Equal(got, slices.Sorted(slices.Values(tags))) {
				t.Errorf("remote tags changed on a refusal: %q", got)
			}
		})
	}
}

// TestReleaseAlphaNeverDerivesAVersionAtOrBelowAnExistingTag: semver order, not
// the alpha count alone, decides. An rc or a final release outranks the alpha of
// the same X.Y.Z, and a higher tag of any kind outranks a lower alpha. Local and
// remote-only tags both count. Every case is refused with nothing written.
func TestReleaseAlphaNeverDerivesAVersionAtOrBelowAnExistingTag(t *testing.T) {
	cases := []struct {
		name       string
		tags       []string
		remoteOnly []string
		blocker    string
	}{
		{"rc of the same X.Y.Z, local", []string{"v0.3.1-alpha", "v0.3.2-rc.1"}, nil, "v0.3.2-rc.1"},
		{"final of the same X.Y.Z, remote only", []string{"v0.3.1-alpha", "v0.3.2"}, []string{"v0.3.2"}, "v0.3.2"},
		{"rc of a higher X.Y.Z", []string{"v0.9.5-alpha", "v1.0.0-rc.3"}, nil, "v1.0.0-rc.3"},
		{"final of a higher X.Y.Z, remote only", []string{"v0.9.5-alpha", "v1.2.0"}, []string{"v1.2.0"}, "v1.2.0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			work, remote, agentGit := releaseFixture(t, "0.0.0", "0.3.2-alpha", "0.9.6-alpha")
			tagFixture(t, work, c.tags, c.remoteOnly)
			head := gitIn(t, work, "rev-parse", "HEAD")
			out, ok := runTarget(t, "release-alpha", work, agentGit, "")
			if ok {
				t.Fatalf("make release-alpha succeeded; want refusal:\n%s", out)
			}
			for _, want := range []string{"does not outrank the existing tag " + c.blocker, "state the version explicitly: make release-alpha VERSION=vX.Y.Z-alpha"} {
				if !strings.Contains(out, want) {
					t.Errorf("refusal does not say %q:\n%s", want, out)
				}
			}
			if got := gitIn(t, work, "rev-parse", "HEAD"); got != head {
				t.Errorf("HEAD moved from %s to %s on a refusal", head, got)
			}
			if got := remoteTags(t, remote); !slices.Equal(got, slices.Sorted(slices.Values(c.tags))) {
				t.Errorf("remote tags changed on a refusal: %q", got)
			}
		})
	}
}

// TestReleaseAlphaRunsEveryGuardOnTheDerivedVersion: the derived version goes
// through the same guards as a typed one, so a missing CHANGELOG section, a
// side branch or an unreachable remote refuses it with nothing cut.
func TestReleaseAlphaRunsEveryGuardOnTheDerivedVersion(t *testing.T) {
	t.Run("no changelog section", func(t *testing.T) {
		work, remote, agentGit := releaseFixture(t, "0.0.0", "0.3.1-alpha")
		tagFixture(t, work, []string{"v0.3.1-alpha"}, nil)
		out, ok := runTarget(t, "release-alpha", work, agentGit, "")
		if ok || !strings.Contains(out, "no \"## [0.3.2-alpha]\" section heading") {
			t.Fatalf("missing CHANGELOG section not refused (ok=%v):\n%s", ok, out)
		}
		if got := remoteTags(t, remote); !slices.Equal(got, []string{"v0.3.1-alpha"}) {
			t.Errorf("remote tags changed on a refusal: %q", got)
		}
	})
	t.Run("not on main", func(t *testing.T) {
		work, _, agentGit := releaseFixture(t, "0.0.0", "0.3.2-alpha")
		tagFixture(t, work, []string{"v0.3.1-alpha"}, nil)
		gitIn(t, work, "checkout", "-q", "-b", "side")
		out, ok := runTarget(t, "release-alpha", work, agentGit, "")
		if ok || !strings.Contains(out, "releases are cut from main") {
			t.Fatalf("non-main branch not refused (ok=%v):\n%s", ok, out)
		}
	})
	t.Run("unreachable remote", func(t *testing.T) {
		work, _, agentGit := releaseFixture(t, "0.0.0", "0.3.2-alpha")
		tagFixture(t, work, []string{"v0.3.1-alpha"}, nil)
		gitIn(t, work, "remote", "set-url", "dev", filepath.Join(t.TempDir(), "absent.git"))
		out, ok := runTarget(t, "release-alpha", work, agentGit, "")
		if ok || !strings.Contains(out, "could not list the tags") {
			t.Fatalf("unreachable remote not refused (ok=%v):\n%s", ok, out)
		}
		if got := gitIn(t, work, "tag", "--list", "v0.3.2-alpha"); got != "" {
			t.Errorf("a version was derived from local tags alone and cut: %q", got)
		}
	})
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
