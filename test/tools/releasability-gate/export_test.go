// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/test/internal/labstrings"
)

// These tests hold the strip-at-publish set to the mechanism that strips it.
// labstrings.DefaultStripAtPublish is the one list: a path added there that
// .gitattributes does not export-ignore, or that .dockerignore does not keep
// out of a build context, fails here rather than shipping. They read this
// checkout, so they live with the gate and not in labstrings, whose tests
// must pass in a source tree with no .git.

// gitOut runs git in root and returns its stdout, failing the test on error.
// Git is required: a missing git fails the test, it does not skip it.
func gitOut(t *testing.T, root string, stdin []byte, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...) // #nosec G204 -- fixed git argv; root is this checkout or a test repository
	cmd.Env = gitEnv(root)
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, stderr.String())
	}
	return out
}

// samplePaths turns a strip-at-publish pattern into concrete paths it must
// match: at the root and nested, where the pattern says any depth. A pattern
// this cannot expand fails the test, so a new kind of entry gets a sample
// rather than going untested.
func samplePaths(t *testing.T, pattern string) []string {
	t.Helper()
	heads := []string{pattern}
	if rest, ok := strings.CutPrefix(pattern, "**/"); ok {
		heads = []string{rest, "nested/dir/" + rest}
	}
	var out []string
	for _, h := range heads {
		names := []string{h}
		// A directory gets a file directly in it as well as one deeper: git
		// archive writes the directory's own entry only for the former.
		if dir, ok := strings.CutSuffix(h, "/**"); ok {
			names = []string{dir + "/project.yml", dir + "/sub/settings.json"}
		}
		for _, name := range names {
			if strings.ContainsAny(name, "*?[") {
				t.Fatalf("no sample path for strip-at-publish pattern %q: extend samplePaths", pattern)
			}
			if ok, err := labstrings.MatchPath(pattern, name); err != nil || !ok {
				t.Fatalf("sample %q does not match its pattern %q (%v)", name, pattern, err)
			}
			out = append(out, name)
		}
	}
	return out
}

// TestThisGitattributes_GitArchiveLeavesOutEveryStripAtPublishPath builds a
// throwaway repository carrying this tree's .gitattributes and a sample of
// every strip-at-publish path, archives it as a forge would, and requires no
// archive entry, file or directory, to name or lie under a strip-at-publish
// path, and the rest to be kept.
func TestThisGitattributes_GitArchiveLeavesOutEveryStripAtPublishPath(t *testing.T) {
	attributes, err := os.ReadFile(filepath.Join(moduleRoot(t), ".gitattributes")) // #nosec G304 -- this module's own .gitattributes
	if err != nil {
		t.Fatalf("read .gitattributes: %v", err)
	}
	keep := []string{"go.mod", "docs/README.md", ".github/workflows/ci.yml", "cmd/luks2/main.go"}
	files := map[string]string{".gitattributes": string(attributes)}
	for _, name := range keep {
		files[name] = "kept\n"
	}
	var stripped []string
	for _, rule := range labstrings.DefaultStripAtPublish {
		for _, name := range samplePaths(t, rule.Path) {
			files[name] = "internal\n"
			stripped = append(stripped, name)
		}
	}
	root := gitRepo(t, files)
	gitIn(t, root, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false",
		"commit", "-q", "-m", "fixture")

	// The archive a clean publishing checkout produces: only the committed
	// .gitattributes decides, not this machine's git configuration.
	archive, err := labstrings.ArchiveHEAD(root)
	if err != nil {
		t.Fatal(err)
	}
	archived := map[string]bool{}
	tr := tar.NewReader(bytes.NewReader(archive))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read archive: %v", err)
		}
		archived[strings.TrimSuffix(h.Name, "/")] = true
	}
	// The fixtures, among them files under .serena/ and .claude/ at the root
	// and nested, are tracked, so the archive below is built from them.
	gitIn(t, root, append([]string{"ls-files", "--error-unmatch", "--"}, stripped...)...)
	// Every entry, file or directory: a directory entry such as .serena/ shows
	// the public tree that the tool directory exists even when it is empty.
	for name := range archived {
		for _, rule := range labstrings.DefaultStripAtPublish {
			file, _ := labstrings.MatchPath(rule.Path, name)
			dir, _ := labstrings.MatchPath(rule.Path, name+"/x")
			if file || dir {
				t.Errorf("git archive ships %s (strip-at-publish %s); .gitattributes must export-ignore it", name, rule.Path)
			}
		}
	}
	for _, name := range keep {
		if !archived[name] {
			t.Errorf("git archive left out %s, which is published", name)
		}
	}
}

// TestThisDockerignore_ListsEveryStripAtPublishPath requires .dockerignore to
// carry every strip-at-publish pattern verbatim, so a broad COPY never bakes
// an internal file into an image layer.
func TestThisDockerignore_ListsEveryStripAtPublishPath(t *testing.T) {
	content, err := os.ReadFile(filepath.Join(moduleRoot(t), ".dockerignore")) // #nosec G304 -- this module's own .dockerignore
	if err != nil {
		t.Fatalf("read .dockerignore: %v", err)
	}
	listed := map[string]bool{}
	for _, line := range strings.Split(string(content), "\n") {
		listed[strings.TrimSpace(line)] = true
	}
	for _, rule := range labstrings.DefaultStripAtPublish {
		want := []string{rule.Path}
		// A directory entry also names the directory, so it is not left behind empty.
		if dir, ok := strings.CutSuffix(rule.Path, "/**"); ok {
			want = append(want, dir)
		}
		for _, line := range want {
			if !listed[line] {
				t.Errorf(".dockerignore does not list %s", line)
			}
		}
	}
}
