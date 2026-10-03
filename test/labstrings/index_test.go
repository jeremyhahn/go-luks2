// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package labstrings

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitEnv is the environment for a git process confined to dir: no inherited
// GIT_DIR or work-tree override can point it at another repository, and
// GIT_CEILING_DIRECTORIES stops discovery from climbing out of dir into
// whatever checkout the test happens to run inside.
func gitEnv(dir string) []string {
	var env []string
	for _, kv := range os.Environ() {
		switch {
		case strings.HasPrefix(kv, "GIT_DIR="),
			strings.HasPrefix(kv, "GIT_WORK_TREE="),
			strings.HasPrefix(kv, "GIT_INDEX_FILE="),
			strings.HasPrefix(kv, "GIT_CEILING_DIRECTORIES="):
			continue
		}
		env = append(env, kv)
	}
	return append(env, "GIT_CEILING_DIRECTORIES="+filepath.Dir(dir))
}

// git runs git in root and returns its trimmed stdout.
func git(t *testing.T, root, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	cmd.Env = gitEnv(root)
	cmd.Stdin = strings.NewReader(stdin)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, stderr.String())
	}
	return strings.TrimSpace(string(out))
}

// gitIndexTree writes files into a fresh repository of its own and stages
// them. These tests build their own index rather than read this module's: the
// package tests also run where there is no checkout at all (the integration
// image excludes .git/), and a test that needs the enclosing checkout fails
// there for a reason that has nothing to do with the code.
func gitIndexTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	writeFiles(t, root, files)
	git(t, root, "", "init", "-q")
	git(t, root, "", "add", "-A")
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(root))
	return root
}

// stageBlob stages content at path without writing it to the working tree,
// the state a sparse checkout leaves a path it never wrote.
func stageBlob(t *testing.T, root, mode, path, content string) {
	t.Helper()
	oid := git(t, root, content, "hash-object", "-w", "--stdin")
	git(t, root, "", "update-index", "--add", "--cacheinfo", mode+","+oid+","+path)
}

func TestIndexEntries_ReadsTheIndexSortedWithItsKinds(t *testing.T) {
	root := gitIndexTree(t, map[string]string{
		"z.go":                          "package z\n",
		"test/labstrings/labstrings.go": "package labstrings\n",
		"docs/a.md":                     "# a\n",
	})
	if err := os.Symlink("docs/a.md", filepath.Join(root, "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	git(t, root, "", "add", "link")
	git(t, root, "", "update-index", "--add", "--cacheinfo",
		"160000,1111111111111111111111111111111111111111,vendor/sub")
	// Untracked litter is nobody's release problem: it must not be listed.
	writeFiles(t, root, map[string]string{"untracked.txt": "x\n"})

	got, err := IndexEntries(root)
	if err != nil {
		t.Fatalf("IndexEntries: %v", err)
	}
	want := []Entry{
		{Path: "docs/a.md", Kind: KindFile, Content: []byte("# a\n")},
		{Path: "link", Kind: KindSymlink, Content: []byte("docs/a.md")},
		{Path: "test/labstrings/labstrings.go", Kind: KindFile, Content: []byte("package labstrings\n")},
		{Path: "vendor/sub", Kind: KindGitlink},
		{Path: "z.go", Kind: KindFile, Content: []byte("package z\n")},
	}
	if len(got) != len(want) {
		t.Fatalf("IndexEntries = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i].Path != want[i].Path || got[i].Kind != want[i].Kind || string(got[i].Content) != string(want[i].Content) {
			t.Errorf("entry %d = {%s %d %q}, want {%s %d %q}", i,
				got[i].Path, got[i].Kind, got[i].Content, want[i].Path, want[i].Kind, want[i].Content)
		}
	}
}

// The index is what the next commit carries. A value staged and then edited
// out of the working tree, a staged file deleted from the working tree, and a
// staged file a sparse checkout never wrote all still ship, so all three must
// still be reported -- by both halves of the gate.
func TestIndexEntries_TheStagedContentIsScannedNotTheWorkingTree(t *testing.T) {
	leak := "endpoint: https://198.51.100.51:8443\n" // lab-string-ok: fixture the gate must report; nothing is dialed
	script := "#!/bin/sh\nlosetup -D\n"
	root := gitIndexTree(t, map[string]string{
		"docs/sanitized-unstaged.md": leak,
		"docs/deleted-unstaged.md":   leak,
		"tools/reap-deleted":         script,
		"tools/reap-sanitized":       script,
	})
	writeFiles(t, root, map[string]string{
		"docs/sanitized-unstaged.md": "endpoint: https://luks.example.com:8443\n",
		"tools/reap-sanitized":       "package reap\n",
	})
	for _, name := range []string{"docs/deleted-unstaged.md", "tools/reap-deleted"} {
		if err := os.Remove(filepath.Join(root, filepath.FromSlash(name))); err != nil {
			t.Fatalf("remove %s: %v", name, err)
		}
	}
	stageBlob(t, root, "100644", "docs/never-checked-out.md", leak)
	stageBlob(t, root, "100755", "tools/never-checked-out", script)

	entries, err := IndexEntries(root)
	if err != nil {
		t.Fatalf("IndexEntries: %v", err)
	}

	findings, err := Scan(entries, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	reported := map[string]bool{}
	for _, f := range findings {
		reported[f.Path] = true
	}
	for _, name := range []string{"docs/sanitized-unstaged.md", "docs/deleted-unstaged.md", "docs/never-checked-out.md"} {
		if !reported[name] {
			t.Errorf("%s: the staged lab address was not reported: %v", name, findings)
		}
	}

	files, err := ScanUnpublishable(entries, DefaultUnpublishable)
	if err != nil {
		t.Fatalf("ScanUnpublishable: %v", err)
	}
	scripts := map[string]bool{}
	for _, f := range files {
		scripts[f.Path] = true
	}
	for _, name := range []string{"tools/reap-deleted", "tools/reap-sanitized", "tools/never-checked-out"} {
		if !scripts[name] {
			t.Errorf("%s: the staged script was not reported: %v", name, files)
		}
	}
}

func TestIndexEntries_RefusesADirectoryWithNoIndex(t *testing.T) {
	// A temporary directory is not a work tree. Reading it must fail loudly:
	// a gate that cannot enumerate must not report a clean tree.
	dir := t.TempDir()
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
	_, err := IndexEntries(dir)
	var listErr *ListError
	if !errors.As(err, &listErr) {
		t.Fatalf("err = %v, want *ListError", err)
	}
	if listErr.Root != dir {
		t.Errorf("ListError.Root = %q, want %q", listErr.Root, dir)
	}
}

// A blob the object store does not have -- a partial clone, a damaged
// repository -- is content that would ship and that the gate has not seen.
func TestIndexEntries_AMissingBlobFailsRatherThanPasses(t *testing.T) {
	root := gitIndexTree(t, map[string]string{"README.md": "# x\n"})
	git(t, root, "", "update-index", "--add", "--cacheinfo",
		"100644,2222222222222222222222222222222222222222,logs/run.log")

	entries, err := IndexEntries(root)
	var entryErr *IndexEntryError
	if !errors.As(err, &entryErr) {
		t.Fatalf("err = %v (entries %d), want *IndexEntryError", err, len(entries))
	}
	if entryErr.Path != "logs/run.log" || !strings.Contains(entryErr.Error(), "missing") {
		t.Errorf("error = %v, want it to name logs/run.log as missing", entryErr)
	}
}

// The gate cannot vouch for a blob it did not read, so one over the limit fails
// the gate instead of passing it. The limit is lowered for the test; the
// command's own test covers the real one.
func TestIndexEntries_ABlobOverTheLimitFailsRatherThanPasses(t *testing.T) {
	root := gitIndexTree(t, map[string]string{
		"a.txt":    "12345678",
		"huge.log": "123456789",
	})

	_, err := indexEntries(root, 8)
	var tooLarge *FileTooLargeError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("err = %v, want *FileTooLargeError", err)
	}
	if tooLarge.Path != "huge.log" || tooLarge.Size != 9 || tooLarge.Limit != 8 {
		t.Errorf("error = %+v, want huge.log at 9 bytes over an 8-byte limit", tooLarge)
	}

	// Exactly at the limit is read.
	if _, err := indexEntries(root, 9); err != nil {
		t.Fatalf("a blob at the limit was refused: %v", err)
	}
}

func TestParseStaged_RefusesWhatItDoesNotUnderstand(t *testing.T) {
	for _, record := range []string{
		"040000 1111111111111111111111111111111111111111 0\tsparse/dir/",
		"100644 1111111111111111111111111111111111111111\tno-stage",
		"no tab at all",
	} {
		var entryErr *IndexEntryError
		if _, err := parseStaged(record); !errors.As(err, &entryErr) {
			t.Errorf("%q: err = %v, want *IndexEntryError", record, err)
		}
	}
}
