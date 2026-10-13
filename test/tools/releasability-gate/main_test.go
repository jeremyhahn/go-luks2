// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/test/internal/labstrings"
)

// entriesOf returns an index reader that reports exactly files, standing in for
// the git index.
func entriesOf(files map[string]string) indexReader {
	entries := make([]labstrings.Entry, 0, len(files))
	for name, content := range files {
		// As this repository's .gitattributes does: every strip-at-publish
		// file is export-ignored.
		stripped := len(labstrings.StripAtPublish([]labstrings.Entry{{Path: name}}, labstrings.DefaultStripAtPublish)) > 0
		entries = append(entries, labstrings.Entry{Path: name, Kind: labstrings.KindFile, Content: []byte(content), ExportIgnored: stripped})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return func(string) ([]labstrings.Entry, error) { return entries, nil }
}

// gitRepo writes files into a fresh repository of its own and stages them.
func gitRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	gitIn(t, root, "init", "-q")
	gitIn(t, root, "add", "-A")
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(root))
	return root
}

// gitIn runs git confined to root.
func gitIn(t *testing.T, root string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	cmd.Env = gitEnv(root)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// gitEnv confines a git process to dir; see labstrings' helper of the same name.
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

func runGate(root string, read indexReader) (int, string, string) {
	var stdout, stderr strings.Builder
	code := run([]string{root}, read, repositoryPolicy, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestRun_ACleanTreePasses(t *testing.T) {
	list := entriesOf(map[string]string{
		"go.mod":        "module example.com/x\n",
		"pkg/x/x.go":    "package x\n",
		"docs/guide.md": "Mount it with luks2 mount.\n",
	})
	code, stdout, stderr := runGate(t.TempDir(), list)
	if code != exitClean {
		t.Fatalf("exit = %d, want %d; stderr:\n%s", code, exitClean, stderr)
	}
	if !strings.Contains(stdout, "3 tracked files") {
		t.Errorf("stdout does not say how much it scanned: %q", stdout)
	}
}

func TestRun_ALabValueFails(t *testing.T) {
	list := entriesOf(map[string]string{
		"cmd/luks2/help.go": "const help = \"--keyserver https://198.51.100.51:8443\"\n", // lab-string-ok: fixture the gate must report; nothing is dialed
	})
	code, _, stderr := runGate(t.TempDir(), list)
	if code != exitDirty {
		t.Fatalf("exit = %d, want %d; stderr:\n%s", code, exitDirty, stderr)
	}
	if !strings.Contains(stderr, "cmd/luks2/help.go") {
		t.Errorf("report does not name the file:\n%s", stderr)
	}
}

func TestRun_AnUnpublishableFileFails(t *testing.T) {
	for _, name := range []string{"tools/reap.bash", "test/integration/docker-run.sh", ".github/workflows/task-worker.yml", ".github/workflows/claude-review.yml"} {
		t.Run(name, func(t *testing.T) {
			list := entriesOf(map[string]string{name: "x\n"})
			code, _, stderr := runGate(t.TempDir(), list)
			if code != exitDirty {
				t.Fatalf("exit = %d, want %d; stderr:\n%s", code, exitDirty, stderr)
			}
			if !strings.Contains(stderr, name) {
				t.Errorf("report does not name %s:\n%s", name, stderr)
			}
		})
	}
}

// A staged blob the scanner will not read is a gate that did not run for that
// file, so the verdict is "could not run", never "publishable". This goes
// through a real index, at the real limit.
func TestRun_AFileTooLargeToScanFailsRatherThanPasses(t *testing.T) {
	root := gitRepo(t, map[string]string{"README.md": "# x\n"})
	huge, err := os.Create(filepath.Join(root, "capture.log"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := huge.Truncate(33 << 20); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if err := huge.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	gitIn(t, root, "add", "capture.log")

	code, stdout, stderr := runGate(root, labstrings.IndexEntries)
	if code != exitFailed {
		t.Fatalf("exit = %d, want %d; stderr:\n%s", code, exitFailed, stderr)
	}
	if stdout != "" {
		t.Errorf("a gate that did not read every file printed a verdict: %q", stdout)
	}
	if !strings.Contains(stderr, "capture.log") {
		t.Errorf("stderr does not name the unread file: %q", stderr)
	}
}

// The index is what ships. A lab value staged and then edited out of the
// working tree without staging the edit is still in the next commit, so the
// gate must still fail on it.
func TestRun_AStagedValueHiddenByAnUnstagedEditFails(t *testing.T) {
	root := gitRepo(t, map[string]string{
		"docs/guide.md": "endpoint: https://198.51.100.51:8443\n", // lab-string-ok: fixture the gate must report; nothing is dialed
	})
	if err := os.WriteFile(filepath.Join(root, "docs", "guide.md"), []byte("endpoint: https://luks.example.com\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	code, _, stderr := runGate(root, labstrings.IndexEntries)
	if code != exitDirty {
		t.Fatalf("exit = %d, want %d; stderr:\n%s", code, exitDirty, stderr)
	}
	if !strings.Contains(stderr, "docs/guide.md") {
		t.Errorf("report does not name the file:\n%s", stderr)
	}
}

func TestRun_AnUnlistableRootFailsRatherThanPasses(t *testing.T) {
	listErr := &labstrings.ListError{Root: "/nowhere", Stderr: "fatal: not a git repository", Err: errors.New("exit status 128")}
	code, stdout, stderr := runGate("/nowhere", func(string) ([]labstrings.Entry, error) { return nil, listErr })
	if code != exitFailed {
		t.Fatalf("exit = %d, want %d", code, exitFailed)
	}
	if stdout != "" {
		t.Errorf("a gate that could not list printed a verdict: %q", stdout)
	}
	if !strings.Contains(stderr, "not a git repository") {
		t.Errorf("stderr does not carry git's reason: %q", stderr)
	}
}

func TestRun_AnEmptyIndexIsRefused(t *testing.T) {
	code, _, stderr := runGate(t.TempDir(), func(string) ([]labstrings.Entry, error) { return nil, nil })
	if code != exitFailed {
		t.Fatalf("exit = %d, want %d", code, exitFailed)
	}
	if !strings.Contains(stderr, "lists no files") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestRun_NeedsExactlyOneRoot(t *testing.T) {
	for _, args := range [][]string{nil, {"a", "b"}} {
		var stderr strings.Builder
		code := run(args, func(string) ([]labstrings.Entry, error) {
			t.Fatal("listed files for a bad invocation")
			return nil, nil
		}, repositoryPolicy, io.Discard, &stderr)
		if code != exitFailed {
			t.Errorf("args %q: exit = %d, want %d", args, code, exitFailed)
		}
		if !strings.Contains(stderr.String(), "usage:") {
			t.Errorf("args %q: stderr = %q", args, stderr.String())
		}
	}
}

// TestRun_ReadsARealIndex runs the command's real index reader against a
// repository the test builds for itself, so the git-backed path is covered
// without depending on the checkout the test runs in (there may be none).
func TestRun_ReadsARealIndex(t *testing.T) {
	root := gitRepo(t, map[string]string{"tools/run.sh": "#!/bin/sh\n", "go.mod": "module example.com/x\n"})
	code, _, stderr := runGate(root, labstrings.IndexEntries)
	if code != exitDirty {
		t.Fatalf("exit = %d, want %d; stderr:\n%s", code, exitDirty, stderr)
	}

	plain := t.TempDir()
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(plain))
	if code, _, _ := runGate(plain, labstrings.IndexEntries); code != exitFailed {
		t.Fatalf("a directory with no index: exit = %d, want %d", code, exitFailed)
	}
}

// moduleRoot walks up from the working directory to go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod above the working directory")
		}
		dir = parent
	}
}

// TestRun_RefusesToRunOnABrokenPolicy: a malformed allow-list or rule list is
// an error (exit 2), never a clean pass over rules that match nothing.
func TestRun_RefusesToRunOnABrokenPolicy(t *testing.T) {
	read := entriesOf(map[string]string{"README.md": "nothing to see\n"})
	broken := map[string]policy{
		"allow-list":         {allow: []labstrings.AllowRule{{Path: ""}}, unpublishable: labstrings.DefaultUnpublishable, strip: labstrings.DefaultStripAtPublish},
		"unpublishable list": {allow: labstrings.DefaultAllowList, unpublishable: []labstrings.Unpublishable{{Path: "x"}}, strip: labstrings.DefaultStripAtPublish},
		"strip list":         {allow: labstrings.DefaultAllowList, unpublishable: labstrings.DefaultUnpublishable, strip: []labstrings.Unpublishable{{Path: "x"}}},
	}
	for name, p := range broken {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			if code := run([]string{"."}, read, p, &stdout, &stderr); code != exitFailed {
				t.Fatalf("exit = %d, want %d; stderr %q", code, exitFailed, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Errorf("a gate that could not run reported %q", stdout.String())
			}
		})
	}
}

// failingWriter refuses every write.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// TestRun_AReportThatCannotBeWrittenIsAFailure: the findings must reach the
// reader; a dirty tree whose report is lost exits 2, not 1 and never 0.
func TestRun_AReportThatCannotBeWrittenIsAFailure(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"lab value":          {"notes.txt": "ssh jhahn@vm-host-4\n"}, // lab-string-ok: the fixture the gate must catch
		"unpublishable file": {"tools/run.sh": "#!/bin/sh\n"},
	} {
		t.Run(name, func(t *testing.T) {
			if code := run([]string{"."}, entriesOf(files), repositoryPolicy, io.Discard, failingWriter{}); code != exitFailed {
				t.Fatalf("exit = %d, want %d", code, exitFailed)
			}
		})
	}
}

// TestRun_AStripAtPublishFileIsListedAsExportIgnored: exit 0, and the output
// names each file .gitattributes keeps out of every archive of the tree.
func TestRun_AStripAtPublishFileIsListedAsExportIgnored(t *testing.T) {
	read := entriesOf(map[string]string{
		".github/workflows/ci.yml":        "on: push\n",
		".github/workflows/automerge.yml": "on: push\n",
		"CLAUDE.md":                       "# agent notes\n",
	})
	code, stdout, stderr := runGate(".", read)
	if code != exitClean {
		t.Fatalf("exit = %d, want %d; stderr %q", code, exitClean, stderr)
	}
	for _, want := range []string{"excluded from every archive by .gitattributes", ".github/workflows/automerge.yml", "CLAUDE.md"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	for _, old := range []string{"NOT YET PUBLISHABLE", "tracked files, publishable"} {
		if strings.Contains(stdout, old) {
			t.Errorf("stdout = %q says %q", stdout, old)
		}
	}
}

// A strip-at-publish file that .gitattributes does not export-ignore would
// ship in the archive the public tree is made from: it is a finding, named
// with what to add.
func TestRun_AStripAtPublishFileNotExportIgnoredFails(t *testing.T) {
	read := func(string) ([]labstrings.Entry, error) {
		return []labstrings.Entry{
			{Path: "AGENTS.md", Kind: labstrings.KindFile, Content: []byte("# agent notes\n"), ExportIgnored: true},
			{Path: "CLAUDE.md", Kind: labstrings.KindFile, Content: []byte("# agent notes\n")},
		}, nil
	}
	code, stdout, stderr := runGate(".", read)
	if code != exitDirty {
		t.Fatalf("exit = %d, want %d; stderr %q", code, exitDirty, stderr)
	}
	if !strings.Contains(stderr, "CLAUDE.md: listed as stripped at publish") || !strings.Contains(stderr, labstrings.GitAttributes) {
		t.Errorf("report does not name CLAUDE.md and %s:\n%s", labstrings.GitAttributes, stderr)
	}
	if strings.Contains(stderr, "AGENTS.md:") {
		t.Errorf("an export-ignored file is reported:\n%s", stderr)
	}
	if stdout != "" {
		t.Errorf("a failing gate printed a verdict: %q", stdout)
	}
}

// TestRun_TrackedAgentFilesPassARealIndex: CLAUDE.md, a nested AGENTS.md and a
// .claude/ file, tracked in a real index beside this repository's
// .gitattributes, pass the gate and are each listed as stripped at publish; a
// script beside them still fails it, and so does each of them once no
// .gitattributes export-ignores it.
func TestRun_TrackedAgentFilesPassARealIndex(t *testing.T) {
	attributes, err := os.ReadFile(filepath.Join(moduleRoot(t), labstrings.GitAttributes)) // #nosec G304 -- this module's own .gitattributes
	if err != nil {
		t.Fatalf("read %s: %v", labstrings.GitAttributes, err)
	}
	agentFiles := map[string]string{
		"CLAUDE.md":                  "# agent notes\n",
		"AGENTS.md":                  "# agent notes\n",
		"test/integration/AGENTS.md": "# agent notes\n",
		".claude/settings.json":      "{}\n",
	}
	files := map[string]string{"go.mod": "module example.com/x\n", labstrings.GitAttributes: string(attributes)}
	for name, content := range agentFiles {
		files[name] = content
	}
	code, stdout, stderr := runGate(gitRepo(t, files), labstrings.IndexEntries)
	if code != exitClean {
		t.Fatalf("exit = %d, want %d; stderr:\n%s", code, exitClean, stderr)
	}
	for name := range agentFiles {
		if !strings.Contains(stdout, name+": ") {
			t.Errorf("%s is not listed as stripped at publish:\n%s", name, stdout)
		}
	}

	files["tools/run.sh"] = "#!/bin/sh\n"
	code, _, stderr = runGate(gitRepo(t, files), labstrings.IndexEntries)
	if code != exitDirty || !strings.Contains(stderr, "tools/run.sh") {
		t.Fatalf("exit = %d, stderr %q; want %d naming the script", code, stderr, exitDirty)
	}
	for name := range agentFiles {
		if strings.Contains(stderr, name+": ") {
			t.Errorf("%s is reported as a finding:\n%s", name, stderr)
		}
	}

	// Without the export-ignore entries every agent file is a finding.
	delete(files, "tools/run.sh")
	delete(files, labstrings.GitAttributes)
	code, _, stderr = runGate(gitRepo(t, files), labstrings.IndexEntries)
	if code != exitDirty {
		t.Fatalf("no %s: exit = %d, want %d; stderr:\n%s", labstrings.GitAttributes, code, exitDirty, stderr)
	}
	for name := range agentFiles {
		if !strings.Contains(stderr, name+": listed as stripped at publish") {
			t.Errorf("%s is not reported as missing from %s:\n%s", name, labstrings.GitAttributes, stderr)
		}
	}
}

// failAfter accepts n writes, then refuses every one after.
type failAfter struct{ n int }

func (w *failAfter) Write(p []byte) (int, error) {
	if w.n == 0 {
		return 0, errors.New("disk full")
	}
	w.n--
	return len(p), nil
}

// TestRun_AQualificationThatCannotBeWrittenIsAFailure: the strip notice and
// the exemption list are what make a clean exit honest, so losing either --
// at its header or at an item -- exits 2, as does losing the final verdict.
func TestRun_AQualificationThatCannotBeWrittenIsAFailure(t *testing.T) {
	stripped := entriesOf(map[string]string{
		".github/workflows/ci.yml":        "on: push\n",
		".github/workflows/automerge.yml": "on: push\n",
	})
	exempt := func(string) ([]labstrings.Entry, error) {
		return []labstrings.Entry{
			{Path: "fixture.bin", Kind: labstrings.KindFile, Content: []byte("\x00"), Exemption: "a golden fixture"},
		}, nil
	}
	clean := entriesOf(map[string]string{"README.md": "text\n"})

	for name, tc := range map[string]struct {
		read   indexReader
		writes int
	}{
		"strip header":     {stripped, 0},
		"strip item":       {stripped, 1},
		"exemption header": {exempt, 0},
		"exemption item":   {exempt, 1},
		"final verdict":    {clean, 0},
	} {
		t.Run(name, func(t *testing.T) {
			var stderr strings.Builder
			if code := run([]string{"."}, tc.read, repositoryPolicy, &failAfter{n: tc.writes}, &stderr); code != exitFailed {
				t.Fatalf("exit = %d, want %d", code, exitFailed)
			}
			if !strings.Contains(stderr.String(), "disk full") {
				t.Errorf("stderr = %q, want the write failure", stderr.String())
			}
		})
	}
}

// TestRun_ListsWhatAnExemptionAccepted: an exempt binary passes, and the
// output names it with its reason rather than accepting it silently.
func TestRun_ListsWhatAnExemptionAccepted(t *testing.T) {
	read := func(string) ([]labstrings.Entry, error) {
		return []labstrings.Entry{
			{Path: "fixture.bin", Kind: labstrings.KindFile, Content: []byte("\x00"), Exemption: "a golden fixture"},
			{Path: "huge.img", Kind: labstrings.KindFile, Exemption: "a captured image", Unread: true},
		}, nil
	}
	code, stdout, stderr := runGate(".", read)
	if code != exitClean {
		t.Fatalf("exit = %d, want %d; stderr %q", code, exitClean, stderr)
	}
	for _, want := range []string{labstrings.ExemptFile, "fixture.bin: a golden fixture", "huge.img: NOT READ", "publishable"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
}

// TestRun_AnUnexemptedBinaryFails through the command.
func TestRun_AnUnexemptedBinaryFails(t *testing.T) {
	code, _, stderr := runGate(".", entriesOf(map[string]string{"capture.bin": "\x00\x01payload"}))
	if code != exitDirty || !strings.Contains(stderr, "capture.bin: a binary file") {
		t.Fatalf("exit %d, stderr %q; want %d and the binary named", code, stderr, exitDirty)
	}
}
