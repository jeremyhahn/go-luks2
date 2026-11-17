// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package labstrings

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// TestThePlantedUnpublishableFilesAreCaught proves the gate's second half can fail: one
// of each kind this repository has actually carried, planted, and each one
// must come back. Agent instructions are no longer among them -- they are
// stripped at publish (#252), see TestScanUnpublishable_AgentFilesAreStrippedNotFailed
// -- but a script or a workflow under an agent directory still fails.
func TestThePlantedUnpublishableFilesAreCaught(t *testing.T) {
	planted := map[string]string{
		".github/require-tool.sh":             "#!/bin/sh\nset -eu\n",
		"test/integration/docker-run.sh":      "#!/usr/bin/env bash\n",
		".claude/hooks/pre-commit.sh":         "#!/bin/sh\n",
		".github/workflows/task-worker.yml":   "on: workflow_dispatch\n",
		".github/workflows/claude-review.yml": "on: pull_request\n",
		// No extension, but a script all the same.
		"tools/reap": "#!/bin/sh\nlosetup -D\n",
	}
	files := entriesOf(planted)

	findings, err := ScanUnpublishable(files, DefaultUnpublishable, DefaultStripAtPublish)
	if err != nil {
		t.Fatalf("ScanUnpublishable: %v", err)
	}
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Path] = true
		if f.Reason == "" {
			t.Errorf("%s: finding carries no reason", f.Path)
		}
	}
	for name := range planted {
		if !got[name] {
			t.Errorf("%s was not reported: %v", name, findings)
		}
	}

	var report strings.Builder
	dirty, err := ReportUnpublishable(&report, findings)
	if err != nil {
		t.Fatalf("ReportUnpublishable: %v", err)
	}
	if !dirty {
		t.Fatal("the report says a tree with planted files is clean")
	}
	for _, want := range []string{"tools/reap", "#211", "git rm --cached"} {
		if !strings.Contains(report.String(), want) {
			t.Errorf("report omits %q:\n%s", want, report.String())
		}
	}
}

// The shebang check reads the staged content of every regular file, so a
// binary payload after the interpreter line does not hide a script, and a
// symlink whose target happens to start with #! is not one.
func TestScanUnpublishable_CatchesAScriptWhateverItCarries(t *testing.T) {
	entries := entriesOf(map[string]string{
		"tools/self-extracting": "#!/bin/sh\nexec tail -c +64 \"$0\"\n\x00\x01\x02payload",
	})
	entries = append(entries, Entry{Path: "tools/odd-link", Kind: KindSymlink, Content: []byte("#!weird-name")})

	findings, err := ScanUnpublishable(entries, DefaultUnpublishable, DefaultStripAtPublish)
	if err != nil {
		t.Fatalf("ScanUnpublishable: %v", err)
	}
	if len(findings) != 1 || findings[0].Path != "tools/self-extracting" {
		t.Fatalf("findings = %v, want exactly tools/self-extracting", findings)
	}
}

func TestScanUnpublishable_AcceptsWhatShips(t *testing.T) {
	files := entriesOf(map[string]string{
		"README.md":                        "# go-luks2\n",
		"docs/cli/key-input.md":            "Example:\n\n```\n#!/bin/sh\n```\n",
		".github/workflows/ci.yml":         "on: push\n",
		".github/workflows/release.yml":    "on: push\n",
		".github/workflows/signatures.yml": "on: pull_request_target\n",
		"test/integration/Dockerfile":      "FROM golang\n",
		"test/integration/seccomp.json":    "{}\n",
		"test/ci/cmd/require-tool/x.go":    "package main\n",
		"docs/CLAUDE.md.txt":               "not the file\n",
		"pkg/luks2/claude_test_names.go":   "package luks2\n",
	})
	findings, err := ScanUnpublishable(files, DefaultUnpublishable, DefaultStripAtPublish)
	if err != nil {
		t.Fatalf("ScanUnpublishable: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %v", findings)
	}
}

func TestValidateUnpublishable_RefusesEveryUnusableEntry(t *testing.T) {
	cases := []struct {
		rule    Unpublishable
		problem string
	}{
		{Unpublishable{Reason: "because it must not ship"}, "no path pattern"},
		{Unpublishable{Path: "**/*.sh"}, "no reason given"},
		{Unpublishable{Path: "**/*.sh", Reason: "  "}, "no reason given"},
		{Unpublishable{Path: "x/[a-", Reason: "because"}, "malformed path pattern"},
	}
	for _, tc := range cases {
		err := ValidateUnpublishable([]Unpublishable{tc.rule})
		var ruleErr *AllowRuleError
		if !errors.As(err, &ruleErr) {
			t.Fatalf("%+v: err = %v, want *AllowRuleError", tc.rule, err)
		}
		if !strings.Contains(ruleErr.Error(), tc.problem) {
			t.Errorf("%+v: %q does not report %q", tc.rule, ruleErr.Error(), tc.problem)
		}
	}

	files := entriesOf(map[string]string{"a.txt": "x\n"})
	if _, err := ScanUnpublishable(files, []Unpublishable{{Path: "**/*.sh"}}, DefaultStripAtPublish); err == nil {
		t.Fatal("a rule with no reason was accepted by the scan")
	}
	var stripErr *AllowRuleError
	if _, err := ScanUnpublishable(files, DefaultUnpublishable, []Unpublishable{{Path: "CLAUDE.md"}}); !errors.As(err, &stripErr) {
		t.Fatalf("a strip-at-publish rule with no reason: err = %v, want *AllowRuleError", err)
	}
}

func TestDefaultUnpublishable_IsUsable(t *testing.T) {
	if err := ValidateUnpublishable(DefaultUnpublishable); err != nil {
		t.Fatalf("the shipped list is not usable: %v", err)
	}
}

func TestReportUnpublishable_AWriteFailureIsATypedError(t *testing.T) {
	dirty, err := ReportUnpublishable(failingWriter{}, []FileFinding{{Path: "x.sh", Reason: "r"}})
	if !dirty {
		t.Error("dirty = false although findings were passed")
	}
	var reportErr *ReportError
	if !errors.As(err, &reportErr) {
		t.Fatalf("err = %v, want *ReportError", err)
	}

	var clean strings.Builder
	dirty, err = ReportUnpublishable(&clean, nil)
	if err != nil || dirty || clean.Len() != 0 {
		t.Errorf("a clean report: dirty=%v err=%v wrote %q", dirty, err, clean.String())
	}
}

// Only the named public workflows ship. The check is an allow-list, so an
// alternate extension, a renamed factory workflow or a nested file under the
// workflows directory fails as surely as the original name did.
func TestScanUnpublishable_OnlyThePublicWorkflowsShip(t *testing.T) {
	rejected := []string{
		".github/workflows/task-worker.yaml",
		".github/workflows/ci.yaml",
		".github/workflows/Release.yml",
		".github/workflows/signatures.yaml",
		".github/workflows/sub/signatures.yml",
		".github/workflows/factory-dispatch.yml",
		".github/workflows/sub/ci.yml",
		".github/workflows/README.md",
	}
	files := map[string]string{}
	for _, name := range rejected {
		files[name] = "on: push\n"
	}
	for _, name := range PublishedWorkflows {
		files[".github/workflows/"+name] = "on: push\n"
	}

	findings, err := ScanUnpublishable(entriesOf(files), DefaultUnpublishable, DefaultStripAtPublish)
	if err != nil {
		t.Fatalf("ScanUnpublishable: %v", err)
	}
	got := map[string]string{}
	for _, f := range findings {
		got[f.Path] = f.Reason
	}
	for _, name := range rejected {
		reason, ok := got[name]
		if !ok {
			t.Errorf("%s was not reported: %v", name, findings)
			continue
		}
		if !strings.Contains(reason, "ci.yml, nightly.yml, release.yml and signatures.yml") {
			t.Errorf("%s: reason does not name the public workflows: %q", name, reason)
		}
	}
	if len(findings) != len(rejected) {
		t.Errorf("findings = %v, want exactly the %d rejected workflows", findings, len(rejected))
	}
}

// TestPublishedWorkflows_CarriesTheSignatureGate: the public repository's
// required Signatures check comes from signatures.yml, so the release must
// ship it, by that exact name, and must not strip it.
func TestPublishedWorkflows_CarriesTheSignatureGate(t *testing.T) {
	want := []string{"ci.yml", "nightly.yml", "release.yml", "signatures.yml"}
	if !slices.Equal(PublishedWorkflows, want) {
		t.Fatalf("PublishedWorkflows = %v, want %v", PublishedWorkflows, want)
	}
	path := ".github/workflows/signatures.yml"
	files := entriesOf(map[string]string{path: "on: pull_request_target\n"})
	findings, err := ScanUnpublishable(files, DefaultUnpublishable, DefaultStripAtPublish)
	if err != nil {
		t.Fatalf("ScanUnpublishable: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("%s is refused: %v", path, findings)
	}
	if listed := StripAtPublish(files, DefaultStripAtPublish); len(listed) != 0 {
		t.Errorf("%s is stripped at publish: %v", path, listed)
	}
}

// The internal review workflow is tracked on main and stripped at publish:
// ScanUnpublishable passes it and StripAtPublish lists it. Exact names only,
// so a `.yaml` variant or a nested copy is still an unknown workflow and fails.
func TestStripAtPublish_ListsTheReviewWorkflows(t *testing.T) {
	reviewWorkflows := []string{".github/workflows/code-review.yml"}
	files := map[string]string{
		".github/workflows/code-review.yml":     "on: pull_request\n",
		".github/workflows/code-review.yaml":    "on: pull_request\n",
		".github/workflows/sub/code-review.yml": "on: pull_request\n",
		".github/workflows/ci.yml":              "on: push\n",
	}
	entries := entriesOf(files)

	findings, err := ScanUnpublishable(entries, DefaultUnpublishable, DefaultStripAtPublish)
	if err != nil {
		t.Fatalf("ScanUnpublishable: %v", err)
	}
	failed := map[string]bool{}
	for _, f := range findings {
		failed[f.Path] = true
	}
	for _, name := range reviewWorkflows {
		if failed[name] {
			t.Errorf("%s failed the scan; it is stripped at publish, not failed", name)
		}
	}
	for _, name := range []string{".github/workflows/code-review.yaml", ".github/workflows/sub/code-review.yml"} {
		if !failed[name] {
			t.Errorf("%s passed the scan; only the exact name is stripped", name)
		}
	}

	stripped := map[string]string{}
	for _, s := range StripAtPublish(entries, DefaultStripAtPublish) {
		stripped[s.Path] = s.Reason
	}
	if len(stripped) != len(reviewWorkflows) {
		t.Errorf("StripAtPublish = %v, want exactly %v", stripped, reviewWorkflows)
	}
	for _, name := range reviewWorkflows {
		reason, ok := stripped[name]
		if !ok {
			t.Errorf("%s is not stripped at publish", name)
			continue
		}
		if !strings.Contains(reason, "#211") {
			t.Errorf("%s: the reason does not name the release issue: %q", name, reason)
		}
	}
}

// Agent instructions are tracked on main and stripped at publish (owner
// ruling 2026-10-04, #252): at the root or nested, they pass the scan and are
// listed. Content checks still apply -- a script under .claude/ fails as a
// script -- and lookalike names are ordinary files.
func TestScanUnpublishable_AgentFilesAreStrippedNotFailed(t *testing.T) {
	agentFiles := []string{
		"CLAUDE.md",
		"AGENTS.md",
		"test/integration/CLAUDE.md",
		"test/integration/AGENTS.md",
		".claude/settings.json",
		".claude/agents/go-luks2.md",
		"cmd/.claude/settings.json",
	}
	files := map[string]string{
		".claude/hooks/guard.sh": "#!/bin/sh\n",
		".claude/hooks/guard":    "#!/bin/sh\n",
		"docs/CLAUDE.md.txt":     "not the file\n",
		"docs/claude.md":         "not the file either\n",
	}
	for _, name := range agentFiles {
		files[name] = "# agent notes\n"
	}
	entries := entriesOf(files)

	findings, err := ScanUnpublishable(entries, DefaultUnpublishable, DefaultStripAtPublish)
	if err != nil {
		t.Fatalf("ScanUnpublishable: %v", err)
	}
	failed := map[string]string{}
	for _, f := range findings {
		failed[f.Path] = f.Reason
	}
	for _, name := range agentFiles {
		if reason, ok := failed[name]; ok {
			t.Errorf("%s failed the scan (%s); agent files are stripped at publish", name, reason)
		}
	}
	for _, name := range []string{".claude/hooks/guard.sh", ".claude/hooks/guard"} {
		if !strings.Contains(failed[name], "no shell scripts") {
			t.Errorf("%s: a script under .claude/ must fail as a script, got %q", name, failed[name])
		}
	}
	if len(findings) != 2 {
		t.Errorf("findings = %v, want exactly the two scripts", findings)
	}

	listed := map[string]string{}
	for _, f := range StripAtPublish(entries, DefaultStripAtPublish) {
		listed[f.Path] = f.Reason
	}
	for _, name := range agentFiles {
		if !strings.Contains(listed[name], "#252") {
			t.Errorf("%s: not listed as stripped at publish with its ruling: %q", name, listed[name])
		}
	}
	for _, name := range []string{"docs/CLAUDE.md.txt", "docs/claude.md"} {
		if _, ok := listed[name]; ok {
			t.Errorf("%s is listed as an agent file; only the exact names are", name)
		}
	}
}

// The strip list is usable, carries a reason per entry, and never strips a
// public workflow -- a rule that did would publish a release without its CI.
func TestDefaultStripAtPublish_IsUsableAndStripsNothingPublished(t *testing.T) {
	if err := ValidateUnpublishable(DefaultStripAtPublish); err != nil {
		t.Fatalf("the shipped strip list is not usable: %v", err)
	}
	for _, name := range PublishedWorkflows {
		path := ".github/workflows/" + name
		if listed := StripAtPublish(entriesOf(map[string]string{path: "on: push\n"}), DefaultStripAtPublish); len(listed) != 0 {
			t.Errorf("%s is both published and stripped: %v", path, listed)
		}
	}
}
