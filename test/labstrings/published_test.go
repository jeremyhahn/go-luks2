// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package labstrings

import (
	"errors"
	"strings"
	"testing"
)

// TestThePlantedUnpublishableFilesAreCaught proves the gate's second half can fail: one
// of each kind this repository has actually carried, planted, and each one
// must come back.
func TestThePlantedUnpublishableFilesAreCaught(t *testing.T) {
	planted := map[string]string{
		".github/require-tool.sh":             "#!/bin/sh\nset -eu\n",
		"test/integration/docker-run.sh":      "#!/usr/bin/env bash\n",
		"CLAUDE.md":                           "# go-luks2\n",
		"test/integration/AGENTS.md":          "# mirror\n",
		".claude/settings.local.json":         "{}\n",
		".github/workflows/task-worker.yml":   "on: workflow_dispatch\n",
		".github/workflows/claude-review.yml": "on: pull_request\n",
		// No extension, but a script all the same.
		"tools/reap": "#!/bin/sh\nlosetup -D\n",
	}
	files := entriesOf(planted)

	findings, err := ScanUnpublishable(files, DefaultUnpublishable)
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

	findings, err := ScanUnpublishable(entries, DefaultUnpublishable)
	if err != nil {
		t.Fatalf("ScanUnpublishable: %v", err)
	}
	if len(findings) != 1 || findings[0].Path != "tools/self-extracting" {
		t.Fatalf("findings = %v, want exactly tools/self-extracting", findings)
	}
}

func TestScanUnpublishable_AcceptsWhatShips(t *testing.T) {
	files := entriesOf(map[string]string{
		"README.md":                      "# go-luks2\n",
		"docs/cli/key-input.md":          "Example:\n\n```\n#!/bin/sh\n```\n",
		".github/workflows/ci.yml":       "on: push\n",
		".github/workflows/release.yml":  "on: push\n",
		"test/integration/Dockerfile":    "FROM golang\n",
		"test/integration/seccomp.json":  "{}\n",
		"test/ci/cmd/require-tool/x.go":  "package main\n",
		"docs/CLAUDE.md.txt":             "not the file\n",
		"pkg/luks2/claude_test_names.go": "package luks2\n",
	})
	findings, err := ScanUnpublishable(files, DefaultUnpublishable)
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
	if _, err := ScanUnpublishable(files, []Unpublishable{{Path: "**/*.sh"}}); err == nil {
		t.Fatal("a rule with no reason was accepted by the scan")
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

	findings, err := ScanUnpublishable(entriesOf(files), DefaultUnpublishable)
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
		if !strings.Contains(reason, "ci.yml, nightly.yml and release.yml") {
			t.Errorf("%s: reason does not name the public workflows: %q", name, reason)
		}
	}
	if len(findings) != len(rejected) {
		t.Errorf("findings = %v, want exactly the %d rejected workflows", findings, len(rejected))
	}
}

// A pending workflow is neither a finding nor publishable: ScanUnpublishable
// passes it and Pending lists it. Its .yaml variant and a nested copy are not
// pending -- the exemption is the exact name -- and fail like any unknown
// workflow.
func TestPending_ListsThePendingWorkflowAndNothingElse(t *testing.T) {
	files := map[string]string{
		".github/workflows/automerge.yml":     "on: push\n",
		".github/workflows/automerge.yaml":    "on: push\n",
		".github/workflows/sub/automerge.yml": "on: push\n",
		".github/workflows/ci.yml":            "on: push\n",
		"docs/automerge.yml":                  "not a workflow\n",
	}
	entries := entriesOf(files)

	findings, err := ScanUnpublishable(entries, DefaultUnpublishable)
	if err != nil {
		t.Fatalf("ScanUnpublishable: %v", err)
	}
	failed := map[string]bool{}
	for _, f := range findings {
		failed[f.Path] = true
	}
	if failed[".github/workflows/automerge.yml"] {
		t.Error("the pending workflow failed the scan; it is listed as open, not failed")
	}
	for _, name := range []string{".github/workflows/automerge.yaml", ".github/workflows/sub/automerge.yml"} {
		if !failed[name] {
			t.Errorf("%s passed the scan; only the exact pending name is exempt", name)
		}
	}

	open := Pending(entries)
	if len(open) != 1 || open[0].Path != ".github/workflows/automerge.yml" {
		t.Fatalf("Pending = %v, want exactly .github/workflows/automerge.yml", open)
	}
	if !strings.Contains(open[0].Reason, "owner ruling") {
		t.Errorf("the pending reason does not say what settles it: %q", open[0].Reason)
	}
}

// Every pending workflow carries a reason, and none is also a public one.
func TestPendingWorkflows_AreReasonedAndNotPublished(t *testing.T) {
	for name, reason := range PendingWorkflows {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("%s has no reason", name)
		}
		for _, published := range PublishedWorkflows {
			if name == published {
				t.Errorf("%s is both pending and published", name)
			}
		}
	}
}
