// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package labstrings

import (
	"bytes"
	"fmt"
	"io"
	"path"
	"strings"
)

// The second half of the gate. A lab value is a line that has to change; the
// files below are files the public release must not carry at all, whatever is
// in them. Both are enforced for the same reason: the published tree is an
// archive export of the release commit, so the only place to keep something
// out of it is the source -- the file itself, or its export-ignore entry in
// GitAttributes -- before tagging.

// Unpublishable is one kind of tracked file the public release must not carry.
type Unpublishable struct {
	// Path is a pattern in AllowRule's syntax: `*` within a segment, `**`
	// across any number of them.
	Path string

	// Reason says why the file cannot ship and what to do instead. It is
	// printed with every finding, so the engineer who trips it does not have
	// to come looking for the ruling.
	Reason string
}

// noShellScripts is the reason shared by every script rule.
const noShellScripts = "the public release ships no shell scripts (owner ruling on #211): " +
	"write it as a Go command under test/ or cmd/, or as a Makefile recipe"

// agentInstructions is the reason shared by the agent-file strip rules.
const agentInstructions = "agent instructions: tracked in every repository and stripped at publish " +
	"(standards project-scaffold.md §7, #252); the public release removes them (#211)"

// workflowDir is where GitHub and Gitea Actions look for workflows.
const workflowDir = ".github/workflows/"

// PublishedWorkflows is every workflow file the public release carries, by
// exact name under workflowDir. It is an allow-list, not a deny-list: a
// deny-list of the internal factory workflows is defeated by a `.yaml`
// extension or a rename, and anything the factory adds later would ship by
// default. Everything else under workflowDir fails the gate.
// signatures.yml is the commit signature gate: it runs on
// pull_request_target from the base branch, so the public repository's
// pull requests are judged by the base's verifier and registry.
var PublishedWorkflows = []string{"ci.yml", "nightly.yml", "release.yml", "signatures.yml"}

// DefaultStripAtPublish is the list of tracked files Gitea main carries and
// the public release does not (#211). The gate does not fail on them -- they
// belong on main -- but each must be export-ignored by GitAttributes, which
// keeps it out of `git archive` and a forge's tag tarball; the public tree is
// produced as such an export. A listed file GitAttributes does not exclude is
// a finding (NotExportIgnored), and every run lists the rest, with its reason.
// .gitattributes and .dockerignore carry each pattern here verbatim, and the
// gate's tests fail when either misses one.
//
// A strip rule exempts a file from the file-class checks only, never from its
// content: a script or a binary under .claude/ still fails, and the lab-value
// scan reads every stripped file like any other.
//
// So is the internal review workflow code-review.yml. The workflow rule is an exact name: `code-review.yaml` or a nested
// copy is an unknown workflow and fails.
//
// A test file that reads only a stripped file is stripped with it (#211), so
// `go test ./...` passes on the published tree.
var DefaultStripAtPublish = []Unpublishable{
	{Path: "**/CLAUDE.md", Reason: agentInstructions},
	{Path: "**/AGENTS.md", Reason: agentInstructions},
	{Path: "**/.claude/**", Reason: agentInstructions},
	{Path: "**/.serena/**", Reason: "code-analysis tool state for the agents: gitignored whole, and " +
		"stripped from the public release should any of it be committed"},
	{Path: workflowDir + "code-review.yml", Reason: internalReviewWorkflow},
	{Path: fleetPatterns, Reason: "the fleet pattern set: shapes and digests of the fleet's values, " +
		"which a short value's digest does not keep secret (#211)"},
	{Path: fleetTests, Reason: "the fleet pattern set's tests, which pin its digest table; stripped " +
		"with the set they test (#211)"},
}

// fleetPatterns and fleetTests are the only files that spell the fleet's
// values. Both are stripped at publish, and DefaultAllowList accepts them.
const (
	fleetPatterns = "test/internal/labstrings/fleet.go"
	fleetTests    = "test/internal/labstrings/fleet_test.go"
)

// internalReviewWorkflow is the reason given for the internal code-review
// workflows (#336).
const internalReviewWorkflow = "internal Gitea code-review workflow: tracked on main, " +
	"stripped from the public release (#211, #336)"

// internalWorkflow is the reason given for any file under workflowDir that
// PublishedWorkflows does not name.
const internalWorkflow = "only the public workflows ship (#211): ci.yml, nightly.yml, release.yml and signatures.yml; " +
	"anything else under .github/workflows/ -- an internal factory workflow, a renamed one, a .yaml " +
	"variant -- stays out of the published tree"

// DefaultUnpublishable is the list for THIS repository.
var DefaultUnpublishable = []Unpublishable{
	{Path: "**/*.sh", Reason: noShellScripts},
	{Path: "**/*.bash", Reason: noShellScripts},
}

// shebang opens every interpreted script, whatever its name. A script renamed
// to drop its extension is still a script.
var shebang = []byte("#!")

// FileFinding is one tracked file the public release must not carry.
type FileFinding struct {
	// Path is slash-separated and relative to the scan root.
	Path string

	// Reason is why it cannot ship and what to do instead.
	Reason string
}

// String renders a finding in the file:message form editors jump to.
func (f FileFinding) String() string {
	return fmt.Sprintf("%s: %s", f.Path, f.Reason)
}

// ValidateUnpublishable reports the first unusable entry, so a malformed rule
// fails the gate instead of silently matching nothing.
func ValidateUnpublishable(rules []Unpublishable) error {
	for i, r := range rules {
		switch {
		case r.Path == "":
			return &AllowRuleError{Index: i, Problem: "no path pattern"}
		case strings.TrimSpace(r.Reason) == "":
			return &AllowRuleError{Index: i, Path: r.Path, Problem: "no reason given"}
		}
		// Every segment is tried on its own: matching the whole pattern
		// against a probe stops at the first segment that differs, and would
		// never reach a malformed one behind it.
		for _, segment := range strings.Split(r.Path, "/") {
			if segment == "**" {
				continue
			}
			if _, err := path.Match(segment, "probe"); err != nil {
				return &AllowRuleError{Index: i, Path: r.Path, Problem: "malformed path pattern: " + err.Error()}
			}
		}
	}
	return nil
}

// ScanUnpublishable reports every entry that matches a rule, every entry under
// .github/workflows/ that neither PublishedWorkflows nor a strip rule names,
// every regular
// file whose staged content opens with a shebang, and every binary regular
// file ExemptFile does not list. The content is the whole
// staged blob (see IndexEntries), so neither a file's size nor what follows
// the interpreter line can hide a script -- except for an oversize file
// ExemptFile lists, whose content is not read (Unread) and which the gate
// prints as NOT READ: its exemption is a person's statement that it ships. A symlink is not itself a script; a
// tracked link target is checked under its own name.
func ScanUnpublishable(entries []Entry, rules, strip []Unpublishable) ([]FileFinding, error) {
	if err := ValidateUnpublishable(rules); err != nil {
		return nil, err
	}
	if err := ValidateUnpublishable(strip); err != nil {
		return nil, err
	}
	var findings []FileFinding
	for _, e := range entries {
		if reason, ok := matchUnpublishable(rules, e.Path); ok {
			findings = append(findings, FileFinding{Path: e.Path, Reason: reason})
			continue
		}
		_, stripped := matchUnpublishable(strip, e.Path)
		if !stripped && unpublishedWorkflow(e.Path) {
			findings = append(findings, FileFinding{Path: e.Path, Reason: internalWorkflow})
			continue
		}
		if e.Kind == KindFile && bytes.HasPrefix(e.Content, shebang) {
			findings = append(findings, FileFinding{Path: e.Path, Reason: "an executable script (it opens with #!): " + noShellScripts})
			continue
		}
		// A binary file fails unless ExemptFile lists it: its content is
		// scanned for lab values like any other, but a person has to have
		// accepted shipping bytes nobody can read as text (owner ruling on
		// #211). An oversize exempt file arrives Unread and is exempt by the
		// same line.
		if e.Kind == KindFile && e.Exemption == "" && IsBinary(e.Content) {
			findings = append(findings, FileFinding{Path: e.Path, Reason: binaryFile})
		}
	}
	return findings, nil
}

// unpublishedWorkflow reports whether name lies under workflowDir without
// being one of PublishedWorkflows. The comparison is exact: `ci.yaml`,
// `Release.yml` and `sub/ci.yml` are not the public workflows.
func unpublishedWorkflow(name string) bool {
	rest, ok := strings.CutPrefix(name, workflowDir)
	if !ok {
		return false
	}
	for _, published := range PublishedWorkflows {
		if rest == published {
			return false
		}
	}
	return true
}

// StripAtPublish reports every tracked entry a strip rule names, so the gate
// can list it on every run. Patterns are validated by ScanUnpublishable, which
// the gate runs first; an unusable one matches nothing here.
func StripAtPublish(entries []Entry, strip []Unpublishable) []FileFinding {
	var out []FileFinding
	for _, e := range entries {
		if reason, ok := matchUnpublishable(strip, e.Path); ok {
			out = append(out, FileFinding{Path: e.Path, Reason: reason})
		}
	}
	return out
}

// matchUnpublishable returns the reason of the first rule matching name.
// Patterns are validated before this runs.
func matchUnpublishable(rules []Unpublishable, name string) (string, bool) {
	for _, r := range rules {
		if ok, err := MatchPath(r.Path, name); err == nil && ok {
			return r.Reason, true
		}
	}
	return "", false
}

// ReportUnpublishable writes the findings and returns whether anything was
// written, exactly as Report does for lab values.
func ReportUnpublishable(w io.Writer, findings []FileFinding) (bool, error) {
	if len(findings) == 0 {
		return false, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d tracked file(s) the public release must not carry:\n\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(&b, "%s\n\n", f)
	}
	b.WriteString("Remove the file from the index (git rm --cached, and .gitignore it if it\n")
	b.WriteString("must still exist in a checkout), or replace it as the reason says.\n")
	b.WriteString("See test/internal/labstrings/published.go for the list.\n")
	if _, err := io.WriteString(w, b.String()); err != nil {
		return true, &ReportError{Err: err}
	}
	return true, nil
}

// Exempted reports every entry ExemptFile lists, so the gate can print what it
// accepted on a person's word rather than accept it silently.
func Exempted(entries []Entry) []FileFinding {
	var out []FileFinding
	for _, e := range entries {
		if e.Exemption == "" {
			continue
		}
		reason := e.Exemption
		if e.Unread {
			reason = "NOT READ (over the scan limit): " + reason
		}
		out = append(out, FileFinding{Path: e.Path, Reason: reason})
	}
	return out
}
