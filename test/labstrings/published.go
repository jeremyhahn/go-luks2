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
// in them. Both are enforced for the same reason: the published tree is the
// release tag's tree byte for byte, so the only place to keep something out of
// it is the source, before tagging.

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

// agentInstructions is the reason shared by the agent-context rules.
const agentInstructions = "agent instructions are internal working context and stay out of the " +
	"published tree (owner ruling on #211); the file is gitignored, so it can exist in a " +
	"checkout without being tracked"

// workflowDir is where GitHub and Gitea Actions look for workflows.
const workflowDir = ".github/workflows/"

// PublishedWorkflows is every workflow file the public release carries, by
// exact name under workflowDir. It is an allow-list, not a deny-list: a
// deny-list of the internal factory workflows is defeated by a `.yaml`
// extension or a rename, and anything the factory adds later would ship by
// default. Everything else under workflowDir fails the gate.
var PublishedWorkflows = []string{"ci.yml", "nightly.yml", "release.yml"}

// PendingWorkflows are workflows under workflowDir that the public release
// must not carry but that Gitea main carries anyway, each held open by a
// conflict of rulings this gate cannot settle. The gate does not fail on them
// -- failing would make main unmergeable, which is the opposite of what either
// ruling wants -- but it never calls them publishable either: every run lists
// each one, with its reason, as an open item (Pending), and #211's checklist
// stays open until the list is empty.
//
// automerge.yml: the owner ruled on 2026-10-02 (automatethethings#200) that
// every project carries the label-gated automerge workflow, and on 2026-09-28
// (#211) that only ci.yml, nightly.yml and release.yml ship. The published
// tree is the release tag's tree byte for byte (version-control.md 5a), so
// both cannot hold for one tag. Its job is inert on github.com -- it is
// guarded by `github.server_url != 'https://github.com'` -- but it names the
// forge's agent principals and internal paths, so it is not publishable as it
// stands.
var PendingWorkflows = map[string]string{
	"automerge.yml": "Gitea-only automerge workflow (owner ruling 2026-10-02, automatethethings#200) " +
		"that the public release must not carry (owner ruling 2026-09-28, #211); an owner ruling " +
		"must say whether it leaves main, or how the release tag excludes it",
}

// internalWorkflow is the reason given for any file under workflowDir that
// PublishedWorkflows does not name.
const internalWorkflow = "only the public workflows ship (#211): ci.yml, nightly.yml and release.yml; " +
	"anything else under .github/workflows/ -- an internal factory workflow, a renamed one, a .yaml " +
	"variant -- stays out of the published tree"

// DefaultUnpublishable is the list for THIS repository.
var DefaultUnpublishable = []Unpublishable{
	{Path: "**/*.sh", Reason: noShellScripts},
	{Path: "**/*.bash", Reason: noShellScripts},
	{Path: "**/CLAUDE.md", Reason: agentInstructions},
	{Path: "**/AGENTS.md", Reason: agentInstructions},
	{Path: ".claude/**", Reason: agentInstructions},
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
// .github/workflows/ that PublishedWorkflows does not name, every regular
// file whose staged content opens with a shebang, and every binary regular
// file ExemptFile does not list. The content is the whole
// staged blob (see IndexEntries), so neither a file's size nor what follows
// the interpreter line can hide a script -- except for an oversize file
// ExemptFile lists, whose content is not read (Unread) and which the gate
// prints as NOT READ: its exemption is a person's statement that it ships. A symlink is not itself a script; a
// tracked link target is checked under its own name.
func ScanUnpublishable(entries []Entry, rules []Unpublishable) ([]FileFinding, error) {
	if err := ValidateUnpublishable(rules); err != nil {
		return nil, err
	}
	var findings []FileFinding
	for _, e := range entries {
		if reason, ok := matchUnpublishable(rules, e.Path); ok {
			findings = append(findings, FileFinding{Path: e.Path, Reason: reason})
			continue
		}
		if unpublishedWorkflow(e.Path) {
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
	_, pending := PendingWorkflows[rest]
	return !pending
}

// Pending reports every tracked entry PendingWorkflows names, so the gate can
// list it as an open item on every run. The name comparison is exact, as in
// unpublishedWorkflow: `automerge.yaml` is not pending, it fails.
func Pending(entries []Entry) []FileFinding {
	var open []FileFinding
	for _, e := range entries {
		rest, ok := strings.CutPrefix(e.Path, workflowDir)
		if !ok {
			continue
		}
		if reason, pending := PendingWorkflows[rest]; pending {
			open = append(open, FileFinding{Path: e.Path, Reason: reason})
		}
	}
	return open
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
	b.WriteString("See test/labstrings/published.go for the list.\n")
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
