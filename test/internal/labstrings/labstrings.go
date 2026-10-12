// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package labstrings is the release gate that keeps this repository publicly
// releasable. It reports every tracked file that names a host, an address or a
// filesystem path belonging to the private development fleet, and every
// tracked file the public release must not carry at all (published.go).
//
// WHY THIS IS A GATE AND NOT A CONVENTION. go-luks2 is published: its public
// release is one commit whose tree is byte-identical to the internal release
// tag, so anything tracked here at the tag is published, and a value has to be
// scrubbed in the source before tagging because rewriting it at publication
// would break that identity. The model is go-quicbaas's gate of the same name,
// written after go-quicbaas#944 found a symlink into the lab's NFS mount, the
// private forge in a release workflow and in documentation links, the private
// registry in captured CI logs, and lab hosts in `--help` text and godoc. None
// of it was load-bearing and nothing prevented any of it. This is what
// prevents it here.
//
// WHAT IS REPORTED, and why each class is a leak rather than a style problem:
//
//   - ClassLabAddress — an address on the fleet's subnet. Unreachable for every
//     public reader, so a copy-pasteable example containing one is broken
//     documentation, and it publishes the operator's network layout.
//   - ClassLabHost — a fleet hostname. Same, plus it names the machines an
//     attacker would go looking for.
//   - ClassOwnerPath — a path under the owner's home directory or the lab's NFS
//     mount. Meaningless off that one machine, and it leaks the account name.
//
// WHAT TO DO WITH A FINDING. In order of preference:
//
//   - Use a documentation value: RFC 5737 addresses (192.0.2.0/24,
//     198.51.100.0/24, 203.0.113.0/24), RFC 2606 names (example.com,
//     *.example, *.invalid), or a role rather than a machine — `ci-runner-01`,
//     `*.internal` for an unrouted service.
//   - Move the value out of the tree: a forge address belongs in a CI
//     repository variable, a fleet address in the private infra repository.
//   - If the value IS the point — provenance for a measurement, the host a
//     captured log came from — waive the line in place (below).
//
// TWO WAYS TO ACCEPT A LINE, both explicit:
//
//   - An inline waiver: the text `lab-string-ok: <reason>` on the offending
//     line or the line immediately above it, in whatever comment syntax the
//     file uses. The justification then lives next to the value it explains,
//     and it is preferred. An empty reason is not a waiver.
//   - An entry in DefaultAllowList, for whole trees and for files that cannot
//     carry a comment (captured logs, JSON). Each entry carries the classes it
//     accepts and a reason; see allowlist.go.
//
// WHAT IS READ. The git index, blob by blob (index.go): the index is the ship
// manifest, and its staged content -- not the working tree -- is what the next
// commit carries. An entry the gate cannot read in full fails the gate.
//
// WHERE THIS LIVES. The command test/tools/releasability-gate runs it,
// through `make releasability`, which `make ci` and the CI workflow call. It is
// under test/internal rather than pkg/ because pkg/ is this library's public
// API, and a release gate is not something a consumer imports; only test/ may
// import this package.
//
// FILES THAT ARE NEVER PUBLISHED, whatever their content (published.go):
//
//   - Shell scripts: `*.sh`, `*.bash`, or anything starting with `#!`. Tools are
//     Go commands (test/tools/require-tool, test/tools/docker-run) or Makefile
//     recipes.
//   - Workflows other than ci.yml, nightly.yml and release.yml
//     (PublishedWorkflows), including `.yaml` variants and subdirectories.
//
// FILES TRACKED ON main AND STRIPPED AT PUBLISH (#211), listed by
// DefaultStripAtPublish: the agent files CLAUDE.md, AGENTS.md and `.claude/` at
// any depth (standards project-scaffold.md §7, #252; only the local tool state
// `.claude/settings.local.json` is gitignored), and
// .github/workflows/automerge.yml, which the forge requires (that exact name; a
// `.yaml` variant or nested copy fails), and the internal review workflows
// .github/workflows/code-review.yml and qwen-review.yml (#336), and the
// internal batch-runner workflow .github/workflows/batch.yml (#350). The gate passes them, lists each on
// every run and does not call the tree publishable while one is tracked. Their
// content is still scanned, and a script or binary among them still fails.
// There is no waiver for an unpublishable file: remove it from the index.
//
// FAILURES AND EXEMPTIONS. A failure names the file, line, class, matched text
// and the replacement; a match in a path is reported as such. Without a git
// checkout, or with an unreadable blob, the gate exits 2 rather than reporting
// clean. A binary (a NUL byte) or an oversize blob (over 32 MiB, exit 2) fails
// unless listed in releasability-exempt.txt with a reason. A listed binary is
// still scanned; a listed oversize file is not, and the gate says so on every
// run. The list is read from the index, and a stale entry, a missing reason or a
// duplicate stops the gate. It is empty. The replacement values for each class
// are the RFC 5737 / RFC 2606 / role names above and, for owner-path, a
// repository-relative path or /var/lib, /srv, /var/tmp.
//
// THE FIRST-RELEASE SCRUB. When the gate was added the tree already held no lab
// address, hostname or owner path. The scrub replaced .github/require-tool.sh
// and test/integration/docker-run.sh with the Go commands above (same
// behavior) and removed CLAUDE.md from the index; #252 tracks it again,
// stripped at publish.
//
// Where the patterns live: `patterns`, below. The only DefaultAllowList entry is
// the gate's own test fixtures.
//
// This is the canonical statement of the public-releasability rule.
//
// RESOLUTION is textual, deliberately: it needs no build tags, no module
// loading and no parser, so it runs on every tree state including one that does
// not compile, and it covers Markdown, YAML, Dockerfiles and JSON as readily as
// Go.
package labstrings

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Class groups the findings by what the matched text leaks. It is a string so a
// report, an allow-list entry and a test name all spell it the same way.
type Class string

const (
	// ClassLabAddress is an IP address on the development fleet's subnet.
	ClassLabAddress Class = "lab-address"

	// ClassLabHost is a hostname belonging to the development fleet.
	ClassLabHost Class = "lab-host"

	// ClassOwnerPath is a filesystem path that exists only on the owner's
	// machine or on the lab's network mount.
	ClassOwnerPath Class = "owner-path"
)

// waiverPrefix marks a line whose lab value is the point of the line. The text
// after it is the reason and must not be empty.
const waiverPrefix = "lab-string-ok:"

// Pattern is one rule the scanner applies to every line.
type Pattern struct {
	// Class says what a match leaks.
	Class Class

	// Expr matches the offending text. It matches the value, not the whole
	// line, so the report can quote exactly what has to change.
	Expr *regexp.Regexp

	// Needle is a lowercase literal that every string Expr can match must
	// contain. It is the cheap precondition the sieve uses: a substring
	// search runs at memory bandwidth where this regexp runs at a few
	// megabytes a second, and the whole tree has to be read on every unit
	// test pass. A Needle that is not implied by Expr would make the gate
	// silently blind, so TestPatterns_EveryNeedleIsImpliedByItsExpr pins it.
	Needle string

	// Guidance is what the engineer who tripped this rule should do instead.
	Guidance string
}

// patterns is the rule set. It is a package-level var rather than a constant
// list so a new fleet subnet or hostname is one line, and so the lab's own
// values are written down in exactly one place in this repository.
//
// Note what is NOT here: 192.168.0.0/16 at large. Tests across this tree use
// RFC 1918 literals as opaque addresses that are never dialed, and banning the
// whole space would bury the real findings under hundreds of them. The fleet
// subnet is named precisely instead.
var patterns = []Pattern{
	{
		Class:    ClassLabAddress,
		Expr:     regexp.MustCompile(`\b192\.168\.101\.\d{1,3}\b`),
		Needle:   "192.168.101.",
		Guidance: "use an RFC 5737 documentation address (198.51.100.0/24) or a name under .example.com",
	},
	{
		Class:    ClassLabHost,
		Expr:     regexp.MustCompile(`(?i)\bvstation-\d{2}\b`),
		Needle:   "vstation-",
		Guidance: "name the role, not the machine: ci-runner-01, gpu-host.internal, luks.example.com",
	},
	{
		Class:    ClassLabHost,
		Expr:     regexp.MustCompile(`(?i)\bdellemc-\d{2}\b`),
		Needle:   "dellemc-",
		Guidance: "a CI runner's own hostname is never load-bearing: ci-runner-01 reads the same",
	},
	{
		Class:    ClassLabHost,
		Expr:     regexp.MustCompile(`(?i)\bgodlike(\.internal)?\b`), // lab-string-ok: the hostname this rule exists to find
		Needle:   "gpu-host",
		Guidance: "name the role, not the machine: gpu-host.internal, npu-host.internal",
	},
	{
		Class:    ClassLabHost,
		Expr:     regexp.MustCompile(`(?i)\bomega(\.internal)?\b`), // lab-string-ok: the hostname this rule exists to find
		Needle:   "omega",
		Guidance: "name the role, not the machine: build-host.internal, batch-runner",
	},
	{
		Class:    ClassOwnerPath,
		Expr:     regexp.MustCompile(`/home/jhahn\b`), // lab-string-ok: the path prefix this rule exists to find
		Needle:   "/home/jhahn",
		Guidance: "make the path relative to the repository root, or use /var/lib, /srv, /home/agent",
	},
	{
		Class:    ClassOwnerPath,
		Expr:     regexp.MustCompile(`/mnt/vstation`), // lab-string-ok: the mount prefix this rule exists to find
		Needle:   "/mnt/vstation",
		Guidance: "the lab's NFS mount does not exist anywhere else; use a repository-relative path",
	},
}

// sieveNeedles is every pattern's Needle, in the form the sieve wants them.
// Almost no file in this tree contains a lab value, and the whole tracked tree
// is read on every unit-test pass: settling "there is nothing here" has
// to be cheap, and a substring search is two orders of magnitude cheaper than
// the patterns themselves.
var sieveNeedles = func() [][]byte {
	needles := make([][]byte, 0, len(patterns))
	for _, p := range patterns {
		needles = append(needles, []byte(p.Needle))
	}
	return needles
}()

// mayContainLabValue reports whether any pattern could possibly match inside
// content. Case is folded because a hostname is as likely to appear shouted in a
// log line as lowercased in a config file.
func mayContainLabValue(content []byte) bool {
	folded := bytes.ToLower(content)
	for _, needle := range sieveNeedles {
		if bytes.Contains(folded, needle) {
			return true
		}
	}
	return false
}

// Finding is one line that must change before this tree can be published.
type Finding struct {
	// Path is slash-separated and relative to the scan root.
	Path string

	// Line is 1-based, so the report is clickable. Line 0 means the value
	// is in the file's path rather than its content.
	Line int

	// Class says what the matched text leaks.
	Class Class

	// Match is the offending text exactly as it appears.
	Match string

	// Excerpt is the whole line, trimmed and truncated: a finding with no
	// context around it costs the reader a second trip to the file.
	Excerpt string

	// Guidance is the pattern's remediation advice.
	Guidance string
}

// String renders a finding in the file:line:message form every editor and every
// CI log viewer already knows how to jump to.
func (f Finding) String() string {
	if f.Line == 0 {
		return fmt.Sprintf("%s: [%s] %q in the file path -- %s", f.Path, f.Class, f.Match, f.Guidance)
	}
	return fmt.Sprintf("%s:%d: [%s] %q -- %s\n\t%s", f.Path, f.Line, f.Class, f.Match, f.Guidance, f.Excerpt)
}

// excerptLimit bounds the quoted line. Generated files can be single lines of a
// megabyte or more; a report is useless if one finding fills the screen.
const excerptLimit = 160

// maxFileSize bounds what the scanner will read into memory. Nothing shipped in
// this tree is larger, and a scan must not be the thing that runs a CI runner
// out of memory. A tracked file over it fails the gate with FileTooLargeError:
// the gate cannot vouch for content it did not read.
const maxFileSize = 32 << 20

// ScanRepo is the lab-value half of the gate: it reads the git index at root
// and reports every entry that names a lab value and is neither waived in
// place nor covered by DefaultAllowList.
func ScanRepo(root string) ([]Finding, error) {
	entries, err := IndexEntries(root)
	if err != nil {
		return nil, err
	}
	return Scan(entries, DefaultAllowList)
}

// Scan reports the lab values in entries. Rules are validated first: an
// allow-list that does not say why it allows something is a defect in the
// gate, not a pass.
//
// Every entry's path is scanned, because a tracked filename ships as surely as
// its content, and so is every entry's content, binary content included. Entries come from
// IndexEntries, which reads the staged blobs and fails rather than return an
// entry it did not read in full -- with one exception: an oversize file that
// ExemptFile lists by exact path, with a reason, arrives Unread. Its path is
// still scanned here, its content is not, and the gate prints it as NOT READ
// on every run (Exempted).
func Scan(entries []Entry, rules []AllowRule) ([]Finding, error) {
	if err := ValidateAllowList(rules); err != nil {
		return nil, err
	}
	var findings []Finding
	for _, e := range entries {
		accepted := acceptedClasses(rules, e.Path)
		if len(accepted) == len(patterns) {
			// Every class this gate knows about is allowed here;
			// scanning the entry cannot produce a finding.
			continue
		}
		findings = append(findings, scanPath(e.Path, accepted)...)
		findings = append(findings, scanContent(e.Path, e.Content, accepted)...)
	}
	return findings, nil
}

// scanPath applies every pattern whose class is not accepted for this file to
// the file's path. A path cannot carry an inline waiver; DefaultAllowList is
// the only way to accept one.
func scanPath(name string, accepted map[Class]bool) []Finding {
	if !mayContainLabValue([]byte(name)) {
		return nil
	}
	var findings []Finding
	for _, p := range patterns {
		if accepted[p.Class] {
			continue
		}
		for _, match := range p.Expr.FindAllString(name, -1) {
			findings = append(findings, Finding{
				Path:     name,
				Class:    p.Class,
				Match:    match,
				Excerpt:  excerpt(name),
				Guidance: p.Guidance,
			})
		}
	}
	return findings
}

// scanContent applies every pattern whose class is not accepted for this file to
// every line of it.
func scanContent(name string, content []byte, accepted map[Class]bool) []Finding {
	if !mayContainLabValue(content) {
		return nil
	}
	lines := strings.Split(string(content), "\n")
	var findings []Finding
	for i, line := range lines {
		if waived(line) || (i > 0 && waived(lines[i-1])) {
			continue
		}
		for _, p := range patterns {
			if accepted[p.Class] {
				continue
			}
			for _, match := range p.Expr.FindAllString(line, -1) {
				findings = append(findings, Finding{
					Path:     name,
					Line:     i + 1,
					Class:    p.Class,
					Match:    match,
					Excerpt:  excerpt(line),
					Guidance: p.Guidance,
				})
			}
		}
	}
	return findings
}

// waived reports whether a line carries an inline waiver with a reason. The
// reason is what makes it a waiver: `lab-string-ok:` on its own says only that
// somebody wanted the gate to stop talking.
func waived(line string) bool {
	idx := strings.Index(line, waiverPrefix)
	if idx < 0 {
		return false
	}
	reason := strings.TrimSpace(line[idx+len(waiverPrefix):])
	// Trim the comment closers the host syntaxes need, so a reason that ends
	// at `-->` or `*/` is still a reason.
	for _, closer := range []string{"-->", "*/"} {
		reason = strings.TrimSpace(strings.TrimSuffix(reason, closer))
	}
	return reason != ""
}

// excerpt trims and bounds a line for the report.
func excerpt(line string) string {
	trimmed := strings.TrimSpace(line)
	if len(trimmed) <= excerptLimit {
		return trimmed
	}
	return trimmed[:excerptLimit] + " ..."
}

// Report writes the findings in a form an engineer can act on without opening
// this file, and returns whether anything was written. Findings are the gate's
// product: a gate whose output does not say what to do next gets waived
// wholesale by the next person who trips it.
func Report(w io.Writer, findings []Finding) (bool, error) {
	if len(findings) == 0 {
		return false, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d lab value(s) in tracked files -- this tree ships publicly:\n\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(&b, "%s\n\n", f)
	}
	b.WriteString("Replace the value, move it to CI/infra configuration, or -- if the value\n")
	b.WriteString("is the point (benchmark provenance, a captured log) -- waive the line with\n")
	b.WriteString("a `" + waiverPrefix + " <reason>` comment. See test/internal/labstrings for the full list.\n")
	if _, err := io.WriteString(w, b.String()); err != nil {
		return true, &ReportError{Err: err}
	}
	return true, nil
}
