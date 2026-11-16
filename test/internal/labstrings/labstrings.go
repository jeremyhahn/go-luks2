// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package labstrings is the release gate that keeps this repository publicly
// releasable. It reports every tracked file that names a host, an address or a
// filesystem path belonging to the private development fleet, and every
// tracked file the public release must not carry at all (published.go).
//
// WHY THIS IS A GATE AND NOT A CONVENTION. go-luks2 is published, and the
// internal release tag is not what is published. That tag names a commit on
// main, which still tracks the internal-only files. The public tree is that
// commit's `git archive` output: the paths .gitattributes marks export-ignore
// (the strip-at-publish set, published.go) are removed, and every other
// tracked file is published byte-for-byte, as it stands at the tag. Nothing
// rewrites a file on the way out, so a lab value has to be scrubbed in the
// source before tagging. Publishing that tree and tagging it on the public
// side are separate steps, each taken by the owner. The model is go-quicbaas's gate of the same name,
// written after go-quicbaas#944 found a symlink into the lab's NFS mount, the
// private forge in a release workflow and in documentation links, the private
// registry in captured CI logs, and lab hosts in `--help` text and godoc. None
// of it was load-bearing and nothing prevented any of it. This is what
// prevents it here.
//
// WHAT IS REPORTED, and why each class is a leak rather than a style problem:
//
//   - ClassLabAddress — an address on the fleet's subnet, or the private
//     forge's web or ssh port. Unreachable for every
//     public reader, so a copy-pasteable example containing one is broken
//     documentation, and it publishes the operator's network layout.
//   - ClassLabHost — a fleet hostname, of every host family the fleet runs:
//     the agent workstations, the CI runners, the GPU and build hosts, the
//     tunnel gateway, the mini nodes and the coordinator hosts. Same, plus it
//     names the machines an attacker would go looking for.
//   - ClassOwnerPath — a path under the owner's home directory or the lab's NFS
//     mount. Meaningless off that one machine, and it leaks the account name.
//   - ClassOwnerAccount — the owner's login on its own: an ssh target, an
//     author line, a mail address. Inside an owner path it is the same leak
//     and reported once, as owner-path. The forge owner in the module path is
//     a different, public name and does not match.
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
//   - Workflows other than ci.yml, nightly.yml, release.yml and
//     signatures.yml (PublishedWorkflows), including `.yaml` variants and subdirectories.
//
// FILES TRACKED ON main AND STRIPPED AT PUBLISH (#211), listed by
// DefaultStripAtPublish: the agent files CLAUDE.md, AGENTS.md and `.claude/` at
// any depth (standards project-scaffold.md §7, #252; only the local tool state
// `.claude/settings.local.json` is gitignored), the code-analysis tool
// configuration `.serena/` at any depth, the internal review workflow
// .github/workflows/code-review.yml (that exact name; a `.yaml` variant or
// nested copy fails), and the fleet pattern set test/internal/labstrings/fleet.go with its tests
// fleet_test.go. Each is
// export-ignored by .gitattributes, so `git archive` and a forge's tag tarball
// leave it out, and listed in .dockerignore. The gate passes them and lists
// each on every run; one .gitattributes does not export-ignore is a finding.
// Their content is still scanned, and a script or binary among them still
// fails.
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
// Where the patterns live: fleet.go, returned by Fleet. A pattern is a shape
// and a set of digests: the shape is a generic regexp that names no fleet
// value (any IPv4 address, a port after a colon, a /home/<name> path
// component, a <word>-<2 digits> host name, a bare word), and the digests are
// the hex SHA-256 of the fleet values that shape may match. A match of the
// shape is a finding only when the digest of its key is in the set. The key
// is the shape's first submatch -- for an address, its /24 prefix, the first
// three octets -- folded to lower case (Digest). So the gate's source and its
// tests spell no fleet value, and fleet_test.go proves each shape with
// synthetic values whose digests it computes. This is hygiene, not secrecy:
// a short value's digest is brute-forced in seconds. The published scanner
// tests use documentation values, and a test in fleet_test.go requires that
// `git archive HEAD` names no value of the set anywhere, waiver or not. A tree
// with no pattern set refuses to scan (NoPatternsError); the releasability
// gate then fails a development tree -- one that tracks a strip-at-publish
// file -- and passes a published tree only with the notice that its content
// was not scanned.
//
// This is the canonical statement of the public-releasability rule.
//
// RESOLUTION is textual, deliberately: it needs no build tags, no module
// loading and no parser, so it runs on every tree state including one that does
// not compile, and it covers Markdown, YAML, Dockerfiles and JSON as readily as
// Go.
package labstrings

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"slices"
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

	// ClassOwnerAccount is the owner's login name on its own, outside a path:
	// an ssh target, an author line, a mail address.
	ClassOwnerAccount Class = "owner-account"
)

// waiverPrefix marks a line whose lab value is the point of the line. The text
// after it is the reason and must not be empty.
const waiverPrefix = "lab-string-ok:"

// Pattern is one rule the scanner applies to every line.
type Pattern struct {
	// Class says what a match leaks.
	Class Class

	// Expr is the shape of the offending text: a generic regexp that names no
	// value. It matches the value, not the whole line, so the report can quote
	// exactly what has to change. Its first submatch, when it has one, is the
	// key; otherwise the whole match is.
	Expr *regexp.Regexp

	// Digests are the hex SHA-256 digests (Digest) of the keys this pattern
	// reports. A match of Expr whose key's digest is not listed is not a
	// finding, so the values the gate hunts are never spelled in its source.
	Digests []string

	// Guidance is what the engineer who tripped this rule should do instead.
	Guidance string

	// YieldsTo, when set, names a more specific class: a match lying inside
	// a match of that class on the same line is the same leak and is not
	// reported again, and an allow rule accepting that class accepts it.
	YieldsTo Class
}

// fleet is this repository's pattern set. Its patterns carry digests of the
// fleet's values, never the values: a gate that spelled them in its source
// would be the leak it exists to stop. fleet.go assigns it. In a build without
// fleet.go the set is empty, and Scan refuses an empty set rather than report
// clean.
var fleet []Pattern

// Fleet returns the pattern set compiled into this build: shapes and the
// digests of the fleet's values.
func Fleet() []Pattern { return fleet }

// classes is every class a pattern or an allow rule may name.
var classes = []Class{ClassLabAddress, ClassLabHost, ClassOwnerPath, ClassOwnerAccount}

// mayContainLabValue reports whether any pattern of set matches anywhere in
// content. Almost no file in this tree contains a lab value, and the whole
// tracked tree is read on every unit-test pass: settling "there is nothing
// here" has to be cheap, so each distinct shape runs once over the whole
// content, against the digests of every pattern that shares it, and the
// line-by-line scan runs only on a file that has a hit. No shape matches
// across a newline, so a hit in a line is a hit in the content.
func mayContainLabValue(set []Pattern, content []byte) bool {
	text := string(content)
	byShape := map[*regexp.Regexp][]string{}
	var shapes []*regexp.Regexp
	for _, p := range set {
		if _, ok := byShape[p.Expr]; !ok {
			shapes = append(shapes, p.Expr)
		}
		byShape[p.Expr] = append(byShape[p.Expr], p.Digests...)
	}
	for _, shape := range shapes {
		if len(Pattern{Expr: shape, Digests: byShape[shape]}.find(text)) > 0 {
			return true
		}
	}
	return false
}

// Digest returns the hex SHA-256 digest of key folded to lower case: the form
// a Pattern's Digests are written in.
func Digest(key string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(key)))
	return hex.EncodeToString(sum[:])
}

// find returns the span of every match of p.Expr in s whose key's digest is
// one of p.Digests.
func (p Pattern) find(s string) [][]int {
	var spans [][]int
	for _, m := range p.Expr.FindAllStringSubmatchIndex(s, -1) {
		key := s[m[0]:m[1]]
		if len(m) >= 4 && m[2] >= 0 {
			key = s[m[2]:m[3]]
		}
		if slices.Contains(p.Digests, Digest(key)) {
			spans = append(spans, m[:2])
		}
	}
	return spans
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
	return Scan(entries, Fleet(), DefaultAllowList)
}

// Scan reports the matches of set in entries. An empty set is refused with
// NoPatternsError: it would find nothing and so report clean. Rules are
// validated next: an allow-list that does not say why it allows something is
// a defect in the gate, not a pass.
//
// Every entry's path is scanned, because a tracked filename ships as surely as
// its content, and so is every entry's content, binary content included. Entries come from
// IndexEntries, which reads the staged blobs and fails rather than return an
// entry it did not read in full -- with one exception: an oversize file that
// ExemptFile lists by exact path, with a reason, arrives Unread. Its path is
// still scanned here, its content is not, and the gate prints it as NOT READ
// on every run (Exempted).
func Scan(entries []Entry, set []Pattern, rules []AllowRule) ([]Finding, error) {
	if len(set) == 0 {
		return nil, &NoPatternsError{Tracked: len(entries)}
	}
	if err := ValidateAllowList(rules); err != nil {
		return nil, err
	}
	var findings []Finding
	for _, e := range entries {
		accepted := acceptedClasses(rules, e.Path)
		if acceptsAll(accepted, set) {
			// Every class this set reports is allowed here; scanning
			// the entry cannot produce a finding.
			continue
		}
		findings = append(findings, scanPath(e.Path, set, accepted)...)
		findings = append(findings, scanContent(e.Path, e.Content, set, accepted)...)
	}
	return findings, nil
}

// acceptsAll reports whether accepted holds the class of every pattern in set.
func acceptsAll(accepted map[Class]bool, set []Pattern) bool {
	for _, p := range set {
		if !accepted[p.Class] {
			return false
		}
	}
	return true
}

// scanPath applies every pattern whose class is not accepted for this file to
// the file's path. A path cannot carry an inline waiver; DefaultAllowList is
// the only way to accept one.
func scanPath(name string, set []Pattern, accepted map[Class]bool) []Finding {
	if !mayContainLabValue(set, []byte(name)) {
		return nil
	}
	var findings []Finding
	for _, p := range set {
		if accepted[p.Class] {
			continue
		}
		for _, span := range p.find(name) {
			if p.YieldsTo != "" && insideClass(set, name, span, p.YieldsTo) {
				continue
			}
			findings = append(findings, Finding{
				Path:     name,
				Class:    p.Class,
				Match:    name[span[0]:span[1]],
				Excerpt:  excerpt(name),
				Guidance: p.Guidance,
			})
		}
	}
	return findings
}

// scanContent applies every pattern whose class is not accepted for this file to
// every line of it.
func scanContent(name string, content []byte, set []Pattern, accepted map[Class]bool) []Finding {
	if !mayContainLabValue(set, content) {
		return nil
	}
	lines := strings.Split(string(content), "\n")
	var findings []Finding
	for i, line := range lines {
		if waived(line) || (i > 0 && waived(lines[i-1])) {
			continue
		}
		for _, p := range set {
			if accepted[p.Class] {
				continue
			}
			for _, span := range p.find(line) {
				if p.YieldsTo != "" && insideClass(set, line, span, p.YieldsTo) {
					continue
				}
				findings = append(findings, Finding{
					Path:     name,
					Line:     i + 1,
					Class:    p.Class,
					Match:    line[span[0]:span[1]],
					Excerpt:  excerpt(line),
					Guidance: p.Guidance,
				})
			}
		}
	}
	return findings
}

// insideClass reports whether span lies within a match of class on line,
// whether or not that class is accepted where the line was found.
func insideClass(set []Pattern, line string, span []int, class Class) bool {
	for _, p := range set {
		if p.Class != class {
			continue
		}
		for _, outer := range p.find(line) {
			if outer[0] <= span[0] && span[1] <= outer[1] {
				return true
			}
		}
	}
	return false
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
