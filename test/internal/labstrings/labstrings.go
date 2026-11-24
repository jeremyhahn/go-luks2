// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package labstrings is the release gate that reports every tracked file naming a private-fleet host, address or path, and every file the public release must not carry.
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

	// ClassOwnerPath is a filesystem path that exists only on a private machine or network mount.
	ClassOwnerPath Class = "owner-path"

	// ClassOwnerAccount is a private login name on its own, outside a path.
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

// mayContainLabValue reports whether any pattern of set matches anywhere in content, running each distinct shape once.
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

// Scan reports the matches of set in entries' paths and contents; an empty set is NoPatternsError and an invalid rule fails.
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
