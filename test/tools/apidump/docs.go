// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Exception is one row of the doc-exceptions file: an export of Package (its
// directory under the pkg root) that no feature doc is expected to name, and
// why.
type Exception struct {
	Package string
	Name    string
	Reason  string
}

// FeatureDoc is what one docs/<feature>/*.md offers the coverage rule: the
// whole identifiers its code spans and fenced blocks name, and every
// Qualifier.Name pair among them.
type FeatureDoc struct {
	Path      string
	Words     map[string]bool
	Qualified map[string]bool
}

// DumpTree dumps every package directory under root (one holding a non-test
// .go file), keyed by its path relative to root.
func DumpTree(root string) (map[string][]Entry, error) {
	out := map[string][]Entry{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error { // #nosec G703 -- a source tree the operator names on the command line
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		dir := filepath.Dir(path)
		rel, err := filepath.Rel(root, dir)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if _, done := out[rel]; done {
			return nil
		}
		entries, err := Dump(dir)
		if err != nil {
			return err
		}
		out[rel] = entries
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("dump %s: %w", root, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no package under %s", ErrNoAPI, root)
	}
	return out, nil
}

// ReadFeatureDocs reads every *.md of every feature directory under root. A
// feature directory is one holding an api.md; anything else (docs/README.md, a directory
// without an api.md) is not a feature doc.
func ReadFeatureDocs(root string) ([]FeatureDoc, error) {
	apis, err := filepath.Glob(filepath.Join(root, "*", "api.md"))
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", root, err)
	}
	var out []FeatureDoc
	for _, api := range apis {
		paths, err := filepath.Glob(filepath.Join(filepath.Dir(api), "*.md"))
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", filepath.Dir(api), err)
		}
		for _, path := range paths {
			data, err := os.ReadFile(path) // #nosec G304 G703 -- a docs tree the operator names on the command line
			if err != nil {
				return nil, fmt.Errorf("read feature doc: %w", err)
			}
			doc := FeatureDoc{Path: path, Words: map[string]bool{}, Qualified: map[string]bool{}}
			for _, code := range codeText(string(data)) {
				doc.scan(code)
			}
			out = append(out, doc)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no */api.md under %s", ErrNoDocs, root)
	}
	return out, nil
}

// codeText returns the code a Markdown document holds: every fenced block,
// and every inline code span. Spans are paired within a paragraph, so one that
// wraps across lines is still read whole, and a stray backtick cannot flip
// the rest of the document between prose and code.
func codeText(doc string) []string {
	var code []string
	var paragraph []string
	var fence string
	flush := func() {
		parts := strings.Split(strings.Join(paragraph, "\n"), "`")
		for i := 1; i < len(parts)-1; i += 2 {
			code = append(code, parts[i])
		}
		paragraph = paragraph[:0]
	}
	for _, line := range strings.Split(doc, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case fence != "":
			if strings.HasPrefix(trimmed, fence) {
				fence = ""
			} else {
				code = append(code, line)
			}
		case strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~"):
			flush()
			fence = trimmed[:3]
		case trimmed == "":
			flush()
		default:
			paragraph = append(paragraph, line)
		}
	}
	flush()
	return code
}

// scan records the whole identifiers in code, and each pair joined by a
// single dot (luks2.Volume.Open records luks2.Volume and Volume.Open).
func (d FeatureDoc) scan(code string) {
	prev, prevEnd := "", -1
	for i := 0; i < len(code); {
		if !isIdentByte(code[i]) {
			i++
			continue
		}
		start := i
		for i < len(code) && isIdentByte(code[i]) {
			i++
		}
		word := code[start:i]
		if word[0] >= '0' && word[0] <= '9' {
			prev = ""
			continue
		}
		d.Words[word] = true
		if prev != "" && prevEnd == start-1 && code[start-1] == '.' {
			d.Qualified[prev+"."+word] = true
		}
		prev, prevEnd = word, i
	}
}

// covers reports whether doc names e: a top-level identifier as a whole
// identifier in code; a method as Type.Method in code, or as Method in code
// in a doc whose code also names Type.
func (d FeatureDoc) covers(e Entry) bool {
	if e.Kind != "method" {
		return d.Words[e.Name]
	}
	recv, method, _ := strings.Cut(e.Name, ".")
	return d.Qualified[e.Name] || (d.Words[method] && d.Words[recv])
}

// ReadExceptions reads a doc-exceptions file: package, identifier and reason,
// tab separated, one export per line. Blank lines and # comments are skipped.
// A row without a reason, or a second row for one export, is malformed.
func ReadExceptions(path string) ([]Exception, error) {
	data, err := os.ReadFile(path) // #nosec G304 G703 -- an exceptions file the operator names on the command line
	if err != nil {
		return nil, fmt.Errorf("read exceptions: %w", err)
	}
	var out []Exception
	seen := map[string]bool{}
	for i, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 || fields[0] == "" || fields[1] == "" || strings.TrimSpace(fields[2]) == "" {
			return nil, fmt.Errorf("%w: %s line %d: want package, identifier and reason: %q", ErrMalformed, path, i+1, line)
		}
		x := Exception{Package: fields[0], Name: fields[1], Reason: fields[2]}
		key := x.Package + "." + x.Name
		if seen[key] {
			return nil, fmt.Errorf("%w: %s line %d: %s excepted twice", ErrMalformed, path, i+1, key)
		}
		seen[key] = true
		out = append(out, x)
	}
	return out, nil
}

// CheckDocumented fails unless every exported identifier in apis (see
// Entry.Identifier) is named by some feature doc or excepted. An exception
// for an export that is gone, or that a doc now names, fails too, so the
// exceptions list cannot outlive its reasons.
func CheckDocumented(apis map[string][]Entry, docs []FeatureDoc, exceptions []Exception) error {
	excepted := map[string]bool{}
	for _, x := range exceptions {
		excepted[x.Package+"."+x.Name] = true
	}
	exported := map[string]bool{}
	var problems []string
	for pkg, entries := range apis {
		for _, e := range entries {
			if !e.Identifier() {
				continue
			}
			key := pkg + "." + e.Name
			exported[key] = true
			documented := false
			for _, d := range docs {
				if d.covers(e) {
					documented = true
					break
				}
			}
			switch {
			case documented && excepted[key]:
				problems = append(problems, "excepted but documented: "+key)
			case !documented && !excepted[key]:
				problems = append(problems, "not named in any feature doc: "+key)
			}
		}
	}
	for key := range excepted {
		if !exported[key] {
			problems = append(problems, "excepted but not exported: "+key)
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("%w:\n  %s", ErrUndocumented, strings.Join(problems, "\n  "))
	}
	return nil
}
