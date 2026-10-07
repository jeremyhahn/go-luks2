// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// Action is what the API redesign does to one baseline identifier
// (DESIGN.md §B.6).
type Action string

// The five actions. KEEP keeps the name in its package; RENAME gives it a new
// name or shape; MOVE puts it in another public package; UNEXPORT takes it out
// of the public API; DELETE removes it, with Target naming the replacement.
const (
	Keep     Action = "KEEP"
	Rename   Action = "RENAME"
	Move     Action = "MOVE"
	Unexport Action = "UNEXPORT"
	Delete   Action = "DELETE"
)

var actions = map[Action]bool{Keep: true, Rename: true, Move: true, Unexport: true, Delete: true}

// Disposition is one row of a disposition file: an identifier, its action and
// the target or replacement in words.
type Disposition struct {
	Name   string
	Action Action
	Target string
}

// ReadDispositions parses a disposition file: one tab-separated
// name/action/target row per identifier. The target may be empty only for
// KEEP.
func ReadDispositions(path string) ([]Disposition, error) {
	data, err := os.ReadFile(path) // #nosec G304 G703 -- a disposition file the operator names on the command line
	if err != nil {
		return nil, fmt.Errorf("read dispositions: %w", err)
	}
	var out []Disposition
	for i, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 || fields[0] == "" {
			return nil, fmt.Errorf("%w: %s line %d: %q", ErrMalformed, path, i+1, line)
		}
		d := Disposition{Name: fields[0], Action: Action(fields[1]), Target: fields[2]}
		if !actions[d.Action] {
			return nil, fmt.Errorf("%w: %s line %d: unknown action %q", ErrMalformed, path, i+1, d.Action)
		}
		if d.Target == "" && d.Action != Keep {
			return nil, fmt.Errorf("%w: %s line %d: %s %s names no target", ErrMalformed, path, i+1, d.Action, d.Name)
		}
		out = append(out, d)
	}
	return out, nil
}

// CheckCoverage reports an error unless every identifier in base has exactly
// one disposition and every disposition names an identifier in base: none
// missing, none extra, none twice.
func CheckCoverage(base []Entry, dispositions []Disposition) error {
	want := map[string]bool{}
	for _, e := range base {
		if e.Identifier() {
			want[e.Name] = true
		}
	}
	seen := map[string]bool{}
	var problems []string
	for _, d := range dispositions {
		switch {
		case seen[d.Name]:
			problems = append(problems, "disposed twice: "+d.Name)
		case !want[d.Name]:
			problems = append(problems, "not in the baseline: "+d.Name)
		}
		seen[d.Name] = true
	}
	for _, e := range base {
		if e.Identifier() && !seen[e.Name] {
			problems = append(problems, "no disposition: "+e.Name)
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w:\n  %s", ErrCoverage, strings.Join(problems, "\n  "))
	}
	return nil
}

// CheckHonored reports an error unless the current API matches every
// disposition exactly: a KEEP identifier is still there under the same
// kind and name, and every RENAME/MOVE/UNEXPORT/DELETE identifier is gone
// from the current API under its old kind and name. Fields and interface
// methods ride with their type (Entry.Identifier) and are not checked on
// their own; a disposition naming something outside base is not this
// check's job (CheckCoverage reports it).
func CheckHonored(base, current []Entry, dispositions []Disposition) error {
	byName := map[string]Action{}
	targetByName := map[string]string{}
	for _, d := range dispositions {
		byName[d.Name] = d.Action
		targetByName[d.Name] = d.Target
	}
	inCurrent := map[string]bool{}
	aliasedType := map[string]bool{}
	for _, e := range current {
		inCurrent[e.Kind+"\t"+e.Name] = true
		if e.Kind == "alias" {
			aliasedType[e.Name] = true
		}
	}
	var problems []string
	for _, e := range base {
		if !e.Identifier() {
			continue
		}
		action, ok := byName[e.Name]
		if !ok {
			continue
		}
		present := inCurrent[e.Kind+"\t"+e.Name]
		// A KEEP method whose receiver type is now a type alias (type X =
		// some.ForeignType) is honored without being found directly: Go
		// gives X every method the foreign type declares, but no FuncDecl
		// with receiver X exists in this package's source for an AST-only
		// dump to see (a method cannot be added to an alias of a foreign
		// type, so the design never writes one).
		if e.Kind == "method" && action == Keep && !present && aliasedType[receiverOf(e.Name)] {
			continue
		}
		switch {
		case action == Keep && !present:
			problems = append(problems, "KEEP but gone from the current API: "+e.Name)
		case action != Keep && present:
			// A RENAME whose target text names the identifier itself
			// (Segment, H9: redefined in place rather than renamed away)
			// can never read as honored by the Kind+Name comparison above,
			// because the "new" name is the old one. CheckHonored has no
			// structural comparison to fall back on -- Fields/ifacemethods
			// are not Identifiers (see Entry.Identifier) -- so it trusts
			// the disposition's own words instead: if the row that disposed
			// of this identifier chose to keep naming it, its continued
			// presence is what that row asked for, not a dishonored rename.
			if action == Rename && renameKeepsName(e.Name, targetByName[e.Name]) {
				continue
			}
			problems = append(problems, string(action)+" but still in the current API under its old name: "+e.Name)
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("%w:\n  %s", ErrDishonored, strings.Join(problems, "\n  "))
	}
	return nil
}

// renameKeepsName reports whether a RENAME disposition's target text names
// the identifier itself: the row describes a type redefined in place
// (Segment, H9) rather than a move to a different name. Matched on
// identifier boundaries, so a target mentioning the name only as part of a
// longer word ("SegmentGroup") does not count.
func renameKeepsName(name, target string) bool {
	for i := 0; i+len(name) <= len(target); i++ {
		if target[i:i+len(name)] != name {
			continue
		}
		var before, after byte
		if i > 0 {
			before = target[i-1]
		}
		if i+len(name) < len(target) {
			after = target[i+len(name)]
		}
		if !isIdentByte(before) && !isIdentByte(after) {
			return true
		}
	}
	return false
}

// isIdentByte reports whether b can appear in a Go identifier.
func isIdentByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// receiverOf returns the type part of a "method" Entry's Name ("Type" from
// "Type.Method").
func receiverOf(methodName string) string {
	if i := strings.IndexByte(methodName, '.'); i >= 0 {
		return methodName[:i]
	}
	return methodName
}
