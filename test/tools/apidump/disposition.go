// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
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
