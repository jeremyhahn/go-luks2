// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// block is one coverage block: how many statements it holds and whether any
// test executed it.
type block struct {
	statements int64
	covered    bool
}

// profile is the union of one or more coverage profiles, keyed by block
// position (`<import path>/<file>.go:<line>.<col>,<line>.<col>`).
//
// Merging is by position, not by concatenation. The same block appears once
// per test binary that compiled its package -- a unit profile and an
// integration profile both carry every block of pkg/luks2 -- so summing lines
// would count those statements twice and inflate the denominator and numerator
// alike. A block is covered if ANY profile executed it.
type profile struct {
	blocks map[string]block
}

func newProfile() *profile {
	return &profile{blocks: make(map[string]block)}
}

// maxBlockStatements bounds the statement count of one block. A Go basic block
// holds a handful of statements; the bound exists so that no profile, however
// it was produced, can push the tallies or the floor comparison into overflow.
const maxBlockStatements = 1 << 20

// add merges one profile, as written by `go test -coverprofile`, into p, and
// returns how many blocks it held.
//
// The FIRST non-blank line must be a valid `mode:` header -- it is what makes
// the file a coverage profile at all. Further `mode:` lines may follow,
// because concatenating profiles is how legs used to be merged and a
// concatenation is still a valid input, but each must name a real mode too.
// Any other line that is not a well-formed block is an error: a profile the
// gate cannot read in full is a profile whose coverage it does not know.
func (p *profile) add(name string, r io.Reader) (int, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo, blocks, sawHeader := 0, 0, false
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if mode, ok := strings.CutPrefix(line, "mode:"); ok {
			if !validModes[strings.TrimSpace(mode)] {
				return blocks, fmt.Errorf("%w: %s:%d: %q is not a coverage mode", ErrProfileMalformed, name, lineNo, strings.TrimSpace(mode))
			}
			sawHeader = true
			continue
		}
		if !sawHeader {
			return blocks, fmt.Errorf("%w: %s:%d: a profile starts with a mode: line", ErrProfileMalformed, name, lineNo)
		}
		pos, b, err := parseBlock(line)
		if err != nil {
			return blocks, fmt.Errorf("%w: %s:%d: %v", ErrProfileMalformed, name, lineNo, err)
		}
		if prev, ok := p.blocks[pos]; ok {
			if prev.statements != b.statements {
				return blocks, fmt.Errorf("%w: %s:%d: %s holds %d statements here and %d elsewhere",
					ErrProfileConflict, name, lineNo, pos, b.statements, prev.statements)
			}
			b.covered = b.covered || prev.covered
		}
		p.blocks[pos] = b
		blocks++
	}
	if err := scanner.Err(); err != nil {
		return blocks, fmt.Errorf("%w: %s: %v", ErrProfileMalformed, name, err)
	}
	return blocks, nil
}

// validModes are the modes `go test -covermode` writes.
var validModes = map[string]bool{"set": true, "count": true, "atomic": true}

// blockRange matches a block's position: start line.column, end line.column,
// and nothing else.
var blockRange = regexp.MustCompile(`^([0-9]+)\.([0-9]+),([0-9]+)\.([0-9]+)$`)

// parseBlock parses `<file>:<sl>.<sc>,<el>.<ec> <statements> <count>`.
func parseBlock(line string) (string, block, error) {
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return "", block{}, fmt.Errorf("want 3 fields, got %d in %q", len(fields), line)
	}
	pos := fields[0]
	colon := strings.LastIndexByte(pos, ':')
	if colon <= 0 || !strings.HasSuffix(pos[:colon], ".go") {
		return "", block{}, fmt.Errorf("no <file>.go:<range> position in %q", pos)
	}
	m := blockRange.FindStringSubmatch(pos[colon+1:])
	if m == nil {
		return "", block{}, fmt.Errorf("unreadable range in %q", pos)
	}
	var coord [4]int
	for i := range coord {
		v, err := strconv.Atoi(m[i+1])
		if err != nil || v < 1 {
			return "", block{}, fmt.Errorf("range %q has a coordinate that is not a positive line or column", pos)
		}
		coord[i] = v
	}
	if sl, sc, el, ec := coord[0], coord[1], coord[2], coord[3]; el < sl || (el == sl && ec < sc) {
		return "", block{}, fmt.Errorf("range %q ends before it starts", pos)
	}
	statements, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || statements < 0 || statements > maxBlockStatements {
		return "", block{}, fmt.Errorf("statement count %q is not between 0 and %d", fields[1], maxBlockStatements)
	}
	count, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || count < 0 {
		return "", block{}, fmt.Errorf("unreadable execution count %q", fields[2])
	}
	return pos, block{statements: statements, covered: count > 0}, nil
}

// tally is a package's covered and total statement counts.
type tally struct {
	covered, total int64
}

// byPackage sums the blocks of every file into the package that holds it. A
// file's package is its directory, which is its import path in a profile.
func (p *profile) byPackage() map[string]tally {
	out := make(map[string]tally)
	for pos, b := range p.blocks {
		file := pos[:strings.LastIndexByte(pos, ':')]
		pkg := path.Dir(file)
		t := out[pkg]
		t.total += b.statements
		if b.covered {
			t.covered += b.statements
		}
		out[pkg] = t
	}
	return out
}
