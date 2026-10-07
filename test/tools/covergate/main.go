// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Command covergate is the repository's coverage gate (#141). It refuses
// coverage below the per-package floors in coverage-floors.txt.
//
//	covergate -floors coverage-floors.txt -tier unit -profile coverage.out $(go list ./...)
//	covergate -floors coverage-floors.txt -tier combined \
//	    -profile coverage-unit.out -profile coverage-integration.out $(go list ./...)
//
// It exists because the gate it replaces could not fail in the ways that
// mattered. The total was printed and never compared; the merge swallowed a
// missing leg, so losing a package made the total go UP; and the one
// comparison anywhere truncated the percentage to an integer. Here every
// package is compared on its own, in integer arithmetic, against floors that
// must name every package `go list` reports.
//
// Exit codes: 0 every check passed, 1 a check failed, 2 the inputs were
// unusable. Both non-zero codes fail the build.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// profileList is a repeatable -profile flag.
type profileList []string

func (p *profileList) String() string { return strings.Join(*p, ",") }

func (p *profileList) Set(v string) error {
	*p = append(*p, v)
	return nil
}

func run(args []string, stdout, stderr io.Writer) int {
	g, err := configure(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "covergate: %v\n", err)
		return 2
	}
	if failures := g.evaluate(stdout); failures > 0 {
		fmt.Fprintf(stdout, "coverage gate FAILED: %d check(s) did not pass\n", failures)
		return 1
	}
	fmt.Fprintf(stdout, "coverage is at or above every %s floor\n", g.tier)
	return 0
}

// configure parses the flags and reads every input. Any input that cannot be
// read in full is an error, never an empty measurement.
func configure(args []string, stderr io.Writer) (gate, error) {
	fs := flag.NewFlagSet("covergate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	floorsPath := fs.String("floors", "", "the floors file: `<import path> <tier> <floor>` per line")
	tier := fs.String("tier", "", "which floors to check: unit or combined")
	target := fs.String("target", "90", "the coverage every package must be held to in at least one tier")
	var profiles profileList
	fs.Var(&profiles, "profile", "a coverage profile; repeat to merge several")
	if err := fs.Parse(args); err != nil {
		return gate{}, fmt.Errorf("%w: %v", ErrUsage, err)
	}

	switch {
	case *floorsPath == "":
		return gate{}, fmt.Errorf("%w: -floors is required", ErrUsage)
	case *tier != tierUnit && *tier != tierCombined:
		return gate{}, fmt.Errorf("%w: -tier must be %q or %q, got %q", ErrUsage, tierUnit, tierCombined, *tier)
	case len(profiles) == 0:
		return gate{}, fmt.Errorf("%w: at least one -profile is required", ErrUsage)
	case fs.NArg() == 0:
		return gate{}, fmt.Errorf("%w: name the packages to gate (go list ./...)", ErrUsage)
	}
	want, err := parsePercent(*target)
	if err != nil {
		return gate{}, fmt.Errorf("%w: -target: %v", ErrUsage, err)
	}

	floors, err := readFloors(*floorsPath)
	if err != nil {
		return gate{}, err
	}
	merged := newProfile()
	for _, p := range profiles {
		if err := readProfile(merged, p); err != nil {
			return gate{}, err
		}
	}
	return gate{floors: floors, packages: fs.Args(), tier: *tier, target: want, profile: merged}, nil
}

func readFloors(name string) ([]floor, error) {
	f, err := os.Open(name) // #nosec G304 -- the floors file the caller names
	if err != nil {
		return nil, fmt.Errorf("reading the floors file: %w", err)
	}
	defer func() { _ = f.Close() }() // read-only; a close error loses nothing
	return parseFloors(name, f)
}

// readProfile merges one profile file. A missing or empty file is an error:
// a leg that wrote no profile is exactly what the old merge swallowed.
func readProfile(into *profile, name string) error {
	data, err := os.ReadFile(name) // #nosec G304 -- a profile the caller names
	if err != nil {
		return fmt.Errorf("reading coverage profile: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return fmt.Errorf("%w: %s is empty", ErrProfileMalformed, name)
	}
	blocks, err := into.add(name, bytes.NewReader(data))
	if err != nil {
		return err
	}
	// A header and nothing else is a leg that measured nothing. Merged with a
	// leg that did, it would vanish into the union -- which is the shape of the
	// missing-leg defect this gate exists to refuse.
	if blocks == 0 {
		return fmt.Errorf("%w: %s holds a header and no coverage blocks", ErrProfileMalformed, name)
	}
	return nil
}
