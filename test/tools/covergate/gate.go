// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"math/big"
	"sort"
)

// gate is one evaluation: the floors, the packages that exist, the tier being
// measured, the target every package must be held to, and the merged profile.
type gate struct {
	floors   []floor
	packages []string
	tier     string
	target   percent
	profile  *profile
}

// evaluate prints one line per check and returns how many failed.
//
// Two kinds of check run, and both fail closed:
//
//   - The floors file against the package list, whatever the tier. Every
//     package must have a unit floor, every floor must name a package that
//     exists, and every package must be held to the target in at least one
//     tier. A package added without a floor, or a floor quietly lowered below
//     the target everywhere, is a gate switched off one package at a time.
//   - Every floor of the requested tier against the profile. A package with no
//     statements recorded fails: that is the missing leg the old merge
//     swallowed, which made the reported total go UP.
func (g gate) evaluate(w io.Writer) int {
	failures := 0
	fail := func(format string, args ...any) {
		failures++
		fmt.Fprintf(w, "FAIL "+format+"\n", args...)
	}

	exists := make(map[string]bool, len(g.packages))
	for _, pkg := range g.packages {
		exists[pkg] = true
	}
	hasUnit := make(map[string]bool)
	heldToTarget := make(map[string]bool)
	for _, f := range g.floors {
		if !exists[f.pkg] {
			fail("%s [%s]: the floors file names a package that does not exist (line %d)", f.pkg, f.tier, f.line)
			continue
		}
		if f.tier == tierUnit {
			hasUnit[f.pkg] = true
		}
		if f.none || f.min >= g.target {
			heldToTarget[f.pkg] = true
		}
	}
	packages := append([]string(nil), g.packages...)
	sort.Strings(packages)
	for _, pkg := range packages {
		if !hasUnit[pkg] {
			fail("%s: no %s floor, so nothing would measure it", pkg, tierUnit)
		}
		if !heldToTarget[pkg] {
			fail("%s: no tier holds it to the %s target", pkg, g.target)
		}
	}

	measured := g.profile.byPackage()
	checked := 0
	var sum tally
	for _, f := range g.floors {
		if f.tier != g.tier || !exists[f.pkg] {
			continue
		}
		checked++
		t := measured[f.pkg]
		if f.none {
			if t.total != 0 {
				fail("%s [%s]: declared to hold no statements, but the profile records %d", f.pkg, f.tier, t.total)
				continue
			}
			fmt.Fprintf(w, "ok   %s [%s]: no statements, as declared\n", f.pkg, f.tier)
			continue
		}
		if t.total == 0 {
			fail("%s [%s]: the profile records no statements for it -- its tests did not run, or ran without a profile", f.pkg, f.tier)
			continue
		}
		sum.covered += t.covered
		sum.total += t.total
		got := coverage(t)
		if !atLeast(t, f.min) {
			fail("%s [%s]: %s (%d of %d statements) is below its floor of %s", f.pkg, f.tier, got, t.covered, t.total, f.min)
			continue
		}
		fmt.Fprintf(w, "ok   %s [%s]: %s (%d of %d statements), floor %s\n", f.pkg, f.tier, got, t.covered, t.total, f.min)
	}
	if checked == 0 {
		fail("the floors file holds no %s floor, so this gate examined nothing", g.tier)
	}
	if sum.total > 0 {
		fmt.Fprintf(w, "     %s aggregate over the packages above: %s (%d of %d statements)\n",
			g.tier, coverage(sum), sum.covered, sum.total)
	}
	return failures
}

// atLeast reports whether t's coverage is at or above min, EXACTLY: it
// compares covered/total >= min/10000 as covered*10000 >= min*total, in
// arbitrary precision so that no tally can overflow the comparison.
func atLeast(t tally, min percent) bool {
	lhs := new(big.Int).Mul(big.NewInt(t.covered), big.NewInt(10000))
	rhs := new(big.Int).Mul(big.NewInt(int64(min)), big.NewInt(t.total))
	return lhs.Cmp(rhs) >= 0
}

// coverage is t's coverage truncated, never rounded, to hundredths of a
// percent, so a value printed as meeting a floor always does.
func coverage(t tally) percent {
	if t.total == 0 {
		return 0
	}
	q := new(big.Int).Mul(big.NewInt(t.covered), big.NewInt(10000))
	return percent(q.Quo(q, big.NewInt(t.total)).Int64())
}
