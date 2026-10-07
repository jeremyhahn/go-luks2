// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// profileOf builds a profile in which pkg has covered of total statements, one
// statement per block, so a test can state coverage as a fraction.
func profileOf(t *testing.T, counts map[string][2]int) *profile {
	t.Helper()
	var b strings.Builder
	b.WriteString("mode: atomic\n")
	for pkg, c := range counts {
		covered, total := c[0], c[1]
		for i := 0; i < total; i++ {
			hits := 0
			if i < covered {
				hits = 1
			}
			fmt.Fprintf(&b, "%s/f.go:%d.1,%d.9 1 %d\n", pkg, i+1, i+1, hits)
		}
	}
	p := newProfile()
	if _, err := p.add("fixture", strings.NewReader(b.String())); err != nil {
		t.Fatalf("building the fixture profile: %v", err)
	}
	return p
}

func evaluate(g gate) (int, string) {
	var out bytes.Buffer
	failures := g.evaluate(&out)
	return failures, out.String()
}

// TestGateComparesExactlyRatherThanRounded is the arithmetic the old gate got
// wrong: 8999 of 10000 statements is 89.99%, which `go tool cover` prints as
// 90.0% and an integer-truncating comparison never saw at all.
func TestGateComparesExactlyRatherThanRounded(t *testing.T) {
	for _, tc := range []struct {
		name           string
		covered, total int
		fails          bool
	}{
		{"one statement short of 90%", 8999, 10000, true},
		{"exactly 90%", 9000, 10000, false},
		{"just over", 9001, 10000, false},
		{"0.014 points short, which go tool cover prints as 90.0%", 2696, 2996, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := gate{
				floors:   []floor{{pkg: "m/a", tier: tierUnit, min: 9000}},
				packages: []string{"m/a"},
				tier:     tierUnit,
				target:   9000,
				profile:  profileOf(t, map[string][2]int{"m/a": {tc.covered, tc.total}}),
			}
			failures, out := evaluate(g)
			if (failures > 0) != tc.fails {
				t.Fatalf("%d of %d: failures = %d, want failing=%v\n%s", tc.covered, tc.total, failures, tc.fails, out)
			}
			if tc.fails && !strings.Contains(out, "is below its floor of 90.00%") {
				t.Errorf("output does not explain the failure:\n%s", out)
			}
		})
	}
}

// TestGateFailsAPackageEvenWhenTheAggregatePasses is the second control: an
// aggregate above the bar can hide a package far below it.
func TestGateFailsAPackageEvenWhenTheAggregatePasses(t *testing.T) {
	g := gate{
		floors: []floor{
			{pkg: "m/big", tier: tierUnit, min: 9000},
			{pkg: "m/small", tier: tierUnit, min: 9000},
		},
		packages: []string{"m/big", "m/small"},
		tier:     tierUnit,
		target:   9000,
		profile:  profileOf(t, map[string][2]int{"m/big": {990, 1000}, "m/small": {5, 10}}),
	}
	failures, out := evaluate(g)
	if failures != 1 || !strings.Contains(out, "FAIL m/small [unit]: 50.00%") {
		t.Fatalf("failures = %d, want m/small alone to fail\n%s", failures, out)
	}
	if !strings.Contains(out, "aggregate over the packages above: 98.51%") {
		t.Errorf("the aggregate is not reported:\n%s", out)
	}
}

// TestGateFailsALegThatWroteNoProfile is the case the old merge swallowed:
// a package whose profile is missing contributes nothing, and the total of the
// rest went UP.
func TestGateFailsALegThatWroteNoProfile(t *testing.T) {
	g := gate{
		floors: []floor{
			{pkg: "m/a", tier: tierUnit, min: 9000},
			{pkg: "m/b", tier: tierUnit, min: 9000},
		},
		packages: []string{"m/a", "m/b"},
		tier:     tierUnit,
		target:   9000,
		profile:  profileOf(t, map[string][2]int{"m/a": {10, 10}}),
	}
	failures, out := evaluate(g)
	if failures != 1 || !strings.Contains(out, "FAIL m/b [unit]: the profile records no statements") {
		t.Fatalf("failures = %d, want m/b to fail for having no profile\n%s", failures, out)
	}
}

func TestGateHoldsTheFloorsFileToThePackageList(t *testing.T) {
	for _, tc := range []struct {
		name     string
		floors   []floor
		packages []string
		want     string
	}{
		{
			name:     "a package with no unit floor",
			floors:   []floor{{pkg: "m/a", tier: tierUnit, min: 9000}},
			packages: []string{"m/a", "m/new"},
			want:     "FAIL m/new: no unit floor",
		},
		{
			name: "a package held to the target in no tier",
			floors: []floor{
				{pkg: "m/a", tier: tierUnit, min: 9000},
				{pkg: "m/low", tier: tierUnit, min: 8000},
			},
			packages: []string{"m/a", "m/low"},
			want:     "FAIL m/low: no tier holds it to the 90.00% target",
		},
		{
			name: "a floor for a package that no longer exists",
			floors: []floor{
				{pkg: "m/a", tier: tierUnit, min: 9000},
				{pkg: "m/gone", tier: tierUnit, min: 9000, line: 7},
			},
			packages: []string{"m/a"},
			want:     "FAIL m/gone [unit]: the floors file names a package that does not exist (line 7)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			counts := map[string][2]int{}
			for _, p := range tc.packages {
				counts[p] = [2]int{10, 10}
			}
			g := gate{floors: tc.floors, packages: tc.packages, tier: tierUnit, target: 9000, profile: profileOf(t, counts)}
			failures, out := evaluate(g)
			if failures == 0 || !strings.Contains(out, tc.want) {
				t.Fatalf("failures = %d, want %q\n%s", failures, tc.want, out)
			}
		})
	}
}

// TestGateHoldsAKernelBoundPackageToTheTargetInTheCombinedTier is the shape
// pkg/luks2 has: a unit floor below the target, which is legitimate only
// because the combined tier holds it to 90 -- and the unit run does not check
// the combined floor, the combined run does.
func TestGateHoldsAKernelBoundPackageToTheTargetInTheCombinedTier(t *testing.T) {
	floors := []floor{
		{pkg: "m/lib", tier: tierUnit, min: 8000},
		{pkg: "m/lib", tier: tierCombined, min: 9000},
	}
	unit := gate{floors: floors, packages: []string{"m/lib"}, tier: tierUnit, target: 9000,
		profile: profileOf(t, map[string][2]int{"m/lib": {85, 100}})}
	if failures, out := evaluate(unit); failures != 0 {
		t.Fatalf("unit tier: failures = %d, want 0 at 85%% against a unit floor of 80%%\n%s", failures, out)
	}

	combined := unit
	combined.tier = tierCombined
	failures, out := evaluate(combined)
	if failures != 1 || !strings.Contains(out, "FAIL m/lib [combined]: 85.00%") {
		t.Fatalf("combined tier: failures = %d, want the 90%% combined floor to fail 85%%\n%s", failures, out)
	}
}

func TestGateChecksADeclaredEmptyPackageAgainstTheProfile(t *testing.T) {
	floors := []floor{{pkg: "m/doc", tier: tierUnit, none: true}, {pkg: "m/a", tier: tierUnit, min: 9000}}
	packages := []string{"m/doc", "m/a"}

	empty := gate{floors: floors, packages: packages, tier: tierUnit, target: 9000,
		profile: profileOf(t, map[string][2]int{"m/a": {10, 10}})}
	if failures, out := evaluate(empty); failures != 0 || !strings.Contains(out, "ok   m/doc [unit]: no statements, as declared") {
		t.Fatalf("failures = %d, want the declared-empty package to pass\n%s", failures, out)
	}

	grew := empty
	grew.profile = profileOf(t, map[string][2]int{"m/a": {10, 10}, "m/doc": {0, 3}})
	if failures, out := evaluate(grew); failures != 1 || !strings.Contains(out, "declared to hold no statements, but the profile records 3") {
		t.Fatalf("failures = %d, want a package that grew code to need a real floor\n%s", failures, out)
	}
}

func TestGateFailsWhenItExaminedNothing(t *testing.T) {
	g := gate{
		floors:   []floor{{pkg: "m/a", tier: tierUnit, min: 9000}},
		packages: []string{"m/a"},
		tier:     tierCombined,
		target:   9000,
		profile:  profileOf(t, map[string][2]int{"m/a": {10, 10}}),
	}
	failures, out := evaluate(g)
	if failures != 1 || !strings.Contains(out, "holds no combined floor, so this gate examined nothing") {
		t.Fatalf("failures = %d, want a gate with nothing to check to fail\n%s", failures, out)
	}
}

func TestCoverageTruncatesSoAPrintedPassIsAPass(t *testing.T) {
	// 89.999...%: rounding would print 90.00% beside a FAIL.
	if got := coverage(tally{covered: 89999, total: 100000}); got != 8999 {
		t.Fatalf("coverage = %s, want 89.99%%", got)
	}
	if got := coverage(tally{}); got != 0 {
		t.Fatalf("coverage of nothing = %s, want 0", got)
	}
}

// TestGateArithmeticCannotOverflow: the comparison is exact at any size, so
// a tally no multiplication in int64 could hold still compares correctly.
func TestGateArithmeticCannotOverflow(t *testing.T) {
	huge := tally{covered: 1 << 61, total: 1<<62 - 1} // just over 50%
	if !atLeast(huge, 5000) || atLeast(huge, 5001) {
		t.Fatalf("atLeast misjudged %d of %d against 50.00%% and 50.01%%", huge.covered, huge.total)
	}
	if got := coverage(huge); got != 5000 {
		t.Fatalf("coverage = %s, want 50.00%%", got)
	}
}
