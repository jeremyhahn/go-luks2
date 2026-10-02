// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"strings"
	"testing"
)

func TestParsePercentReadsHundredthsExactly(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want percent
	}{
		{"90", 9000},
		{"90.0", 9000},
		{"89.99", 8999},
		{"81.7", 8170},
		{"0", 0},
		{"100", 10000},
		{"100.00", 10000},
		{"007.5", 750},
	} {
		got, err := parsePercent(tc.in)
		if err != nil {
			t.Errorf("parsePercent(%q) = %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parsePercent(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestParsePercentRefusesWhatIsNotAPercentage(t *testing.T) {
	for _, in := range []string{
		"", ".5", "90.", "89.999", "9O", "-1", "+90", "100.01", "101", "1e2", "90.5x",
		"99999999999999999999",
	} {
		if got, err := parsePercent(in); err == nil {
			t.Errorf("parsePercent(%q) = %d, want an error", in, got)
		}
	}
}

func TestPercentPrintsTwoDecimalPlaces(t *testing.T) {
	for p, want := range map[percent]string{9000: "90.00%", 8999: "89.99%", 5: "0.05%", 10000: "100.00%"} {
		if got := p.String(); got != want {
			t.Errorf("percent(%d).String() = %q, want %q", int64(p), got, want)
		}
	}
}

func TestParseFloorsReadsEveryTierAndSkipsCommentary(t *testing.T) {
	body := `# a comment
example.com/m/a  unit      81.70

example.com/m/a  combined  90
   # an indented comment
example.com/m/doc  unit    none
`
	floors, err := parseFloors("floors", strings.NewReader(body))
	if err != nil {
		t.Fatalf("parseFloors: %v", err)
	}
	want := []floor{
		{pkg: "example.com/m/a", tier: tierUnit, min: 8170, line: 2},
		{pkg: "example.com/m/a", tier: tierCombined, min: 9000, line: 4},
		{pkg: "example.com/m/doc", tier: tierUnit, none: true, line: 6},
	}
	if len(floors) != len(want) {
		t.Fatalf("parsed %d floors, want %d: %+v", len(floors), len(want), floors)
	}
	for i := range want {
		if floors[i] != want[i] {
			t.Errorf("floor %d = %+v, want %+v", i, floors[i], want[i])
		}
	}
}

func TestParseFloorsRefusesAFileItCannotTrust(t *testing.T) {
	for _, tc := range []struct {
		name, body, mention string
	}{
		{"missing floor", "example.com/m/a unit\n", ":1:"},
		{"extra field", "example.com/m/a unit 90 strict\n", ":1:"},
		{"unknown tier", "example.com/m/a nightly 90\n", `"nightly"`},
		{"unreadable floor", "example.com/m/a unit ninety\n", "ninety"},
		{"floor over 100", "example.com/m/a unit 100.5\n", "100.5"},
		{"a package twice in one tier", "example.com/m/a unit 90\nexample.com/m/a unit 95\n", "line 1"},
		{"line too long", "example.com/m/" + strings.Repeat("a", 70*1024) + " unit 90\n", "floors"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseFloors("floors", strings.NewReader(tc.body))
			if !errors.Is(err, ErrFloorsMalformed) {
				t.Fatalf("parseFloors = %v, want ErrFloorsMalformed", err)
			}
			if !strings.Contains(err.Error(), tc.mention) {
				t.Errorf("error %q does not mention %q", err, tc.mention)
			}
		})
	}
}
