// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestProfileMergesOneBlockSeenByTwoTestBinaries(t *testing.T) {
	// The same block, as a unit profile and an integration profile both
	// record it. Concatenated, it would count its 4 statements twice.
	unit := "mode: atomic\nexample.com/m/p/a.go:1.1,3.2 4 0\nexample.com/m/p/a.go:4.1,5.2 1 1\n"
	integration := "mode: set\nexample.com/m/p/a.go:1.1,3.2 4 1\n"

	p := newProfile()
	if _, err := p.add("unit", strings.NewReader(unit)); err != nil {
		t.Fatalf("add unit: %v", err)
	}
	if _, err := p.add("integration", strings.NewReader(integration)); err != nil {
		t.Fatalf("add integration: %v", err)
	}

	got := p.byPackage()["example.com/m/p"]
	if got != (tally{covered: 5, total: 5}) {
		t.Fatalf("tally = %+v, want 5 of 5: the block is covered by the second profile and counted once", got)
	}
}

func TestProfileKeepsACoveredBlockCoveredWhicheverProfileComesLast(t *testing.T) {
	hit := "mode: set\nexample.com/m/p/a.go:1.1,3.2 2 7\n"
	miss := "mode: set\nexample.com/m/p/a.go:1.1,3.2 2 0\n"
	for _, order := range [][2]string{{hit, miss}, {miss, hit}} {
		p := newProfile()
		for i, body := range order {
			if _, err := p.add(fmt.Sprint(i), strings.NewReader(body)); err != nil {
				t.Fatalf("add %d: %v", i, err)
			}
		}
		if got := p.byPackage()["example.com/m/p"]; got != (tally{covered: 2, total: 2}) {
			t.Fatalf("order %q: tally = %+v, want 2 of 2", order, got)
		}
	}
}

func TestProfileAttributesFilesToTheirOwnPackage(t *testing.T) {
	body := strings.Join([]string{
		"mode: atomic",
		"example.com/m/cmd/tool/main.go:1.1,2.2 3 1",
		"example.com/m/cmd/tool/run.go:1.1,2.2 2 0",
		"example.com/m/cmd/main.go:1.1,2.2 1 1",
		"",
	}, "\n")
	p := newProfile()
	if _, err := p.add("p", strings.NewReader(body)); err != nil {
		t.Fatalf("add: %v", err)
	}
	got := p.byPackage()
	if got["example.com/m/cmd/tool"] != (tally{covered: 3, total: 5}) {
		t.Errorf("cmd/tool = %+v, want 3 of 5", got["example.com/m/cmd/tool"])
	}
	if got["example.com/m/cmd"] != (tally{covered: 1, total: 1}) {
		t.Errorf("cmd = %+v, want 1 of 1: a parent directory is a different package", got["example.com/m/cmd"])
	}
}

func TestProfileRefusesWhatGoTestDoesNotWrite(t *testing.T) {
	for _, tc := range []struct {
		name, line string
	}{
		{"too few fields", "example.com/m/p/a.go:1.1,3.2 4"},
		{"too many fields", "example.com/m/p/a.go:1.1,3.2 4 1 1"},
		{"no position", "example.com/m/p/a.go 4 1"},
		{"not a go file", "example.com/m/p/a.txt:1.1,3.2 4 1"},
		{"unreadable range", "example.com/m/p/a.go:one,two 4 1"},
		{"truncated range", "example.com/m/p/a.go:1.1,3 4 1"},
		{"non-numeric statements", "example.com/m/p/a.go:1.1,3.2 four 1"},
		{"negative statements", "example.com/m/p/a.go:1.1,3.2 -4 1"},
		{"non-numeric count", "example.com/m/p/a.go:1.1,3.2 4 once"},
		{"negative count", "example.com/m/p/a.go:1.1,3.2 4 -1"},
		{"trailing junk after the range", "example.com/m/p/a.go:1.1,3.2x 4 1"},
		{"a zero line", "example.com/m/p/a.go:0.1,3.2 4 1"},
		{"a zero column", "example.com/m/p/a.go:1.0,3.2 4 1"},
		{"a range that ends on an earlier line", "example.com/m/p/a.go:5.1,3.2 4 1"},
		{"a range that ends at an earlier column", "example.com/m/p/a.go:3.9,3.2 4 1"},
		{"a statement count no block holds", "example.com/m/p/a.go:1.1,3.2 1152921504606846976 0"},
		{"a mode that does not exist", "mode: garbage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newProfile().add("bad.out", strings.NewReader("mode: set\n"+tc.line+"\n"))
			if !errors.Is(err, ErrProfileMalformed) {
				t.Fatalf("add = %v, want ErrProfileMalformed", err)
			}
			if !strings.Contains(err.Error(), "bad.out:2") {
				t.Errorf("error %q does not name the file and line", err)
			}
		})
	}
}

func TestProfileRefusesTwoProfilesOfDifferentSource(t *testing.T) {
	p := newProfile()
	if _, err := p.add("a", strings.NewReader("mode: set\nexample.com/m/p/a.go:1.1,3.2 4 1\n")); err != nil {
		t.Fatalf("add a: %v", err)
	}
	_, err := p.add("b", strings.NewReader("mode: set\nexample.com/m/p/a.go:1.1,3.2 5 1\n"))
	if !errors.Is(err, ErrProfileConflict) {
		t.Fatalf("add b = %v, want ErrProfileConflict", err)
	}
}

func TestProfileRefusesALineTooLongToScan(t *testing.T) {
	long := "mode: set\nexample.com/m/p/" + strings.Repeat("x", 2<<20) + ".go:1.1,2.2 1 1\n"
	if _, err := newProfile().add("long", strings.NewReader(long)); !errors.Is(err, ErrProfileMalformed) {
		t.Fatalf("add = %v, want ErrProfileMalformed", err)
	}
}

// TestProfileMustStartWithAModeHeader: the header is what makes a file a
// coverage profile. One that starts with a block, or names a mode go test
// never writes, is not one -- whatever the blocks after it say.
func TestProfileMustStartWithAModeHeader(t *testing.T) {
	for name, body := range map[string]string{
		"no header":         "example.com/m/p/a.go:1.1,3.2 4 1\n",
		"an unknown mode":   "mode: garbage\nexample.com/m/p/a.go:1.1,3.2 4 1\n",
		"an empty mode":     "mode:\nexample.com/m/p/a.go:1.1,3.2 4 1\n",
		"a block before it": "example.com/m/p/a.go:1.1,3.2 4 1\nmode: set\n",
	} {
		if _, err := newProfile().add(name, strings.NewReader(body)); !errors.Is(err, ErrProfileMalformed) {
			t.Errorf("%s: add = %v, want ErrProfileMalformed", name, err)
		}
	}
}

// TestProfileCountsTheBlocksItRead lets the caller refuse a leg that measured
// nothing: a header alone parses, and reports zero blocks.
func TestProfileCountsTheBlocksItRead(t *testing.T) {
	n, err := newProfile().add("p", strings.NewReader("mode: atomic\n"))
	if err != nil || n != 0 {
		t.Fatalf("header only: add = %d, %v; want 0 blocks and no error", n, err)
	}
	n, err = newProfile().add("p", strings.NewReader("mode: atomic\nexample.com/m/p/a.go:1.1,3.2 4 1\nexample.com/m/p/a.go:4.1,5.2 1 0\n"))
	if err != nil || n != 2 {
		t.Fatalf("two blocks: add = %d, %v; want 2", n, err)
	}
}
