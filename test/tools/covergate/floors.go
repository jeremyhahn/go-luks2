// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Tiers a floor can be measured in.
const (
	// tierUnit is the default-tag unit suite, measured on its own.
	tierUnit = "unit"

	// tierCombined is the union of the unit suite and the devcontainer
	// integration suite, for a package whose remaining statements need a real
	// kernel -- loop devices, device-mapper, mount(2) -- to execute.
	tierCombined = "combined"
)

// noStatements is the floor spelled for a package that declares no statements
// at all (doc.go only). The gate checks the claim rather than trusting it: a
// package listed this way that turns up statements fails.
const noStatements = "none"

// percent is a coverage percentage in hundredths of a percent, so 90 is 9000
// and 81.74 is 8174. Floors are compared in integers: rounding is how a
// coverage of 89.95% printed as 90.0% and passed a 90% bar.
type percent int64

func (p percent) String() string {
	return fmt.Sprintf("%d.%02d%%", int64(p)/100, int64(p)%100)
}

// parsePercent reads a percentage with at most two decimal places, between 0
// and 100 inclusive.
func parsePercent(s string) (percent, error) {
	whole, frac, hasFrac := strings.Cut(s, ".")
	if whole == "" || (hasFrac && (frac == "" || len(frac) > 2)) || !digits(whole+frac) {
		return 0, fmt.Errorf("%q is not a percentage with at most two decimal places", s)
	}
	w, err := strconv.ParseInt(whole, 10, 64)
	if err != nil || w > 100 {
		return 0, fmt.Errorf("%q is not a percentage between 0 and 100", s)
	}
	p := w * 100
	for i, scale := 0, int64(10); i < len(frac); i, scale = i+1, scale/10 {
		p += int64(frac[i]-'0') * scale
	}
	if p > 10000 {
		return 0, fmt.Errorf("%q is not a percentage between 0 and 100", s)
	}
	return percent(p), nil
}

// digits reports whether s is made of ASCII digits only.
func digits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// floor is one line of the floors file.
type floor struct {
	pkg  string
	tier string
	// none is set for a package declared to hold no statements; min is then
	// unused.
	none bool
	min  percent
	line int
}

// parseFloors reads `<import path> <tier> <floor>` lines. Blank lines and
// lines starting with # are ignored. A package may appear once per tier.
func parseFloors(name string, r io.Reader) ([]floor, error) {
	var floors []floor
	seen := make(map[[2]string]int)
	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("%w: %s:%d: want `<import path> <tier> <floor>`, got %q",
				ErrFloorsMalformed, name, lineNo, line)
		}
		f := floor{pkg: fields[0], tier: fields[1], line: lineNo}
		if f.tier != tierUnit && f.tier != tierCombined {
			return nil, fmt.Errorf("%w: %s:%d: tier %q is neither %q nor %q",
				ErrFloorsMalformed, name, lineNo, f.tier, tierUnit, tierCombined)
		}
		if fields[2] == noStatements {
			f.none = true
		} else {
			p, err := parsePercent(fields[2])
			if err != nil {
				return nil, fmt.Errorf("%w: %s:%d: %v", ErrFloorsMalformed, name, lineNo, err)
			}
			f.min = p
		}
		key := [2]string{f.pkg, f.tier}
		if prev, ok := seen[key]; ok {
			return nil, fmt.Errorf("%w: %s:%d: %s already has a %s floor on line %d",
				ErrFloorsMalformed, name, lineNo, f.pkg, f.tier, prev)
		}
		seen[key] = lineNo
		floors = append(floors, f)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrFloorsMalformed, name, err)
	}
	return floors, nil
}
