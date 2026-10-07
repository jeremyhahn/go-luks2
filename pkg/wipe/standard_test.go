// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package wipe

import (
	"slices"
	"testing"
)

func TestStandardString(t *testing.T) {
	for _, tc := range []struct {
		standard Standard
		want     string
	}{
		{NoStandard, "none"},
		{DoD3Pass, "dod3"},
		{DoD7Pass, "dod7"},
		{NIST, "nist"},
		{Standard(99), "unknown"},
	} {
		if got := tc.standard.String(); got != tc.want {
			t.Errorf("Standard(%d).String() = %q, want %q", tc.standard, got, tc.want)
		}
	}
}

func TestStandardPatterns(t *testing.T) {
	for _, tc := range []struct {
		standard Standard
		want     []Pattern
	}{
		{NoStandard, nil},
		{NIST, []Pattern{Random}},
		{DoD3Pass, []Pattern{Zeros, Ones, Random}},
		{DoD7Pass, []Pattern{Zeros, Ones, Random, Random, Zeros, Ones, Random}},
	} {
		if got := tc.standard.Patterns(); !slices.Equal(got, tc.want) {
			t.Errorf("%s.Patterns() = %v, want %v", tc.standard, got, tc.want)
		}
	}
}

func TestStandardRequiresVerification(t *testing.T) {
	for _, tc := range []struct {
		standard Standard
		want     bool
	}{
		{NoStandard, false},
		{NIST, false},
		{DoD3Pass, true},
		{DoD7Pass, true},
	} {
		if got := tc.standard.requiresVerification(); got != tc.want {
			t.Errorf("%s.requiresVerification() = %v, want %v", tc.standard, got, tc.want)
		}
	}
}
