// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

// TestOptionsGivenRecordsPresence: Given tells an option given an empty value
// from one not given at all, for every kind of option (#237).
func TestOptionsGivenRecordsPresence(t *testing.T) {
	o := newOptions("test")
	inline := o.String("inline", "default")
	separate := o.String("separate", "default")
	o.String("absent", "")
	o.Bool("flag")
	o.Int("count", 0)

	if _, err := o.parse([]string{"--inline=", "--separate", "", "--flag", "--count=3"}); err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	for _, name := range []string{"inline", "separate", "flag", "count"} {
		if !o.Given(name) {
			t.Errorf("Given(%q) = false, want true", name)
		}
	}
	if *inline != "" || *separate != "" {
		t.Errorf("empty values were not kept: inline %q, separate %q", *inline, *separate)
	}
	for _, name := range []string{"absent", "undeclared"} {
		if o.Given(name) {
			t.Errorf("Given(%q) = true for an option that was not given", name)
		}
	}
}

// TestOptionsGivenIsNotSetByARefusedOption: an unknown option is refused and
// records nothing.
func TestOptionsGivenIsNotSetByARefusedOption(t *testing.T) {
	o := newOptions("test")
	if _, err := o.parse([]string{"--unknown=1"}); err == nil {
		t.Fatal("parse accepted an unknown option")
	}
	if o.Given("unknown") {
		t.Fatal("Given reported an option that was refused")
	}
}
