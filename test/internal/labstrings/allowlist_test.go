// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package labstrings

import (
	"errors"
	"strings"
	"testing"
)

func TestMatchPath(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"**/*_test.go", "pkg/luks2/header_test.go", true},
		{"**/*_test.go", "main_test.go", true},
		{"**/*_test.go", "pkg/luks2/header.go", false},
		{"test/internal/labstrings/*_test.go", "test/internal/labstrings/repo_test.go", true},
		{"test/internal/labstrings/*_test.go", "test/internal/harness/ledger_test.go", false},
		{"Makefile", "Makefile", true},
		{"Makefile", "test/Makefile", false},
		{"docs/**", "docs/cli/mount.md", true},
		{"docs/**", "docs", true},
		{"docs/**", "pkg/docs/x.md", false},
		{"docs/*.md", "docs/TESTING.md", true},
		{"docs/*.md", "docs/cli/mount.md", false},
		{"pkg/**/testdata/*.json", "pkg/luks2/testdata/a.json", true},
		{"pkg/**/testdata/*.json", "pkg/a/b/testdata/a.json", true},
		{"pkg/**/testdata/*.json", "pkg/luks2/a.json", false},
	}

	for _, tc := range cases {
		t.Run(tc.pattern+" vs "+tc.path, func(t *testing.T) {
			got, err := MatchPath(tc.pattern, tc.path)
			if err != nil {
				t.Fatalf("MatchPath: %v", err)
			}
			if got != tc.want {
				t.Errorf("MatchPath(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
			}
		})
	}
}

func TestMatchPath_AMalformedPatternIsReported(t *testing.T) {
	if _, err := MatchPath("pkg/[a-", "pkg/x"); err == nil {
		t.Fatal("a malformed character class matched silently")
	}
}

func TestValidateAllowList_RefusesEveryUnusableEntry(t *testing.T) {
	cases := []struct {
		name    string
		rule    AllowRule
		problem string
	}{
		{
			name:    "no path",
			rule:    AllowRule{Classes: []Class{ClassLabHost}, Reason: "because"},
			problem: "no path pattern",
		},
		{
			name:    "no reason",
			rule:    AllowRule{Path: "pkg/**", Classes: []Class{ClassLabHost}},
			problem: "no reason given",
		},
		{
			name:    "whitespace reason",
			rule:    AllowRule{Path: "pkg/**", Classes: []Class{ClassLabHost}, Reason: "   "},
			problem: "no reason given",
		},
		{
			name:    "no classes",
			rule:    AllowRule{Path: "pkg/**", Reason: "because"},
			problem: "no classes listed",
		},
		{
			name:    "unknown class",
			rule:    AllowRule{Path: "pkg/**", Classes: []Class{Class("whatever")}, Reason: "because"},
			problem: "unknown class whatever",
		},
		{
			name:    "malformed pattern",
			rule:    AllowRule{Path: "pkg/[a-", Classes: []Class{ClassLabHost}, Reason: "because"},
			problem: "malformed path pattern",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAllowList([]AllowRule{tc.rule})
			var ruleErr *AllowRuleError
			if !errors.As(err, &ruleErr) {
				t.Fatalf("err = %v, want *AllowRuleError", err)
			}
			if !strings.Contains(ruleErr.Error(), tc.problem) {
				t.Errorf("error %q does not report %q", ruleErr.Error(), tc.problem)
			}
		})
	}
}

func TestDefaultAllowList_IsUsableAndExplainsItself(t *testing.T) {
	if err := ValidateAllowList(DefaultAllowList); err != nil {
		t.Fatalf("the shipped allow-list is not usable: %v", err)
	}
	for _, rule := range DefaultAllowList {
		// A one-word reason is not a reason. The allow-list is the record
		// of what this repository knowingly publishes; each entry has to
		// tell the next reader why, or who owns removing it.
		if len(strings.Fields(rule.Reason)) < 5 {
			t.Errorf("%s: reason is too thin to be a decision: %q", rule.Path, rule.Reason)
		}
	}
}

func TestAcceptedClasses_UnionsEveryMatchingRule(t *testing.T) {
	rules := []AllowRule{
		{Path: "**/*_test.go", Classes: []Class{ClassLabHost}, Reason: "fleet hostnames in fixtures"},
		{Path: "pkg/x/y_test.go", Classes: []Class{ClassOwnerPath}, Reason: "one file, owned elsewhere"},
	}
	accepted := acceptedClasses(rules, "pkg/x/y_test.go")
	if !accepted[ClassLabHost] || !accepted[ClassOwnerPath] {
		t.Fatalf("accepted = %v, want both classes", accepted)
	}
	if accepted[ClassLabAddress] {
		t.Error("a class no rule names was accepted")
	}

	other := acceptedClasses(rules, "pkg/x/z_test.go")
	if other[ClassOwnerPath] {
		t.Error("the single-file rule reached a sibling file")
	}
}
