// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package wipe

import "testing"

func TestPatternString(t *testing.T) {
	for _, tc := range []struct {
		pattern Pattern
		want    string
	}{
		{Zeros, "zeros"},
		{Ones, "ones"},
		{Random, "random"},
		{Pattern(99), "unknown"},
	} {
		if got := tc.pattern.String(); got != tc.want {
			t.Errorf("Pattern(%d).String() = %q, want %q", tc.pattern, got, tc.want)
		}
	}
}
