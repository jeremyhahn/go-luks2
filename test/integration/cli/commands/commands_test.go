// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package commands

import "testing"

// TestRequiredArgCount covers both branches RequiredArgCount's loop can take:
// an argument marked Required, and one that is not. Every entry in Commands
// today has every argument Required (see commands.go's doc comment), so the
// table alone never exercises the "not required" branch; this constructs the
// mixed case directly rather than waiting for the table to grow one.
func TestRequiredArgCount(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmd  CommandDefinition
		want int
	}{
		{"no args", CommandDefinition{Verb: "noop"}, 0},
		{"all required", CommandDefinition{Verb: "open", Args: []ArgDefinition{
			{Name: "device", Required: true},
			{Name: "name", Required: true},
		}}, 2},
		{"mixed", CommandDefinition{Verb: "mixed", Args: []ArgDefinition{
			{Name: "device", Required: true},
			{Name: "flag", Required: false},
		}}, 1},
		{"none required", CommandDefinition{Verb: "optional", Args: []ArgDefinition{
			{Name: "flag", Required: false},
		}}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cmd.RequiredArgCount(); got != tc.want {
				t.Errorf("RequiredArgCount() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestCommandsTableRequiredArgsAreLeading guards the invariant the parity
// runner relies on: Commands lists only required positional arguments today
// (commands.go's doc comment), so RequiredArgCount must equal len(Args) for
// every entry the table currently carries.
func TestCommandsTableRequiredArgsAreLeading(t *testing.T) {
	for _, c := range Commands {
		seenOptional := false
		for _, a := range c.Args {
			if !a.Required {
				seenOptional = true
				continue
			}
			if seenOptional {
				t.Errorf("%s: required arg %q follows an optional one", c.Verb, a.Name)
			}
		}
	}
}
