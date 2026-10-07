// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"strconv"
	"strings"
)

// flags is a minimal, interspersed command-line flag parser: --name value,
// --name=value, and bare booleans, in any order relative to the positional
// arguments it returns. It exists because the standard flag package stops
// parsing at the first positional argument, and this CLI's commands put
// positionals before, after and between flags (`luks2 open --key-file f
// /dev/sdb1 name`).
type flags struct {
	command string
	strings map[string]*string
	bools   map[string]*bool
	ints    map[string]*int
	order   []string

	// given records every flag that appeared on the command line, so a
	// caller can tell a flag given an empty value from one not given.
	given map[string]bool
}

func newFlags(command string) *flags {
	return &flags{
		command: command,
		strings: make(map[string]*string),
		bools:   make(map[string]*bool),
		ints:    make(map[string]*int),
		given:   make(map[string]bool),
	}
}

// Given reports whether name appeared on the command line.
func (f *flags) Given(name string) bool {
	return f.given[name]
}

// String declares a string flag with a default value and returns a pointer
// parse fills in.
func (f *flags) String(name, def string) *string {
	v := def
	f.strings[name] = &v
	f.order = append(f.order, name)
	return &v
}

// Int declares an integer flag with a default value.
func (f *flags) Int(name string, def int) *int {
	v := def
	f.ints[name] = &v
	f.order = append(f.order, name)
	return &v
}

// Bool declares a boolean flag, false unless given.
func (f *flags) Bool(name string) *bool {
	v := false
	f.bools[name] = &v
	f.order = append(f.order, name)
	return &v
}

// parse consumes the declared flags out of args, wherever they appear, and
// returns the remaining positional arguments in order.
func (f *flags) parse(args []string) ([]string, error) {
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]

		// A bare "-" is a positional argument, not a flag: it is how a key
		// file names standard input.
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positional = append(positional, arg)
			continue
		}

		name, inline, hasInline := strings.Cut(arg, "=")
		name = strings.TrimLeft(name, "-")

		if f.bools[name] != nil || f.strings[name] != nil || f.ints[name] != nil {
			f.given[name] = true
		}

		switch {
		case f.bools[name] != nil:
			if hasInline {
				value, err := strconv.ParseBool(inline)
				if err != nil {
					return nil, &UsageError{Command: f.command, Detail: fmt.Sprintf("--%s takes no value", name)}
				}
				*f.bools[name] = value
				continue
			}
			*f.bools[name] = true

		case f.strings[name] != nil, f.ints[name] != nil:
			value := inline
			if !hasInline {
				if i+1 >= len(args) {
					return nil, &UsageError{Command: f.command, Detail: fmt.Sprintf("--%s requires a value", name)}
				}
				i++
				value = args[i]
			}
			if p := f.strings[name]; p != nil {
				*p = value
				continue
			}
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, &UsageError{Command: f.command, Detail: fmt.Sprintf("--%s requires a number, not %q", name, value)}
			}
			*f.ints[name] = n

		default:
			return nil, &UsageError{Command: f.command, Detail: fmt.Sprintf("unknown option %s", arg)}
		}
	}

	return positional, nil
}

// batchFlags declares --batch-mode and --yes, cryptsetup's two spellings
// for "skip the confirmation prompt", and returns a function reporting
// whether either was given.
func batchFlags(f *flags) func() bool {
	batch := f.Bool("batch-mode")
	yes := f.Bool("yes")
	return func() bool { return *batch || *yes }
}
