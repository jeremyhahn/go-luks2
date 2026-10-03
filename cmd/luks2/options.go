// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strconv"
	"strings"
)

// options is the option parser the subcommands share.
//
// It accepts `--name value` and `--name=value` IN ANY POSITION, which is what
// the commands that came before do -- `luks2 wipe --full /dev/x` and `luks2
// wipe /dev/x --full` both work today -- and what an operator who also uses
// cryptsetup expects. The standard library's flag package stops at the first
// non-flag argument, so adopting it would have made `luks2 open /dev/x name
// --key-file f` silently ignore the key file, which for an unattended unlock
// means falling back to a terminal prompt that is not there.
//
// An UNKNOWN option is refused rather than treated as a positional argument. A
// misspelled `--key-fil` that lands in the positional list becomes a device
// path, and the error an operator then reads is about the wrong thing entirely.
type options struct {
	command string
	strings map[string]*string
	bools   map[string]*bool
	ints    map[string]*int
	order   []string

	// given records every option that appeared on the command line, so a
	// caller can tell an option given an empty value from one not given.
	given map[string]bool
}

func newOptions(command string) *options {
	return &options{
		command: command,
		strings: make(map[string]*string),
		bools:   make(map[string]*bool),
		ints:    make(map[string]*int),
		given:   make(map[string]bool),
	}
}

// Given reports whether the option appeared on the command line, whatever
// its value -- including an empty one.
func (o *options) Given(name string) bool {
	return o.given[name]
}

// String declares an option taking a value.
func (o *options) String(name, def string) *string {
	v := def
	o.strings[name] = &v
	o.order = append(o.order, name)
	return &v
}

// Int declares an option taking a whole number.
func (o *options) Int(name string, def int) *int {
	v := def
	o.ints[name] = &v
	o.order = append(o.order, name)
	return &v
}

// Bool declares an option that is either present or absent.
func (o *options) Bool(name string) *bool {
	v := false
	o.bools[name] = &v
	o.order = append(o.order, name)
	return &v
}

// parse consumes the declared options out of args and returns the positional
// arguments that remain, in order.
func (o *options) parse(args []string) ([]string, error) {
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]

		// A bare "-" is a positional argument, not an option: it is how a key
		// file names standard input.
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positional = append(positional, arg)
			continue
		}

		name, inline, hasInline := strings.Cut(arg, "=")
		name = strings.TrimLeft(name, "-")

		if o.bools[name] != nil || o.strings[name] != nil || o.ints[name] != nil {
			o.given[name] = true
		}

		switch {
		case o.bools[name] != nil:
			if hasInline {
				value, err := strconv.ParseBool(inline)
				if err != nil {
					return nil, &UsageError{Command: o.command, Detail: fmt.Sprintf("--%s takes no value", name)}
				}
				*o.bools[name] = value
				continue
			}
			*o.bools[name] = true

		case o.strings[name] != nil, o.ints[name] != nil:
			value := inline
			if !hasInline {
				if i+1 >= len(args) {
					return nil, &UsageError{Command: o.command, Detail: fmt.Sprintf("--%s requires a value", name)}
				}
				i++
				value = args[i]
			}
			if p := o.strings[name]; p != nil {
				*p = value
				continue
			}
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, &UsageError{Command: o.command, Detail: fmt.Sprintf("--%s requires a number, not %q", name, value)}
			}
			*o.ints[name] = n

		default:
			return nil, &UsageError{Command: o.command, Detail: fmt.Sprintf("unknown option %s", arg)}
		}
	}

	return positional, nil
}

// usage prints a subcommand's usage block and returns the exit code that goes
// with it.
//
// It goes to STDOUT because an operator who typed the command wrong asked for
// it; the error that explains WHY goes to stderr through usageError. Splitting
// them is what makes `luks2 addkey 2>/dev/null` still show the help.
func (c *CLI) usage(command, synopsis, description string, lines ...string) int {
	_, _ = fmt.Fprintf(c.Stdout, "Usage: %s\n\n%s\n\nExamples:\n", synopsis, description)
	for _, line := range lines {
		_, _ = fmt.Fprintln(c.Stdout, line)
	}
	_, _ = fmt.Fprintln(c.Stdout, "\nOptions:")
	_, _ = fmt.Fprintf(c.Stdout, "%s", keyFileHelp)
	return 1
}

// usageError reports an argument this tool cannot act on. Nothing was
// attempted, which is why it is distinct from fail.
func (c *CLI) usageError(err error) int {
	_, _ = fmt.Fprintf(c.Stderr, "%v\n", err)
	return 1
}

// fail reports an operation that was attempted and did not succeed.
func (c *CLI) fail(err error) int {
	_, _ = fmt.Fprintf(c.Stderr, "Error: %v\n", err)
	return 1
}
