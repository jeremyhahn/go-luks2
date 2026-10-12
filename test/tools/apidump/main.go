// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Command apidump records and compares the exported API of a Go package.
//
//	apidump dump <dir>                        print the exported API declared in dir
//	apidump diff <baseline> <dir>             print what dir removed (-) and added (+) since baseline
//	apidump check <baseline> <dispositions>   fail unless every baseline identifier has exactly one disposition
//	apidump honor <baseline> <dispositions> <dir>        fail unless dir's API honors every disposition
//	apidump documented <exceptions> <docs> <pkg-root>    fail unless every export under pkg-root is named in a feature doc
//
// baseline/ holds the API as released in 0.5.0-alpha (luks2.tsv,
// cmd-luks2.tsv) and the redesign's disposition of every pkg/luks2 identifier
// (disposition-luks2.tsv). The check runs as a unit test of
// this package, so a disposition file that drifts from its baseline fails CI.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
)

const usage = `usage:
  apidump dump <dir>
  apidump diff <baseline> <dir>
  apidump check <baseline> <dispositions>
  apidump honor <baseline> <dispositions> <dir>
  apidump documented <exceptions> <docs> <pkg-root>`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if err := dispatch(args, stdout); err != nil {
		fmt.Fprintln(stderr, "apidump:", err)
		if errors.Is(err, ErrUsage) {
			fmt.Fprintln(stderr, usage)
		}
		return 1
	}
	return 0
}

var commands = map[string]struct {
	operands int
	run      func(operands []string, stdout io.Writer) error
}{
	"dump":  {1, dumpCommand},
	"diff":  {2, diffCommand},
	"check": {2, checkCommand},
	"honor": {3, honorCommand},

	"documented": {3, documentedCommand},
}

func dispatch(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return ErrUsage
	}
	cmd, ok := commands[args[0]]
	if !ok {
		return fmt.Errorf("%w: unknown command %q", ErrUsage, args[0])
	}
	if len(args)-1 != cmd.operands {
		return fmt.Errorf("%w: %s takes %d operand(s)", ErrUsage, args[0], cmd.operands)
	}
	return cmd.run(args[1:], stdout)
}

func dumpCommand(operands []string, stdout io.Writer) error {
	entries, err := Dump(operands[0])
	if err != nil {
		return err
	}
	for _, e := range entries {
		fmt.Fprintln(stdout, e)
	}
	return nil
}

func diffCommand(operands []string, stdout io.Writer) error {
	base, err := ReadDump(operands[0])
	if err != nil {
		return err
	}
	current, err := Dump(operands[1])
	if err != nil {
		return err
	}
	removed, added := Diff(base, current)
	for _, e := range removed {
		fmt.Fprintln(stdout, "-", e)
	}
	for _, e := range added {
		fmt.Fprintln(stdout, "+", e)
	}
	fmt.Fprintf(stdout, "%d removed, %d added since %s\n", len(removed), len(added), operands[0])
	return nil
}

func checkCommand(operands []string, stdout io.Writer) error {
	base, err := ReadDump(operands[0])
	if err != nil {
		return err
	}
	dispositions, err := ReadDispositions(operands[1])
	if err != nil {
		return err
	}
	if err := CheckCoverage(base, dispositions); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%d dispositions cover %s exactly\n", len(dispositions), operands[0])
	return nil
}

func honorCommand(operands []string, stdout io.Writer) error {
	base, err := ReadDump(operands[0])
	if err != nil {
		return err
	}
	dispositions, err := ReadDispositions(operands[1])
	if err != nil {
		return err
	}
	current, err := Dump(operands[2])
	if err != nil {
		return err
	}
	if err := CheckHonored(base, current, dispositions); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s honors every disposition in %s\n", operands[2], operands[1])
	return nil
}

func documentedCommand(operands []string, stdout io.Writer) error {
	exceptions, err := ReadExceptions(operands[0])
	if err != nil {
		return err
	}
	docs, err := ReadFeatureDocs(operands[1])
	if err != nil {
		return err
	}
	apis, err := DumpTree(operands[2])
	if err != nil {
		return err
	}
	if err := CheckDocumented(apis, docs, exceptions); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "every export under %s is named in a feature doc under %s, or excepted in %s\n", operands[2], operands[1], operands[0])
	return nil
}
