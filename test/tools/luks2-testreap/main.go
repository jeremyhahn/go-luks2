// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Command luks2-testreap removes the host state a previous integration run
// recorded and did not clean up.
//
// It runs in the container entrypoint before the device-mapper guard, and
// that order is the whole point: the guard refuses on any mapping it cannot
// attribute, so a reap that ran after it would never execute on the hosts that
// need it. Reap, then guard, then the suite.
//
// It removes only what a ledger recorded, only where the live resource still
// carries the recorded identity. It has no sweep, no name pattern and no
// "looks like ours" branch. A host carrying state this suite never recorded is
// left exactly as it was found, and the guard behind it is what decides whether
// running is safe.
//
// No flag adds a sweep. An unrecorded device is cleared by an operator, per device,
// on positive attribution with stock losetup, with the reasoning in docs/volumes/engineering.md, "A device no ledger recorded is an
// operator's job, not this repository's". An --all here would be losetup -D
// under a new spelling.
//
// Exit codes:
//
//	0  nothing recorded, or everything recorded has been dealt with
//	1  recorded state could not be removed, or a ledger could not be read
//
// A non-zero exit means the host is NOT known to be clean. It is deliberately
// fatal to the job: the alternative is a run that proceeds onto a host in an
// unknown state and reports whatever it finds as a test result.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

func main() {
	os.Exit(run(os.Args[1:], harness.SystemRemover{}, os.Stdout, os.Stderr))
}

// run is the reaper with the host and streams injected; it returns the exit code.
func run(args []string, rm harness.Remover, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("luks2-testreap", flag.ContinueOnError)
	fs.SetOutput(stderr)

	// harness.StateDir(), the same directory BeginSuite writes to.
	dir := fs.String("state-dir", harness.StateDir(),
		"directory holding the run ledgers; must outlive the container")
	self := fs.String("self", "",
		"run id to leave alone, for a reap performed from inside a live run; empty means every ledger is stale")
	if err := fs.Parse(args); err != nil {
		// An unparseable invocation has not looked at the host at all, so it
		// cannot vouch for it: the same exit as a failed reap.
		return 1
	}

	if *dir == "" {
		// Only reachable if -state-dir was passed empty explicitly, since the
		// default is never empty. Kept so that spelling does something
		// predictable rather than reaping the process's working directory.
		fmt.Fprintf(stderr, "reap: -state-dir was given as empty; nothing to look at\n")
		return 0
	}

	report, err := harness.Reap(*dir, *self, rm, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "reap: FAILED, the host is not known to be clean: %v\n", err)
		return 1
	}

	for _, entry := range report.NotOurs {
		fmt.Fprintf(stderr,
			"reap: WARNING: %s %q was recorded by a previous run but is not the resource that was recorded; left alone\n",
			entry.Kind, entry.Value)
	}
	return 0
}
