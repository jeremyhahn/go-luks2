// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Command releasability-gate is the public-releasability gate (#211). It reads
// every entry in the git index of the checkout it is given -- the staged
// content, not the working tree, because the index is what the next commit
// carries -- and fails on a fleet address, hostname or owner path in any of
// them, and on any tracked file the public release must not carry.
//
// It is a command and not a test because it needs the git index, and this
// module's package tests also run where there is none: the integration image
// excludes .git/ and runs `go test -tags=integration ./...`. Run it through
// `make releasability`, which `make ci` and the CI workflow both call.
//
// Exit status: 0 the tree has no finding -- publishable, or publishable but
// for the pending items it lists (labstrings.PendingWorkflows) -- 1 it is not (the report says why),
// 2 the gate could not run -- a missing or extra argument, a root that is not
// a git checkout, an unusable releasability-exempt.txt, or an index entry it
// could not read in full (a blob over the scan limit that the exemption list
// does not name, one missing from the object store, or an I/O failure). A
// tree the gate could not list is never reported clean, and the only entry it
// passes without reading -- an oversize file the staged exemption list names
// with a reason -- is printed as NOT READ on every run.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/jeremyhahn/go-luks2/test/labstrings"
)

// Exit statuses.
const (
	exitClean  = 0
	exitDirty  = 1
	exitFailed = 2
)

// indexReader reads the index entries under a root. The real one is
// labstrings.IndexEntries; tests substitute their own so the command's
// decisions are exercised without a git checkout.
type indexReader func(root string) ([]labstrings.Entry, error)

// policy is what the gate enforces: the lab-value allow-list and the
// unpublishable-file rules. main passes this repository's; tests pass broken
// ones to see the gate refuse to run on them.
type policy struct {
	allow         []labstrings.AllowRule
	unpublishable []labstrings.Unpublishable
}

// repositoryPolicy is this repository's policy.
var repositoryPolicy = policy{allow: labstrings.DefaultAllowList, unpublishable: labstrings.DefaultUnpublishable}

func main() {
	os.Exit(run(os.Args[1:], labstrings.IndexEntries, repositoryPolicy, os.Stdout, os.Stderr))
}

// run gates the checkout named by args and returns the exit status.
func run(args []string, read indexReader, p policy, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, &UsageError{Args: args})
		return exitFailed
	}
	root := args[0]
	entries, err := read(root)
	if err != nil {
		fmt.Fprintf(stderr, "releasability-gate: %v\n", err)
		return exitFailed
	}
	if len(entries) == 0 {
		fmt.Fprintln(stderr, &EmptyIndexError{Root: root})
		return exitFailed
	}

	findings, err := labstrings.Scan(entries, p.allow)
	if err != nil {
		fmt.Fprintf(stderr, "releasability-gate: %v\n", err)
		return exitFailed
	}
	unpublishable, err := labstrings.ScanUnpublishable(entries, p.unpublishable)
	if err != nil {
		fmt.Fprintf(stderr, "releasability-gate: %v\n", err)
		return exitFailed
	}

	if len(findings) > 0 || len(unpublishable) > 0 {
		fmt.Fprint(stderr, "this tree cannot be published as it stands:\n\n")
		if _, err := labstrings.Report(stderr, findings); err != nil {
			fmt.Fprintf(stderr, "releasability-gate: %v\n", err)
			return exitFailed
		}
		if _, err := labstrings.ReportUnpublishable(stderr, unpublishable); err != nil {
			fmt.Fprintf(stderr, "releasability-gate: %v\n", err)
			return exitFailed
		}
		return exitDirty
	}

	// What the gate accepted on a person's word is printed, never accepted
	// silently.
	if exempt := labstrings.Exempted(entries); len(exempt) > 0 {
		header := fmt.Sprintf("releasability-gate: %d file(s) accepted by %s:\n\n", len(exempt), labstrings.ExemptFile)
		if err := writeItems(stdout, header, exempt); err != nil {
			fmt.Fprintf(stderr, "releasability-gate: %v\n", err)
			return exitFailed
		}
	}

	// Pending items do not fail the gate, and the tree is not called
	// publishable while any exists: each is printed on every run, so the open
	// checklist item is in front of whoever reads the log. A report that
	// cannot be written is a failure -- the qualification is the point.
	if open := labstrings.Pending(entries); len(open) > 0 {
		header := fmt.Sprintf("releasability-gate: %d tracked files; no finding, but NOT YET PUBLISHABLE -- %d item(s) await an owner ruling (#211):\n\n", len(entries), len(open))
		if err := writeItems(stdout, header, open); err != nil {
			fmt.Fprintf(stderr, "releasability-gate: %v\n", err)
			return exitFailed
		}
		return exitClean
	}
	if _, err := fmt.Fprintf(stdout, "releasability-gate: %d tracked files, publishable\n", len(entries)); err != nil {
		fmt.Fprintf(stderr, "releasability-gate: %v\n", &labstrings.ReportError{Err: err})
		return exitFailed
	}
	return exitClean
}

// writeItems writes header and then each item, stopping at the first write
// that fails.
func writeItems(w io.Writer, header string, items []labstrings.FileFinding) error {
	if _, err := io.WriteString(w, header); err != nil {
		return &labstrings.ReportError{Err: err}
	}
	for _, item := range items {
		if _, err := fmt.Fprintf(w, "%s\n\n", item); err != nil {
			return &labstrings.ReportError{Err: err}
		}
	}
	return nil
}
