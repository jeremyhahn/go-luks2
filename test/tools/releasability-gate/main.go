// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Command releasability-gate (make releasability) fails on a fleet address, hostname or owner path, or an unpublishable file, in the git index; exit 0 publishable, 1 findings, 2 could not run.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/jeremyhahn/go-luks2/test/internal/labstrings"
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

// policy is what the gate enforces: the lab-value allow-list, the
// unpublishable-file rules and the strip-at-publish rules. main passes this
// repository's; tests pass broken ones to see the gate refuse to run on them.
type policy struct {
	patterns      []labstrings.Pattern
	allow         []labstrings.AllowRule
	unpublishable []labstrings.Unpublishable
	strip         []labstrings.Unpublishable
}

// repositoryPolicy is this repository's policy.
var repositoryPolicy = policy{
	patterns:      labstrings.Fleet(),
	allow:         labstrings.DefaultAllowList,
	unpublishable: labstrings.DefaultUnpublishable,
	strip:         labstrings.DefaultStripAtPublish,
}

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

	// The fleet pattern set comes from a strip-at-publish file; only an archive export runs without it, and says so.
	scanContent := len(p.patterns) > 0 || len(labstrings.StripAtPublish(entries, p.strip)) > 0
	var findings []labstrings.Finding
	if scanContent {
		findings, err = labstrings.Scan(entries, p.patterns, p.allow)
		if err != nil {
			fmt.Fprintf(stderr, "releasability-gate: %v\n", err)
			return exitFailed
		}
	}
	unpublishable, err := labstrings.ScanUnpublishable(entries, p.unpublishable, p.strip)
	if err != nil {
		fmt.Fprintf(stderr, "releasability-gate: %v\n", err)
		return exitFailed
	}
	// The strip is mechanical only for a file the archive leaves out.
	unpublishable = append(unpublishable, labstrings.NotExportIgnored(entries, p.strip)...)

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

	// Strip-at-publish files pass and are listed on every run; a report that cannot be written fails.
	if stripped := labstrings.StripAtPublish(entries, p.strip); len(stripped) > 0 {
		header := fmt.Sprintf("releasability-gate: %d tracked files; no finding, publishable as an archive export -- %d file(s) excluded from every archive by %s (export-ignore):\n\n", len(entries), len(stripped), labstrings.GitAttributes)
		if err := writeItems(stdout, header, stripped); err != nil {
			fmt.Fprintf(stderr, "releasability-gate: %v\n", err)
			return exitFailed
		}
		return exitClean
	}
	if !scanContent {
		if _, err := fmt.Fprintf(stdout, "releasability-gate: %d tracked files; no strip-at-publish file and no "+
			"fleet pattern set, as in a published tree: file rules checked, content NOT scanned for lab values\n", len(entries)); err != nil {
			fmt.Fprintf(stderr, "releasability-gate: %v\n", &labstrings.ReportError{Err: err})
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
