// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package labstrings

import "strconv"

// The gate distinguishes "this tree has a violation" from "this gate could not
// run", so each way it can fail to run is its own type carrying what a caller
// needs to fix it. A finding is a value, never an error.

// ListError is returned when the tracked-file enumeration fails. The gate reads
// the git index because that is the ship manifest, so a tree with no index — an
// extracted tarball, a module cache entry — cannot be gated, and says so.
type ListError struct {
	// Root is the directory git was asked about.
	Root string

	// Stderr is what git said, which is the only thing that distinguishes
	// "not a work tree" from "git is not installed".
	Stderr string

	// Err is the underlying exec failure.
	Err error
}

func (e *ListError) Error() string {
	msg := "labstrings: cannot list tracked files in " + e.Root + ": " + e.Err.Error()
	if e.Stderr != "" {
		msg += ": " + e.Stderr
	}
	return msg
}

func (e *ListError) Unwrap() error { return e.Err }

// ReadError is returned when a staged blob cannot be read from git: the
// cat-file stream ended or failed part-way through it.
type ReadError struct {
	// Path is the index entry whose blob could not be read.
	Path string

	// Err is the underlying I/O failure.
	Err error
}

func (e *ReadError) Error() string {
	return "labstrings: cannot read " + e.Path + ": " + e.Err.Error()
}

func (e *ReadError) Unwrap() error { return e.Err }

// AttrError reports that git could not say which tracked files .gitattributes
// export-ignores. The gate cannot then vouch that a strip-at-publish file stays
// out of the archive, so it stops rather than reporting clean.
type AttrError struct {
	// Root is the directory git was asked about.
	Root string

	// Stderr is what git said, if anything.
	Stderr string

	// Err is the underlying exec or parse failure.
	Err error
}

func (e *AttrError) Error() string {
	msg := "labstrings: cannot read the export-ignore attribute in " + e.Root + ": " + e.Err.Error()
	if e.Stderr != "" {
		msg += ": " + e.Stderr
	}
	return msg
}

func (e *AttrError) Unwrap() error { return e.Err }

// ArchiveError reports that the archive of a commit could not be produced. A
// check of the archive cannot then vouch for what it publishes, so it stops
// rather than reporting clean.
type ArchiveError struct {
	// Root is the repository whose HEAD was to be archived.
	Root string

	// Stderr is what git said, if anything.
	Stderr string

	// Err is the underlying exec or file system failure.
	Err error
}

func (e *ArchiveError) Error() string {
	msg := "labstrings: cannot archive HEAD of " + e.Root + ": " + e.Err.Error()
	if e.Stderr != "" {
		msg += ": " + e.Stderr
	}
	return msg
}

func (e *ArchiveError) Unwrap() error { return e.Err }

// IndexEntryError is returned when an index entry cannot be scanned: its blob
// is missing from the object store (a partial clone), its mode is one the gate
// does not understand, or git's answer about it is malformed. The gate cannot
// vouch for content it did not see, so it fails instead of passing the entry.
type IndexEntryError struct {
	// Path is the index entry, empty if the record was unparseable.
	Path string

	// Problem says what is wrong.
	Problem string
}

func (e *IndexEntryError) Error() string {
	return "labstrings: index entry " + e.Path + ": " + e.Problem
}

// FileTooLargeError is returned when a staged blob is larger than the scanner
// will read. Skipping it would let whatever it names ship unexamined, so the
// gate fails instead; the fix is to stop tracking the file or to raise the
// limit deliberately.
type FileTooLargeError struct {
	// Path is the file that was not scanned.
	Path string

	// Size is the file's size in bytes.
	Size int64

	// Limit is the largest file the scanner reads.
	Limit int64
}

func (e *FileTooLargeError) Error() string {
	return "labstrings: " + e.Path + " is " + strconv.FormatInt(e.Size, 10) +
		" bytes, over the " + strconv.FormatInt(e.Limit, 10) + "-byte scan limit; the gate cannot vouch for a file it did not read"
}

// AllowRuleError is returned when an allow-list entry is not usable. An
// allow-list is the gate's own configuration: a malformed or unexplained entry
// silently accepts whatever it covers, so it fails the gate instead.
type AllowRuleError struct {
	// Index is the entry's position in the list.
	Index int

	// Path is the entry's path pattern, empty if that is the defect.
	Path string

	// Problem says what is wrong with the entry.
	Problem string
}

func (e *AllowRuleError) Error() string {
	return "labstrings: allow-list entry " + strconv.Itoa(e.Index) + " (" + e.Path + "): " + e.Problem
}

// ReportError is returned when the report cannot be written. The report is the
// gate's product, so a silent write failure would turn a failing gate into a
// passing one.
type ReportError struct {
	// Err is the underlying write failure.
	Err error
}

func (e *ReportError) Error() string {
	return "labstrings: cannot write report: " + e.Err.Error()
}

func (e *ReportError) Unwrap() error { return e.Err }

// NoPatternsError is returned when a scan is asked to run with no pattern set.
// Such a scan cannot find anything, so it is a failure, never a clean result.
// The development tree's set is compiled in from fleet.go, which is stripped
// at publish; a development tree built without it is the case this catches.
type NoPatternsError struct {
	// Tracked is how many tracked files the scan would have read.
	Tracked int
}

func (e *NoPatternsError) Error() string {
	return "labstrings: no lab-value pattern set is compiled in (fleet.go is missing from this build), so " +
		strconv.Itoa(e.Tracked) + " tracked files cannot be scanned; a scan with no patterns would report clean"
}

// ExemptionError reports an unusable line in ExemptFile.
type ExemptionError struct {
	Line    int
	Path    string
	Problem string
}

func (e *ExemptionError) Error() string {
	return ExemptFile + ":" + strconv.Itoa(e.Line) + ": " + e.Path + ": " + e.Problem
}
