// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"time"
)

// Every refusal is its own type and says what to do about it. Each one stops a
// release: none of them is retried past the deadline or downgraded to a
// warning.

// UsageError reports a command line this command cannot act on.
type UsageError struct {
	Problem string
}

func (e *UsageError) Error() string {
	return "usage: release-gate -sha <commit> -main-ref <ref> -status-context <context> -check-name <name>: " + e.Problem
}

// NotOnMainError reports a tag whose commit main never received. Both release
// kinds are tags on main; a tag on a branch commit would publish code that was
// never merged, reviewed or gated as main.
type NotOnMainError struct {
	SHA     string
	MainRef string
}

func (e *NotOnMainError) Error() string {
	return fmt.Sprintf("commit %s is not on main (not an ancestor of %s). Releases are cut from main "+
		"only; delete the tag and cut it from a main commit", e.SHA, e.MainRef)
}

// AncestryError reports that git could not answer whether the commit is on main.
// An unanswered question is not a yes.
type AncestryError struct {
	SHA     string
	MainRef string
	Output  string
	Err     error
}

func (e *AncestryError) Error() string {
	return fmt.Sprintf("could not establish whether %s is on main (%s): %v\n%s", e.SHA, e.MainRef, e.Err, e.Output)
}

func (e *AncestryError) Unwrap() error { return e.Err }

// GateFailedError reports that CI's gate finished on the tagged commit and did
// not pass.
type GateFailedError struct {
	SHA   string
	Gate  string
	State string
}

func (e *GateFailedError) Error() string {
	return fmt.Sprintf("CI's gate %q reported %q for %s, so this commit is not releasable. "+
		"If the run was canceled or flaked, re-run CI for this commit and then re-run this release",
		e.Gate, e.State, e.SHA)
}

// GateTimeoutError reports a gate that never reported a result in time.
type GateTimeoutError struct {
	SHA     string
	Gate    string
	Waited  time.Duration
	LastErr error
}

func (e *GateTimeoutError) Error() string {
	msg := fmt.Sprintf("CI's gate %q reported no result for %s within %s; refusing to release a commit "+
		"CI has not passed", e.Gate, e.SHA, e.Waited)
	if e.LastErr != nil {
		msg += fmt.Sprintf(" (last error reading it: %v)", e.LastErr)
	}
	return msg
}

func (e *GateTimeoutError) Unwrap() error { return e.LastErr }

// ForgeError reports an answer from the forge API that retrying will not fix:
// a refused token, a repository or commit that does not exist, a body that is
// not the documented shape.
type ForgeError struct {
	URL    string
	Status int
	Body   string
	Err    error
}

func (e *ForgeError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("reading %s: %v", e.URL, e.Err)
	}
	return fmt.Sprintf("reading %s: HTTP %d: %s", e.URL, e.Status, e.Body)
}

func (e *ForgeError) Unwrap() error { return e.Err }

// transientError is a forge answer worth asking again: a 5xx or a request that
// never got an answer. It is retried until the deadline and never treated as a
// pass.
type transientError struct {
	URL string
	Err error
}

func (e *transientError) Error() string { return fmt.Sprintf("reading %s: %v", e.URL, e.Err) }

func (e *transientError) Unwrap() error { return e.Err }

// ExitStatusError is a command that ran and exited with a status it does not
// document.
type ExitStatusError struct {
	Command string
	Status  int
}

func (e *ExitStatusError) Error() string {
	return fmt.Sprintf("%s exited %d", e.Command, e.Status)
}

// HTTPStatusError is a server-side failure worth asking again about.
type HTTPStatusError struct {
	Status int
}

func (e *HTTPStatusError) Error() string { return fmt.Sprintf("HTTP %d", e.Status) }
