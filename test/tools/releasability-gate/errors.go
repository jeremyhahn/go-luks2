// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"
)

// UsageError is an invocation without exactly one checkout root.
type UsageError struct {
	// Args is what the command was given.
	Args []string
}

func (e *UsageError) Error() string {
	return fmt.Sprintf("usage: releasability-gate <checkout-root>; got %d argument(s): %s",
		len(e.Args), strings.Join(e.Args, " "))
}

// EmptyIndexError is a root whose index lists no file at all. An empty
// manifest scans clean trivially, so the gate refuses it rather than pass a
// tree it never looked at.
type EmptyIndexError struct {
	// Root is the directory whose index was empty.
	Root string
}

func (e *EmptyIndexError) Error() string {
	return fmt.Sprintf("releasability-gate: the git index at %s lists no files; refusing to call an unscanned tree publishable", e.Root)
}
