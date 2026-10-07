// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import "context"

// command is one entry in the dispatch registry: either a leaf that runs
// against the remaining arguments, or a group whose next argument selects a
// sub-command (sub non-nil, run nil).
type command struct {
	name     string
	synopsis string
	usage    string
	run      func(ctx context.Context, e *env, args []string) error
	sub      map[string]*command
}
