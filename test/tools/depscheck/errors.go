// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"
)

// UsageError reports command-line arguments the command does not accept.
type UsageError struct {
	Msg string
}

func (e *UsageError) Error() string {
	return "usage: depscheck [-modfile go.mod] [-first-party prefix]: " + e.Msg
}

// ModfileError reports a go.mod that cannot be read or parsed. A go.mod the
// check cannot read is not evidence that nothing in it is behind.
type ModfileError struct {
	Path string
	Line int
	Msg  string
}

func (e *ModfileError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%s:%d: %s", e.Path, e.Line, e.Msg)
	}
	return fmt.Sprintf("%s: %s", e.Path, e.Msg)
}

// QueryError reports a module whose latest version could not be resolved.
// The check fails closed: an unanswered query is not evidence of currency.
type QueryError struct {
	Module string
	Output string
	Err    error
}

func (e *QueryError) Error() string {
	msg := fmt.Sprintf("cannot resolve the latest version of %s: %v", e.Module, e.Err)
	if out := strings.TrimSpace(e.Output); out != "" {
		msg += "\n" + out
	}
	if strings.Contains(e.Output, "GOPROXY=off") {
		msg += "\n(module lookup is disabled: run with DEPS_CHECK_GOPROXY set to a module proxy list)"
	}
	return msg
}

func (e *QueryError) Unwrap() error { return e.Err }

// VersionError reports a version string that is not semantic versioning.
type VersionError struct {
	Module  string
	Version string
}

func (e *VersionError) Error() string {
	return fmt.Sprintf("%s: %q is not a semantic version", e.Module, e.Version)
}

// BehindError reports modules that are behind their latest release with no
// reason written beside their require or replace line.
type BehindError struct {
	Modules []string
}

func (e *BehindError) Error() string {
	return fmt.Sprintf("%d module(s) behind the latest release with no documented reason: %s",
		len(e.Modules), strings.Join(e.Modules, ", "))
}
