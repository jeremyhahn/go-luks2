// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import "fmt"

// Every way this command refuses is its own type, carrying what the person
// reading the CI log needs to fix it. None of them is a finding about the code
// under test: each says the scan that was about to run could not be attributed
// to a known scanner version, and so must not run at all.

// UsageError reports a command line this command cannot act on.
type UsageError struct {
	Problem string
}

func (e *UsageError) Error() string {
	return "usage: require-tool <binary> <pin> <module-path> [go-install args...]: " + e.Problem
}

// MissingToolError reports a tool absent from a self-hosted runner. That is an
// IMAGE defect, and it is not papered over with a network install: doing so
// would restore precisely the intermittent failure baking the tools in removed
// (#44), while reporting success.
type MissingToolError struct {
	Bin string
	Pin string
}

func (e *MissingToolError) Error() string {
	return fmt.Sprintf("%s is not installed on this runner. It is supposed to be baked "+
		"into the runner image at %s. Refusing to install it over the network: that is "+
		"the intermittent ENETUNREACH failure this arrangement exists to remove, and a job "+
		"that silently reinstates it hides an image defect (#44). Ask for the runner image "+
		"to be rebuilt", e.Bin, e.Pin)
}

// InstallError reports that the GitHub-hosted fallback install failed.
type InstallError struct {
	Module string
	Pin    string
	Output string
	Err    error
}

func (e *InstallError) Error() string {
	return fmt.Sprintf("go install %s@%s failed: %v\n%s", e.Module, e.Pin, e.Err, e.Output)
}

func (e *InstallError) Unwrap() error { return e.Err }

// NotOnPathError reports an install that succeeded but left the binary
// unreachable. It is caught HERE because an exported PATH does not survive this
// process: if the binary is not reachable now it will not be reachable in the
// step that runs it, and that failure would arrive looking like a missing tool
// rather than a broken PATH.
type NotOnPathError struct {
	Bin    string
	Module string
	Pin    string
}

func (e *NotOnPathError) Error() string {
	return fmt.Sprintf("installed %s@%s but %s is still not on PATH; expected "+
		"$(go env GOPATH)/bin to be on PATH (actions/setup-go)", e.Module, e.Pin, e.Bin)
}

// VersionUnreadableError reports a tool that answered neither --version nor
// -version with anything. An unreadable self-report is not evidence of a
// matching version.
type VersionUnreadableError struct {
	Bin string
}

func (e *VersionUnreadableError) Error() string {
	return e.Bin + " would not report a version. An unreadable version is not a matching version"
}

// UnknownToolError reports a tool whose version format nobody has read. A
// version that cannot be verified is not guessed at: guessing is how the
// substring comparison this replaced came to be written.
type UnknownToolError struct {
	Bin string
}

func (e *UnknownToolError) Error() string {
	return fmt.Sprintf("no documented version format is known for '%s'. Refusing to "+
		"verify it by guessing at its output. Add its format to knownTools in "+
		"test/ci/cmd/require-tool, having read what the tool actually prints", e.Bin)
}

// VersionParseError reports a self-report that does not carry the tool's
// documented version line. It fails rather than falling back to a looser
// comparison.
type VersionParseError struct {
	Bin    string
	Report string
}

func (e *VersionParseError) Error() string {
	return fmt.Sprintf("could not extract a version from %s's output. A version that "+
		"could not be parsed is not a matching version. It said:\n%s", e.Bin, indent(e.Report))
}

// VersionMismatchError reports a tool that says it is not the pinned version.
type VersionMismatchError struct {
	Bin    string
	Got    string
	Pin    string
	Report string
}

func (e *VersionMismatchError) Error() string {
	return fmt.Sprintf("%s is version %s, not the pinned %s. Scan and lint results that "+
		"cannot be attributed to a known version are not reproducible, which is the "+
		"defect this check exists for (#21). Bump the pin in .github/workflows/ci.yml and "+
		"the Makefile deliberately, together with the runner image, or restore the image. "+
		"It said:\n%s", e.Bin, e.Got, e.Pin, indent(e.Report))
}
