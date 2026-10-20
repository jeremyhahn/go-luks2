// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Command depscheck is `make deps-check`: it fails when any module go.mod
// requires is behind a latest release at least 7 days old and no reason is
// written for holding it there.
//
//	go run ./test/tools/depscheck [-modfile go.mod] [-first-party prefix]
//
// Every require line is checked, direct and indirect, first-party and
// third-party alike. A module may stay behind only with its reason written
// beside it in go.mod, as a comment on its require or replace line or on the
// comment lines directly above it (`// indirect; <reason>` for an indirect
// one). The reason is printed with the result, so a held-back module is a
// visible decision rather than drift.
//
// "Latest" is resolved through the go command, so it follows the same
// GOPROXY, GOPRIVATE and git configuration the build does:
//
//   - a first-party module (under -first-party) is behind when a higher tag
//     exists, prereleases included, because the portfolio releases alpha
//     tags and a consumer takes the newest one;
//   - a third-party module is behind when the go command's `@latest` is
//     higher, which is the newest release, or the newest prerelease or
//     pseudo-version when the module has no release.
//
// A version the build already uses that is NEWER than every tag (a
// pseudo-version after the last tag) is current, not behind.
//
// A new release does not turn every build red at once: an undocumented lag
// behind a latest version released under 7 days ago is REPORTED, as a status
// line, and does not fail the check; at 7 days or more it fails. The release
// time is the one the go command reports for that version (for a first-party
// tag newer than `@latest`, a lookup of that tag). A release time in the
// future counts as young. A missing or zero release time counts as old, so
// the lag fails.
//
// FAIL-CLOSED: a module whose latest version cannot be resolved fails the
// check. With GOPROXY=off nothing can be resolved, so the check reports that
// rather than calling the module current. Lookups run in an empty directory
// with a private module cache, so the check neither reads the module's
// `-mod` setting nor needs the shared module cache to be writable.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"
)

// youngRelease is how long an undocumented lag behind a new release is
// reported rather than failed.
const youngRelease = 7 * 24 * time.Hour

// listing is what the go command reports for `go list -m -versions -json
// <module>@latest`: Go's latest version, every tagged version, and the
// latest version's release time. A tag lookup fills Version and Time only.
type listing struct {
	Version  string
	Versions []string
	Time     time.Time
}

// host is the outside world: reading go.mod, asking the go command, and the
// clock a release's age is measured against.
type host struct {
	readFile func(name string) ([]byte, error)
	// list answers `go list -m -json module@query`; query is "latest" or a
	// tag.
	list func(module, query string) (listing, error)
	now  func() time.Time
}

func main() {
	os.Exit(cli(os.Args[1:], os.Stdout, os.Stderr, systemHost()))
}

// cli runs the check and returns the process exit status.
func cli(args []string, stdout, stderr io.Writer, h host) int {
	if err := run(args, stdout, h); err != nil {
		fmt.Fprintln(stderr, "FAIL:", err)
		return 1
	}
	return 0
}

func run(args []string, stdout io.Writer, h host) error {
	fs := flag.NewFlagSet("depscheck", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	modfile := fs.String("modfile", "go.mod", "go.mod to check")
	firstParty := fs.String("first-party", "github.com/jeremyhahn/", "module path prefix of first-party modules")
	if err := fs.Parse(args); err != nil {
		return &UsageError{Msg: err.Error()}
	}
	if fs.NArg() != 0 {
		return &UsageError{Msg: "unexpected argument " + fs.Arg(0)}
	}
	data, err := h.readFile(*modfile)
	if err != nil {
		return &ModfileError{Path: *modfile, Msg: err.Error()}
	}
	reqs, err := parseGoMod(*modfile, data)
	if err != nil {
		return err
	}
	if len(reqs) == 0 {
		fmt.Fprintln(stdout, "deps-check: no requirements")
		return nil
	}

	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "MODULE\tUSED\tLATEST\tSTATUS")
	var (
		behind []string
		failed []error
		now    = h.now()
	)
	for _, r := range reqs {
		latest, released, err := latestFor(h, r, strings.HasPrefix(r.Path, *firstParty))
		if err != nil {
			fmt.Fprintf(tw, "%s\t%s\t?\tERROR\n", r.Path, r.Version)
			failed = append(failed, err)
			continue
		}
		used, _ := parseVersion(r.Version)
		newest, _ := parseVersion(latest)
		switch {
		case used.compare(newest) >= 0:
			fmt.Fprintf(tw, "%s\t%s\t%s\tok\n", r.Path, r.Version, latest)
		case r.Reason != "":
			fmt.Fprintf(tw, "%s\t%s\t%s\tbehind, documented: %s\n", r.Path, r.Version, latest, r.Reason)
		case !released.IsZero() && now.Sub(released) < youngRelease:
			fmt.Fprintf(tw, "%s\t%s\t%s\tbehind, released %s (under 7 days): reported\n", r.Path, r.Version, latest, released.Format(time.RFC3339))
		default:
			fmt.Fprintf(tw, "%s\t%s\t%s\tBEHIND, UNDOCUMENTED (%s:%d)\n", r.Path, r.Version, latest, *modfile, r.Line)
			behind = append(behind, r.Path+" "+r.Version+" < "+latest)
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(behind) > 0 {
		failed = append(failed, &BehindError{Modules: behind})
	}
	return errors.Join(failed...)
}

// latestFor resolves the newest version r should be compared against.
func latestFor(h host, r requirement, firstParty bool) (string, time.Time, error) {
	if _, ok := parseVersion(r.Version); !ok {
		return "", time.Time{}, &VersionError{Module: r.Path, Version: r.Version}
	}
	l, err := h.list(r.Path, "latest")
	if err != nil {
		return "", time.Time{}, err
	}
	best, ok := parseVersion(l.Version)
	if !ok {
		return "", time.Time{}, &VersionError{Module: r.Path, Version: l.Version}
	}
	latest := l.Version
	if firstParty {
		for _, v := range l.Versions {
			pv, ok := parseVersion(v)
			if !ok {
				return "", time.Time{}, &VersionError{Module: r.Path, Version: v}
			}
			if pv.compare(best) > 0 {
				best, latest = pv, v
			}
		}
	}
	if latest == l.Version {
		return latest, l.Time, nil
	}
	// A higher first-party tag than @latest: its own release time.
	tl, err := h.list(r.Path, latest)
	if err != nil {
		return "", time.Time{}, err
	}
	return latest, tl.Time, nil
}

// systemHost reads files from disk and asks the real go command.
func systemHost() host {
	return host{
		readFile: os.ReadFile,
		list: func(module, query string) (listing, error) {
			return goList(module, query, runCommand)
		},
		now: time.Now,
	}
}

// runner executes the go command with args in dir with extra environment,
// returning its combined output.
type runner func(dir string, env []string, args ...string) ([]byte, error)

func runCommand(dir string, env []string, args ...string) ([]byte, error) {
	// The only variable argument is a module path read from this
	// repository's own go.mod, not untrusted input.
	cmd := exec.Command("go", args...) // #nosec G204 -- module path from this repository's go.mod
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	return cmd.CombinedOutput()
}

// goList runs `go list -m -versions -json <module>@latest`, or `go list -m
// -json <module>@<tag>` for a tag, outside any module, with a module cache of
// its own that is removed afterwards.
func goList(module, query string, run runner) (listing, error) {
	var l listing
	dir, err := os.MkdirTemp("", "depscheck-")
	if err != nil {
		return l, &QueryError{Module: module, Err: err}
	}
	defer func() { _ = os.RemoveAll(dir) }()
	env := []string{
		"GOMODCACHE=" + dir + "/modcache",
		"GOFLAGS=-modcacherw",
		"GOWORK=off",
	}
	args := []string{"list", "-m", "-json", module + "@" + query}
	if query == "latest" {
		args = []string{"list", "-m", "-versions", "-json", module + "@latest"}
	}
	out, err := run(dir, env, args...)
	if err != nil {
		return l, &QueryError{Module: module, Output: string(out), Err: err}
	}
	if err := json.Unmarshal(out, &l); err != nil {
		return l, &QueryError{Module: module, Output: string(out), Err: err}
	}
	return l, nil
}
