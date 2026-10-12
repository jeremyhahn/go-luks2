// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/jeremyhahn/go-luks2/internal/cli"
)

// version is set at build time via -ldflags -X main.version=...
var version = "dev"

// osExit is one of main's two seams: a test overrides it so main can be called
// directly, in-process, without ending the test binary.
var osExit = os.Exit

// cliRun is the CLI run hands off to, and main's other seam. cli.Run hardens
// the process it runs in, and an unprivileged process cannot raise the core
// limit again afterwards, so a test that only checks main's wiring swaps it
// and leaves the test binary unhardened; tests that need the real CLI run it
// in a re-executed child. Nothing outside this package's tests assigns it,
// and package main cannot be imported.
var cliRun = cli.Run

func main() {
	osExit(run(os.Args, os.Stdin, os.Stdout, os.Stderr))
}

// run is main's body, kept separate so a test can drive it without the
// os.Exit a real invocation ends with.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cli.Version = version
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return cliRun(ctx, args, stdin, stdout, stderr)
}
