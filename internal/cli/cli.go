// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package cli is the luks2 command-line tool, built on
// pkg/luks2's Volume API, pkg/dmcrypt, pkg/loop, pkg/filesystem,
// pkg/keyprovider and pkg/wipe only -- never on the old free-function
// pkg/luks2 API cmd/luks2 used before this package existed. cmd/luks2 is
// now just main.go: signal context in, Run, os.Exit.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// sysT holds the process-level operations Run reaches outside this package.
// It is a struct, not a package func var, so a test swaps the whole of sys.
type sysT struct {
	// hardenProcess applies go-enclave's process hardening: RLIMIT_CORE 0/0
	// and, on Linux, PR_SET_DUMPABLE 0.
	hardenProcess func() (enclave.ProcessHardening, error)
}

func defaultSys() sysT {
	return sysT{hardenProcess: enclave.HardenProcess}
}

var sys = defaultSys()

// harden runs sys.hardenProcess and requires both protections it reports:
// the CLI runs only on Linux, where both exist.
func harden() error {
	report, err := sys.hardenProcess()
	if err == nil && (!report.NotDumpable || !report.CoreDumpsDisabled) {
		err = &Error{Kind: errHardeningIncomplete, Detail: fmt.Sprintf("not dumpable: %t, core dumps disabled: %t", report.NotDumpable, report.CoreDumpsDisabled)}
	}
	if err != nil {
		return &HardeningError{Err: err}
	}
	return nil
}

// env carries everything a command needs that is not one of its own
// arguments: the three streams, the terminal and root-only boundaries, and
// the custody a credential is built and released through.
type env struct {
	stdin      io.Reader
	stdout     io.Writer
	stderr     io.Writer
	term       terminal
	host       host
	custody    secret.Custody
	getStdinFd func() int
}

// Version is the version string "version"/"--version"/"-v" prints. main.go
// sets it from its own version, which -ldflags -X main.version=... sets at
// build time: the linker flag names main's variable, not this package's, so
// this one exists to receive the value rather than to be set directly.
var Version = "dev"

const topUsage = `
USAGE:
    luks2 <command> [options]

COMMANDS:
    create <path> [size] [filesystem]  Create a LUKS2 volume (file or block device)
    open <device> <name>         Unlock and open a LUKS volume
    close <name>                 Lock and close a LUKS volume
    mount <name> <mountpoint>    Mount an unlocked volume (type detected, or --type)
    unmount <mountpoint>         Unmount a volume
    info <device>                Show a summary of a volume's header
    keyslots <device>            List the keyslots on a volume
    testkey <device>             Check that a passphrase opens a volume
    addkey <device>              Add another passphrase
    changekey <device> <slot>    Replace the passphrase in a keyslot
    removekey <device> <slot>    Remove a keyslot with its own passphrase
    killslot <device> <slot>     Remove a keyslot with any valid passphrase
    recovery <generate|add|verify>  Generate, add or verify a recovery key
    token <subcommand> <device> [id]  Inspect or edit LUKS2 tokens
    wipe [--full] <device>       Overwrite a device's header, or the whole device
                                 (asks for YES unless --batch-mode)
    header <show|secondary|restore> <device>  Inspect or repair a LUKS2 header
                                 (restore asks for YES unless --batch-mode)
    isluks [--luks2] <device>    Exit 0 if the device holds a LUKS container

    help                         Show this help message
    version                      Show version information

NON-INTERACTIVE USE:
    Commands that read a passphrase accept --key-file:

    printf %s 'my passphrase' > /etc/luks/backup.key
    luks2 open --key-file /etc/luks/backup.key /dev/sdb1 backup
    printf %s 'my passphrase' | luks2 open --key-file - /dev/sdb1 backup
    echo 'my passphrase' | luks2 open /dev/sdb1 backup
`

// Run dispatches args[1] (and, for a command group, args[2]) to its
// handler and returns a cryptsetup(8)-compatible exit code. args follows
// os.Args's own shape: args[0] is the program name.
//
// Run hardens the process (enclave.HardenProcess) before it dispatches, so
// no command reads a credential in a process that could dump core; a
// hardening failure is a *HardeningError and a non-zero exit.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	// First, before any command can read a credential: Run is the binary's
	// only entry point (cmd/luks2 main → run → Run), and go-enclave leaves
	// process hardening to the binary. Failing to harden fails the command,
	// unsupported platform included; there is no unhardened fallback.
	if err := harden(); err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return exitCode(err)
	}

	fd := -1
	if f, ok := stdin.(*os.File); ok {
		fd = int(f.Fd())
	}
	e := &env{
		stdin:      stdin,
		stdout:     stdout,
		stderr:     stderr,
		term:       defaultTerminal{},
		host:       host{activator: realActivator{}, looper: realLooper{}, mounter: realMounter{}},
		custody:    secret.System(),
		getStdinFd: func() int { return fd },
	}
	return dispatch(ctx, e, args)
}

func dispatch(ctx context.Context, e *env, args []string) int {
	if len(args) < 2 {
		_, _ = fmt.Fprintf(e.stdout, "%s", topUsage)
		return 1
	}

	switch args[1] {
	case "help", "--help", "-h":
		_, _ = fmt.Fprintf(e.stdout, "%s", topUsage)
		return 0
	case "version", "--version", "-v":
		_, _ = fmt.Fprintf(e.stdout, "luks2 version %s\n", Version)
		return 0
	}

	cmd, ok := registry()[args[1]]
	if !ok {
		_, _ = fmt.Fprintf(e.stderr, "Unknown command: %s\n\n", args[1])
		_, _ = fmt.Fprintf(e.stdout, "%s", topUsage)
		return 1
	}

	rest := args[2:]
	for cmd.sub != nil {
		if len(rest) == 0 {
			_, _ = fmt.Fprint(e.stdout, cmd.usage)
			return 1
		}
		next, ok := cmd.sub[rest[0]]
		if !ok {
			_, _ = fmt.Fprintf(e.stderr, "Unknown command: %s %s\n\n", cmd.name, rest[0])
			_, _ = fmt.Fprint(e.stdout, cmd.usage)
			return 1
		}
		cmd = next
		rest = rest[1:]
	}

	err := cmd.run(ctx, e, rest)
	if err != nil {
		_, _ = fmt.Fprintf(e.stderr, "%v\n", err)
	}
	return exitCode(err)
}

// registry builds the command dispatch table. It is rebuilt on every call
// rather than held in a package variable: nothing in it is a seam (every
// run func takes its env as a parameter, never a closure over one), so
// nothing is gained by keeping it alive between calls, and a fresh map
// cannot carry state from one Run to the next by accident.
func registry() map[string]*command {
	return map[string]*command{
		"create":    createCommand(),
		"open":      openCommand(),
		"close":     closeCommand(),
		"mount":     mountCommand(),
		"unmount":   unmountCommand(),
		"info":      infoCommand(),
		"keyslots":  keyslotsCommand(),
		"testkey":   testkeyCommand(),
		"addkey":    addkeyCommand(),
		"changekey": changekeyCommand(),
		"removekey": removekeyCommand(),
		"killslot":  killslotCommand(),
		"recovery":  recoveryCommand(),
		"token":     tokenCommand(),
		"wipe":      wipeCommand(),
		"header":    headerCommand(),
		"isluks":    isluksCommand(),
	}
}

// RegisteredVerbs returns every verb this package's dispatch table answers
// to -- "<verb>" for a bare command, "<verb> <sub>" for each entry of a
// command group -- for test/integration/cli/commands's enumerating parity
// check: the table there must have a CommandDefinition for
// every name this returns, or the check fails. This is the minimum this
// package exports toward that: the registry's keys, nothing of the
// unexported command type itself.
func RegisteredVerbs() []string {
	reg := registry()
	verbs := make([]string, 0, len(reg))
	for name, cmd := range reg {
		if cmd.sub == nil {
			verbs = append(verbs, name)
			continue
		}
		for subName := range cmd.sub {
			verbs = append(verbs, name+" "+subName)
		}
	}
	return verbs
}
