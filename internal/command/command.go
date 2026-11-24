// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build unix

// Package command runs the external programs this module needs from fixed system directories with a minimal environment, never through PATH.
package command

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// killGrace is exec.Cmd.WaitDelay for a program this package started: how
// long a program gets to exit, after its process group is killed on ctx
// cancellation, before Wait gives up and reports it anyway.
const killGrace = 5 * time.Second

// Tools resolves and runs programs from Dirs, in order, with Env as their
// whole environment.
type Tools struct {
	// Dirs is where programs are looked for, in order.
	Dirs []string

	// Env is the whole environment a program runs with.
	Env []string

	// KillGrace is how long a canceled program gets after SIGTERM before its process group is killed; zero means killGrace.
	KillGrace time.Duration
}

// System is the production Tools: the system program directories, a PATH over them, and the C locale.
func System() Tools {
	return Tools{
		Dirs: []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"},
		Env:  []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin", "LC_ALL=C"},
	}
}

// Program is a trusted executable held open by the descriptor it was checked on, and always run through that descriptor.
type Program struct {
	// Name is the path the program was asked for, which becomes argv[0].
	Name string

	file *os.File
}

// pinnedPath is where the child finds the program's descriptor: ExtraFiles[0]
// is descriptor 3, and /proc/self is the child once it has forked.
const pinnedPath = "/proc/self/fd/3"

// Cmd builds the command that runs p with args, under the name p was asked
// for. The caller sets the environment and anything else the run needs, but
// must not replace ExtraFiles, and must keep p open until Start returns.
func (p *Program) Cmd(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, pinnedPath, args...) // #nosec G204 -- the descriptor Open checked; args are the caller's
	cmd.Args[0] = p.Name
	cmd.ExtraFiles = []*os.File{p.file}
	return cmd
}

// Close releases the descriptor. A command already started keeps its own copy.
func (p *Program) Close() error {
	return p.file.Close()
}

// Resolve opens the program name as it is found in the first of t.Dirs that
// holds it, with Open's checks; the Program's Name is the path it was found
// under. An absent program is refused rather than looked up anywhere else.
func (t Tools) Resolve(name string) (*Program, error) {
	if name == "" || filepath.Base(name) != name {
		return nil, &errs.Error{Kind: ErrTool, Detail: "the program name " + name + " is not a bare name"}
	}
	for _, dir := range t.Dirs {
		candidate := filepath.Join(dir, name)
		// Only whether the entry is there: Open decides whether it is trusted.
		if _, err := os.Lstat(candidate); err != nil {
			continue
		}
		return Open(candidate)
	}
	return nil, &errs.Error{Kind: ErrTool, Detail: name + " was not found in any of " + strings.Join(t.Dirs, ", ")}
}

// ownedAndUnwritable errors unless path is owned by root or the current user and not group- or world-writable (sticky directories allowed when stickyOK).
func ownedAndUnwritable(path string, uid uint32, mode os.FileMode, stickyOK bool) error {
	if uid != 0 && int64(uid) != int64(os.Geteuid()) {
		return &errs.Error{Kind: ErrTool, Detail: path + " is owned by another user, so it could have been replaced"}
	}
	if mode.Perm()&0o022 != 0 && (!stickyOK || mode&os.ModeSticky == 0) {
		return &errs.Error{Kind: ErrTool, Detail: path + " is writable by group or others, so it could have been replaced"}
	}
	return nil
}

// command runs the checked file as argv[0] = its found path, in its own process group that a canceled ctx kills whole, with t.Env as its environment.
func (t Tools) command(ctx context.Context, prog *Program, args ...string) *exec.Cmd {
	cmd := prog.Cmd(ctx, args...)
	cmd.Env = t.Env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	grace := t.KillGrace
	if grace <= 0 {
		grace = killGrace
	}
	cmd.Cancel = func() error {
		pgid := cmd.Process.Pid
		// Kill the whole group when WaitDelay expires, since os/exec's kill reaches only the leader.
		time.AfterFunc(grace, func() { _ = syscall.Kill(-pgid, syscall.SIGKILL) })
		return syscall.Kill(-pgid, syscall.SIGTERM)
	}
	cmd.WaitDelay = grace
	return cmd
}

// Run runs the program name with args and returns its combined output; an unresolvable program matches ErrTool, and a canceled ctx reports ctx's error.
func (t Tools) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	prog, err := t.Resolve(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = prog.Close() }()
	cmd := t.command(ctx, prog, args...)
	out, err := cmd.CombinedOutput()
	return out, ctxError(ctx, err)
}

// Output is Run for a program whose standard output alone is parsed; stderr is not returned.
func (t Tools) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	prog, err := t.Resolve(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = prog.Close() }()
	cmd := t.command(ctx, prog, args...)
	out, err := cmd.Output()
	return out, ctxError(ctx, err)
}

// ctxError is the one place a failed run is reconciled with its ctx: err
// stands unless ctx is the reason the program died, in which case the error
// is classified as ctx's own, with err kept as the cause.
func ctxError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return &errs.Error{Kind: ctxErr, Err: err}
	}
	return err
}
