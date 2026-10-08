// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build unix

// Package command runs the external programs this module depends on -- mkfs.*,
// e2fsck, xfs_repair, fsck.fat, zpool, zfs, blkid -- from a FIXED set of
// system directories with a minimal environment, never through the caller's
// PATH.
//
// They run as root against a block device, so whichever binary answers to
// "mkfs.ext4" decides what is written to that device. Resolving the name
// through PATH let anyone who could influence the environment of a privileged
// caller choose that binary, and the inherited environment carried whatever
// else that caller had set -- LD_PRELOAD among it (#250, C7).
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

	// KillGrace is how long a canceled program gets after SIGTERM before its
	// process group is killed. Zero is the default, killGrace.
	KillGrace time.Duration
}

// System is the production Tools: the system program directories, and an
// environment of a PATH over the same directories -- for programs that run
// helpers of their own -- and the C locale, so their output is the output this
// module parses.
func System() Tools {
	return Tools{
		Dirs: []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"},
		Env:  []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin", "LC_ALL=C"},
	}
}

// Program is an executable file that passed the trust checks, held open by
// the descriptor those checks were made on.
//
// It is run through that descriptor, never by path again: Cmd executes
// pinnedPath, which names descriptor 3 of the child, and hands the descriptor
// over as ExtraFiles[0]. The file that runs is therefore the file that was
// checked, whatever has been renamed over its path since. The descriptor is
// left open in the program -- a script's interpreter reopens it by that name
// -- and refers only to the program's own file.
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

// ownedAndUnwritable reports an error unless path, with owner uid and mode, is
// owned by root or the current user and is not writable by group or others. A
// directory that is group- or world-writable passes only when stickyOK and its
// sticky bit is set.
func ownedAndUnwritable(path string, uid uint32, mode os.FileMode, stickyOK bool) error {
	if uid != 0 && int64(uid) != int64(os.Geteuid()) {
		return &errs.Error{Kind: ErrTool, Detail: path + " is owned by another user, so it could have been replaced"}
	}
	if mode.Perm()&0o022 != 0 && (!stickyOK || mode&os.ModeSticky == 0) {
		return &errs.Error{Kind: ErrTool, Detail: path + " is writable by group or others, so it could have been replaced"}
	}
	return nil
}

// command builds the command that runs prog with args: the checked file is
// executed, argv[0] is the path it was found under -- mke2fs decides which
// filesystem to make from it, so mkfs.ext4 must stay mkfs.ext4 -- and t.Env is
// its entire environment.
//
// The program runs in its own process group (Setpgid), and a canceled ctx
// kills that whole group rather than just the program named directly: mkfs.*,
// fsck.* and zpool/zfs can each fork their own helpers, and a cancellation
// that left those running would not be a cancellation. WaitDelay bounds how
// long Wait gives the group to actually exit after that kill.
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
		// os/exec's own kill when WaitDelay expires reaches only the leader,
		// so the group's SIGKILL is scheduled here, for the same moment: a
		// helper that ignores SIGTERM must not outlive the cancellation.
		time.AfterFunc(grace, func() { _ = syscall.Kill(-pgid, syscall.SIGKILL) })
		return syscall.Kill(-pgid, syscall.SIGTERM)
	}
	cmd.WaitDelay = grace
	return cmd
}

// Run runs the program name with args and returns its combined output. A
// program that cannot be resolved is an error matching ErrTool, and nothing is
// run.
//
// A program killed by a canceled ctx exits on the signal Cancel sent it --
// a non-success status -- and os/exec reports that as the plain exit error,
// not ctx.Err() (its Cancel doc: that substitution happens only when the
// killed program manages to still exit 0). So ctx is checked explicitly once
// CombinedOutput returns, and its error takes over whenever ctx is the
// reason, which is what lets a caller match errors.Is(err, context.Canceled).
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

// Output is Run for a program whose STANDARD OUTPUT alone is parsed: stderr
// is not part of what is returned. A cancellation is reported as in Run.
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
