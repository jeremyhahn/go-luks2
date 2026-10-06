// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// Tools resolves and runs programs from Dirs, in order, with Env as their
// whole environment.
type Tools struct {
	// Dirs is where programs are looked for, in order.
	Dirs []string

	// Env is the whole environment a program runs with.
	Env []string
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

// Resolve returns the program name as it is found in the first of t.Dirs
// that holds it: the path to execute, which has every symlink
// resolved, and the path it was found under, which becomes argv[0].
//
// A candidate is accepted only when the file it resolves to is a regular,
// executable file that no one but root or this process's own user can write,
// and every directory above it -- and above the allowlisted entry -- is the
// same, or is sticky (as /tmp is), so nobody else can replace an entry in it.
// A symlink into a writable directory is refused rather than followed, and an
// absent program is refused rather than looked up anywhere else.
func (t Tools) Resolve(name string) (execPath, argv0 string, err error) {
	if name == "" || filepath.Base(name) != name {
		return "", "", &errs.Error{Kind: ErrTool, Detail: "the program name " + name + " is not a bare name"}
	}
	for _, dir := range t.Dirs {
		candidate := filepath.Join(dir, name)
		if _, err := os.Lstat(candidate); err != nil {
			continue
		}
		canonical, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			return "", "", &errs.Error{Kind: ErrTool, Detail: "cannot resolve " + candidate, Err: err}
		}
		if err := trustedExecutable(canonical); err != nil {
			return "", "", err
		}
		if err := trustedDirectories(dir); err != nil {
			return "", "", err
		}
		return canonical, candidate, nil
	}
	return "", "", &errs.Error{Kind: ErrTool, Detail: name + " was not found in any of " + strings.Join(t.Dirs, ", ")}
}

// trustedExecutable reports an error unless path, which has no symlinks left
// in it, is an executable regular file writable only by root or the current
// user, in directories with the property trustedDirectories checks.
func trustedExecutable(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return &errs.Error{Kind: ErrTool, Detail: "cannot inspect " + path, Err: err}
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return &errs.Error{Kind: ErrTool, Detail: path + " is not an executable regular file"}
	}
	if err := ownedAndUnwritable(path, info, false); err != nil {
		return err
	}
	return trustedDirectories(filepath.Dir(path))
}

// trustedDirectories walks from dir up to / and reports an error unless every
// directory is owned by root or the current user and is not writable by group
// or others -- unless it is sticky, which stops others replacing what they do
// not own.
func trustedDirectories(dir string) error {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return &errs.Error{Kind: ErrTool, Detail: "cannot resolve " + dir, Err: err}
	}
	for current := resolved; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return &errs.Error{Kind: ErrTool, Detail: "cannot inspect " + current, Err: err}
		}
		if err := ownedAndUnwritable(current, info, true); err != nil {
			return err
		}
		if current == filepath.Dir(current) {
			return nil
		}
	}
}

// ownedAndUnwritable reports an error unless path is owned by root or the
// current user and is not writable by group or others. A directory that is
// group- or world-writable passes only when stickyOK and its sticky bit is set.
func ownedAndUnwritable(path string, info os.FileInfo, stickyOK bool) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return &errs.Error{Kind: ErrTool, Detail: "cannot read the owner of " + path}
	}
	if st.Uid != 0 && int64(st.Uid) != int64(os.Geteuid()) {
		return &errs.Error{Kind: ErrTool, Detail: path + " is owned by another user, so it could have been replaced"}
	}
	if info.Mode().Perm()&0o022 != 0 && (!stickyOK || info.Mode()&os.ModeSticky == 0) {
		return &errs.Error{Kind: ErrTool, Detail: path + " is writable by group or others, so it could have been replaced"}
	}
	return nil
}

// Command builds the command that runs the program name with args: the
// resolved file is executed, argv[0] is the path it was found under -- mke2fs
// decides which filesystem to make from it, so mkfs.ext4 must stay mkfs.ext4 --
// and t.Env is its entire environment.
func (t Tools) Command(name string, args ...string) (*exec.Cmd, error) {
	execPath, argv0, err := t.Resolve(name)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(execPath, args...) // #nosec G204 -- execPath is resolved from fixed system directories by Resolve; args are flags the caller builds, "--", and a validated operand
	cmd.Args[0] = argv0
	cmd.Env = t.Env
	return cmd, nil
}

// Run runs the program name with args and returns its combined output. A
// program that cannot be resolved is an error matching ErrTool, and nothing is
// run.
func (t Tools) Run(name string, args ...string) ([]byte, error) {
	cmd, err := t.Command(name, args...)
	if err != nil {
		return nil, err
	}
	return cmd.CombinedOutput()
}
