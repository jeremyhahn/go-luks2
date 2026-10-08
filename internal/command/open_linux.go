// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package command

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// maxSymlinks bounds the symlinks one Open follows, as the kernel's own
// MAXSYMLINKS does, so a loop is refused rather than walked for ever.
const maxSymlinks = 40

// Open checks the program at path, an absolute path, and returns it pinned
// to the descriptor the checks were made on.
//
// The path is walked one component at a time from "/", each opened with
// O_PATH|O_NOFOLLOW relative to the directory before it, and each judged by
// fstat of that descriptor -- never by name, so nothing can be swapped between
// a check and the next step. Every directory on the walk must be owned by root
// or this process's user and not writable by group or others, unless it is
// sticky (as /tmp is). The file at the end must be a regular, executable file
// owned the same way and writable by neither group nor others.
//
// A symlink is followed only through the same walk: it must itself be owned
// by root or this user, it is read from its own descriptor, and its target is
// walked with the same checks -- from "/" when absolute, from the checked
// directory holding the link when relative. So every directory a program is
// reached through is judged, not only the ones left once symlinks are
// resolved, and ".." climbs only to a directory already checked.
func Open(path string) (*Program, error) {
	if !filepath.IsAbs(path) {
		return nil, &errs.Error{Kind: ErrTool, Detail: path + " is not an absolute path"}
	}
	fd, err := walk(path)
	if err != nil {
		return nil, err
	}
	return &Program{Name: path, file: os.NewFile(uintptr(fd), path)}, nil
}

// checkedDir is one directory of the walk: its descriptor, and the path it
// was reached at, for messages.
type checkedDir struct {
	fd   int
	path string
}

// walk returns the O_PATH descriptor of the executable path names, checked as
// Open describes.
func walk(path string) (int, error) {
	root, err := openChecked(unix.AT_FDCWD, "/", "/")
	if err != nil {
		return -1, err
	}
	dirs := []checkedDir{{fd: root, path: "/"}}
	defer func() {
		for _, d := range dirs {
			_ = unix.Close(d.fd)
		}
	}()

	rest := components(path)
	links := 0
	for len(rest) > 0 {
		name := rest[0]
		rest = rest[1:]
		parent := dirs[len(dirs)-1]
		if name == ".." {
			if len(dirs) > 1 {
				_ = unix.Close(parent.fd)
				dirs = dirs[:len(dirs)-1]
			}
			continue
		}
		where := filepath.Join(parent.path, name)

		fd, err := unix.Openat(parent.fd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return -1, &errs.Error{Kind: ErrTool, Detail: "cannot open " + where, Err: err}
		}
		st, err := fstat(fd, where)
		if err != nil {
			_ = unix.Close(fd)
			return -1, err
		}

		switch st.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			target, err := readlink(fd, where, st)
			_ = unix.Close(fd)
			if err != nil {
				return -1, err
			}
			if links++; links > maxSymlinks {
				return -1, &errs.Error{Kind: ErrTool, Detail: "too many symlinks resolving " + path}
			}
			if filepath.IsAbs(target) {
				for _, d := range dirs[1:] {
					_ = unix.Close(d.fd)
				}
				dirs = dirs[:1]
			}
			rest = append(components(target), rest...)
		case unix.S_IFDIR:
			if err := ownedAndUnwritable(where, st.Uid, statMode(st), true); err != nil {
				_ = unix.Close(fd)
				return -1, err
			}
			dirs = append(dirs, checkedDir{fd: fd, path: where})
		default:
			if len(rest) > 0 {
				_ = unix.Close(fd)
				return -1, &errs.Error{Kind: ErrTool, Detail: "cannot open " + path, Err: unix.ENOTDIR}
			}
			if err := executable(where, st); err != nil {
				_ = unix.Close(fd)
				return -1, err
			}
			return fd, nil
		}
	}
	return -1, &errs.Error{Kind: ErrTool, Detail: path + " is not an executable regular file"}
}

// openChecked opens the directory name relative to dirfd and checks it as a
// directory of the walk.
func openChecked(dirfd int, name, where string) (int, error) {
	fd, err := unix.Openat(dirfd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, &errs.Error{Kind: ErrTool, Detail: "cannot open " + where, Err: err}
	}
	st, err := fstat(fd, where)
	if err == nil {
		err = ownedAndUnwritable(where, st.Uid, statMode(st), true)
	}
	if err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// executable reports an error unless st, the file at where, is a regular file
// with an execute bit that only root or this user can write.
func executable(where string, st *unix.Stat_t) error {
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o111 == 0 {
		return &errs.Error{Kind: ErrTool, Detail: where + " is not an executable regular file"}
	}
	return ownedAndUnwritable(where, st.Uid, statMode(st), false)
}

// readlink returns the target of the symlink fd, the link at where whose
// status is st. The link must be owned by root or this user: in a sticky
// directory anyone may create one, and only its owner can replace it.
func readlink(fd int, where string, st *unix.Stat_t) (string, error) {
	if err := ownedAndUnwritable(where, st.Uid, 0, false); err != nil {
		return "", err
	}
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(fd, "", buf)
	if err != nil {
		return "", &errs.Error{Kind: ErrTool, Detail: "cannot read the link " + where, Err: err}
	}
	if n == len(buf) || n == 0 {
		return "", &errs.Error{Kind: ErrTool, Detail: "the link " + where + " has an empty or overlong target"}
	}
	return string(buf[:n]), nil
}

func fstat(fd int, where string) (*unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, &errs.Error{Kind: ErrTool, Detail: "cannot inspect " + where, Err: err}
	}
	return &st, nil
}

// statMode is the permission and sticky bits of st, as an os.FileMode.
func statMode(st *unix.Stat_t) os.FileMode {
	mode := os.FileMode(st.Mode & 0o777)
	if st.Mode&unix.S_ISVTX != 0 {
		mode |= os.ModeSticky
	}
	return mode
}

// components splits a path into the names to walk, dropping the empty and
// "." ones a path can hold.
func components(path string) []string {
	var out []string
	for _, name := range strings.Split(path, "/") {
		if name != "" && name != "." {
			out = append(out, name)
		}
	}
	return out
}
