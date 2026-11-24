// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build unix && !linux

package command

import "github.com/jeremyhahn/go-luks2/internal/errs"

// Open fails closed off Linux: a program is run only through the descriptor
// it was checked on (O_PATH and /proc/self/fd), and without both there is no
// way to run the file that was checked rather than whatever its path names
// by then.
func Open(path string) (*Program, error) {
	return nil, &errs.Error{Kind: ErrTool, Detail: "cannot run " + path + ": running a checked program needs Linux"}
}
