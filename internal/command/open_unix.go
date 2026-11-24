// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build unix && !linux

package command

import "github.com/jeremyhahn/go-luks2/internal/errs"

// Open fails closed off Linux: running through the checked descriptor needs O_PATH and /proc/self/fd.
func Open(path string) (*Program, error) {
	return nil, &errs.Error{Kind: ErrTool, Detail: "cannot run " + path + ": running a checked program needs Linux"}
}
