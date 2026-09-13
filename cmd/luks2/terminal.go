// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"golang.org/x/term"
)

// DefaultTerminal implements Terminal using the actual term package
type DefaultTerminal struct{}

func (d *DefaultTerminal) ReadPassword(fd int) ([]byte, error) {
	return term.ReadPassword(fd)
}

// IsTerminal reports whether fd is a terminal.
//
// It is asked about the DESCRIPTOR and not about an io.Reader because that is
// what ReadPassword needs: putting a pipe into raw mode is what fails, and the
// descriptor is the thing that either is or is not a tty.
func (d *DefaultTerminal) IsTerminal(fd int) bool {
	return term.IsTerminal(fd)
}
