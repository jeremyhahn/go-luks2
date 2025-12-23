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
