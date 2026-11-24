// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package command

import "errors"

// ErrTool indicates a program was not found in the fixed directories, or its path could have been replaced by someone other than root or the current user.
var ErrTool = errors.New("program is not available from a trusted location")
