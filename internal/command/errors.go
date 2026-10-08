// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package command

import "errors"

// ErrTool indicates a program could not be found in the fixed directories
// programs are run from, or was found -- there, or at the absolute path Open
// was given -- but could have been replaced by someone other than root or the
// current user, or reached through a directory or symlink that could have.
var ErrTool = errors.New("program is not available from a trusted location")
