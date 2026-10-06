// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package command

import "errors"

// ErrTool indicates a program could not be found in the fixed directories
// programs are run from, or was found but could have been replaced by someone
// other than root or the current user.
var ErrTool = errors.New("filesystem tool is not available from a trusted system directory")
