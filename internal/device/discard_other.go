// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package device

import "os"

// Discard is a no-op off Linux: BLKDISCARD has no portable equivalent
// (A.3), and it is advisory everywhere it exists.
func Discard(f *os.File, size int64) error {
	return nil
}
