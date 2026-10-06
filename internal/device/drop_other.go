// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package device

import "os"

// DropCache is a no-op off Linux: posix_fadvise(..., FADV_DONTNEED) has no
// portable equivalent, and nothing off Linux exercises the page-cache
// verification this supports (A.3).
func DropCache(f *os.File) error {
	return nil
}
