// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package device

import (
	"os"

	"golang.org/x/sys/unix"
)

// DropCache evicts f's clean pages from the page cache, so the next read of
// them comes from the medium. It is meant to be called only after the
// device has been synced, when no page of it should be dirty; one that is
// (written since by another process) is not evicted, which is the kernel's
// contract and leaves what is read current rather than stale.
func DropCache(f *os.File) error {
	return unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED)
}
