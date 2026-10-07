// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package luks2

import "github.com/jeremyhahn/go-luks2/internal/device"

// cacheIsTheStorage reports whether path lives on a memory filesystem
// (tmpfs, ramfs), where the page cache is the only copy there is. A block
// device never does, whatever filesystem its node sits on (devtmpfs is
// tmpfs). Linux-only (§A.3): internal/device has no darwin implementation,
// since there is no portable way to answer this off Linux.
func cacheIsTheStorage(path string) (bool, error) {
	return device.CacheIsTheStorage(path)
}

// isMemoryFilesystemMagic reports whether a statfs filesystem magic is a
// memory filesystem's: tmpfs or ramfs.
func isMemoryFilesystemMagic(magic uint32) bool {
	return device.IsMemoryFilesystemMagic(magic)
}
