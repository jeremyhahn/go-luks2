// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package luks2

import "github.com/jeremyhahn/go-luks2/internal/device"

// cacheIsTheStorage reports whether path lives on a memory filesystem (tmpfs, ramfs); a block device never does.
func cacheIsTheStorage(path string) (bool, error) {
	return device.CacheIsTheStorage(path)
}

// isMemoryFilesystemMagic reports whether a statfs filesystem magic is a
// memory filesystem's: tmpfs or ramfs.
func isMemoryFilesystemMagic(magic uint32) bool {
	return device.IsMemoryFilesystemMagic(magic)
}
