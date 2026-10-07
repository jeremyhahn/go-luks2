// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

// cryptsetupLockDir is cryptsetup's default locking directory. A variable so
// this package's tests can lock in a directory of their own; nothing else
// changes it. The real locking (node flock, cryptsetup's own lock file,
// O_DIRECT medium reads) lives in internal/device.
var cryptsetupLockDir = "/run/cryptsetup"
