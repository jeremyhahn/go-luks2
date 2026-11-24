// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package luks2 reads, writes, formats and unlocks LUKS2 volumes in cryptsetup(8)'s on-disk format.
//
// # Key custody and core dumps
//
// Credentials and keys cross the API as go-enclave locked-memory handles; a handle reporting another backend is refused with ErrNotLockedMemory before it is read.
// The standard-library crypto still makes short-lived heap copies, so the application must call enclave.HardenProcess from main and treat its error as fatal; this package never calls it.
package luks2
