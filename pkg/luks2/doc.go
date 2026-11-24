// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package luks2 reads, writes, formats and unlocks LUKS2 volumes in the
// on-disk format cryptsetup(8) uses.
//
// # Key custody and core dumps
//
// Credentials and keys cross this API as enclave.ByteAccess handles, borrowed
// only for the call that needs the raw bytes. Every handle that crosses the
// API, or that this package creates, is go-enclave locked memory, excluded
// from core dumps: a handle reporting any other backend is refused with
// ErrNotLockedMemory, wrapping a *NotLockedMemoryError that names the
// reported backend, before it is read, and it is not destroyed. The check
// reads the backend the handle reports. go-enclave has no unforgeable
// provenance check, so a handle that misreports its backend is outside the
// guarantee, like any caller that already holds the key. The standard-library
// KDF, AES and hash code those calls reach
// still makes short-lived plain copies on the heap, and go-enclave cannot
// keep those out of a core file.
//
// Keeping them out is the application's choice, made once for the process:
// call enclave.HardenProcess from main, before handling a secret, and treat
// its error as fatal. It sets RLIMIT_CORE to 0/0 and, on Linux, makes the
// process non-dumpable, which also stops a piped core_pattern that the rlimit
// alone does not. Importing this package changes no process state and it never
// calls HardenProcess itself. The luks2 command does call it, and refuses to
// run when it fails.
package luks2
