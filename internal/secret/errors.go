// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"errors"
	"strconv"
)

// ErrProtectedMemory indicates key material could not be placed in or read from protected memory, and the operation was refused (fail closed, never the heap). Budget 8 MiB of RLIMIT_MEMLOCK per concurrent operation.
var ErrProtectedMemory = errors.New("luks2: key material could not be held in protected memory")

// ErrNotLockedMemory indicates a handle reports a backend other than go-enclave locked memory; refused before it is read.
var ErrNotLockedMemory = errors.New("luks2: handle is not go-enclave locked memory")

// NotLockedMemoryError is the reason behind ErrNotLockedMemory: the backend
// name the refused handle reported. errors.Is matches it to
// ErrNotLockedMemory.
type NotLockedMemoryError struct {
	// Backend is the name the handle's Backend reported.
	Backend string
}

func (e *NotLockedMemoryError) Error() string {
	return "luks2: handle backend " + strconv.Quote(e.Backend) + " is not go-enclave locked memory"
}

// Unwrap returns ErrNotLockedMemory.
func (e *NotLockedMemoryError) Unwrap() error { return ErrNotLockedMemory }
