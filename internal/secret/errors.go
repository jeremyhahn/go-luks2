// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"errors"
	"strconv"
)

// ErrProtectedMemory indicates that key material could not be placed in, or
// read back from, protected memory, and that the operation was therefore
// REFUSED rather than completed with the material on the ordinary heap.
//
// It is almost always a deployment condition rather than a defect: the process
// has hit RLIMIT_MEMLOCK, or the budget the binary gave go-enclave's process
// Allocator. The error's Detail names the material or step that needed the
// memory -- never key content and never a key length, which is a fact about
// the volume the error path has no reason to publish. Its cause is
// go-enclave's: it matches enclave.ErrLockedMemoryUnavailable when the kernel
// refused the lock, enclave.ErrBudgetExhausted when the allocator did, and
// enclave.ErrEnclaveDestroyed for a use after release.
//
// # Why this is fatal and never a degradation
//
// Every path that meets one of these FAILS CLOSED: the operation is abandoned
// and no key material is placed on the ordinary heap instead. Failing an
// unlock has a real availability cost, and it is paid deliberately:
//
//   - A caller that gets a successful return believes the protected-memory
//     mandate held for that operation. A silent fallback makes that belief
//     wrong exactly when it matters -- on a machine already under memory
//     pressure, which is also where swapping is most likely.
//   - The failure is recoverable and the leak is not. An operator can raise
//     RLIMIT_MEMLOCK and retry; a master key that reached swap or a core dump
//     cannot be recalled, and nothing tells anyone it happened.
//   - This is disk encryption. The material at stake is the volume master key,
//     which is the entire secret -- not a session token that expires.
//
// # What an operator has to provide
//
// The locked memory one operation needs is dominated by the anti-forensic
// stripes, key_size * stripes bytes, held alongside their decrypted
// counterpart. For a container this library wrote that is 256 KiB each, about
// 512 KiB per operation in flight. That is the DEFAULT GEOMETRY, not the
// requirement: the header bounds allow key_size up to 1024 bytes and stripes up
// to 4000, so budget 8 MiB per concurrent operation for containers whose
// headers are not yours. 8 MiB is a typical host default exactly, and well
// above the 64 KiB some container runtimes still impose.
//
// # The aggregate bounds (#26)
//
// Every enclave is admitted against go-enclave's process Allocator before its
// pages are mapped (Admitted). A keyslot scan whose largest keyslot could never
// be admitted is refused before any derivation (Custody.Admissible); keyslots
// are opened one at a time, so that keyslot is the scan's peak. The key
// DERIVATION of one operation is bounded too, by the module's KDF budget.
var ErrProtectedMemory = errors.New("luks2: key material could not be held in protected memory")

// ErrNotLockedMemory indicates that a handle crossing the API reports a
// backend other than go-enclave locked memory, and that the operation was
// therefore REFUSED before the handle was read. The handle is the caller's:
// it is neither read nor destroyed. The error's chain carries a
// *NotLockedMemoryError naming the backend the handle reported.
//
// The check reads the backend the handle reports. go-enclave has no
// unforgeable provenance check, so a handle that misreports its backend is
// outside the guarantee, like any caller that already holds the key.
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
