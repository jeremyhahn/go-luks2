// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package errs

import "errors"

// Kinds raised by more than one internal package; pkg/luks2 re-exports each by value.
var (
	// ErrInvalidHeader indicates a LUKS header is invalid or corrupted.
	ErrInvalidHeader = errors.New("luks2: invalid LUKS header")

	// ErrInvalidKeyslot indicates a keyslot that is invalid or unavailable.
	ErrInvalidKeyslot = errors.New("luks2: invalid keyslot")

	// ErrUnsupportedHash indicates a hash this module does not implement for that use; a FIPS refusal is fips.ErrNotApproved instead.
	ErrUnsupportedHash = errors.New("luks2: unsupported hash algorithm")

	// ErrSHA1NotWritten indicates a request to write SHA-1 into a keyslot or digest; SHA-1 is read, never written.
	ErrSHA1NotWritten = errors.New("luks2: SHA-1 is read from existing keyslots but never written to a new keyslot or digest")

	// ErrInvalidArgument indicates a caller-supplied argument this module refuses.
	ErrInvalidArgument = errors.New("luks2: invalid argument")

	// ErrInvalidCredential indicates a credential refused before any comparison (too short, too long or empty); distinct from ErrWrongKey.
	ErrInvalidCredential = errors.New("luks2: invalid credential")

	// ErrIO indicates an I/O failure not otherwise classified.
	ErrIO = errors.New("luks2: I/O error")
)
