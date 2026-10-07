// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package errs

import "errors"

// The kinds more than one internal package raises. A kind raised by one
// package only is declared there; these are the ones with no single owner
// below the public API. pkg/luks2 re-exports each by value, so errors.Is
// matches the same sentinel on either side.
var (
	// ErrInvalidHeader indicates a LUKS header is invalid or corrupted.
	ErrInvalidHeader = errors.New("luks2: invalid LUKS header")

	// ErrInvalidKeyslot indicates a keyslot that is invalid or unavailable.
	ErrInvalidKeyslot = errors.New("luks2: invalid keyslot")

	// ErrUnsupportedHash indicates a hash algorithm, named by a header or by a
	// caller, that this module does not implement for that use. A
	// FIPS-refused algorithm is NOT this error: the algorithm is implemented
	// and the mode refuses it (fips.ErrNotApproved).
	ErrUnsupportedHash = errors.New("luks2: unsupported hash algorithm")

	// ErrSHA1NotWritten indicates a request to WRITE SHA-1 into a keyslot or
	// digest. This module reads SHA-1 -- to open volumes cryptsetup and LUKS1
	// wrote -- and never writes it (#236, #239). It is carried alongside the
	// kind of the rejected option.
	ErrSHA1NotWritten = errors.New("luks2: SHA-1 is read from existing keyslots but never written to a new keyslot or digest")

	// ErrInvalidArgument indicates a caller-supplied argument this module
	// refuses: out of range, malformed, or structurally wrong for the call.
	// It has no single owner below the public API -- every package from
	// internal/af to pkg/luks2 refuses a bad argument somewhere -- so it
	// lives here, the H3c rule generalised. Re-exported by value from every
	// top-level package that needs it.
	ErrInvalidArgument = errors.New("luks2: invalid argument")

	// ErrInvalidCredential indicates a caller-supplied passphrase, recovery
	// key or other credential this module refuses before it is ever
	// compared against a keyslot: too short, too long, or empty. It is
	// distinct from ErrWrongKey, which is a comparison that ran and matched
	// nothing.
	ErrInvalidCredential = errors.New("luks2: invalid credential")

	// ErrIO indicates a read, write or other I/O operation failed for a
	// reason that is not itself classified (not found, not permitted, in
	// use, ...). Like ErrInvalidArgument, no single internal package owns
	// every I/O failure site below the public API.
	ErrIO = errors.New("luks2: I/O error")
)
