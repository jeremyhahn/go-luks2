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
	ErrInvalidHeader = errors.New("invalid LUKS header")

	// ErrInvalidKeyslot indicates a keyslot that is invalid or unavailable.
	ErrInvalidKeyslot = errors.New("invalid keyslot")

	// ErrUnsupportedHash indicates a hash algorithm, named by a header or by a
	// caller, that this module does not implement for that use. A
	// FIPS-refused algorithm is NOT this error: the algorithm is implemented
	// and the mode refuses it (fips.ErrNotApproved).
	ErrUnsupportedHash = errors.New("unsupported hash algorithm")

	// ErrSHA1NotWritten indicates a request to WRITE SHA-1 into a keyslot or
	// digest. This module reads SHA-1 -- to open volumes cryptsetup and LUKS1
	// wrote -- and never writes it (#236, #239). It is carried alongside the
	// kind of the rejected option.
	ErrSHA1NotWritten = errors.New("SHA-1 is read from existing keyslots but never written to a new keyslot or digest")
)
