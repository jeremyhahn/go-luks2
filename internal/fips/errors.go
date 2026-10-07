// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package fips

import "errors"

// ErrNotApproved indicates the requested algorithm is not approved by the Go
// Cryptographic Module and is refused while the process runs in FIPS 140-3
// mode. See docs/FIPS.md.
var ErrNotApproved = errors.New("luks2: algorithm not approved in FIPS 140-3 mode")
