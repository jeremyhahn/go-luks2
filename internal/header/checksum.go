// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"bytes"
	"strconv"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// HeaderChecksumAlgorithm is the only checksum algorithm this package reads or
// writes a LUKS2 binary header with.
//
// It is the one cryptsetup writes: LUKS2_generate_hdr names "sha256" for every
// header it creates (measured against cryptsetup 2.7.5 in the integration
// devcontainer). cryptsetup READS whatever hash the field names -- a header
// re-checksummed with sha1 or sha512 opens there -- but this package computes
// sha256 only, so a header naming anything else is refused rather than
// verified against a hash it did not ask for.
const HeaderChecksumAlgorithm = "sha256"

// checkHeaderChecksumAlgorithm refuses a header whose NUL-padded csum_alg names anything but sha256.
func checkHeaderChecksumAlgorithm(hdr *BinaryHeader) error {
	name, _, _ := bytes.Cut(hdr.ChecksumAlgorithm[:], []byte{0})
	if string(name) == HeaderChecksumAlgorithm {
		return nil
	}
	return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "checksum algorithm " + strconv.Quote(string(name)), Err: ErrUnsupportedHeaderChecksum}
}
