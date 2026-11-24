// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"bytes"
	"strconv"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// HeaderChecksumAlgorithm is the only header checksum algorithm read or written: sha256, as cryptsetup writes.
const HeaderChecksumAlgorithm = "sha256"

// checkHeaderChecksumAlgorithm refuses a header whose NUL-padded csum_alg names anything but sha256.
func checkHeaderChecksumAlgorithm(hdr *BinaryHeader) error {
	name, _, _ := bytes.Cut(hdr.ChecksumAlgorithm[:], []byte{0})
	if string(name) == HeaderChecksumAlgorithm {
		return nil
	}
	return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "checksum algorithm " + strconv.Quote(string(name)), Err: ErrUnsupportedHeaderChecksum}
}
