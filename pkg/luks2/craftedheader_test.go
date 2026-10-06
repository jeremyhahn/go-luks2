// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// writeHeaderUnvalidated writes hdr and metadata exactly as writeHeaderInternal
// does -- both copies, checksummed, primary first -- but WITHOUT the
// structural validation every write by this package passes (#248).
//
// It exists for fixtures that model a header this package did not write: a
// damaged one, a hostile one, or one cryptsetup itself would refuse. Those are
// exactly the headers the reader has to cope with, and since #248 the package
// can no longer produce them through its own writer.
func writeHeaderUnvalidated(device string, hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata) error {
	f, err := os.OpenFile(filepath.Clean(device), os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	jsonData, area, err := encodeMetadata(hdr, metadata)
	if err != nil {
		return err
	}
	return writeEncodedHeader(f, hdr, jsonData, area)
}

// writeHeaderIgnoringRequirements is writeHeaderUnvalidated without the
// requirements guard either, for a fixture that models a container declaring
// a requirement this package does not implement -- an online reencryption,
// above all -- which the normal write path refuses to produce (#248).
func writeHeaderIgnoringRequirements(device string, hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata) error {
	f, err := os.OpenFile(filepath.Clean(device), os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	jsonData, area, err := header.EncodeMetadataIgnoringRequirements(hdr, metadata)
	if err != nil {
		return err
	}
	return writeEncodedHeader(f, hdr, jsonData, area)
}
