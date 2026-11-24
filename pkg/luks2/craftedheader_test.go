// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// writeHeaderUnvalidated writes hdr and metadata like writeHeaderInternal but without structural validation, for fixtures of foreign or damaged headers.
func writeHeaderUnvalidated(device string, hdr *header.BinaryHeader, metadata *header.Metadata) error {
	f, err := os.OpenFile(filepath.Clean(device), os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	jsonData, area, err := encodeMetadata(hdr, metadata)
	if err != nil {
		return err
	}
	return header.WriteEncodedHeader(f, hdr, jsonData, area, (*os.File).Sync)
}

// writeHeaderIgnoringRequirements is writeHeaderUnvalidated without the requirements guard.
func writeHeaderIgnoringRequirements(device string, hdr *header.BinaryHeader, metadata *header.Metadata) error {
	f, err := os.OpenFile(filepath.Clean(device), os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	jsonData, area, err := header.EncodeMetadataIgnoringRequirements(hdr, metadata)
	if err != nil {
		return err
	}
	return header.WriteEncodedHeader(f, hdr, jsonData, area, (*os.File).Sync)
}
