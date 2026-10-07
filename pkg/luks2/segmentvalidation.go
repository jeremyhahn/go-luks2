// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"fmt"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// Crypt-segment validation now lives in internal/header; see
// docs/design/DECISIONS.md's H5 entry. These are transitional forwards, kept
// under their original names so every existing caller and test in this
// package keeps compiling unchanged. They are removed at H13.

// maxSegmentEncryptionLength forwards to header.MaxSegmentEncryptionLength.
const maxSegmentEncryptionLength = header.MaxSegmentEncryptionLength

// segmentSectorSizes forwards to header.SegmentSectorSizes.
var segmentSectorSizes = header.SegmentSectorSizes

// cryptTableParams forwards to header.CryptTableParams.
func cryptTableParams(metadata *header.Metadata, id string, segment *header.Segment) (header.CryptSegmentParams, error) {
	return header.CryptTableParams(metadata, id, segment)
}

// segmentLabel is a private copy of internal/header's unexported helper of
// the same name, for the one call site (unlock.go) that needs it outside the
// package.
func segmentLabel(id string) string {
	if id == "" {
		return "the crypt segment"
	}
	return fmt.Sprintf("segment %q", id)
}
