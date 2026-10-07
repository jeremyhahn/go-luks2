// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import "errors"

// Sentinels raised only by this package. Re-exported by value from
// pkg/luks2 (errors.md §4): they read as the bare condition, not
// "header: ...", because the calling package's errs.Error composes its own
// prefix.
var (
	// ErrUnsupportedRequirement indicates the container declares a mandatory
	// requirement this package does not implement, so it must not be
	// modified. The container is still READABLE; see Requirements.
	ErrUnsupportedRequirement = errors.New("luks2: container declares a mandatory requirement this package does not implement")

	// ErrAmbiguousJSONMember indicates a LUKS2 metadata object that names one
	// member twice, or names a member this package models in a case LUKS2
	// does not spell it.
	ErrAmbiguousJSONMember = errors.New("JSON object names a member twice or in a case that differs from the LUKS2 spelling")

	// ErrMetadataJSON indicates that a LUKS2 metadata object could not be
	// converted to or from JSON; see MetadataJSONError.
	ErrMetadataJSON = errors.New("LUKS2 metadata object could not be converted to or from JSON")

	// ErrMetadataTooLarge indicates the JSON metadata does not fit the header
	// area.
	ErrMetadataTooLarge = errors.New("metadata does not fit the header area")

	// ErrPrimaryHeaderCurrent indicates RestorePrimaryHeader was refused
	// because the primary is intact and not older than the secondary.
	ErrPrimaryHeaderCurrent = errors.New("luks2: the primary header is intact and not older than the secondary; restoring would roll the volume back")

	// ErrUnsupportedLUKSVersion indicates a header names a LUKS version other
	// than 2.
	ErrUnsupportedLUKSVersion = errors.New("luks2: unsupported LUKS version")

	// ErrUnsupportedHeaderChecksum indicates a binary header whose checksum
	// algorithm field names anything but sha256.
	ErrUnsupportedHeaderChecksum = errors.New("header checksum algorithm is not sha256")

	// errOverflow is the cause reported by the Safe*ToInt* conversions in
	// codec.go. It is never returned on its own: every caller wraps it in an
	// *errs.Error with Kind ErrInvalidHeader, so a caller classifies the
	// failure the same way regardless of which conversion produced it.
	errOverflow = errors.New("integer overflow detected")
)
