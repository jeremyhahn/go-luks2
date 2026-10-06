// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// The LUKS2 structural validator now lives in internal/header; see
// docs/design/DECISIONS.md's H5 entry. These are transitional forwards, kept
// under their original names so every existing caller and test in this
// package keeps compiling unchanged. They are removed at H13.

// sortedIDs forwards to header.SortedIDs. It stays a generic wrapper rather
// than a package-level var because Go does not allow a generic function
// value to be assigned to a var of inferred type.
func sortedIDs[V any](m map[string]V) []string {
	return header.SortedIDs(m)
}

// onlineReencryptRequirements forwards to header.OnlineReencryptRequirements.
var onlineReencryptRequirements = header.OnlineReencryptRequirements

// validateHeaderStructure forwards to header.ValidateHeaderStructure.
var validateHeaderStructure = header.ValidateHeaderStructure
