// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"fmt"
)

// segmentLabel is a private copy of internal/header's unexported helper of
// the same name, for the one call site (unlock.go) that needs it outside the
// package.
func segmentLabel(id string) string {
	if id == "" {
		return "the crypt segment"
	}
	return fmt.Sprintf("segment %q", id)
}
