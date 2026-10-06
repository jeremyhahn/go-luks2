// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"reflect"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// The JSON passthrough for metadata objects this package does not fully
// model now lives in internal/header; see docs/design/DECISIONS.md's H5
// entry. This is a transitional forward, kept under its original name so
// every existing caller and test in this package keeps compiling unchanged.
// It is removed at H13.

// jsonMemberNames forwards to header.JSONMemberNames.
func jsonMemberNames(t reflect.Type) []string {
	return header.JSONMemberNames(t)
}
