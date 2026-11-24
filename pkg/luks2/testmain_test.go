// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"os"
	"testing"
)

// TestMain runs the package's tests.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
