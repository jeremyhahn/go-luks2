// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"os"
	"testing"
)

// TestMain used to also install an in-memory kernel keyring for the whole
// unit suite (#78, #268): every test that called Unlock reached the real
// keyring otherwise, which a default-seccomp CI container refuses. Unlock
// and the keyring are pkg/dmcrypt's now, and that package carries its own
// fake and its own TestMain. What stays here is the unrelated half this
// file always also did.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
