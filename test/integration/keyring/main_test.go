// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package keyring_test

import (
	"context"
	"os"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

// CheckKeyringAvailable is luks2.CheckKeyringAvailable, now
// pkg/dmcrypt.CheckKeyring (#268): the free function the old activation API
// collapsed into. See cmd/luks2/cli.go's DefaultLuksOperations for the same
// forward.
func CheckKeyringAvailable() error {
	return dmcrypt.CheckKeyring(context.Background())
}

// TestMain records the host state this suite is about to create (#96),
// matching every other test/integration/<pkg> package.
func TestMain(m *testing.M) {
	suite, err := harness.BeginSuite(os.Stderr)
	if err != nil {
		os.Stderr.WriteString("integration suite: " + err.Error() + "\n")
		os.Exit(1)
	}
	os.Exit(suite.Finish(m.Run(), os.Stderr))
}
