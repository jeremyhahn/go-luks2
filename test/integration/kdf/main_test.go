// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package kdf_test

import (
	"os"
	"testing"

	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

func TestMain(m *testing.M) {
	suite, err := harness.BeginSuite(os.Stderr)
	if err != nil {
		os.Stderr.WriteString("integration suite: " + err.Error() + "\n")
		os.Exit(1)
	}
	os.Exit(suite.Finish(m.Run(), os.Stderr))
}
