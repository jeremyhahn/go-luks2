// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package loop_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

// TestMain records the host state this suite is about to create (#96), the
// same pattern as test/integration/pkg and test/integration/luks2: every
// loop device this package attaches is backed by a file under t.TempDir(),
// which this suite points at the recorded root before any test runs.
func TestMain(m *testing.M) {
	suite, err := harness.BeginSuite(os.Stderr)
	if err != nil {
		os.Stderr.WriteString("integration suite: " + err.Error() + "\n")
		os.Exit(1)
	}
	os.Exit(suite.Finish(m.Run(), os.Stderr))
}

// TestSuiteAllocatesUnderTheRecordedTempRoot is the assertion that the
// recorded root is actually wired to where this suite allocates.
func TestSuiteAllocatesUnderTheRecordedTempRoot(t *testing.T) {
	root := filepath.Clean(os.Getenv("TMPDIR"))
	if root == "" || root == "." {
		t.Fatal("TMPDIR is unset; the suite is allocating outside any recorded root")
	}

	got := filepath.Clean(t.TempDir())
	if !strings.HasPrefix(got, root+string(filepath.Separator)) {
		t.Fatalf("t.TempDir() returned %q, which is not under the recorded root %q", got, root)
	}
}
