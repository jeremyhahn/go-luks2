// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli_test

import (
	"testing"

	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

// runSuite is the harness suite this process registered, and the single source
// of the two identity terms every device-mapper name carries. TestMain sets it.
var runSuite *harness.Suite

// runVolume returns a device-mapper name unique to this container and process (harness.VolumeName), failing the test rather than falling back.
func runVolume(t *testing.T, base string) string {
	t.Helper()

	if runSuite == nil {
		t.Fatalf("runVolume(%q): TestMain did not register the suite, so this name would be "+
			"host-global and could collide with a concurrent run.", base)
	}
	name, err := runSuite.VolumeName(base)
	if err != nil {
		t.Fatalf("runVolume(%q): %v", base, err)
	}
	return name
}
