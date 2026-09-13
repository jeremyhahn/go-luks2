// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli_test

import (
	"testing"

	"github.com/jeremyhahn/go-luks2/test/harness"
)

// runSuite is the harness suite this process registered, and the single source
// of the two identity terms every device-mapper name carries. TestMain sets it.
var runSuite *harness.Suite

// runVolume returns a device-mapper name unique to this container and process.
//
// This tier used FIXED names -- test-keyring, test-workflow, test-cli-workflow,
// test-cli-open, test-kdf-<case>, and a bare "test" -- while pkg/luks2 had
// already been made run-unique. device-mapper is a flat, host-wide namespace and
// is not namespaced by containers, so two concurrent runs of this tier contended
// for every one of those names, and the entrypoint guard refused a run whenever
// a sibling's mapping was live.
//
// The rule itself lives in test/harness (VolumeName) because all three tiers
// allocate in that one namespace, and a rule reimplemented per tier is a rule
// two of them can drift from.
//
// It FAILS THE TEST rather than falling back to the bare name: a fallback is
// silent, and the suite would pass either way until two runs happened to
// overlap.
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
