// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

// runSuite is the harness suite this process registered, and the single
// source of the two identity terms every device-mapper name carries.
// TestMain sets it.
var runSuite *harness.Suite

// runVolume returns a device-mapper name unique to this container and
// process: device-mapper is a flat, host-wide namespace, so every tier that creates a
// mapping draws its name from the one rule in test/internal/harness.
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

// TestMain records the host state this suite is about to create (#96).
//
// # What it covers
//
// Loop devices, through the recorded temp root (below), and dm mappings:
// Unlock records each mapping it activates in the run ledger right after
// dmcrypt.Activate (activation is public in pkg/dmcrypt), and every test still
// removes its mapping on pass, fail and panic through releaseVolume. The
// cross-run reaper (test/internal/harness's reap.go) removes what a killed run
// left behind.
func TestMain(m *testing.M) {
	suite, err := harness.BeginSuite(os.Stderr)
	if err != nil {
		os.Stderr.WriteString("integration suite: " + err.Error() + "\n")
		os.Exit(1)
	}

	// Registered before any test runs: runVolume refuses without it.
	runSuite = suite

	os.Exit(suite.Finish(m.Run(), os.Stderr))
}

// TestSuiteAllocatesUnderTheRecordedTempRoot is the assertion that the
// covered half is actually wired: a recorded root nothing allocates under is
// a record of nothing.
func TestSuiteAllocatesUnderTheRecordedTempRoot(t *testing.T) {
	root := filepath.Clean(os.Getenv("TMPDIR"))
	if root == "" || root == "." {
		t.Fatal("TMPDIR is unset; the suite is allocating outside any recorded root")
	}

	got := filepath.Clean(t.TempDir())
	if !strings.HasPrefix(got, root+string(filepath.Separator)) {
		t.Fatalf("t.TempDir() returned %q, which is not under the recorded root %q", got, root)
	}

	f, err := os.CreateTemp("", "luks2-integration-*.img")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	name := f.Name()
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(name) })

	if !strings.HasPrefix(filepath.Clean(name), root+string(filepath.Separator)) {
		t.Fatalf("os.CreateTemp(\"\") returned %q, which is not under the recorded root %q", name, root)
	}
}
