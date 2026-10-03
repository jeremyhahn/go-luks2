// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// fakeDockerExit is set in the environment of a launcher run that should find
// this test binary as `docker`. The launcher execs docker with its own
// environment, so the variable arrives here and TestMain exits with it.
const fakeDockerExit = "GO_LUKS2_FAKE_DOCKER_EXIT"

func TestMain(m *testing.M) {
	if code, ok := os.LookupEnv(fakeDockerExit); ok && filepath.Base(os.Args[0]) == "docker" {
		n, err := strconv.Atoi(code)
		if err != nil {
			os.Exit(255)
		}
		os.Exit(n)
	}
	os.Exit(m.Run())
}

// TestBinary_PropagatesDockersExitStatus builds the launcher the way the
// Makefile does and runs it against a stand-in docker that exits with a chosen
// status. Every status must come back unchanged -- in particular docker's own
// 125 (daemon or flag error), 126 (command not executable) and 127 (command not
// found), which callers use to tell an infrastructure failure from a test
// failure. Under `go run` all three came back as 1: the go tool stays the
// parent and flattens any nonzero child status. That is why the Makefile and
// the workflow run the built binary.
func TestBinary_PropagatesDockersExitStatus(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go tool is not on PATH: %v", err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	// The launcher reads the dm major before it reaches docker. Linking it
	// against a fixture keeps this test independent of whether the host has
	// device-mapper loaded; the real read is TestDMMajor's subject.
	bin := t.TempDir()
	devices := filepath.Join(t.TempDir(), "devices")
	if err := os.WriteFile(devices, []byte(procDevices), 0o644); err != nil { // #nosec G306 -- test fixture
		t.Fatalf("write the devices fixture: %v", err)
	}
	launcher := filepath.Join(bin, "docker-run")
	build := exec.Command(goBin, "build", "-ldflags", "-X main.procDevicesPath="+devices, "-o", launcher, ".") // #nosec G204 -- the go tool on PATH, fixed arguments
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	if err := os.Symlink(self, filepath.Join(bin, "docker")); err != nil {
		t.Fatalf("symlink the stand-in docker: %v", err)
	}

	for _, want := range []int{0, 1, 2, 125, 126, 127} {
		t.Run(strconv.Itoa(want), func(t *testing.T) {
			cmd := exec.Command(launcher, "--rm", "--", "true") // #nosec G204 -- the launcher this test just built
			cmd.Dir = wd
			cmd.Env = append(os.Environ(),
				"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
				fakeDockerExit+"="+strconv.Itoa(want),
				"TEST_STATE_DIR="+t.TempDir())
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()
			got := 0
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				got = exitErr.ExitCode()
			} else if err != nil {
				t.Fatalf("running the launcher: %v", err)
			}
			if got != want {
				t.Fatalf("exit status = %d, want %d (docker's own); stderr:\n%s", got, want, stderr.String())
			}
		})
	}
}
