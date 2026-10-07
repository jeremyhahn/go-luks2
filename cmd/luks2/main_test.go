// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"testing"
)

func TestRunHelp(t *testing.T) {
	stdout := &bytes.Buffer{}
	code := run([]string{"luks2", "help"}, &bytes.Buffer{}, stdout, &bytes.Buffer{})
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if stdout.Len() == 0 {
		t.Error("stdout should carry the usage text")
	}
}

func TestRunUnknownCommand(t *testing.T) {
	stderr := &bytes.Buffer{}
	code := run([]string{"luks2", "frobnicate"}, &bytes.Buffer{}, &bytes.Buffer{}, stderr)
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if stderr.Len() == 0 {
		t.Error("stderr should report the unknown command")
	}
}

func TestRunSetsVersion(t *testing.T) {
	old := version
	version = "test-version-marker"
	defer func() { version = old }()

	stdout := &bytes.Buffer{}
	code := run([]string{"luks2", "version"}, &bytes.Buffer{}, stdout, &bytes.Buffer{})
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !bytes.Contains(stdout.Bytes(), []byte("test-version-marker")) {
		t.Errorf("stdout = %q, want it to carry Version", stdout.String())
	}
}

func TestMainCallsOSExitWithRunsCode(t *testing.T) {
	oldExit := osExit
	oldArgs := os.Args
	defer func() {
		osExit = oldExit
		os.Args = oldArgs
	}()

	var gotCode int
	exited := false
	osExit = func(code int) {
		gotCode = code
		exited = true
	}
	os.Args = []string{"luks2", "help"}

	main()

	if !exited {
		t.Fatal("main: want osExit to be called")
	}
	if gotCode != 0 {
		t.Errorf("code = %d, want 0", gotCode)
	}
}
