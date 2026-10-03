// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// procDevices is /proc/devices as a real host prints it, with the dm major at
// 252 -- the value on the machine this was first measured on, and a value other
// hosts do not share, which is why it is read rather than written down.
const procDevices = `Character devices:
  1 mem
  4 tty
 10 misc
 13 input
252 dax
Block devices:
  7 loop
  8 sd
  9 md
252 device-mapper
253 virtblk
259 blkext
`

func TestDMMajor_ReadsTheDynamicMajor(t *testing.T) {
	got, err := dmMajor([]byte(procDevices))
	if err != nil {
		t.Fatalf("dmMajor: %v", err)
	}
	if got != "252" {
		t.Errorf("dmMajor = %q, want 252", got)
	}
}

func TestDMMajor_RefusesAHostWithoutDeviceMapper(t *testing.T) {
	cases := map[string]string{
		"no dm line": "Block devices:\n  7 loop\n  8 sd\n",
		// A name that merely contains the word is not the dm driver.
		"lookalike": "Block devices:\n254 device-mapper-ish\n",
		"empty":     "",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := dmMajor([]byte(content))
			var noDM *NoDeviceMapperError
			if !errors.As(err, &noDM) {
				t.Fatalf("err = %v, want *NoDeviceMapperError", err)
			}
			if !strings.Contains(err.Error(), "modprobe dm_mod") {
				t.Errorf("the error does not say how to fix it: %v", err)
			}
		})
	}
}

func TestSplitArgs(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		flags   []string
		command []string
	}{
		{
			name:    "flags and a command",
			args:    []string{"--rm", "--", "go", "test", "-tags=integration", "./..."},
			flags:   []string{"--rm"},
			command: []string{"go", "test", "-tags=integration", "./..."},
		},
		{
			name:  "an empty command runs the image default",
			args:  []string{"--name", "go-luks2-test-runner", "--"},
			flags: []string{"--name", "go-luks2-test-runner"},
		},
		{
			name:    "only the first -- separates; a later one belongs to the command",
			args:    []string{"--rm", "-it", "--", "sh", "-c", "--"},
			flags:   []string{"--rm", "-it"},
			command: []string{"sh", "-c", "--"},
		},
		{
			name:    "no docker flags",
			args:    []string{"--", "bash"},
			command: []string{"bash"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flags, command, err := splitArgs(tc.args)
			if err != nil {
				t.Fatalf("splitArgs: %v", err)
			}
			if strings.Join(flags, "|") != strings.Join(tc.flags, "|") {
				t.Errorf("flags = %q, want %q", flags, tc.flags)
			}
			if strings.Join(command, "|") != strings.Join(tc.command, "|") {
				t.Errorf("command = %q, want %q", command, tc.command)
			}
		})
	}
}

// The -- is mandatory so neither list can swallow the other: without it, a
// command meant for the container would be handed to docker as flags.
func TestSplitArgs_RefusesAMissingSeparator(t *testing.T) {
	for _, args := range [][]string{nil, {"--rm"}, {"--rm", "go", "test"}} {
		_, _, err := splitArgs(args)
		var usage *UsageError
		if !errors.As(err, &usage) {
			t.Errorf("splitArgs(%q) err = %v, want *UsageError", args, err)
		}
	}
}

// TestPrivileges_IsExactlyTheMeasuredSet pins the privilege set flag by flag.
// Each one was measured (docs/TESTING.md carries the table), so a flag added or
// dropped here is a security decision, and it has to show up as a failing test
// rather than as a quiet diff.
func TestPrivileges_IsExactlyTheMeasuredSet(t *testing.T) {
	got := privileges("/src/test/integration/seccomp.json", "252", "/var/tmp/state")
	want := []string{
		"--cap-add", "SYS_ADMIN",
		"--cap-add", "MKNOD",
		"--cap-drop", "ALL",
		"--security-opt", "seccomp=/src/test/integration/seccomp.json",
		"--security-opt", "apparmor=unconfined",
		"--device", "/dev/mapper/control",
		"--device", "/dev/loop-control",
		"--device-cgroup-rule", "b 7:* rwm",
		"--device-cgroup-rule", "b 252:* rwm",
		"-v", "/var/tmp/state:/var/lib/go-luks2-test-state",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("privileges =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, flag := range got {
		if strings.Contains(flag, "privileged") {
			t.Fatalf("the privilege set contains %q (#80)", flag)
		}
	}
}

func TestDockerArgv_OrdersFlagsPrivilegesImageCommand(t *testing.T) {
	argv := dockerArgv([]string{"--rm", "-it"}, []string{"--cap-drop", "ALL"}, "img", []string{"bash"})
	want := "docker run --rm -it --cap-drop ALL img bash"
	if strings.Join(argv, " ") != want {
		t.Errorf("argv = %q, want %q", strings.Join(argv, " "), want)
	}
}

func TestConfigFromEnv_Defaults(t *testing.T) {
	cfg := configFromEnv(func(string) string { return "" })
	if cfg.stateDir != "/var/tmp/go-luks2-test-state" {
		t.Errorf("stateDir = %q", cfg.stateDir)
	}
	if cfg.image != "go-luks2-integration-test" {
		t.Errorf("image = %q", cfg.image)
	}

	env := map[string]string{"TEST_STATE_DIR": "/srv/state", "IMAGE": "itest:abc"}
	cfg = configFromEnv(func(k string) string { return env[k] })
	if cfg.stateDir != "/srv/state" || cfg.image != "itest:abc" {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestSeccompProfile_IsFoundFromAnywhereInTheModule(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	profileDir := filepath.Join(root, "test", "integration")
	if err := os.MkdirAll(profileDir, 0o750); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(profileDir, "seccomp.json")
	if err := os.WriteFile(profile, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(root, "pkg", "a", "b")
	if err := os.MkdirAll(deep, 0o750); err != nil {
		t.Fatal(err)
	}

	for _, start := range []string{root, deep} {
		got, err := seccompProfile(start)
		if err != nil {
			t.Fatalf("seccompProfile(%s): %v", start, err)
		}
		if got != profile {
			t.Errorf("seccompProfile(%s) = %q, want %q", start, got, profile)
		}
	}
}

// A missing profile must stop the run here. Handed to docker as a path that
// does not exist, it fails later with a message about JSON; handed nothing, the
// container would lose the keyring syscalls the suite needs.
func TestSeccompProfile_RefusesAModuleWithoutTheProfile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := seccompProfile(root)
	var missing *ProfileError
	if !errors.As(err, &missing) {
		t.Fatalf("err = %v, want *ProfileError", err)
	}
}

func TestSeccompProfile_RefusesADirectoryOutsideAnyModule(t *testing.T) {
	_, err := seccompProfile(t.TempDir())
	var missing *ProfileError
	if !errors.As(err, &missing) {
		t.Fatalf("err = %v, want *ProfileError", err)
	}
}

// The real profile is where the command looks for it. If it moves, this fails
// in the unit suite instead of at the start of an integration run.
func TestSeccompProfile_FindsTheRepositorysOwnProfile(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	got, err := seccompProfile(wd)
	if err != nil {
		t.Fatalf("seccompProfile: %v", err)
	}
	if filepath.Base(got) != "seccomp.json" {
		t.Errorf("seccompProfile = %q", got)
	}
}

func TestErrors_NameTheirSubject(t *testing.T) {
	cause := errors.New("cause")
	cases := []struct {
		err      error
		contains []string
		wrapped  error
	}{
		{&UsageError{Problem: "no --"}, []string{"usage", "no --"}, nil},
		{&NoDeviceMapperError{}, []string{"device-mapper", "modprobe dm_mod"}, nil},
		{&ProfileError{Start: "/src", Err: cause}, []string{"/src", "seccomp.json"}, cause},
		{&DockerError{Err: cause}, []string{"docker"}, cause},
	}
	for _, tc := range cases {
		msg := tc.err.Error()
		for _, want := range tc.contains {
			if !strings.Contains(msg, want) {
				t.Errorf("%T: %q omits %q", tc.err, msg, want)
			}
		}
		if tc.wrapped != nil && !errors.Is(tc.err, tc.wrapped) {
			t.Errorf("%T does not unwrap to its cause", tc.err)
		}
	}
}
