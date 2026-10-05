// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fakeSystem records the exec run would perform, over a module the test makes.
type fakeSystem struct {
	devices    string
	devicesErr error
	wd         string
	wdErr      error
	env        map[string]string
	dockerErr  error
	execErr    error

	execed   bool
	argv0    string
	argv     []string
	envvSeen []string
}

func (f *fakeSystem) system() system {
	return system{
		readFile: func(path string) ([]byte, error) {
			if path != procDevicesPath {
				return nil, errors.New("unexpected read of " + path)
			}
			return []byte(f.devices), f.devicesErr
		},
		getwd:  func() (string, error) { return f.wd, f.wdErr },
		getenv: func(k string) string { return f.env[k] },
		lookPath: func(file string) (string, error) {
			if f.dockerErr != nil {
				return "", f.dockerErr
			}
			return "/usr/bin/" + file, nil
		},
		exec: func(argv0 string, argv, envv []string) error {
			f.execed, f.argv0, f.argv, f.envvSeen = true, argv0, argv, envv
			return f.execErr
		},
		environ: func() []string { return []string{"PATH=/usr/bin"} },
	}
}

// moduleWithProfile makes a module root holding the seccomp profile and
// returns a directory inside it.
func moduleWithProfile(t *testing.T) (root, inside string) {
	t.Helper()
	root = t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(root, filepath.FromSlash(profileRel))
	if err := os.MkdirAll(filepath.Dir(profile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profile, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inside = filepath.Join(root, "pkg")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	return root, inside
}

const devicesWithDM = "Block devices:\n  7 loop\n253 device-mapper\n"

func TestRun_ExecsDockerWithTheAssembledArgv(t *testing.T) {
	root, inside := moduleWithProfile(t)
	f := &fakeSystem{
		devices: devicesWithDM,
		wd:      inside,
		env:     map[string]string{"TEST_STATE_DIR": "/var/tmp/state-x", "IMAGE": "img:x"},
	}

	if err := run([]string{"--rm", "--", "go", "test"}, f.system()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !f.execed || f.argv0 != "/usr/bin/docker" {
		t.Fatalf("exec = %v %q, want /usr/bin/docker", f.execed, f.argv0)
	}
	profile := filepath.Join(root, filepath.FromSlash(profileRel))
	want := dockerArgv([]string{"--rm"}, privileges(profile, "253", "/var/tmp/state-x"), "img:x", []string{"go", "test"})
	if !reflect.DeepEqual(f.argv, want) {
		t.Fatalf("argv =\n%q\nwant\n%q", f.argv, want)
	}
	if !reflect.DeepEqual(f.envvSeen, []string{"PATH=/usr/bin"}) {
		t.Fatalf("environment = %q, want the process's own", f.envvSeen)
	}
}

func TestRun_RefusesBeforeExecWhenAPreconditionFails(t *testing.T) {
	_, inside := moduleWithProfile(t)
	outside := t.TempDir()

	tests := []struct {
		name string
		args []string
		f    fakeSystem
		want any
	}{
		{"no separator", []string{"--rm", "go"}, fakeSystem{devices: devicesWithDM, wd: inside}, &UsageError{}},
		{"unreadable /proc/devices", []string{"--"}, fakeSystem{devicesErr: os.ErrNotExist, wd: inside}, &NoDeviceMapperError{}},
		{"no device-mapper", []string{"--"}, fakeSystem{devices: "Block devices:\n  7 loop\n", wd: inside}, &NoDeviceMapperError{}},
		{"no working directory", []string{"--"}, fakeSystem{devices: devicesWithDM, wdErr: os.ErrPermission}, &ProfileError{}},
		{"no profile above it", []string{"--"}, fakeSystem{devices: devicesWithDM, wd: outside}, &ProfileError{}},
		{"no docker", []string{"--"}, fakeSystem{devices: devicesWithDM, wd: inside, dockerErr: errors.New("not found")}, &DockerError{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.f
			err := run(tt.args, f.system())
			if err == nil || reflect.TypeOf(err) != reflect.TypeOf(tt.want) {
				t.Fatalf("run = %v (%T), want a %T", err, err, tt.want)
			}
			if f.execed {
				t.Fatal("docker was exec'd despite the refusal")
			}
		})
	}
}

func TestRun_AFailedExecIsADockerError(t *testing.T) {
	_, inside := moduleWithProfile(t)
	f := &fakeSystem{devices: devicesWithDM, wd: inside, execErr: errors.New("exec format error")}

	err := run([]string{"--", "true"}, f.system())
	var dockerErr *DockerError
	if !errors.As(err, &dockerErr) {
		t.Fatalf("run = %v, want a *DockerError", err)
	}
}

// TestHostSystem_IsTheRealOne: the production system reads, resolves and
// reports from the real process (exec itself is covered by exit_test.go).
func TestHostSystem_IsTheRealOne(t *testing.T) {
	sys := hostSystem()
	wd, err := sys.getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	want, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	if wd != want {
		t.Fatalf("getwd = %q, want %q", wd, want)
	}
	if _, err := sys.readFile(filepath.Join(wd, "main.go")); err != nil {
		t.Fatalf("readFile(main.go): %v", err)
	}
	if _, err := sys.lookPath("go"); err != nil {
		t.Fatalf("lookPath(go): %v", err)
	}
	t.Setenv("DOCKER_RUN_PROBE", "set")
	if sys.getenv("DOCKER_RUN_PROBE") != "set" {
		t.Fatal("getenv does not read the environment")
	}
	if len(sys.environ()) == 0 {
		t.Fatal("environ is empty")
	}
	if sys.exec == nil {
		t.Fatal("exec is nil")
	}
}

// TestLedgerDirMovesBelowAUserOwnedStateDir: a state directory an ordinary
// user owns -- the default, once anything ran as that user -- is not mounted
// as the ledger, which the root reaper must not trust, and is not refused
// either: the ledger is a subdirectory Docker creates as root. A root-owned or
// absent directory is used as configured.
func TestLedgerDirMovesBelowAUserOwnedStateDir(t *testing.T) {
	dir := t.TempDir()
	want := dir
	if os.Getuid() != 0 {
		want = filepath.Join(dir, rootLedgerSubdir)
	}
	if got := ledgerDir(dir, os.Lstat); got != want {
		t.Fatalf("ledgerDir(%s owned by uid %d) = %s, want %s", dir, os.Getuid(), got, want)
	}

	absent := filepath.Join(dir, "absent")
	if got := ledgerDir(absent, os.Lstat); got != absent {
		t.Fatalf("ledgerDir(absent) = %s, want it unchanged", got)
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ledgerDir(file, os.Lstat); got != file {
		t.Fatalf("ledgerDir(a file) = %s, want it unchanged for the harness to refuse", got)
	}
	root := func(string) (os.FileInfo, error) { return os.Lstat("/") }
	if got := ledgerDir(dir, root); got != dir {
		t.Fatalf("ledgerDir(root-owned) = %s, want it unchanged", got)
	}

	_, inside := moduleWithProfile(t)
	f := &fakeSystem{devices: devicesWithDM, wd: inside, env: map[string]string{"TEST_STATE_DIR": dir}}
	sys := f.system()
	sys.lstat = os.Lstat
	if err := run([]string{"--", "true"}, sys); err != nil {
		t.Fatal(err)
	}
	if mount := dir + ":" + containerStateDir; os.Getuid() != 0 && strings.Contains(strings.Join(f.argv, " "), mount) {
		t.Fatalf("the user-owned state directory itself was mounted: %v", f.argv)
	}
}
