// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command docker-run runs the integration container with its measured privilege set (docs/volumes/engineering.md): build/docker-run [docker flags ...] -- [command ...], with TEST_STATE_DIR and IMAGE from the environment.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

const (
	defaultStateDir = "/var/tmp/go-luks2-test-state"
	defaultImage    = "go-luks2-integration-test"

	// containerStateDir is where the harness inside the image reads the
	// ledgers. See test/internal/harness and the integration stage of build/docker/devcontainer/Dockerfile.
	containerStateDir = "/var/lib/go-luks2-test-state"

	// profileRel is the seccomp profile, relative to the module root.
	profileRel = "test/integration/seccomp.json"
)

// procDevicesPath is where the device-mapper major is read from. It is a
// variable only so the exit-status test can link a launcher against a fixture
// (-ldflags -X) and observe the exec on any host; nothing at run time can
// change it.
var procDevicesPath = "/proc/devices"

type config struct {
	stateDir string
	image    string
}

// system is everything run touches outside itself, so each refusal and the
// final exec can be driven by a test without docker, device-mapper or a
// particular working directory. The exit-status test (exit_test.go) covers the
// real one end to end.
type system struct {
	readFile func(path string) ([]byte, error)
	getwd    func() (string, error)
	getenv   func(key string) string
	lookPath func(file string) (string, error)
	// exec replaces the process; it returns only on failure.
	exec    func(argv0 string, argv, envv []string) error
	environ func() []string
	// lstat inspects the state directory; nil leaves it as configured.
	lstat func(path string) (os.FileInfo, error)
}

// hostSystem is the real one.
func hostSystem() system {
	return system{
		readFile: os.ReadFile,
		getwd:    os.Getwd,
		getenv:   os.Getenv,
		lookPath: exec.LookPath,
		exec:     syscall.Exec,
		environ:  os.Environ,
		lstat:    os.Lstat,
	}
}

func main() {
	if err := run(os.Args[1:], hostSystem()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, sys system) error {
	flags, command, err := splitArgs(args)
	if err != nil {
		return err
	}
	devices, err := sys.readFile(procDevicesPath)
	if err != nil {
		return &NoDeviceMapperError{}
	}
	major, err := dmMajor(devices)
	if err != nil {
		return err
	}
	wd, err := sys.getwd()
	if err != nil {
		return &ProfileError{Start: ".", Err: err}
	}
	profile, err := seccompProfile(wd)
	if err != nil {
		return err
	}
	cfg := configFromEnv(sys.getenv)
	if sys.lstat != nil {
		cfg.stateDir = ledgerDir(cfg.stateDir, sys.lstat)
	}

	docker, err := sys.lookPath("docker")
	if err != nil {
		return &DockerError{Err: err}
	}
	argv := dockerArgv(flags, privileges(profile, major, cfg.stateDir), cfg.image, command)
	// argv is this command's fixed privilege set plus the caller's own docker
	// flags and container command. Running exactly what the caller asked for
	// is the purpose of the command, so the taint gosec reports is the design.
	if err := sys.exec(docker, argv, sys.environ()); err != nil { // #nosec G204 G702 -- caller-supplied docker argv is the command's purpose
		return &DockerError{Err: err}
	}
	return nil
}

// configFromEnv reads TEST_STATE_DIR and IMAGE, with the defaults the Makefile
// and CI rely on.
func configFromEnv(getenv func(string) string) config {
	cfg := config{stateDir: getenv("TEST_STATE_DIR"), image: getenv("IMAGE")}
	if cfg.stateDir == "" {
		cfg.stateDir = defaultStateDir
	}
	if cfg.image == "" {
		cfg.image = defaultImage
	}
	return cfg
}

// rootLedgerSubdir is where the ledger goes when the configured state directory
// belongs to an ordinary user.
const rootLedgerSubdir = "root-ledger"

// ledgerDir returns the ledger directory to bind-mount: a subdirectory Docker creates as root, so the harness's ownership check passes.
func ledgerDir(dir string, lstat func(string) (os.FileInfo, error)) string {
	fi, err := lstat(dir)
	if err != nil || !fi.IsDir() {
		return dir // absent: Docker creates it as root; anything else is the harness's to refuse
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return dir
	}
	return filepath.Join(dir, rootLedgerSubdir)
}

// splitArgs separates docker's flags from the container's command at the first
// `--`, which is mandatory.
func splitArgs(args []string) (flags, command []string, err error) {
	for i, arg := range args {
		if arg == "--" {
			return args[:i], args[i+1:], nil
		}
	}
	return nil, nil, &UsageError{Problem: "no `--` separating docker flags from the container command"}
}

// dmMajor reads the dynamically allocated device-mapper block major from /proc/devices.
func dmMajor(procDevices []byte) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(procDevices))
	for scanner.Scan() {
		fields := bytes.Fields(scanner.Bytes())
		if len(fields) == 2 && string(fields[1]) == "device-mapper" {
			return string(fields[0]), nil
		}
	}
	return "", &NoDeviceMapperError{}
}

// seccompProfile finds the profile by walking up from start to the module root.
// The script found it beside itself; a Go command is compiled elsewhere, so it
// finds it from the checkout it is run in instead, and refuses if it cannot.
func seccompProfile(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", &ProfileError{Start: start, Err: err}
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			profile := filepath.Join(dir, filepath.FromSlash(profileRel))
			if _, err := os.Stat(profile); err != nil {
				return "", &ProfileError{Start: start, Err: err}
			}
			return profile, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", &ProfileError{Start: start, Err: errors.New("no go.mod above it")}
		}
		dir = parent
	}
}

// dockerArgv assembles `docker run` with the caller's flags, then the privilege
// set, then the image and the container command.
func dockerArgv(flags, privs []string, image string, command []string) []string {
	argv := make([]string, 0, 2+len(flags)+len(privs)+1+len(command))
	argv = append(argv, "docker", "run")
	argv = append(argv, flags...)
	argv = append(argv, privs...)
	argv = append(argv, image)
	return append(argv, command...)
}

// privileges is the container's whole privilege set.
func privileges(seccompProfile, dmMajor, stateDir string) []string {
	return []string{
		// CAP_SYS_ADMIN, for the device-mapper ioctls only.
		"--cap-add", "SYS_ADMIN",

		// CAP_MKNOD, to create the loop and dm nodes; restored after --cap-drop ALL.
		"--cap-add", "MKNOD",

		// CAP_SETUID and CAP_SETGID, to start a non-root child for the lock-permission tests.
		"--cap-add", "SETUID",
		"--cap-add", "SETGID",

		// Drop every other capability.
		"--cap-drop", "ALL",

		// Docker's default seccomp profile plus add_key, keyctl and request_key, for kernel keyring tests.
		"--security-opt", "seccomp=" + seccompProfile,

		// AppArmor off, because docker-default denies mount(2).
		"--security-opt", "apparmor=unconfined",

		// Only /dev/mapper/control and /dev/loop-control from the host's /dev.
		"--device", "/dev/mapper/control",
		"--device", "/dev/loop-control",

		// Allow the loop (7) and dm block majors; this is not isolation, since loop and dm are not namespaced.
		"--device-cgroup-rule", "b 7:* rwm",
		"--device-cgroup-rule", "b " + dmMajor + ":* rwm",

		// The run ledgers, on the host; see test/internal/harness.
		"-v", stateDir + ":" + containerStateDir,
	}
}
