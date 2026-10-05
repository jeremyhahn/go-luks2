// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command docker-run is the one place the integration container's privilege set
// is written down. It replaces test/integration/docker-run.sh, because the
// public release ships no shell scripts (owner ruling on #211); the privilege
// set is the script's, flag for flag, and TestPrivileges_IsExactlyTheMeasuredSet
// pins it.
//
// It used to be `docker run --privileged`, in five places -- four Makefile
// targets and the CI workflow -- which is how a security-critical invocation
// drifts. --privileged is not a privilege: it is the absence of every
// restriction Docker has. All capabilities, seccomp off, AppArmor off, and the
// whole host /dev bind-mounted in, which on the machine this was measured on
// meant the container could open the root NVMe, an unrelated RAID array and
// every dm mapping on the box. This library holds volume keys for a trusted
// computing platform (owner direction, 2026-08-31), and a test rig is not where
// that gets handed away for convenience.
//
// Every flag was MEASURED, not assumed. docs/TESTING.md carries the table of
// what fails when each one is removed; the reasons are repeated at each flag in
// privileges because that is where someone deletes one.
//
// Usage, from the repository root (the binary itself finds the seccomp profile
// from anywhere inside the checkout, but these paths are root-relative):
// Run the BUILT binary, never `go run`: `go run` is a parent process that
// reports any non-zero child exit as 1, so docker's own 125, 126 and 127 would
// not reach the caller.
//
//	make docker-run-bin
//	build/docker-run [docker flags ...] -- [command ...]
//
// Flags before `--` go to `docker run`; everything after it is the command for
// the container, and an empty command runs the image's default (the whole suite
// with coverage). The `--` is mandatory so neither list can swallow the other.
//
//	build/docker-run --rm -- go test -tags=integration ./...
//	build/docker-run --name go-luks2-test-runner --
//
// Environment:
//
//	TEST_STATE_DIR  host directory holding the run ledgers, bind-mounted in.
//	                Read test/harness before changing it: it is part of the
//	                trust boundary, not a cache.
//	IMAGE           image to run.
//
// The process REPLACES itself with docker (execve), as the script's `exec` did:
// docker's exit status, its signal handling and an interactive -it terminal are
// then docker's own, with nothing in between to lose them.
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
	// ledgers. See test/harness and test/integration/Dockerfile.
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

// ledgerDir returns the directory to bind-mount as the ledger.
//
// The reaper runs as root and acts on what the ledger names, so the harness
// refuses a ledger directory owned by anyone but root (test/harness
// validateStateDir) -- and a state directory an unprivileged user created, by
// running a tool as themselves first, made every later run refuse. Accepting
// that user's ownership would hand the root reaper a list of devices written by
// a non-root account, so instead the ledger moves one level down: a
// subdirectory that does not exist is created by Docker, as root, when it is
// bind-mounted, and the harness checks it exactly as before. A subdirectory
// the user made themselves is still owned by them and still refused.
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

// dmMajor reads the device-mapper block major from /proc/devices.
//
// The major is allocated dynamically at module load -- 252 on the machine this
// was written on, 253 on plenty of others. It is read rather than hard-coded: a
// wrong major does not fail loudly, it produces a container that creates a
// mapping and then cannot open it.
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
		// CAP_SYS_ADMIN -- for device-mapper, and for nothing else here.
		// MEASURED: with everything else below in place but the default
		// capability set, loop attach and luksFormat both succeed and
		// luksOpen fails; DM_DEV_CREATE is the ioctl that needs it. There is
		// no narrower capability to ask for -- the kernel gates the entire
		// dm ioctl interface on CAP_SYS_ADMIN.
		"--cap-add", "SYS_ADMIN",

		// CAP_MKNOD -- to create nodes for what we allocate. /dev in an
		// unprivileged container is a bare tmpfs, so nothing creates
		// /dev/loopN or /dev/dm-N for us: the entrypoint makes the loop
		// nodes and pkg/luks2 mknods the dm nodes itself, which is the
		// fallback unlock.go has always carried for udev-less environments.
		// MEASURED: without it every mknod returns EPERM and nothing past
		// the first step runs.
		//
		// It is in Docker's DEFAULT set already. It is named here because
		// the --cap-drop ALL below takes it away, not because it is an
		// escalation.
		"--cap-add", "MKNOD",

		// Everything else goes. Docker's default set -- CHOWN,
		// DAC_OVERRIDE, FOWNER, NET_RAW, SETUID, SETGID and the rest --
		// buys a suite that runs as root against files it created nothing.
		// MEASURED: the full lifecycle (loop attach, luksFormat, luksOpen,
		// mkfs, mount, close, detach) completes with exactly these two
		// capabilities and no others.
		"--cap-drop", "ALL",

		// The three keyring syscalls, and only those, on top of Docker's
		// default seccomp profile. Kernel keyrings are not namespaced, so
		// the default profile denies add_key, keyctl and request_key
		// outright; pkg/luks2 stores volume keys as logon keys and the
		// suite exercises that against the real kernel. MEASURED: no
		// capability substitutes for this -- add_key fails under the
		// default profile even with CAP_SYS_ADMIN, and succeeds under this
		// profile with no capabilities added at all. The file is Docker's
		// own profile byte for byte with one block appended; its header
		// says where it came from and how to re-verify it.
		"--security-opt", "seccomp=" + seccompProfile,

		// AppArmor off -- and unlike the rest of this list, that is a loss,
		// not a tightening. The docker-default profile denies mount(2)
		// outright and the suite mounts the filesystems it makes inside the
		// unlocked mapping. MEASURED: with docker-default enforcing,
		// everything through mkfs.ext4 succeeds and mount fails with
		// "cannot mount read-only". The alternative -- shipping
		// docker-default plus a mount rule -- means loading a profile into
		// the HOST kernel with apparmor_parser before the suite can run,
		// and this repository does not mutate a CI runner to test itself.
		// Worth revisiting if the runners ever grow a managed profile.
		"--security-opt", "apparmor=unconfined",

		// Two control nodes, instead of the host's entire /dev.
		// /dev/mapper/control is the dm ioctl interface; /dev/loop-control
		// answers LOOP_CTL_GET_FREE. Both are character devices that hand
		// out block devices, and they are the only two entries from the
		// host that the container gets. The root NVMe, the SATA disks, the
		// md arrays and the TPM -- every one of which --privileged handed
		// over -- are not reachable from in here at all.
		"--device", "/dev/mapper/control",
		"--device", "/dev/loop-control",

		// The block majors the suite allocates from: 7 is LOOP_MAJOR, fixed
		// kernel ABI; the dm major was read from /proc/devices. A node is
		// useless without a cgroup rule permitting its major:minor --
		// MEASURED, the mknod still succeeds without the rule and the open
		// that follows returns EPERM, which is the confusing half of this
		// and the reason both rules are here rather than just the
		// capability. Both kernels allocate their minors dynamically, so
		// neither rule can be pinned to the minors a given run happens to
		// get, and Docker's rule syntax has no range form either.
		//
		// BE CLEAR ABOUT WHAT THIS DOES NOT DO. It permits opening any dm
		// mapping and any loop device on the host, including ones the suite
		// did not create, because device-mapper and loop are not namespaced
		// and nothing at the container boundary can make them so. It is a
		// large reduction from --privileged, which permitted every device
		// of every kind, and it is NOT isolation. What keeps this suite off
		// other people's devices is the harness: it records what it
		// creates, removes only what it recorded, and never sweeps.
		"--device-cgroup-rule", "b 7:* rwm",
		"--device-cgroup-rule", "b " + dmMajor + ":* rwm",

		// The run ledgers, on the HOST. A record kept inside the container
		// dies with the run it describes, which is the one run whose host
		// state needs removing. See test/harness and
		// test/integration/Dockerfile.
		"-v", stateDir + ":" + containerStateDir,
	}
}
