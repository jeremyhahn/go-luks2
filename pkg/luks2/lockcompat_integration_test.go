// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"
	"golang.org/x/sys/unix"
)

// cryptsetup's metadata lock, against cryptsetup itself, in every state its
// lock directory can be in (docs/cryptsetup-interop/engineering.md, "Metadata lock").
//
// Each scenario runs in a CHILD of this test binary, in a mount namespace of
// its own with a private /run: the lock directory's state is the variable
// under test, and the real /run/cryptsetup belongs to every other test in the
// run. The child sets the state up, then runs each step -- a cryptsetup
// command, or a go-luks2 operation in a grandchild -- as root or as uid 1000
// in the disk group, and reports what each did. The non-root steps run as a
// real setuid/setgid process: root is what the permission checks under test
// do not apply to.
//
// The parent asserts each step against what cryptsetup was MEASURED to do in
// the same state (cryptsetup 2.7.5), and, where go-luks2 refuses, that the
// header is byte-for-byte unchanged and the volume still opens in both tools.

const (
	lockCompatRoleEnv = "GO_LUKS2_LOCKCOMPAT_ROLE"
	lockCompatSpecEnv = "GO_LUKS2_LOCKCOMPAT_SPEC"

	lockCompatRoleScenario = "scenario"
	lockCompatRoleOp       = "op"

	// lockCompatUID is the unprivileged caller: not root, in the disk group.
	lockCompatUID = 1000

	// lockCompatMount is where the scenario child puts what the unprivileged
	// steps need -- a copy of this binary, a device node in the disk group
	// and the key files -- on a tmpfs of its own namespace.
	lockCompatMount = "/mnt"

	lockCompatNewPassphrase = "lock-compat-new-passphrase"
	lockCompatToken         = `{"type":"x-lock-compat","keyslots":[]}`
)

// A child is recognized before TestMain, so it never registers a second suite
// with the harness.
func init() {
	switch os.Getenv(lockCompatRoleEnv) {
	case lockCompatRoleScenario:
		os.Exit(runLockCompatScenario(os.Getenv(lockCompatSpecEnv)))
	case lockCompatRoleOp:
		os.Exit(runLockCompatOp(os.Getenv(lockCompatSpecEnv)))
	}
}

// lockStep is one command a scenario runs.
type lockStep struct {
	// Tool is "cryptsetup" or "go-luks2".
	Tool string
	// Args is cryptsetup's arguments, with {dev}, {key}, {newkey} and
	// {token} standing for the scenario's files; for go-luks2, Args[0] names
	// the operation (see lockCompatOps).
	Args []string
	// AsUser runs the step as lockCompatUID in the disk group.
	AsUser bool
	// Blocks says the step is expected to wait on the held lock file: it is
	// killed once /proc/locks shows it waiting.
	Blocks bool
}

// lockStepResult is what a step did.
type lockStepResult struct {
	Exit    int
	Output  string
	Blocked bool
	Lib     lockOpResult
}

// lockOpResult is a go-luks2 operation's outcome, classified in the child --
// a typed error does not cross a process boundary.
type lockOpResult struct {
	Err         string
	Unavailable bool // ErrMetadataLockUnavailable
	Contended   bool // ErrLockContended
	Permission  bool // fs.ErrPermission
}

// lockScenarioSpec is what the parent hands the scenario child.
type lockScenarioSpec struct {
	Scenario   string
	Device     string
	Passphrase string
	Steps      []lockStep
}

// lockScenarioReport is what the scenario child hands back.
type lockScenarioReport struct {
	Steps []lockStepResult
	// SymlinkTargetEntries is what the symlink scenario's target directory
	// holds afterwards: a lock taken through the symlink leaves its file there.
	SymlinkTargetEntries int
	Error                string
}

// lockOpSpec is what the scenario child hands an operation grandchild.
type lockOpSpec struct {
	Op         string
	Device     string
	Passphrase string
}

// lockCompatLockWait bounds every lock an operation step waits for: a held
// lock is refused within this, not DefaultLockWait.
const lockCompatLockWait = 300 * time.Millisecond

// lockCompatOp is one go-luks2 operation on a Volume the step opened, with the
// scenario's passphrase.
type lockCompatOp func(ctx context.Context, v *Volume, pass *enclave.Memory) error

// lockCompatOps are the go-luks2 operations a step can run, each through the
// public Volume method a caller uses, so each takes the lock that caller's
// call takes: two reads under cryptsetup's lock held shared (Header, Unlock),
// and three writes under it held exclusively. AddKey unlocks first, as a
// caller must, so a state that refuses reads stops it there; KillSlot and
// ImportToken reach the exclusive lock directly.
var lockCompatOps = map[string]lockCompatOp{
	"ReadHeader": func(ctx context.Context, v *Volume, _ *enclave.Memory) error {
		_, err := v.Header(ctx)
		return err
	},
	"TestKey": func(ctx context.Context, v *Volume, pass *enclave.Memory) error {
		key, err := v.Unlock(ctx, pass)
		if err != nil {
			return err
		}
		key.Destroy()
		return nil
	},
	"AddKey": func(ctx context.Context, v *Volume, pass *enclave.Memory) error {
		key, err := v.Unlock(ctx, pass)
		if err != nil {
			return err
		}
		defer key.Destroy()
		newPass, err := enclave.NewMemoryCopy([]byte(lockCompatNewPassphrase))
		if err != nil {
			return err
		}
		defer func() { _ = newPass.Destroy() }()
		_, err = v.AddKeyslot(ctx, key, newPass, KeyslotParams{KDF: KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond}})
		return err
	},
	"KillSlot": func(ctx context.Context, v *Volume, _ *enclave.Memory) error {
		return v.RemoveKeyslot(ctx, 1)
	},
	"ImportToken": func(ctx context.Context, v *Volume, _ *enclave.Memory) error {
		var t Token
		if err := json.Unmarshal([]byte(lockCompatToken), &t); err != nil {
			return err
		}
		return v.SetToken(ctx, 5, t)
	},
}

// runLockCompatOp is the operation grandchild: one go-luks2 call, its outcome
// as JSON on stdout.
func runLockCompatOp(raw string) int {
	var spec lockOpSpec
	if err := json.Unmarshal([]byte(raw), &spec); err != nil {
		fmt.Printf(`{"Err":%q}`, err.Error())
		return 0
	}

	var res lockOpResult
	op, ok := lockCompatOps[spec.Op]
	if !ok {
		res.Err = "unknown operation " + spec.Op
	} else if err := runLockCompatVolumeOp(spec, op); err != nil {
		res = lockOpResult{Err: err.Error(),
			Unavailable: errors.Is(err, ErrMetadataLockUnavailable),
			Contended:   errors.Is(err, ErrLockContended),
			Permission:  errors.Is(err, fs.ErrPermission)}
	}
	out, _ := json.Marshal(res)
	_, _ = os.Stdout.Write(out)
	return 0
}

// runLockCompatVolumeOp opens the device as a caller does and runs op on it.
func runLockCompatVolumeOp(spec lockOpSpec, op lockCompatOp) error {
	// As the suite's TestMain used to: keyslot cost is not under test.
	sys := defaultVolumeSys()
	sys.calibratedCountFloor = func(string, keyslotCostPolicy) int { return minPBKDF2Iterations }

	ctx := context.Background()
	v, err := Open(ctx, spec.Device, withTestSys(sys), WithLockWait(lockCompatLockWait))
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()
	pass, err := enclave.NewMemoryCopy([]byte(spec.Passphrase))
	if err != nil {
		return err
	}
	defer func() { _ = pass.Destroy() }()
	return op(ctx, v, pass)
}

// runLockCompatScenario is the scenario child, root in a private mount
// namespace with the disk group as its group, so what it creates -- the
// device node, a group lock directory -- belongs to that group.
func runLockCompatScenario(raw string) int {
	report := lockScenarioReport{}
	defer func() {
		out, _ := json.Marshal(report)
		_, _ = os.Stdout.Write(out)
	}()
	var spec lockScenarioSpec
	if err := json.Unmarshal([]byte(raw), &spec); err != nil {
		report.Error = err.Error()
		return 0
	}
	steps, entries, err := lockCompatScenario(spec)
	report.Steps, report.SymlinkTargetEntries = steps, entries
	if err != nil {
		report.Error = err.Error()
	}
	return 0
}

func lockCompatScenario(spec lockScenarioSpec) ([]lockStepResult, int, error) {
	unix.Umask(0)
	disk, err := diskGID()
	if err != nil {
		return nil, 0, err
	}
	var st unix.Stat_t
	if err := unix.Stat(spec.Device, &st); err != nil {
		return nil, 0, err
	}
	rdev := uint64(st.Rdev) //nolint:unconvert // Rdev is not uint64 on every GOARCH

	// What the unprivileged steps need, on a tmpfs this namespace owns.
	if err := unix.Mount("tmpfs", lockCompatMount, "tmpfs", 0, "mode=0755"); err != nil {
		return nil, 0, fmt.Errorf("mount %s: %w", lockCompatMount, err)
	}
	self, err := os.Executable()
	if err != nil {
		return nil, 0, err
	}
	binary := filepath.Join(lockCompatMount, "luks2.test")
	if err := copyFile(self, binary, 0o755); err != nil {
		return nil, 0, err
	}
	node := filepath.Join(lockCompatMount, "dev")
	if err := unix.Mknod(node, unix.S_IFBLK|0o660, int(rdev)); err != nil { // #nosec G115 -- a device number
		return nil, 0, fmt.Errorf("mknod %s: %w", node, err)
	}
	files := map[string]string{
		"{key}":    spec.Passphrase,
		"{newkey}": lockCompatNewPassphrase,
		"{token}":  lockCompatToken,
	}
	for placeholder, content := range files {
		path := filepath.Join(lockCompatMount, strings.Trim(placeholder, "{}"))
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil { // #nosec G306 -- read by the unprivileged step
			return nil, 0, err
		}
		files[placeholder] = path
	}
	files["{dev}"] = node

	symlinkTarget, held, err := lockCompatRun(spec.Scenario, rdev)
	if err != nil {
		return nil, 0, err
	}
	var heldID string
	if held != nil {
		defer func() { _ = held.Close() }()
		var hst unix.Stat_t
		if err := unix.Fstat(int(held.Fd()), &hst); err != nil {
			return nil, 0, err
		}
		heldID = procLocksID(uint64(hst.Dev), hst.Ino) //nolint:unconvert // Dev is not uint64 on every GOARCH
	}

	user := &syscall.Credential{Uid: lockCompatUID, Gid: lockCompatUID, Groups: []uint32{disk}}
	var results []lockStepResult
	for _, step := range spec.Steps {
		var cred *syscall.Credential
		if step.AsUser {
			cred = user
		}
		var res lockStepResult
		if step.Tool == "go-luks2" {
			res, err = lockCompatLibStep(binary, node, spec.Passphrase, step.Args[0], cred)
		} else {
			args := make([]string, len(step.Args))
			for i, a := range step.Args {
				if v, ok := files[a]; ok {
					a = v
				}
				args[i] = a
			}
			res, err = lockCompatCryptsetupStep(args, cred, step.Blocks, heldID)
		}
		if err != nil {
			return results, 0, err
		}
		results = append(results, res)
	}

	entries := 0
	if symlinkTarget != "" {
		list, err := os.ReadDir(symlinkTarget)
		if err != nil {
			return results, 0, err
		}
		entries = len(list)
	}
	return results, entries, nil
}

// lockCompatRun puts /run, and cryptsetup's lock directory in it, into the
// scenario's state. It returns the symlink scenario's target, and the lock
// file held for the held scenarios.
func lockCompatRun(scenario string, rdev uint64) (symlinkTarget string, held *os.File, err error) {
	opts := "mode=0755"
	if scenario == "readonly" {
		opts += ",ro"
	}
	if err := unix.Mount("tmpfs", "/run", "tmpfs", 0, opts); err != nil {
		return "", nil, fmt.Errorf("mount /run: %w", err)
	}
	dir := filepath.Join("/run", "cryptsetup")
	switch scenario {
	case "missing", "readonly":
	case "symlink":
		symlinkTarget = filepath.Join("/run", "elsewhere")
		if err := os.Mkdir(symlinkTarget, 0o700); err != nil {
			return "", nil, err
		}
		if err := os.Symlink(symlinkTarget, dir); err != nil {
			return "", nil, err
		}
	case "rootonly", "held-exclusive", "held-shared":
		if err := os.Mkdir(dir, 0o700); err != nil {
			return "", nil, err
		}
	case "group":
		// Created by this process, whose group is disk.
		if err := os.Mkdir(dir, 0o770); err != nil {
			return "", nil, err
		}
	default:
		return "", nil, fmt.Errorf("unknown scenario %q", scenario)
	}
	if !strings.HasPrefix(scenario, "held-") {
		return symlinkTarget, nil, nil
	}
	name := "L_" + strconv.FormatUint(uint64(unix.Major(rdev)), 10) + ":" + strconv.FormatUint(uint64(unix.Minor(rdev)), 10)
	held, err = os.OpenFile(filepath.Join(dir, name), os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- cryptsetup's lock file in this namespace's /run
	if err != nil {
		return "", nil, err
	}
	how := unix.LOCK_EX
	if scenario == "held-shared" {
		how = unix.LOCK_SH
	}
	if err := unix.Flock(int(held.Fd()), how); err != nil {
		_ = held.Close()
		return "", nil, err
	}
	return "", held, nil
}

// lockCompatLibStep runs one go-luks2 operation in a grandchild.
func lockCompatLibStep(binary, device, passphrase, op string, cred *syscall.Credential) (lockStepResult, error) {
	spec, err := json.Marshal(lockOpSpec{Op: op, Device: device, Passphrase: passphrase})
	if err != nil {
		return lockStepResult{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary) // #nosec G204 -- this test binary, copied
	cmd.Env = append(lockCompatEnv(), lockCompatRoleEnv+"="+lockCompatRoleOp, lockCompatSpecEnv+"="+string(spec))
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return lockStepResult{}, fmt.Errorf("go-luks2 %s: %w\n%s", op, err, stderr.String())
	}
	var res lockStepResult
	if err := json.Unmarshal(out, &res.Lib); err != nil {
		return lockStepResult{}, fmt.Errorf("go-luks2 %s printed %q: %w\n%s", op, out, err, stderr.String())
	}
	return res, nil
}

// lockCompatCryptsetupStep runs cryptsetup. A step expected to block is
// killed once /proc/locks shows it waiting on the held file, and reported as
// Blocked; if it finishes instead, its exit status is reported and the
// parent's expectation fails on it.
func lockCompatCryptsetupStep(args []string, cred *syscall.Credential, blocks bool, heldID string) (lockStepResult, error) {
	cmd := exec.Command("cryptsetup", args...) // #nosec G204 -- test constants and files this scenario made
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return lockStepResult{}, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var res lockStepResult
	if blocks {
		// Polled, re-checking the real condition each pass; the bound only
		// ends a step that neither waits nor finishes.
		deadline := time.Now().Add(time.Minute)
		for !res.Blocked && time.Now().Before(deadline) {
			select {
			case err := <-done:
				res.Exit, res.Output = exitCode(err), out.String()
				return res, nil
			default:
			}
			if waiting, err := flockWaiterOnFile(heldID); err != nil {
				_ = cmd.Process.Kill()
				<-done
				return res, err
			} else if waiting {
				res.Blocked = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		_ = cmd.Process.Kill()
	}
	res.Exit, res.Output = exitCode(<-done), strings.TrimSpace(out.String())
	return res, nil
}

// procLocksID is how /proc/locks names a file: "MAJ:MIN:INODE", the device
// numbers in two-digit hex. The device is part of it because every scenario
// has a tmpfs /run of its own, and their inode numbers coincide.
func procLocksID(dev, ino uint64) string {
	return fmt.Sprintf("%02x:%02x:%d", unix.Major(dev), unix.Minor(dev), ino)
}

// flockWaiterOnFile reports whether /proc/locks shows a process BLOCKED on a
// flock of the file procLocksID names -- the "->" lines.
func flockWaiterOnFile(id string) (bool, error) {
	f, err := os.Open("/proc/locks")
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) > 6 && fields[1] == "->" && fields[2] == "FLOCK" && fields[6] == id {
			return true, nil
		}
	}
	return false, s.Err()
}

// exitCode is a finished command's exit status: -1 when it was killed.
func exitCode(err error) int {
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exitErr):
		return exitErr.ExitCode()
	default:
		return -2
	}
}

// lockCompatEnv is this environment without the roles, so a grandchild is
// given exactly one.
func lockCompatEnv() []string {
	return slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "GO_LUKS2_LOCKCOMPAT_")
	})
}

// diskGID is the disk group's id.
func diskGID() (uint32, error) {
	g, err := user.LookupGroup("disk")
	if err != nil {
		return 0, err
	}
	id, err := strconv.ParseUint(g.Gid, 10, 32)
	return uint32(id), err
}

func copyFile(from, to string, mode os.FileMode) error {
	in, err := os.Open(from) // #nosec G304 -- this test binary
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G304 -- under this namespace's tmpfs
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// The expectations a step is held to.
type lockWant int

const (
	wantOK          lockWant = iota // exit 0, or no error
	wantReadLockErr                 // cryptsetup: exit 5, "Failed to acquire read lock"
	wantSilent5                     // cryptsetup isLuks: exit 5, nothing printed
	wantAborted                     // cryptsetup: exit 5, "Locking aborted"
	wantBlocked                     // cryptsetup: waits on the held file, with no timeout
	wantUnavailable                 // go-luks2: ErrMetadataLockUnavailable
	wantDenied                      // go-luks2: ErrMetadataLockUnavailable, fs.ErrPermission
	wantContended                   // go-luks2: ErrLockContended within its bound
)

type lockCase struct {
	step lockStep
	want lockWant
}

func cs(want lockWant, args ...string) lockCase {
	return lockCase{step: lockStep{Tool: "cryptsetup", Args: args, Blocks: want == wantBlocked}, want: want}
}

func lib(want lockWant, op string) lockCase {
	return lockCase{step: lockStep{Tool: "go-luks2", Args: []string{op}}, want: want}
}

// asUser runs the cases as lockCompatUID in the disk group.
func asUser(cases ...lockCase) []lockCase {
	for i := range cases {
		cases[i].step.AsUser = true
	}
	return cases
}

var (
	csCheap      = []string{"--batch-mode", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000"}
	csLockAddKey = append([]string{"luksAddKey", "--key-file", "{key}"}, append(csCheap, "{dev}", "{newkey}")...)
	csKillSlot   = []string{"luksKillSlot", "--batch-mode", "--key-file", "{key}", "{dev}", "1"}
	csToken      = []string{"token", "import", "--token-id", "3", "--json-file", "{token}", "{dev}"}
	csTestPass   = []string{"open", "--test-passphrase", "--key-file", "{key}", "{dev}"}
)

// lockCompatScenarios is the matrix: each lock directory state, what
// cryptsetup does in it and what go-luks2 does. writes says whether any step
// is expected to change the header.
var lockCompatScenarios = []struct {
	name   string
	writes bool
	cases  []lockCase
}{
	// (a) Missing and creatable: both create it 0700 and proceed.
	{"missing", true, []lockCase{
		cs(wantOK, "luksDump", "{dev}"),
		lib(wantOK, "ImportToken"),
		cs(wantOK, csToken...),
		lib(wantOK, "AddKey"),
	}},
	// (b) Missing and not creatable: cryptsetup refuses every command,
	// reads included, and so does go-luks2, whose reads take the lock shared.
	{"readonly", false, []lockCase{
		cs(wantSilent5, "isLuks", "{dev}"),
		cs(wantReadLockErr, "luksDump", "{dev}"),
		cs(wantReadLockErr, csTestPass...),
		cs(wantReadLockErr, csLockAddKey...),
		cs(wantReadLockErr, csKillSlot...),
		cs(wantReadLockErr, csToken...),
		lib(wantUnavailable, "ReadHeader"),
		lib(wantUnavailable, "TestKey"),
		lib(wantUnavailable, "AddKey"),
		lib(wantUnavailable, "KillSlot"),
		lib(wantUnavailable, "ImportToken"),
	}},
	// A symlink where the directory should be: cryptsetup aborts, and so
	// does go-luks2 rather than locking where cryptsetup never looks.
	{"symlink", false, []lockCase{
		cs(wantAborted, "luksDump", "{dev}"),
		cs(wantAborted, csLockAddKey...),
		lib(wantUnavailable, "ReadHeader"),
		lib(wantUnavailable, "AddKey"),
		lib(wantUnavailable, "ImportToken"),
	}},
	// (c) Present but root's alone, the caller uid 1000 in the disk group:
	// both refuse everything, reads included.
	{"rootonly", false, asUser(
		cs(wantSilent5, "isLuks", "{dev}"),
		cs(wantReadLockErr, "luksDump", "{dev}"),
		cs(wantReadLockErr, csTestPass...),
		cs(wantReadLockErr, csLockAddKey...),
		cs(wantReadLockErr, csToken...),
		lib(wantDenied, "ReadHeader"),
		lib(wantDenied, "TestKey"),
		lib(wantDenied, "AddKey"),
		lib(wantDenied, "KillSlot"),
		lib(wantDenied, "ImportToken"),
	)},
	// The supported route for that caller: the directory granted to the
	// disk group. Both tools then work unprivileged.
	{"group", true, asUser(
		cs(wantOK, "luksDump", "{dev}"),
		cs(wantOK, csToken...),
		lib(wantOK, "ImportToken"),
		lib(wantOK, "AddKey"),
	)},
	// (d) The lock file held exclusively by someone else: cryptsetup waits
	// for it with no timeout, reads included. go-luks2 waits for it too, reads
	// included, and refuses once its bound is spent.
	{"held-exclusive", false, []lockCase{
		cs(wantBlocked, "luksDump", "{dev}"),
		cs(wantBlocked, csLockAddKey...),
		lib(wantContended, "ReadHeader"),
		lib(wantContended, "TestKey"),
		lib(wantContended, "AddKey"),
		lib(wantContended, "ImportToken"),
	}},
	// Held shared, as a reader holds it: reads go ahead, writes wait.
	{"held-shared", false, []lockCase{
		cs(wantOK, "luksDump", "{dev}"),
		cs(wantOK, csTestPass...),
		cs(wantBlocked, csLockAddKey...),
		lib(wantOK, "ReadHeader"),
		lib(wantOK, "TestKey"),
		lib(wantContended, "AddKey"),
	}},
}

// TestCompatMetadataLockDirectoryStates is Part 1: for each state of
// cryptsetup's lock directory, cryptsetup's measured behaviour beside
// go-luks2's, on one volume. go-luks2's steps go through Open and the public
// Volume methods (lockCompatOps), so what is measured is the lock a caller's
// call takes.
func TestCompatMetadataLockDirectoryStates(t *testing.T) {
	requireCryptsetupDeclared(t)
	disk, err := diskGID()
	if err != nil {
		t.Fatalf("the disk group: %v", err)
	}

	for _, sc := range lockCompatScenarios {
		t.Run(sc.name, func(t *testing.T) {
			defer parallel(t)()

			loop, _ := laneDLoop(t)
			if _, err := addKeyForTest(loop, []byte(laneDPassphrase), []byte("lock-compat-slot-one"), &addKeyOptionsForTest{KDFType: kdfTypePBKDF2, PBKDFIterTime: 1}); err != nil {
				t.Fatalf("AddKey: %v", err)
			}
			before := deviceDigest(t, loop, 16<<20)

			steps := make([]lockStep, len(sc.cases))
			for i, c := range sc.cases {
				steps[i] = c.step
			}
			report := runLockScenario(t, disk, lockScenarioSpec{Scenario: sc.name, Device: loop, Passphrase: laneDPassphrase, Steps: steps})

			for i, c := range sc.cases {
				assertLockStep(t, c, report.Steps[i])
			}
			if sc.name == "symlink" && report.SymlinkTargetEntries != 0 {
				t.Errorf("%d file(s) were created through the symlinked lock directory", report.SymlinkTargetEntries)
			}

			changed := deviceDigest(t, loop, 16<<20) != before
			if changed != sc.writes {
				t.Errorf("the header changed = %v, want %v: a refusal must write nothing", changed, sc.writes)
			}

			// Whatever happened, the volume is intact for both tools.
			mustCryptsetupPassphrase(t, laneDPassphrase, "open", "--test-passphrase", loop)
			if err := testKeyForTest(loop, []byte(laneDPassphrase)); err != nil {
				t.Errorf("TestKey afterwards: %v", err)
			}
			if sc.writes {
				mustCryptsetupPassphrase(t, lockCompatNewPassphrase, "open", "--test-passphrase", loop)
				mustCryptsetupPassphrase(t, "", "token", "export", "--token-id", "5", loop)
			}
		})
	}
}

// runLockScenario starts the scenario child: root, the disk group as its
// group, in a mount namespace of its own.
func runLockScenario(t *testing.T, disk uint32, spec lockScenarioSpec) lockScenarioReport {
	t.Helper()
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0]) // #nosec G204 -- this test binary, re-executed
	cmd.Env = append(lockCompatEnv(), lockCompatRoleEnv+"="+lockCompatRoleScenario, lockCompatSpecEnv+"="+string(raw))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Unshareflags: syscall.CLONE_NEWNS,
		Credential:   &syscall.Credential{Uid: 0, Gid: disk},
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("the %s scenario child: %v\n%s", spec.Scenario, err, stderr.String())
	}
	var report lockScenarioReport
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("the %s scenario child printed %q: %v\n%s", spec.Scenario, out, err, stderr.String())
	}
	if report.Error != "" || len(report.Steps) != len(spec.Steps) {
		t.Fatalf("the %s scenario did not run: %s (%d of %d steps)\n%s", spec.Scenario, report.Error, len(report.Steps), len(spec.Steps), stderr.String())
	}
	return report
}

func assertLockStep(t *testing.T, c lockCase, got lockStepResult) {
	t.Helper()
	who := c.step.Tool + " " + strings.Join(c.step.Args, " ")
	if c.step.AsUser {
		who += " (uid " + strconv.Itoa(lockCompatUID) + ", group disk)"
	}
	if c.step.Tool == "go-luks2" {
		lr := got.Lib
		ok := false
		switch c.want {
		case wantOK:
			ok = lr.Err == ""
		case wantUnavailable:
			ok = lr.Unavailable
		case wantDenied:
			ok = lr.Unavailable && lr.Permission
		case wantContended:
			ok = lr.Contended
		}
		if !ok {
			t.Errorf("%s: got %+v, want %s", who, lr, lockWantName(c.want))
		}
		return
	}
	ok := false
	switch c.want {
	case wantOK:
		ok = got.Exit == 0
	case wantReadLockErr:
		ok = got.Exit == 5 && strings.Contains(got.Output, "Failed to acquire read lock")
	case wantSilent5:
		ok = got.Exit == 5 && got.Output == ""
	case wantAborted:
		ok = got.Exit == 5 && strings.Contains(got.Output, "Locking aborted")
	case wantBlocked:
		ok = got.Blocked
	}
	if !ok {
		t.Errorf("%s: exit %d, blocked %v, output %q; cryptsetup was measured to give %s", who, got.Exit, got.Blocked, got.Output, lockWantName(c.want))
	}
}

func lockWantName(w lockWant) string {
	return map[lockWant]string{
		wantOK: "success", wantReadLockErr: `exit 5, "Failed to acquire read lock"`, wantSilent5: "exit 5, silently", wantAborted: `exit 5, "Locking aborted"`,
		wantBlocked: "a wait on the held lock file", wantUnavailable: "ErrMetadataLockUnavailable",
		wantDenied: "ErrMetadataLockUnavailable wrapping a permission error", wantContended: "ErrLockContended",
	}[w]
}

// mustCryptsetupPassphrase runs cryptsetup with passphrase on stdin and fails
// the test on a non-zero exit.
func mustCryptsetupPassphrase(t *testing.T, passphrase string, args ...string) string {
	t.Helper()
	cmd := exec.Command("cryptsetup", args...) // #nosec G204 -- test constants and devices this test made
	cmd.Stdin = strings.NewReader(passphrase)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cryptsetup %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}
