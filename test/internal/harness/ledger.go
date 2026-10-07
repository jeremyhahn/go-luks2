// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package harness records the host state the integration suite is about to
// create, so a later run can remove exactly that state and nothing else.
//
// # The problem this exists for
//
// Neither device-mapper nor loop devices are namespaced, so every dm mapping
// and every loop device the integration suite creates is HOST state. That is a
// property of the kernel, not of how the container is confined: dropping
// --privileged for a scoped capability and device set (#80) changed what the
// container can reach and changed nothing here. When a run dies without cleaning up --
// a failing test, a timeout, a container torn down mid-run -- that state
// outlives it, and the #85 guard then correctly refuses every later run on that
// host because it cannot attribute what it finds. One failed run poisons a
// runner until a human clears it by hand (#96).
//
// # Why a write-ahead ledger, and not the obvious alternatives
//
// t.Cleanup, defer and signal handlers all run INSIDE the process. SIGKILL
// cannot be caught, and the container teardown that produced the measured
// debris used exactly that path, so every in-process mechanism loses. The
// record therefore has to outlive the process, which means it has to be on
// disk, on a path that outlives the container, written BEFORE the resource
// exists.
//
// The ordering is the whole design. A crash between "mapping created" and
// "ledger appended" leaks precisely the thing nothing knows about, so Record
// fsyncs before it returns and its failure is fatal to the caller rather than
// advisory -- see ErrLedgerUnavailable.
//
// # Why not a list of names
//
// Two rejected approaches, both of which read as reasonable:
//
//   - A hardcoded list of the names the suite uses. It is already wrong: the
//     suite creates 28 distinct volume-name literals today, and the next test
//     someone adds is the one that leaks. A cleanup keyed to an enumeration
//     reproduces the bug on the first name outside it.
//   - Matching the dm UUID SHAPE, "CRYPT-LUKS2-<hex>-<name>". That identifies a
//     LUKS2 mapping, not OUR mapping: a developer's live encrypted root has the
//     same shape, so a guard matching it would classify and remove a system
//     volume. It reads as rigorous and is the name-prefix mistake one layer
//     subtler.
//
// What this package does instead is record the EXACT identity before creating
// it -- for a mapping, its name and the dm UUID the creating call is about to
// pass -- and remove only where the live resource still carries that exact
// recorded identity. Ownership is established by record and confirmed by
// observation. A name that was reused between the record and the reap does not
// match, and is left alone.
package harness

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// StateDirEnv names the environment variable holding the directory the ledgers
// live in. It must be on a filesystem that OUTLIVES THE CONTAINER -- a bind
// mount or a docker volume -- or the record dies with the run that wrote it and
// this package guarantees nothing.
const StateDirEnv = "LUKS2_TEST_STATE_DIR"

// StateDir returns the directory the ledgers live in.
//
// It comes from LUKS2_TEST_STATE_DIR, and the default is deliberately a fixed
// path rather than a temp directory: a record that lives inside the run it
// describes is a record that dies with it, which is the one thing this package
// may not do. In the container the CI invocation bind-mounts a host path here,
// so the ledger outlives the container; on a developer host the default already
// outlives the process.
func StateDir() string {
	if dir := os.Getenv(StateDirEnv); dir != "" {
		return dir
	}
	return DefaultStateDir
}

// DefaultStateDir is where ledgers live when LUKS2_TEST_STATE_DIR is unset.
const DefaultStateDir = "/var/tmp/go-luks2-test-state"

// Kind classifies a recorded resource. The reaper removes each kind
// differently, so it is carried in the record rather than inferred.
type Kind string

const (
	// KindMapping is a device-mapper target. Value is the dm name; Identity is
	// the dm UUID the creating call passes, which is what makes removal safe
	// against a name reused in between.
	KindMapping Kind = "dm"

	// KindLoopRoot is a DIRECTORY this run created and owns; any loop device
	// whose backing file lives under it was attached by this run.
	//
	// It exists because the suite allocates its backing files through
	// t.TempDir() and os.CreateTemp(""), both of which land under TMPDIR. The
	// run sets TMPDIR to a directory it creates with os.MkdirTemp and records
	// that directory here, write-ahead, before a single test runs -- so the
	// record precedes every loop device by construction, which is the ordering
	// no per-device record can achieve (see KindLoopBacking).
	//
	// This is a prefix match, and it is safe for one reason only: the value is
	// a uniquely-named directory THIS run created, not a path pattern anyone
	// else could occupy. It is emphatically not "anything under /tmp" -- that
	// would be the global sweep this package exists to avoid, wearing a path
	// instead of a name.
	KindLoopRoot Kind = "loop-root"

	// KindLoopBacking is a loop device, recorded by the path of the file it
	// will back.
	//
	// It cannot be recorded by device node, because the kernel chooses the
	// minor: LOOP_CTL_GET_FREE allocates and returns it, so the name does not
	// exist until after the resource does -- which is exactly the ordering this
	// package cannot accept. The backing path IS known beforehand, is unique
	// per test (it lives under t.TempDir()), and the kernel keeps reporting it
	// in /sys/block/loop<N>/loop/backing_file after the container that created
	// it is gone, marked "(deleted)". So the reaper resolves path to device by
	// observation, against a path it recorded first.
	KindLoopBacking Kind = "loop-backing"
)

// Entry is one recorded resource.
type Entry struct {
	Kind  Kind
	Value string

	// Identity is the additional fact that distinguishes THIS resource from
	// another that later takes the same Value. Empty where the kind has no such
	// fact; a reaper must then rely on Value alone and is correspondingly
	// weaker, which is why KindMapping always carries one.
	Identity string
}

// Ledger is an append-only, fsync-on-write record of host state a run is about
// to create. It is safe for concurrent use: the suite runs tests in one process
// and nothing stops two of them creating a mapping at once.
//
// A ledger holds an exclusive advisory LOCK on its own file for the whole life
// of the run, and that lock is what makes a later reap safe. See TryLock.
type Ledger struct {
	mu    sync.Mutex
	f     *os.File
	path  string
	name  string
	runID string
	// dir is the validated state directory's handle. The ledger is created,
	// re-read and deleted through it, never by path (#247).
	dir *trustedDir
}

// OpenLedger creates the ledger for one run.
//
// runID must be unique per run; the reaper processes every ledger in the
// directory EXCEPT the one belonging to the run asking, so a collision would
// have a live run reaping its own state out from under itself.
func OpenLedger(dir, runID string) (*Ledger, error) {
	// The directory is part of the trust boundary; see statedir.go. Checked on
	// the WRITER path as well as the reaper's, because a check on one path only
	// is one an attacker routes around by racing the other.
	if runID == "" || strings.ContainsAny(runID, `/\`) || runID == "." || runID == ".." {
		return nil, &StateDirError{Dir: dir, Problem: "run id " + strconv.Quote(runID) + " cannot name a ledger"}
	}
	sd, err := openTrustedStateDir(dir)
	if err != nil {
		return nil, err
	}

	name := runID + ledgerSuffix
	path := filepath.Join(dir, name)
	f, err := sd.root.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		_ = sd.Close()
		return nil, &LockFileError{Action: "opening", Path: path, Err: err}
	}

	// Hold an exclusive advisory lock for the life of the run. This is what
	// tells a later reaper that this run is ALIVE, and it is the only signal
	// that is trustworthy: the kernel releases the lock when the holder dies,
	// including on SIGKILL, and it does not release it while the holder runs.
	//
	// It works across containers because flock is a property of the INODE, and
	// the state directory is a bind mount -- every container sees the same one.
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		_ = sd.Close()
		return nil, &LockFileError{Action: "locking", Path: path, Err: err}
	}

	return &Ledger{f: f, path: path, name: name, runID: runID, dir: sd}, nil
}

// TryLock reports whether the run that owns the ledger at path is GONE.
//
// It is the answer to the one question a reaper must get right, and the reason
// it is asked this way rather than any other: on a shared runner several jobs
// run at once, and a live job's loop device is indistinguishable from an orphan
// by every other signal. Measured 2026-09-01 on a shared CI runner -- a live job's
// device showed empty `holders` and empty `fuser`, exactly like the orphans
// swept minutes earlier. The ONLY thing separating them was that a job owned
// it.
//
// So ownership is not inferred from the device at all. The run holds a lock for
// its lifetime; a reaper that can TAKE that lock knows the holder is gone,
// because the kernel would not have released it otherwise. A reaper that cannot
// take it leaves the ledger completely alone.
//
// FAILING TO CLEAN IS RECOVERABLE. Removing a live job's device is not: it
// fails a different run, in a way that reads as a flaky test, on a host that
// looks clean. Every uncertain case therefore resolves to "leave it".
func TryLock(path string) (locked bool, release func(), err error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0) // #nosec G304 -- path comes from a directory listing of the configured state dir
	if err != nil {
		return false, nil, err
	}
	return tryLockFile(f)
}

// tryLockIn is TryLock for a ledger named inside the validated state directory,
// opened through its handle.
func tryLockIn(d *trustedDir, name string) (locked bool, release func(), err error) {
	f, err := d.root.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return false, nil, err
	}
	return tryLockFile(f)
}

// tryLockFile takes f's lock without waiting. It owns f: f is closed unless
// the lock is taken, in which case release closes it.
func tryLockFile(f *os.File) (locked bool, release func(), err error) {
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			// Someone is running. Not an error -- an answer.
			return false, nil, nil
		}
		return false, nil, err
	}

	return true, func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

const ledgerSuffix = ".ledger"

// Path returns the ledger's file path.
func (l *Ledger) Path() string { return l.path }

// RunID returns the id of the run the ledger belongs to.
func (l *Ledger) RunID() string { return l.runID }

// entries re-reads the ledger through the state directory's handle.
func (l *Ledger) entries() ([]Entry, error) {
	return readLedgerIn(l.dir, l.name)
}

// Record appends an entry and does not return until it is DURABLE.
//
// Call it before creating the resource, and treat a returned error as fatal to
// the operation you were about to perform. Creating the resource anyway
// produces host state nothing can attribute -- the exact condition this package
// exists to prevent -- and it does so silently.
func (l *Ledger) Record(kind Kind, value, identity string) error {
	if strings.ContainsAny(value+identity, "\t\n") {
		return &RecordError{Kind: kind, Value: value,
			Err: fmt.Errorf("a recorded value may not contain a tab or a newline, which are the record separators")}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	line := fmt.Sprintf("%s\t%s\t%s\n", kind, value, identity)
	if _, err := l.f.WriteString(line); err != nil {
		return &RecordError{Kind: kind, Value: value, Err: err}
	}

	// The fsync is the point of the exercise. Without it the record sits in the
	// page cache and a container killed a moment later takes it with the
	// resource still on the host.
	if err := l.f.Sync(); err != nil {
		return &RecordError{Kind: kind, Value: value, Err: err}
	}

	return nil
}

// Close releases the file. The ledger REMAINS on disk: its presence is what
// tells the next run that this one may have left state behind. Discard is what
// removes it, and only a run that cleaned up after itself may call that.
func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	err := l.f.Close()
	if derr := l.dir.Close(); err == nil {
		err = derr
	}
	return err
}

// Discard closes the ledger and deletes it, declaring that this run removed
// everything it created.
//
// It is deliberately separate from Close, and it is the only path that deletes
// a ledger without reaping it. A run that ends any other way -- a panic, a
// timeout, a SIGKILL -- leaves the file behind, which is precisely the signal
// the next run needs.
//
// The ledger is unlinked BEFORE its file is closed. Closing releases the lock,
// and a ledger that is visible and unlocked is a dead run's ledger to any
// other run's reaper: closing first let a sibling consume this run's record in
// the window before the unlink, and this run's own Remove then failed a clean
// run with ENOENT (Codex review on #247).
func (l *Ledger) Discard() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	defer func() { _ = l.dir.Close() }()
	rmErr := l.dir.root.Remove(l.name)
	ledgerCloseHook(l)
	closeErr := l.f.Close()
	if rmErr != nil {
		return rmErr
	}
	return closeErr
}

// ledgerCloseHook runs in Discard just before the ledger's file -- and with it
// the lock -- is released. It does nothing outside tests, which use it to look
// at the state directory at exactly that moment.
var ledgerCloseHook = func(*Ledger) {}

// ReadLedger parses one ledger file.
//
// A line it cannot parse is an error, not something to skip. Skipping would
// leave the reaper reporting a clean pass over a set it did not fully read.
func ReadLedger(path string) ([]Entry, error) {
	f, err := os.Open(path) // #nosec G304 -- path comes from a directory listing of the configured state dir
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return parseLedger(f, path)
}

// readLedgerIn reads a ledger named inside the validated state directory,
// through its handle.
func readLedgerIn(d *trustedDir, name string) ([]Entry, error) {
	f, err := d.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return parseLedger(f, filepath.Join(d.path, name))
}

// parseLedger parses one ledger's contents; path names it in errors.
func parseLedger(r io.Reader, path string) ([]Entry, error) {
	var entries []Entry
	scanner := bufio.NewScanner(r)
	for line := 1; scanner.Scan(); line++ {
		text := scanner.Text()
		if text == "" {
			continue
		}

		fields := strings.Split(text, "\t")
		if len(fields) != 3 {
			return nil, &CorruptLedgerError{Path: path, Line: line, Text: text}
		}

		kind := Kind(fields[0])
		if kind != KindMapping && kind != KindLoopBacking && kind != KindLoopRoot {
			return nil, &CorruptLedgerError{Path: path, Line: line, Text: text}
		}
		if fields[1] == "" {
			return nil, &CorruptLedgerError{Path: path, Line: line, Text: text}
		}

		entries = append(entries, Entry{Kind: kind, Value: fields[1], Identity: fields[2]})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

// NewRunID returns an identifier unique to this process on this host.
//
// The pid alone is not enough: pids are reused, and a container's pid namespace
// makes "1" overwhelmingly likely, so two runs would collide on the first
// entry. The start time disambiguates without needing a random source, and
// reads usefully in a directory listing.
func NewRunID(pid int, startNanos int64) string {
	return strconv.Itoa(pid) + "-" + strconv.FormatInt(startNanos, 36)
}
