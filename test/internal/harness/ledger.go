// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package harness records, write-ahead and by exact identity, the host state the integration suite creates (dm mappings, loop devices), so a later run removes exactly that state and nothing else.
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

// StateDirEnv names the environment variable holding the ledger directory, which must outlive the container.
const StateDirEnv = "LUKS2_TEST_STATE_DIR"

// StateDir returns the ledger directory: LUKS2_TEST_STATE_DIR, or a fixed path that outlives the run.
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

	// KindLoopRoot is a uniquely named directory this run created and set TMPDIR to; any loop device backed by a file under it is this run's.
	KindLoopRoot Kind = "loop-root"

	// KindLoopBacking is a loop device recorded by its backing file path, since the kernel picks the device minor.
	KindLoopBacking Kind = "loop-backing"
)

// Entry is one recorded resource.
type Entry struct {
	Kind  Kind
	Value string

	// Identity distinguishes this resource from another that later takes the same Value; KindMapping always carries one.
	Identity string
}

// Ledger is an append-only, fsync-on-write record of host state a run is about to create, safe for concurrent use; it holds an exclusive lock on its file for the run's life.
type Ledger struct {
	mu    sync.Mutex
	f     *os.File
	path  string
	name  string
	runID string
	// dir is the validated state directory's handle; the ledger is used through it, never by path.
	dir *trustedDir
}

// OpenLedger creates the ledger for one run; runID must be unique per run.
func OpenLedger(dir, runID string) (*Ledger, error) {
	// The directory is part of the trust boundary (statedir.go), checked on both writer and reaper paths.
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

	// Hold an exclusive flock for the run's life; the kernel releases it only when the holder dies, which tells a reaper the run is gone.
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		_ = sd.Close()
		return nil, &LockFileError{Action: "locking", Path: path, Err: err}
	}

	return &Ledger{f: f, path: path, name: name, runID: runID, dir: sd}, nil
}

// TryLock reports whether the run owning the ledger at path is gone, by taking its lock; if it cannot, the ledger is left alone.
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

// Record appends an entry and returns only once it is durable; call it before creating the resource and treat an error as fatal.
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

// Close releases the file but leaves the ledger on disk; Discard removes it.
func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	err := l.f.Close()
	if derr := l.dir.Close(); err == nil {
		err = derr
	}
	return err
}

// Discard deletes the ledger, declaring this run removed everything it created; it unlinks before closing so no other reaper can claim it.
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

// NewRunID returns an identifier unique to this process on this host, from the pid and start time.
func NewRunID(pid int, startNanos int64) string {
	return strconv.Itoa(pid) + "-" + strconv.FormatInt(startNanos, 36)
}
