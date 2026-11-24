// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"errors"
	"fmt"
	"time"
)

// Sentinels for the conditions a caller can act on.
var (
	// ErrLedgerUnavailable indicates the write-ahead ledger could not be
	// opened or written, and that the caller must therefore NOT create host
	// state.
	//
	// It is fatal by design. The whole guarantee this package offers is that
	// nothing is created before it is recorded, so a caller that proceeds after
	// a failed record creates exactly the unattributable state the ledger
	// exists to prevent -- and it does so silently, which is worse than not
	// running. See Ledger.Record.
	ErrLedgerUnavailable = errors.New("the write-ahead ledger is unavailable, so host state must not be created")

	// ErrLedgerCorrupt indicates a ledger file could not be parsed.
	//
	// The reaper does not skip past a corrupt line and carry on. A ledger it
	// cannot read in full is a ledger whose contents it does not know, and
	// proceeding would report a clean reap having examined an unknown subset --
	// the failure mode a fail-closed guard exists to refuse.
	ErrLedgerCorrupt = errors.New("the write-ahead ledger could not be parsed")

	// ErrReapIncomplete indicates the reaper found recorded host state it could
	// not remove. The state is named in the error; the caller must not treat
	// the host as clean.
	ErrReapIncomplete = errors.New("recorded host state could not be removed")
)

// RecordError reports that a resource could not be recorded before creation.
type RecordError struct {
	Kind  Kind
	Value string
	Err   error
}

func (e *RecordError) Error() string {
	return fmt.Sprintf("%s: could not record %s %q before creating it: %v",
		ErrLedgerUnavailable.Error(), e.Kind, e.Value, e.Err)
}

func (e *RecordError) Unwrap() error { return e.Err }

// Is reports every RecordError as ErrLedgerUnavailable, so a caller can match
// the sentinel without knowing this type while errors.Is still reaches the
// underlying cause through Unwrap.
func (e *RecordError) Is(target error) bool { return target == ErrLedgerUnavailable }

// ReapError reports host state that a reap could not remove.
//
// It carries every failure rather than the first, because a caller deciding
// whether the host is usable needs the whole list: stopping at the first would
// under-report the damage and invite a retry that fixes one item and reports
// success.
type ReapError struct {
	Failures []ReapFailure
}

// ReapFailure is one resource the reaper could not remove.
type ReapFailure struct {
	Entry Entry
	Err   error
}

func (e *ReapError) Error() string {
	msg := fmt.Sprintf("%s (%d):", ErrReapIncomplete.Error(), len(e.Failures))
	for _, f := range e.Failures {
		msg += fmt.Sprintf("\n  %s %q: %v", f.Entry.Kind, f.Entry.Value, f.Err)
	}
	return msg
}

func (e *ReapError) Is(target error) bool { return target == ErrReapIncomplete }

// Unwrap returns the individual failures so errors.Is and errors.As reach the
// causes underneath.
func (e *ReapError) Unwrap() []error {
	errs := make([]error, 0, len(e.Failures))
	for _, f := range e.Failures {
		errs = append(errs, f.Err)
	}
	return errs
}

// CorruptLedgerError names the file and line that could not be parsed.
type CorruptLedgerError struct {
	Path string
	Line int
	Text string
}

func (e *CorruptLedgerError) Error() string {
	return fmt.Sprintf("%s: %s line %d: %q", ErrLedgerCorrupt.Error(), e.Path, e.Line, e.Text)
}

func (e *CorruptLedgerError) Is(target error) bool { return target == ErrLedgerCorrupt }

// StateDirError reports a state directory that cannot be used. Every one is an
// ErrLedgerUnavailable: nothing may be recorded or reaped through it.
type StateDirError struct {
	Dir     string
	Problem string
	Err     error
}

func (e *StateDirError) Error() string {
	msg := ErrLedgerUnavailable.Error() + ": state directory"
	if e.Dir != "" {
		msg += " " + e.Dir
	}
	msg += ": " + e.Problem
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *StateDirError) Unwrap() error { return e.Err }

func (e *StateDirError) Is(target error) bool { return target == ErrLedgerUnavailable }

// RunRootError reports a recorded run root that is not shaped like a directory
// this suite creates. A ledger is a file, and a damaged or forged line must not
// be able to aim a recursive removal or a loop detach at, say, /var/lib/snapd.
type RunRootError struct {
	Action  string
	Path    string
	Problem string
}

func (e *RunRootError) Error() string {
	return fmt.Sprintf("refusing to %s %q: %s", e.Action, e.Path, e.Problem)
}

// UnboundRunRootError reports a recorded run root whose name does not carry the
// id of the run whose ledger recorded it, while loop devices are backed under
// it. Those devices may be a LIVE run's: before #247 a run root was named only
// by a 32-bit random suffix, so two containers could create the same name. They
// are left alone, the record is kept, and the host is not declared clean.
type UnboundRunRootError struct {
	Root    string
	RunID   string
	Devices []LoopDevice
}

func (e *UnboundRunRootError) Error() string {
	return fmt.Sprintf("%q was recorded by run %s but is not named for it (%s%s-<n>), and loop devices %v are "+
		"backed under it -- they may belong to another, live run with the same root name, so they are left "+
		"alone. If no integration run is live on this host, detach them by hand and delete the ledger",
		e.Root, e.RunID, runRootPrefix, e.RunID, e.Devices)
}

// LockFileError reports a ledger or the reaper mutex that could not be opened
// or locked. Nothing may be recorded or reaped without it, so it is an
// ErrLedgerUnavailable.
type LockFileError struct {
	Action string // "opening" or "locking"
	Path   string
	Err    error
}

func (e *LockFileError) Error() string {
	return fmt.Sprintf("%s: %s %s: %v", ErrLedgerUnavailable.Error(), e.Action, e.Path, e.Err)
}

func (e *LockFileError) Unwrap() error { return e.Err }

func (e *LockFileError) Is(target error) bool { return target == ErrLedgerUnavailable }

// ReaperBusyError reports another reaper holding the host-wide mutex past the
// wait bound. Something is wedged, and the host is not known to be clean.
type ReaperBusyError struct {
	Path   string
	Waited time.Duration
}

func (e *ReaperBusyError) Error() string {
	return fmt.Sprintf("%s: another reaper has held %s for over %s; this host is not known to be clean",
		ErrReapIncomplete.Error(), e.Path, e.Waited)
}

func (e *ReaperBusyError) Is(target error) bool { return target == ErrReapIncomplete }
