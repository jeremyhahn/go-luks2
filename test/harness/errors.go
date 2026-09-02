// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"errors"
	"fmt"
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
